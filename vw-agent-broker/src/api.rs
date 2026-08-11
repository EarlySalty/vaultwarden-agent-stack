//! Agent-facing REST API (Bearer auth) plus the signed ntfy approval links.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::app::{authenticate, sign_action, verify_action, ApiError, Shared};
use crate::bw::{BwError, Item, POLICY_FIELD};
use crate::db::{self, RequestRow, ST_APPROVED, ST_DENIED, ST_EXPIRED, ST_PENDING};
use crate::policy::{decide, Decision, Policy};

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/items", get(list_items))
        .route("/v1/items/{id}/credentials", post(request_credentials))
        .route("/v1/requests/{id}", get(get_request))
        .route("/approve/{id}/{tok}", get(approve_link))
        .route("/deny/{id}/{tok}", get(deny_link))
}

pub const LOCKED_MSG: &str = "Broker gesperrt - im Dashboard entsperren";

fn bw_err(e: BwError) -> ApiError {
    match e {
        BwError::NotFound => ApiError::not_found("Eintrag nicht gefunden"),
        BwError::Locked => ApiError::new(StatusCode::SERVICE_UNAVAILABLE, LOCKED_MSG),
        other => ApiError::new(StatusCode::BAD_GATEWAY, other.to_string()),
    }
}

/// Gate for every /v1 endpoint. Uses the cached lock state and only re-checks
/// live when it believes the vault is locked, so the hot path stays cheap and
/// a stale "locked" heals itself.
async fn ensure_unlocked(st: &Shared) -> Result<(), ApiError> {
    if st.is_unlocked() || crate::app::refresh_lock_state(st).await == "unlocked" {
        return Ok(());
    }
    Err(ApiError::new(StatusCode::SERVICE_UNAVAILABLE, LOCKED_MSG))
}

// -------------------------------------------------------------------- health

async fn healthz(State(st): State<Shared>) -> Response {
    // Doubles as the lock-state refresh: the dashboard polls this every few
    // seconds, which keeps the cached state warm and triggers the one-time
    // "vault is locked" push on a state change.
    let status = crate::app::refresh_lock_state(&st).await;
    let healthy = status == "unlocked";
    let code = if healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        code,
        Json(json!({
            "status": if healthy { "ok" } else { "degraded" },
            "bw": status,
            "locked": !healthy,
        })),
    )
        .into_response()
}

// --------------------------------------------------------------------- items

async fn list_items(
    State(st): State<Shared>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let tok = authenticate(&st, &headers)?;
    ensure_unlocked(&st).await?;
    let items = st.bw.list_items().await.map_err(bw_err)?;

    let mut out = Vec::new();
    for it in items
        .iter()
        .filter(|i| i.in_collections(tok.allowed_collections.as_ref()))
    {
        let remembered = st.db.rule_active(&it.id, tok.id).unwrap_or(false);
        let eff = decide(&Decision {
            item_policy: it.item_policy(),
            default_policy: st.cfg.default_policy,
            token_max: tok.max_policy,
            remembered,
        });
        // Never expose secrets in the listing.
        out.push(json!({
            "id": it.id,
            "name": it.name,
            "username": it.username(),
            "urls": it.urls(),
            "policy": eff.as_str(),
            "has_totp": it.has_totp(),
            // Metadata, no secrets: lets the operator discover the ids needed
            // for a token's allowed_collections.
            "organization_id": it.organization_id,
            "collection_ids": it.collection_ids,
        }));
    }

    st.db.audit(
        "agent",
        "list",
        Some(&tok.name),
        None,
        None,
        "ok",
        Some(&format!("{} Eintraege", out.len())),
    );
    Ok(Json(json!({ "items": out })))
}

#[derive(Deserialize, Default)]
pub struct CredReq {
    #[serde(default)]
    pub fields: Vec<String>,
}

async fn request_credentials(
    State(st): State<Shared>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Option<Json<CredReq>>,
) -> Result<Response, ApiError> {
    let tok = authenticate(&st, &headers)?;
    if let Err(e) = ensure_unlocked(&st).await {
        st.db.audit(
            "agent",
            "request",
            Some(&tok.name),
            Some(&id),
            None,
            "error",
            Some("Tresor gesperrt"),
        );
        return Err(e);
    }
    let mut fields = body.map(|b| b.0.fields).unwrap_or_default();
    if fields.is_empty() {
        fields = vec!["password".to_string()];
    }
    if fields.len() > 16 {
        return Err(ApiError::bad_request("zu viele Felder angefragt"));
    }

    let item = st.bw.item(&id).await.map_err(bw_err)?;

    if !item.in_collections(tok.allowed_collections.as_ref()) {
        st.db.audit(
            "agent",
            "request",
            Some(&tok.name),
            Some(&item.id),
            Some(&item.name),
            "denied",
            Some("ausserhalb der erlaubten Sammlungen"),
        );
        return Err(ApiError::forbidden(
            "Eintrag liegt ausserhalb der fuer dieses Token erlaubten Sammlungen",
        ));
    }

    let remembered = st.db.rule_active(&item.id, tok.id).unwrap_or(false);
    let eff = decide(&Decision {
        item_policy: item.item_policy(),
        default_policy: st.cfg.default_policy,
        token_max: tok.max_policy,
        remembered,
    });

    match eff {
        Policy::Deny => {
            st.db.audit(
                "agent",
                "request",
                Some(&tok.name),
                Some(&item.id),
                Some(&item.name),
                "denied",
                Some("policy=deny"),
            );
            Err(ApiError::forbidden(
                "Zugriff durch Policy verweigert (agent-policy=deny)",
            ))
        }
        Policy::Auto => {
            let values = collect_values(&st, &item, &fields).await?;
            st.db.audit(
                "agent",
                "deliver",
                Some(&tok.name),
                Some(&item.id),
                Some(&item.name),
                "ok",
                Some(&format!(
                    "policy={} felder={}",
                    if remembered { "auto(merken)" } else { "auto" },
                    fields.join(",")
                )),
            );
            Ok((
                StatusCode::OK,
                Json(json!({
                    "status": "ok",
                    "policy": "auto",
                    "item": {"id": item.id, "name": item.name},
                    "values": values,
                })),
            )
                .into_response())
        }
        Policy::Ask => {
            let now = db::now();
            let req = RequestRow {
                id: uuid::Uuid::new_v4().to_string(),
                token_id: tok.id,
                agent: tok.name.clone(),
                item_id: item.id.clone(),
                item_name: item.name.clone(),
                fields: fields.clone(),
                status: ST_PENDING.to_string(),
                created_at: now,
                expires_at: now + st.cfg.request_ttl,
                decided_at: None,
                decided_by: None,
            };
            st.db
                .create_request(&req)
                .map_err(|e| ApiError::internal(format!("DB: {e}")))?;

            let approve_tok = sign_action(&st.cfg.server_secret, "approve", &req.id);
            let deny_tok = sign_action(&st.cfg.server_secret, "deny", &req.id);
            let push = crate::ntfy::send_approval_push(
                &st.cfg,
                &req.id,
                &tok.name,
                &item.name,
                &fields,
                &approve_tok,
                &deny_tok,
            )
            .await;
            if let Err(e) = &push {
                tracing::warn!("ntfy push fehlgeschlagen: {e}");
            }

            st.db.audit(
                "agent",
                "request",
                Some(&tok.name),
                Some(&item.id),
                Some(&item.name),
                "pending",
                Some(&format!(
                    "request={} felder={} ntfy={}",
                    req.id,
                    fields.join(","),
                    match &push {
                        Ok(_) => "ok".to_string(),
                        Err(e) => format!("fehler: {e}"),
                    }
                )),
            );

            Ok((
                StatusCode::ACCEPTED,
                Json(json!({
                    "status": "pending",
                    "policy": "ask",
                    "request_id": req.id,
                    "expires_at": req.expires_at,
                    "poll": format!("/v1/requests/{}", req.id),
                    "item": {"id": item.id, "name": item.name},
                })),
            )
                .into_response())
        }
    }
}

// ------------------------------------------------------------------ requests

async fn get_request(
    State(st): State<Shared>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let tok = authenticate(&st, &headers)?;
    ensure_unlocked(&st).await?;
    let _ = st.db.expire_stale();

    let req = st
        .db
        .request(&id)
        .map_err(|e| ApiError::internal(format!("DB: {e}")))?
        .ok_or_else(|| ApiError::not_found("Anfrage unbekannt oder bereits aufgeraeumt"))?;

    if req.token_id != tok.id {
        return Err(ApiError::not_found("Anfrage unbekannt"));
    }

    match req.status.as_str() {
        ST_PENDING => Ok(Json(json!({
            "status": "pending",
            "request_id": req.id,
            "expires_at": req.expires_at,
        }))
        .into_response()),

        ST_APPROVED => {
            // Single-use: claim the request BEFORE fetching, so a concurrent
            // poll cannot get the values a second time.
            let claimed = st
                .db
                .mark_delivered(&req.id)
                .map_err(|e| ApiError::internal(format!("DB: {e}")))?;
            if !claimed {
                return Ok(Json(json!({
                    "status": "delivered",
                    "detail": "Werte wurden bereits einmalig ausgeliefert"
                }))
                .into_response());
            }
            // Values are fetched fresh from bw at delivery time - never stored.
            let item = st.bw.item(&req.item_id).await.map_err(bw_err)?;
            let values = collect_values(&st, &item, &req.fields).await?;
            st.db.audit(
                "agent",
                "deliver",
                Some(&tok.name),
                Some(&req.item_id),
                Some(&req.item_name),
                "ok",
                Some(&format!(
                    "request={} freigegeben von {}",
                    req.id,
                    req.decided_by.as_deref().unwrap_or("?")
                )),
            );
            Ok(Json(json!({
                "status": "approved",
                "item": {"id": item.id, "name": item.name},
                "values": values,
            }))
            .into_response())
        }

        ST_DENIED => Ok(Json(json!({"status":"denied"})).into_response()),
        ST_EXPIRED => Ok(Json(json!({"status":"expired"})).into_response()),
        other => Ok(Json(json!({"status": other})).into_response()),
    }
}

// ------------------------------------------------------- ntfy one-time links

async fn approve_link(
    State(st): State<Shared>,
    Path((id, tok)): Path<(String, String)>,
) -> Html<String> {
    decide_via_link(st, id, tok, "approve").await
}

async fn deny_link(
    State(st): State<Shared>,
    Path((id, tok)): Path<(String, String)>,
) -> Html<String> {
    decide_via_link(st, id, tok, "deny").await
}

async fn decide_via_link(st: Shared, id: String, tok: String, action: &str) -> Html<String> {
    if !verify_action(&st.cfg.server_secret, action, &id, &tok) {
        st.db.audit(
            "ntfy",
            action,
            None,
            None,
            None,
            "error",
            Some(&format!("ungueltige Signatur fuer {id}")),
        );
        return page("Ungültiger Link", "Die Signatur passt nicht.", false);
    }
    let _ = st.db.expire_stale();

    let Ok(Some(req)) = st.db.request(&id) else {
        return page("Unbekannt", "Diese Anfrage existiert nicht (mehr).", false);
    };

    let status = if action == "approve" {
        ST_APPROVED
    } else {
        ST_DENIED
    };
    match st.db.decide_request(&id, status, "ntfy") {
        Ok(true) => {
            st.db.audit(
                "ntfy",
                action,
                Some(&req.agent),
                Some(&req.item_id),
                Some(&req.item_name),
                status,
                Some(&format!("request={id}")),
            );
            if action == "approve" {
                page(
                    "Freigegeben",
                    &format!(
                        "\"{}\" wurde für Agent \"{}\" freigegeben.",
                        req.item_name, req.agent
                    ),
                    true,
                )
            } else {
                page(
                    "Verweigert",
                    &format!("Der Zugriff auf \"{}\" wurde abgelehnt.", req.item_name),
                    false,
                )
            }
        }
        _ => page(
            "Nicht mehr möglich",
            &format!(
                "Diese Anfrage ist bereits entschieden oder abgelaufen (Status: {}).",
                req.status
            ),
            false,
        ),
    }
}

fn page(title: &str, body: &str, good: bool) -> Html<String> {
    let color = if good { "#4caf50" } else { "#d9534f" };
    Html(format!(
        "<!doctype html><html lang=\"de\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>{title}</title></head>\
<body style=\"background:#16191d;color:#e6e9ef;font-family:system-ui,sans-serif;\
display:flex;align-items:center;justify-content:center;height:100vh;margin:0\">\
<div style=\"text-align:center;max-width:32rem;padding:2rem\">\
<h1 style=\"color:{color};margin:0 0 .5rem\">{title}</h1>\
<p style=\"color:#a3adba;line-height:1.5\">{body}</p></div></body></html>"
    ))
}

// ------------------------------------------------------------------- helpers

/// Read the requested field values. Built-in names first, then custom fields.
/// The `agent-policy` field itself is never returned.
pub async fn collect_values(
    st: &Shared,
    item: &Item,
    fields: &[String],
) -> Result<Map<String, Value>, ApiError> {
    let mut out = Map::new();
    let login = item.login.clone().unwrap_or_default();

    for f in fields {
        let key = f.trim().to_ascii_lowercase();
        match key.as_str() {
            "password" => {
                out.insert("password".into(), json!(login.password));
            }
            "username" => {
                out.insert("username".into(), json!(login.username));
            }
            "notes" => {
                out.insert("notes".into(), json!(item.notes));
            }
            "uri" | "url" | "uris" | "urls" => {
                out.insert("urls".into(), json!(item.urls()));
            }
            "totp" | "totp_code" => {
                if !item.has_totp() {
                    out.insert("totp".into(), Value::Null);
                } else {
                    let code = st.bw.totp(&item.id).await.map_err(bw_err)?;
                    out.insert("totp".into(), json!(code));
                }
            }
            other => {
                if other.eq_ignore_ascii_case(POLICY_FIELD) {
                    continue;
                }
                let val = item.fields.as_ref().and_then(|list| {
                    list.iter()
                        .find(|cf| {
                            cf.name
                                .as_deref()
                                .map(|n| n.trim().eq_ignore_ascii_case(other))
                                .unwrap_or(false)
                        })
                        .and_then(|cf| cf.value.clone())
                });
                match val {
                    Some(v) => {
                        out.insert(f.clone(), json!(v));
                    }
                    None => {
                        return Err(ApiError::bad_request(format!("unbekanntes Feld: {f}")));
                    }
                }
            }
        }
    }
    Ok(out)
}
