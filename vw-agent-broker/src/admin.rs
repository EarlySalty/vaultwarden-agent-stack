//! Dashboard (HTTP basic auth) and its JSON API.

use axum::extract::{Path, Query, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{Html, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::app::{admin_auth, new_secret_hex, sha256_hex, ApiError, Shared};
use crate::db::{ST_APPROVED, ST_DENIED};
use crate::policy::Policy;

const DASHBOARD: &str = include_str!("static/dashboard.html");

pub fn routes(state: Shared) -> Router<Shared> {
    Router::new()
        .route("/admin", get(dashboard))
        .route("/admin/", get(dashboard))
        .route("/admin/audit", get(audit))
        .route("/admin/api/settings", get(settings))
        .route("/admin/api/unlock", post(unlock))
        .route("/admin/api/requests", get(list_requests))
        .route("/admin/api/requests/{id}/approve", post(approve))
        .route("/admin/api/requests/{id}/deny", post(deny))
        .route("/admin/api/rules", get(list_rules))
        .route("/admin/api/rules/{id}", delete(delete_rule))
        .route("/admin/api/tokens", get(list_tokens).post(create_token))
        .route("/admin/api/tokens/{id}", delete(revoke_token))
        .layer(axum::middleware::from_fn_with_state(state, guard))
}

/// Basic-auth gate for everything under /admin.
async fn guard(State(st): State<Shared>, req: Request, next: Next) -> Response {
    if let Some(resp) = admin_auth(&st, req.headers()) {
        return resp;
    }
    next.run(req).await
}

async fn dashboard() -> Html<&'static str> {
    Html(DASHBOARD)
}

async fn settings(State(st): State<Shared>) -> Json<Value> {
    Json(json!({
        "default_policy": st.cfg.default_policy.as_str(),
        "request_ttl": st.cfg.request_ttl,
        "rate_limit": st.cfg.rate_limit,
        "sync_interval": st.cfg.sync_interval,
        "bw_url": st.cfg.bw_url,
        "ntfy_url": st.cfg.ntfy_url,
        "ntfy_topic": st.cfg.ntfy_topic,
        "public_url": st.cfg.public_url,
        "policy_field": crate::bw::POLICY_FIELD,
    }))
}

/// Master password of the agent account. Deliberately NOT `Debug`, so it can
/// never end up in a log line by accident.
#[derive(Deserialize)]
struct UnlockBody {
    password: String,
}

/// Unlock the bw sidecar. The password is used for exactly one upstream call
/// and is never logged, never audited and never written to the database.
async fn unlock(
    State(st): State<Shared>,
    Json(b): Json<UnlockBody>,
) -> Result<Json<Value>, ApiError> {
    if b.password.is_empty() {
        return Err(ApiError::bad_request("Passwort fehlt"));
    }
    match st.bw.unlock(&b.password).await {
        Ok(()) => {
            st.set_unlocked(true);
            // Audit records the event only - never the secret.
            st.db.audit(
                "dashboard",
                "unlock",
                None,
                None,
                None,
                "unlocked",
                Some("Tresor per Dashboard entsperrt"),
            );
            // Pick up everything that changed while the vault was locked.
            let bg = st.clone();
            tokio::spawn(async move {
                if let Err(e) = bg.bw.sync().await {
                    tracing::warn!("Sync nach Entsperren fehlgeschlagen: {e}");
                }
            });
            Ok(Json(json!({"status": "unlocked"})))
        }
        Err(e) => {
            st.db.audit(
                "dashboard",
                "unlock",
                None,
                None,
                None,
                "error",
                Some("Entsperren fehlgeschlagen"),
            );
            Err(ApiError::new(
                StatusCode::BAD_GATEWAY,
                format!("Entsperren fehlgeschlagen: {e}"),
            ))
        }
    }
}

fn limit_of(q: &HashMap<String, String>, default: i64, max: i64) -> i64 {
    q.get("limit")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(default)
        .clamp(1, max)
}

async fn audit(
    State(st): State<Shared>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let rows = st
        .db
        .list_audit(limit_of(&q, 100, 2000))
        .map_err(|e| ApiError::internal(format!("DB: {e}")))?;
    Ok(Json(json!({ "audit": rows })))
}

async fn list_requests(
    State(st): State<Shared>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let _ = st.db.expire_stale();
    let pending_only = q.get("status").map(|s| s == "pending").unwrap_or(false);
    let rows = st
        .db
        .list_requests(pending_only, limit_of(&q, 50, 500))
        .map_err(|e| ApiError::internal(format!("DB: {e}")))?;
    Ok(Json(json!({ "requests": rows, "now": crate::db::now() })))
}

#[derive(Deserialize, Default)]
struct ApproveBody {
    /// "none" | "1h" | "24h" | "forever"
    #[serde(default)]
    remember: Option<String>,
}

async fn approve(
    State(st): State<Shared>,
    Path(id): Path<String>,
    body: Option<Json<ApproveBody>>,
) -> Result<Json<Value>, ApiError> {
    let _ = st.db.expire_stale();
    let req = st
        .db
        .request(&id)
        .map_err(|e| ApiError::internal(format!("DB: {e}")))?
        .ok_or_else(|| ApiError::not_found("Anfrage unbekannt"))?;

    let ok = st
        .db
        .decide_request(&id, ST_APPROVED, "dashboard")
        .map_err(|e| ApiError::internal(format!("DB: {e}")))?;
    if !ok {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!("Anfrage ist bereits {}", req.status),
        ));
    }

    // Optional remember rule. "forever" lives in the broker DB only - the
    // vault item stays untouched.
    let remember = body.and_then(|b| b.0.remember).unwrap_or_else(|| "none".into());
    let expires = match remember.as_str() {
        "1h" => Some(crate::db::now() + 3600),
        "24h" => Some(crate::db::now() + 86_400),
        "forever" | "immer" => None,
        _ => {
            st.db.audit(
                "dashboard",
                "approve",
                Some(&req.agent),
                Some(&req.item_id),
                Some(&req.item_name),
                ST_APPROVED,
                Some(&format!("request={id}")),
            );
            return Ok(Json(json!({"status":"approved","remember":"none"})));
        }
    };
    st.db
        .upsert_rule(&req.item_id, &req.item_name, req.token_id, &req.agent, expires)
        .map_err(|e| ApiError::internal(format!("DB: {e}")))?;
    st.db.audit(
        "dashboard",
        "approve",
        Some(&req.agent),
        Some(&req.item_id),
        Some(&req.item_name),
        ST_APPROVED,
        Some(&format!("request={id} merken={remember}")),
    );
    Ok(Json(json!({"status":"approved","remember":remember})))
}

async fn deny(State(st): State<Shared>, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    let _ = st.db.expire_stale();
    let req = st
        .db
        .request(&id)
        .map_err(|e| ApiError::internal(format!("DB: {e}")))?
        .ok_or_else(|| ApiError::not_found("Anfrage unbekannt"))?;
    let ok = st
        .db
        .decide_request(&id, ST_DENIED, "dashboard")
        .map_err(|e| ApiError::internal(format!("DB: {e}")))?;
    if !ok {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!("Anfrage ist bereits {}", req.status),
        ));
    }
    st.db.audit(
        "dashboard",
        "deny",
        Some(&req.agent),
        Some(&req.item_id),
        Some(&req.item_name),
        ST_DENIED,
        Some(&format!("request={id}")),
    );
    Ok(Json(json!({"status":"denied"})))
}

async fn list_rules(State(st): State<Shared>) -> Result<Json<Value>, ApiError> {
    let _ = st.db.purge_expired_rules();
    let rows = st
        .db
        .list_rules()
        .map_err(|e| ApiError::internal(format!("DB: {e}")))?;
    Ok(Json(json!({ "rules": rows, "now": crate::db::now() })))
}

async fn delete_rule(
    State(st): State<Shared>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    let n = st
        .db
        .delete_rule(id)
        .map_err(|e| ApiError::internal(format!("DB: {e}")))?;
    st.db.audit(
        "dashboard",
        "rule_delete",
        None,
        None,
        None,
        if n > 0 { "ok" } else { "not_found" },
        Some(&format!("rule={id}")),
    );
    Ok(Json(json!({ "deleted": n })))
}

async fn list_tokens(State(st): State<Shared>) -> Result<Json<Value>, ApiError> {
    let rows = st
        .db
        .list_tokens()
        .map_err(|e| ApiError::internal(format!("DB: {e}")))?;
    Ok(Json(json!({ "tokens": rows })))
}

#[derive(Deserialize)]
struct NewToken {
    name: String,
    #[serde(default)]
    allowed_collections: Vec<String>,
    #[serde(default)]
    max_policy: Option<String>,
}

async fn create_token(
    State(st): State<Shared>,
    Json(b): Json<NewToken>,
) -> Result<Json<Value>, ApiError> {
    let name = b.name.trim().to_string();
    if name.is_empty() {
        return Err(ApiError::bad_request("Name fehlt"));
    }
    let max_policy = match b.max_policy.as_deref() {
        None | Some("") | Some("none") => None,
        Some(s) => Some(Policy::parse(s).ok_or_else(|| {
            ApiError::bad_request("max_policy muss auto, ask oder deny sein")
        })?),
    };
    let cols: Vec<String> = b
        .allowed_collections
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let secret = new_secret_hex();
    let hash = sha256_hex(&secret);
    st.db
        .create_token(&name, &hash, Some(&cols), max_policy)
        .map_err(|e| ApiError::bad_request(format!("Token anlegen fehlgeschlagen: {e}")))?;

    st.db.audit(
        "dashboard",
        "token_create",
        Some(&name),
        None,
        None,
        "ok",
        Some(&format!(
            "max_policy={} sammlungen={}",
            max_policy.map(|p| p.as_str()).unwrap_or("-"),
            if cols.is_empty() {
                "alle".to_string()
            } else {
                cols.len().to_string()
            }
        )),
    );
    // The plaintext token is shown exactly once.
    Ok(Json(json!({ "name": name, "token": secret })))
}

async fn revoke_token(
    State(st): State<Shared>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    let name = st
        .db
        .token_by_id(id)
        .ok()
        .flatten()
        .map(|t| t.name)
        .unwrap_or_default();
    let n = st
        .db
        .revoke_token(id)
        .map_err(|e| ApiError::internal(format!("DB: {e}")))?;
    st.db.audit(
        "dashboard",
        "token_revoke",
        Some(&name),
        None,
        None,
        if n > 0 { "ok" } else { "not_found" },
        Some(&format!("token={id}")),
    );
    Ok(Json(json!({ "revoked": n })))
}
