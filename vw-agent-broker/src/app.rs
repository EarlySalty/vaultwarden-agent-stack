//! Shared application state, token hashing, HMAC link signing, rate limiting.

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::bw::BwClient;
use crate::config::Config;
use crate::db::Db;

pub type Shared = Arc<AppState>;

pub struct AppState {
    pub cfg: Config,
    pub db: Db,
    pub bw: BwClient,
    /// token_id -> (window start unix minute, count in window)
    limiter: Mutex<HashMap<i64, (i64, u32)>>,
    /// Cached lock state of the bw sidecar.
    vault_unlocked: AtomicBool,
    /// True once the "vault is locked" push went out for the current episode.
    lock_notified: AtomicBool,
}

impl AppState {
    pub fn new(cfg: Config, db: Db) -> AppState {
        let bw = BwClient::new(&cfg.bw_url);
        AppState {
            cfg,
            db,
            bw,
            limiter: Mutex::new(HashMap::new()),
            // Pessimistic until the first /status check succeeds.
            vault_unlocked: AtomicBool::new(false),
            lock_notified: AtomicBool::new(false),
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.vault_unlocked.load(Ordering::Relaxed)
    }

    pub fn set_unlocked(&self, v: bool) {
        self.vault_unlocked.store(v, Ordering::Relaxed);
        if v {
            // Arm the notification again for the next locked episode.
            self.lock_notified.store(false, Ordering::Relaxed);
        }
    }

    /// True exactly once per locked episode - keeps ntfy from spamming.
    pub fn take_lock_notice(&self) -> bool {
        !self.lock_notified.swap(true, Ordering::Relaxed)
    }

    /// Fixed-window limiter: max `rate_limit` calls per token per minute.
    pub fn rate_ok(&self, token_id: i64) -> bool {
        if self.cfg.rate_limit == 0 {
            return true;
        }
        let window = crate::db::now() / 60;
        let mut m = self.limiter.lock().unwrap_or_else(|e| e.into_inner());
        // Drop stale buckets so the map cannot grow unbounded.
        m.retain(|_, (w, _)| *w >= window - 1);
        let e = m.entry(token_id).or_insert((window, 0));
        if e.0 != window {
            *e = (window, 0);
        }
        e.1 += 1;
        e.1 <= self.cfg.rate_limit
    }
}

// ------------------------------------------------------------------- secrets

pub fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

/// 256 bit of randomness, hex encoded (uuid v4 is CSPRNG-backed).
pub fn new_secret_hex() -> String {
    let a = uuid::Uuid::new_v4();
    let b = uuid::Uuid::new_v4();
    let mut buf = [0u8; 32];
    buf[..16].copy_from_slice(a.as_bytes());
    buf[16..].copy_from_slice(b.as_bytes());
    hex::encode(buf)
}

type HmacSha256 = Hmac<Sha256>;

/// Signature for a one-time approval link. Bound to action + request id;
/// single use and expiry are enforced by the request row itself.
pub fn sign_action(secret: &str, action: &str, request_id: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac accepts any key size");
    mac.update(action.as_bytes());
    mac.update(b":");
    mac.update(request_id.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify_action(secret: &str, action: &str, request_id: &str, provided: &str) -> bool {
    let Ok(raw) = hex::decode(provided) else {
        return false;
    };
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac accepts any key size");
    mac.update(action.as_bytes());
    mac.update(b":");
    mac.update(request_id.as_bytes());
    mac.verify_slice(&raw).is_ok()
}

// --------------------------------------------------------------------- error

pub struct ApiError {
    pub status: StatusCode,
    pub msg: String,
}

impl ApiError {
    pub fn new(status: StatusCode, msg: impl Into<String>) -> ApiError {
        ApiError {
            status,
            msg: msg.into(),
        }
    }
    pub fn unauthorized(m: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::UNAUTHORIZED, m)
    }
    pub fn forbidden(m: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::FORBIDDEN, m)
    }
    pub fn not_found(m: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::NOT_FOUND, m)
    }
    pub fn bad_request(m: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::BAD_REQUEST, m)
    }
    pub fn internal(m: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, m)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.msg }))).into_response()
    }
}

// ---------------------------------------------------------------------- auth

/// Bearer-token auth for the agent API. Also bumps `last_used_at`.
pub fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<crate::db::TokenRow, ApiError> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            state.db.audit(
                "agent",
                "auth",
                None,
                None,
                None,
                "error",
                Some("kein Bearer-Token"),
            );
            ApiError::unauthorized("Bearer-Token fehlt")
        })?;

    let hash = sha256_hex(raw);
    let tok = state
        .db
        .token_by_hash(&hash)
        .map_err(|e| ApiError::internal(format!("DB: {e}")))?;

    let Some(tok) = tok else {
        state.db.audit(
            "agent",
            "auth",
            None,
            None,
            None,
            "denied",
            Some("unbekanntes Token"),
        );
        return Err(ApiError::unauthorized("Token unbekannt"));
    };
    if tok.revoked {
        state.db.audit(
            "agent",
            "auth",
            Some(&tok.name),
            None,
            None,
            "denied",
            Some("Token widerrufen"),
        );
        return Err(ApiError::unauthorized("Token widerrufen"));
    }

    if !state.rate_ok(tok.id) {
        state.db.audit(
            "agent",
            "rate_limit",
            Some(&tok.name),
            None,
            None,
            "denied",
            Some("Limit ueberschritten"),
        );
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "Rate-Limit erreicht",
        ));
    }

    state.db.touch_token(tok.id);
    Ok(tok)
}

// -------------------------------------------------------------- lock state

/// Ask the sidecar for its lock state and refresh the cache. When the vault
/// turns out to be locked, send exactly one ntfy reminder per locked episode.
/// Returns the raw state: "unlocked", "locked", "unauthenticated" or
/// "unreachable".
pub async fn refresh_lock_state(st: &Shared) -> String {
    match st.bw.vault_status().await {
        Ok(s) if s == "unlocked" => {
            st.set_unlocked(true);
            s
        }
        Ok(s) => {
            st.set_unlocked(false);
            // Only a confirmed "locked" is worth a push. "unauthenticated"
            // means the sidecar login failed - unlocking would not fix that.
            if s == "locked" {
                if st.take_lock_notice() {
                    let sent = crate::ntfy::send_locked_push(&st.cfg).await;
                    if let Err(e) = &sent {
                        tracing::warn!("ntfy-Hinweis (gesperrt) fehlgeschlagen: {e}");
                    }
                    st.db.audit(
                        "system",
                        "vault_locked",
                        None,
                        None,
                        None,
                        "locked",
                        Some(&match sent {
                            Ok(_) => "Hinweis per ntfy verschickt".to_string(),
                            Err(e) => format!("ntfy fehlgeschlagen: {e}"),
                        }),
                    );
                }
            } else {
                tracing::warn!("bw meldet Status \"{s}\"");
            }
            s
        }
        Err(e) => {
            // Sidecar unreachable: stay closed, but do not burn the one-time
            // push - this is a different problem than a locked vault.
            st.set_unlocked(false);
            tracing::warn!("bw-Status nicht abrufbar: {e}");
            "unreachable".to_string()
        }
    }
}

/// HTTP basic auth for the dashboard.
/// Returns `None` when the credentials are valid, otherwise the 401 response.
pub fn admin_auth(state: &AppState, headers: &HeaderMap) -> Option<Response> {
    use base64::Engine;

    let ok = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b.trim()).ok())
        .and_then(|d| String::from_utf8(d).ok())
        .map(|s| {
            let (u, p) = s.split_once(':').unwrap_or((s.as_str(), ""));
            // Constant-time-ish compare via fixed-size digests.
            sha256_hex(u) == sha256_hex(&state.cfg.admin_user)
                && sha256_hex(p) == sha256_hex(&state.cfg.admin_pass)
        })
        .unwrap_or(false);

    if ok {
        return None;
    }
    Some(
        (
            StatusCode::UNAUTHORIZED,
            [(
                axum::http::header::WWW_AUTHENTICATE,
                "Basic realm=\"vw-agent-broker\"",
            )],
            "Anmeldung erforderlich",
        )
            .into_response(),
    )
}
