//! ntfy push with two signed one-time action buttons.

use serde::Serialize;
use std::time::Duration;

use crate::config::Config;

#[derive(Serialize)]
struct Action {
    action: &'static str,
    label: String,
    url: String,
    /// Only meaningful for `action: "http"`; omitted for "view" links.
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<&'static str>,
    clear: bool,
}

#[derive(Serialize)]
struct Message {
    topic: String,
    title: String,
    message: String,
    priority: u8,
    tags: Vec<String>,
    actions: Vec<Action>,
}

/// Fire-and-forget: a failing push must never block the approval flow, the
/// request is still visible in the dashboard.
pub async fn send_approval_push(
    cfg: &Config,
    request_id: &str,
    agent: &str,
    item_name: &str,
    fields: &[String],
    approve_tok: &str,
    deny_tok: &str,
) -> Result<(), String> {
    if cfg.ntfy_url.is_empty() || cfg.ntfy_topic.is_empty() {
        return Err("ntfy nicht konfiguriert".into());
    }
    let base = cfg.public_url.trim_end_matches('/');
    let msg = Message {
        topic: cfg.ntfy_topic.clone(),
        title: format!("Zugriff auf \"{item_name}\""),
        message: format!(
            "Agent \"{agent}\" möchte: {}\nGültig {} Minuten.",
            fields.join(", "),
            (cfg.request_ttl / 60).max(1)
        ),
        priority: 4,
        tags: vec!["closed_lock_with_key".into()],
        actions: vec![
            Action {
                action: "http",
                label: "Freigeben".into(),
                url: format!("{base}/approve/{request_id}/{approve_tok}"),
                method: Some("GET"),
                clear: true,
            },
            Action {
                action: "http",
                label: "Verweigern".into(),
                url: format!("{base}/deny/{request_id}/{deny_tok}"),
                method: Some("GET"),
                clear: true,
            },
        ],
    };

    post(cfg, &msg).await
}

/// One-time reminder that the sidecar vault is locked and nothing can be
/// delivered until someone unlocks it in the dashboard.
pub async fn send_locked_push(cfg: &Config) -> Result<(), String> {
    if cfg.ntfy_url.is_empty() || cfg.ntfy_topic.is_empty() {
        return Err("ntfy nicht konfiguriert".into());
    }
    let base = cfg.public_url.trim_end_matches('/');
    let msg = Message {
        topic: cfg.ntfy_topic.clone(),
        title: "Agent-Broker gesperrt".into(),
        message: "Der Tresor des Agent-Kontos ist gesperrt. Bis zum Entsperren im \
Dashboard bekommen Agents keine Zugangsdaten."
            .into(),
        priority: 4,
        tags: vec!["lock".into()],
        actions: vec![Action {
            action: "view",
            label: "Dashboard öffnen".into(),
            url: format!("{base}/admin"),
            method: None,
            clear: false,
        }],
    };
    post(cfg, &msg).await
}

async fn post(cfg: &Config, msg: &Message) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;

    let mut req = client.post(cfg.ntfy_url.trim_end_matches('/')).json(msg);
    if !cfg.ntfy_token.is_empty() {
        req = req.header("Authorization", format!("Bearer {}", cfg.ntfy_token));
    }

    let resp = req.send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("ntfy HTTP {}", resp.status()));
    }
    Ok(())
}
