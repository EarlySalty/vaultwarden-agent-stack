//! Configuration loading: TOML file with environment overrides.

use serde::Deserialize;
use std::path::Path;

use crate::policy::Policy;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Listen address of the broker itself.
    #[serde(default = "d_bind")]
    pub bind: String,

    /// Publicly reachable base URL, used to build the signed ntfy action links.
    #[serde(default = "d_public_url")]
    pub public_url: String,

    /// Base URL of the `bw serve` sidecar (internal docker network only).
    #[serde(default = "d_bw_url")]
    pub bw_url: String,

    /// Seconds between automatic `bw sync` calls. 0 disables periodic sync.
    #[serde(default = "d_sync_interval")]
    pub sync_interval: u64,

    /// Policy applied to vault items without an `agent-policy` custom field.
    #[serde(default = "d_default_policy")]
    pub default_policy: Policy,

    /// Seconds an approval request stays valid.
    #[serde(default = "d_request_ttl")]
    pub request_ttl: i64,

    /// Maximum agent API requests per token per minute.
    #[serde(default = "d_rate_limit")]
    pub rate_limit: u32,

    /// SQLite file.
    #[serde(default = "d_db_path")]
    pub db_path: String,

    /// ntfy server base URL (self-hosted or https://ntfy.sh).
    #[serde(default)]
    pub ntfy_url: String,
    #[serde(default)]
    pub ntfy_topic: String,
    /// Optional bearer token for protected ntfy topics.
    #[serde(default)]
    pub ntfy_token: String,

    /// HTTP basic auth for /admin.
    #[serde(default = "d_admin_user")]
    pub admin_user: String,
    #[serde(default)]
    pub admin_pass: String,

    /// HMAC key for the one-time approval links. Must be set.
    #[serde(default)]
    pub server_secret: String,
}

fn d_bind() -> String {
    "0.0.0.0:8088".into()
}
fn d_public_url() -> String {
    "http://localhost:8088".into()
}
fn d_bw_url() -> String {
    "http://bw:8087".into()
}
fn d_sync_interval() -> u64 {
    60
}
fn d_default_policy() -> Policy {
    Policy::Ask
}
fn d_request_ttl() -> i64 {
    300
}
fn d_rate_limit() -> u32 {
    120
}
fn d_db_path() -> String {
    "/data/broker.db".into()
}
fn d_admin_user() -> String {
    "admin".into()
}

impl Config {
    pub fn load(path: &str) -> Result<Self, String> {
        let mut cfg: Config = if Path::new(path).exists() {
            let raw = std::fs::read_to_string(path)
                .map_err(|e| format!("config {path} nicht lesbar: {e}"))?;
            toml::from_str(&raw).map_err(|e| format!("config {path} ungueltig: {e}"))?
        } else {
            // Allow a pure-environment deployment (e.g. plain docker run).
            toml::from_str("").map_err(|e| format!("interner Defaultfehler: {e}"))?
        };

        // Environment wins over the file so secrets can stay out of the image.
        env_str("BROKER_BIND", &mut cfg.bind);
        env_str("BROKER_PUBLIC_URL", &mut cfg.public_url);
        env_str("BROKER_BW_URL", &mut cfg.bw_url);
        env_str("BROKER_DB_PATH", &mut cfg.db_path);
        env_str("BROKER_NTFY_URL", &mut cfg.ntfy_url);
        env_str("BROKER_NTFY_TOPIC", &mut cfg.ntfy_topic);
        env_str("BROKER_NTFY_TOKEN", &mut cfg.ntfy_token);
        env_str("BROKER_ADMIN_USER", &mut cfg.admin_user);
        env_str("BROKER_ADMIN_PASS", &mut cfg.admin_pass);
        env_str("BROKER_SERVER_SECRET", &mut cfg.server_secret);
        if let Ok(v) = std::env::var("BROKER_SYNC_INTERVAL") {
            if let Ok(n) = v.parse() {
                cfg.sync_interval = n;
            }
        }
        if let Ok(v) = std::env::var("BROKER_REQUEST_TTL") {
            if let Ok(n) = v.parse() {
                cfg.request_ttl = n;
            }
        }
        if let Ok(v) = std::env::var("BROKER_RATE_LIMIT") {
            if let Ok(n) = v.parse() {
                cfg.rate_limit = n;
            }
        }
        if let Ok(v) = std::env::var("BROKER_DEFAULT_POLICY") {
            if let Some(p) = Policy::parse(&v) {
                cfg.default_policy = p;
            }
        }

        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), String> {
        if self.server_secret.len() < 16 {
            return Err(
                "server_secret fehlt oder ist zu kurz (mind. 16 Zeichen). Erzeugen z.B. mit: openssl rand -hex 32"
                    .into(),
            );
        }
        if self.admin_pass.is_empty() {
            return Err("admin_pass fehlt - das Dashboard waere sonst ungeschuetzt.".into());
        }
        if self.ntfy_url.is_empty() || self.ntfy_topic.is_empty() {
            tracing::warn!(
                "ntfy_url/ntfy_topic nicht gesetzt - Freigaben sind nur ueber das Dashboard moeglich"
            );
        }
        Ok(())
    }
}

fn env_str(key: &str, slot: &mut String) {
    if let Ok(v) = std::env::var(key) {
        if !v.is_empty() {
            *slot = v;
        }
    }
}
