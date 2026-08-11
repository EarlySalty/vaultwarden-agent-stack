//! Thin client for the Bitwarden CLI "Vault Management API" (`bw serve`).
//!
//! All Bitwarden crypto stays inside the official CLI - the broker only speaks
//! plain HTTP to the sidecar on the internal docker network.

use serde::Deserialize;
use std::time::Duration;

use crate::policy::Policy;

pub const POLICY_FIELD: &str = "agent-policy";

#[derive(Debug)]
pub enum BwError {
    Http(String),
    NotFound,
    Locked,
    Api(String),
}

impl std::fmt::Display for BwError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BwError::Http(e) => write!(f, "bw nicht erreichbar: {e}"),
            BwError::NotFound => write!(f, "Eintrag nicht gefunden"),
            BwError::Locked => write!(f, "bw-Tresor ist gesperrt"),
            BwError::Api(m) => write!(f, "bw-Fehler: {m}"),
        }
    }
}

/// `bw serve` always answers with {"success":bool,"data":...,"message":...}.
/// Kept non-generic on purpose: a generic `data` field plus `serde(default)`
/// would drag a `Default` bound onto every payload type.
#[derive(Deserialize)]
struct Envelope {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    data: Option<serde_json::Value>,
    #[serde(default)]
    message: Option<String>,
}

#[derive(Deserialize)]
struct ListData<T> {
    #[serde(default = "Vec::new")]
    data: Vec<T>,
}

#[derive(Deserialize)]
struct TotpData {
    #[serde(default = "String::new")]
    data: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Uri {
    #[serde(default)]
    pub uri: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Login {
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub totp: Option<String>,
    #[serde(default)]
    pub uris: Option<Vec<Uri>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Field {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub organization_id: Option<String>,
    #[serde(default)]
    pub collection_ids: Option<Vec<String>>,
    #[serde(default)]
    pub login: Option<Login>,
    #[serde(default)]
    pub fields: Option<Vec<Field>>,
}

impl Item {
    /// Value of the `agent-policy` custom field, if it holds a known policy.
    pub fn item_policy(&self) -> Option<Policy> {
        let fields = self.fields.as_ref()?;
        for f in fields {
            let name = f.name.as_deref().unwrap_or("");
            if name.trim().eq_ignore_ascii_case(POLICY_FIELD) {
                return f.value.as_deref().and_then(Policy::parse);
            }
        }
        None
    }

    pub fn username(&self) -> Option<&str> {
        self.login.as_ref()?.username.as_deref()
    }

    pub fn has_totp(&self) -> bool {
        self.login
            .as_ref()
            .and_then(|l| l.totp.as_deref())
            .map(|t| !t.is_empty())
            .unwrap_or(false)
    }

    pub fn urls(&self) -> Vec<String> {
        self.login
            .as_ref()
            .and_then(|l| l.uris.as_ref())
            .map(|u| u.iter().filter_map(|x| x.uri.clone()).collect())
            .unwrap_or_default()
    }

    /// True if the item lies in at least one of the allowed collections.
    /// `None` on the token means "no restriction".
    pub fn in_collections(&self, allowed: Option<&Vec<String>>) -> bool {
        let Some(allowed) = allowed else { return true };
        if allowed.is_empty() {
            return true;
        }
        let Some(ids) = self.collection_ids.as_ref() else {
            return false;
        };
        ids.iter().any(|id| allowed.iter().any(|a| a == id))
    }
}

#[derive(Clone)]
pub struct BwClient {
    base: String,
    http: reqwest::Client,
}

impl BwClient {
    pub fn new(base_url: &str) -> BwClient {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("reqwest client");
        BwClient {
            base: base_url.trim_end_matches('/').to_string(),
            http,
        }
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, BwError> {
        let url = format!("{}{}", self.base, path);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| BwError::Http(e.to_string()))?;
        Self::unwrap_resp(resp).await
    }

    async fn post_empty<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, BwError> {
        self.post_json(path, &serde_json::json!({})).await
    }

    /// NOTE: the body may contain the master password (see `unlock`). It is
    /// never logged and never leaves this function.
    async fn post_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<T, BwError> {
        let url = format!("{}{}", self.base, path);
        let resp = self
            .http
            .post(&url)
            .json(body)
            .send()
            .await
            .map_err(|e| BwError::Http(e.to_string()))?;
        Self::unwrap_resp(resp).await
    }

    async fn unwrap_resp<T: serde::de::DeserializeOwned>(
        resp: reqwest::Response,
    ) -> Result<T, BwError> {
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| BwError::Http(e.to_string()))?;

        let env: Envelope = match serde_json::from_str(&body) {
            Ok(e) => e,
            Err(e) => {
                return Err(BwError::Api(format!(
                    "unlesbare Antwort (HTTP {status}): {e}"
                )))
            }
        };
        if !env.success {
            let msg = env.message.unwrap_or_else(|| format!("HTTP {status}"));
            let lower = msg.to_ascii_lowercase();
            if status.as_u16() == 404 || lower.contains("not found") {
                return Err(BwError::NotFound);
            }
            if lower.contains("locked") || lower.contains("unlock") {
                return Err(BwError::Locked);
            }
            return Err(BwError::Api(msg));
        }
        let data = env
            .data
            .ok_or_else(|| BwError::Api("leere Antwort".into()))?;
        serde_json::from_value(data)
            .map_err(|e| BwError::Api(format!("unerwartete Datenstruktur: {e}")))
    }

    pub async fn sync(&self) -> Result<(), BwError> {
        let _: serde_json::Value = self.post_empty("/sync").await?;
        Ok(())
    }

    /// Raw `/status` payload - used by /healthz to surface lock state.
    pub async fn status(&self) -> Result<serde_json::Value, BwError> {
        self.get::<serde_json::Value>("/status").await
    }

    /// Lock state of the sidecar: "unlocked", "locked" or "unauthenticated".
    pub async fn vault_status(&self) -> Result<String, BwError> {
        let v = self.status().await?;
        // Some CLI versions wrap the payload in {"template": {...}}.
        let inner = v.get("template").unwrap_or(&v);
        Ok(inner
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("unknown")
            .to_string())
    }

    /// Unlock the sidecar vault with the agent account's master password.
    ///
    /// The password lives only in this call's request body - it is never
    /// logged, never written to the database and never kept in the broker.
    pub async fn unlock(&self, password: &str) -> Result<(), BwError> {
        let _: serde_json::Value = self
            .post_json("/unlock", &serde_json::json!({ "password": password }))
            .await?;
        Ok(())
    }

    pub async fn list_items(&self) -> Result<Vec<Item>, BwError> {
        let list: ListData<Item> = self.get("/list/object/items").await?;
        Ok(list.data)
    }

    pub async fn item(&self, id: &str) -> Result<Item, BwError> {
        self.get(&format!("/object/item/{}", urlenc(id))).await
    }

    pub async fn totp(&self, id: &str) -> Result<String, BwError> {
        let t: TotpData = self.get(&format!("/object/totp/{}", urlenc(id))).await?;
        Ok(t.data)
    }
}

/// Minimal percent-encoding for path segments (item ids are UUIDs in practice).
fn urlenc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
