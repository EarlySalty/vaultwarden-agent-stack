//! Minimal MCP server over stdio (JSON-RPC 2.0, newline delimited).
//!
//! It is a thin proxy in front of the broker REST API, so the agent host
//! (Claude Code / Claude Desktop) never holds a vault credential itself -
//! only BROKER_URL + BROKER_TOKEN.
//!
//! IMPORTANT: stdout carries the protocol. All logging must go to stderr.

use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const PROTOCOL_VERSION: &str = "2025-06-18";
const DEFAULT_TIMEOUT_SECS: u64 = 120;

struct Client {
    base: String,
    token: String,
    http: reqwest::Client,
}

impl Client {
    fn from_env() -> Result<Client, String> {
        let base = std::env::var("BROKER_URL")
            .map_err(|_| "BROKER_URL ist nicht gesetzt".to_string())?
            .trim_end_matches('/')
            .to_string();
        let token = std::env::var("BROKER_TOKEN")
            .map_err(|_| "BROKER_TOKEN ist nicht gesetzt".to_string())?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Client { base, token, http })
    }

    async fn get(&self, path: &str) -> Result<(u16, Value), String> {
        let r = self
            .http
            .get(format!("{}{}", self.base, path))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| format!("Broker nicht erreichbar: {e}"))?;
        let code = r.status().as_u16();
        let body: Value = r.json().await.unwrap_or(Value::Null);
        Ok((code, body))
    }

    async fn post(&self, path: &str, body: Value) -> Result<(u16, Value), String> {
        let r = self
            .http
            .post(format!("{}{}", self.base, path))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("Broker nicht erreichbar: {e}"))?;
        let code = r.status().as_u16();
        let body: Value = r.json().await.unwrap_or(Value::Null);
        Ok((code, body))
    }

    /// Accept an id or a (partial, case-insensitive) name.
    async fn resolve_item(&self, needle: &str) -> Result<(String, String), String> {
        let (code, body) = self.get("/v1/items").await?;
        if code != 200 {
            return Err(err_text(code, &body));
        }
        let items = body
            .get("items")
            .and_then(|i| i.as_array())
            .cloned()
            .unwrap_or_default();

        let name_of = |v: &Value| v.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
        let id_of = |v: &Value| v.get("id").and_then(|n| n.as_str()).unwrap_or("").to_string();

        if let Some(hit) = items.iter().find(|v| id_of(v) == needle) {
            return Ok((id_of(hit), name_of(hit)));
        }
        let lower = needle.to_lowercase();
        let exact: Vec<&Value> = items
            .iter()
            .filter(|v| name_of(v).to_lowercase() == lower)
            .collect();
        let chosen: Vec<&Value> = if !exact.is_empty() {
            exact
        } else {
            items
                .iter()
                .filter(|v| name_of(v).to_lowercase().contains(&lower))
                .collect()
        };
        match chosen.len() {
            0 => Err(format!("Kein Eintrag passt zu \"{needle}\".")),
            1 => Ok((id_of(chosen[0]), name_of(chosen[0]))),
            _ => Err(format!(
                "\"{needle}\" ist mehrdeutig: {}",
                chosen
                    .iter()
                    .map(|v| name_of(v))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        }
    }

    /// Ask for fields; block (polling) while an approval is pending.
    async fn get_credential(
        &self,
        needle: &str,
        fields: Vec<String>,
        timeout_secs: u64,
    ) -> Result<Value, String> {
        let (id, name) = self.resolve_item(needle).await?;
        let (code, body) = self
            .post(
                &format!("/v1/items/{id}/credentials"),
                json!({ "fields": fields }),
            )
            .await?;

        match code {
            200 => Ok(json!({"item": name, "values": body.get("values").cloned().unwrap_or(Value::Null)})),
            202 => {
                let rid = body
                    .get("request_id")
                    .and_then(|v| v.as_str())
                    .ok_or("Broker lieferte keine request_id")?
                    .to_string();
                eprintln!("[mcp] Freigabe angefragt (request {rid}) - warte auf Bestätigung ...");

                let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
                loop {
                    if std::time::Instant::now() >= deadline {
                        return Err(format!(
                            "Zeitüberschreitung: Die Freigabe für \"{name}\" wurde nicht innerhalb von {timeout_secs}s bestätigt."
                        ));
                    }
                    // 3s keeps a long wait well inside the broker rate limit.
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    let (c, b) = self.get(&format!("/v1/requests/{rid}")).await?;
                    if c != 200 {
                        return Err(err_text(c, &b));
                    }
                    match b.get("status").and_then(|s| s.as_str()).unwrap_or("") {
                        "pending" => continue,
                        "approved" => {
                            return Ok(json!({
                                "item": name,
                                "values": b.get("values").cloned().unwrap_or(Value::Null)
                            }))
                        }
                        "denied" => {
                            return Err(format!("Die Freigabe für \"{name}\" wurde verweigert."))
                        }
                        "expired" => {
                            return Err(format!("Die Anfrage für \"{name}\" ist abgelaufen."))
                        }
                        other => return Err(format!("Unerwarteter Status: {other}")),
                    }
                }
            }
            403 => Err(format!(
                "Zugriff auf \"{name}\" ist per Policy gesperrt: {}",
                body.get("error").and_then(|e| e.as_str()).unwrap_or("deny")
            )),
            c => Err(err_text(c, &body)),
        }
    }
}

fn err_text(code: u16, body: &Value) -> String {
    let msg = body
        .get("error")
        .and_then(|e| e.as_str())
        .unwrap_or("unbekannter Fehler");
    if code == 503 {
        return format!(
            "{msg}. Der Tresor des Agent-Kontos ist gesperrt - bis jemand ihn im \
Broker-Dashboard entsperrt, können keine Zugangsdaten ausgeliefert werden."
        );
    }
    format!("Broker-Fehler (HTTP {code}): {msg}")
}

// ------------------------------------------------------------------- schemas

fn tool_defs() -> Value {
    json!([
        {
            "name": "list_credentials",
            "description": "Listet alle Zugangsdaten auf, die der Broker fuer dieses Agent-Token sichtbar macht. \
Liefert niemals Passwoerter, sondern nur Name, Benutzername, URLs, die geltende Policy (auto/ask/deny) und ob ein TOTP hinterlegt ist.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false }
        },
        {
            "name": "get_credential",
            "description": "Holt Felder eines Eintrags (Standard: password). Bei Policy 'ask' wird eine Freigabe per Push angefragt \
und dieser Aufruf blockiert bis zur Entscheidung oder bis zum Timeout. Bei 'deny' schlaegt der Aufruf fehl.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name_or_id": { "type": "string", "description": "Name (auch Teilstring) oder Item-ID des Eintrags" },
                    "fields": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "z.B. password, username, totp, notes, urls oder der Name eines Custom Fields"
                    },
                    "timeout_seconds": { "type": "integer", "description": "Wartezeit auf die Freigabe (Standard 120)" }
                },
                "required": ["name_or_id"],
                "additionalProperties": false
            }
        },
        {
            "name": "request_totp",
            "description": "Liefert den aktuell gueltigen TOTP-Code eines Eintrags. Unterliegt derselben Policy wie get_credential.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name_or_id": { "type": "string" },
                    "timeout_seconds": { "type": "integer" }
                },
                "required": ["name_or_id"],
                "additionalProperties": false
            }
        }
    ])
}

// -------------------------------------------------------------------- server

pub async fn run() -> Result<(), String> {
    let client = Client::from_env()?;
    let stdin = tokio::io::stdin();
    let mut lines = BufReader::new(stdin).lines();
    let mut stdout = tokio::io::stdout();

    eprintln!("[mcp] vw-agent-broker MCP bereit (Broker: {})", client.base);

    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                write_msg(
                    &mut stdout,
                    json!({"jsonrpc":"2.0","id":Value::Null,
                           "error":{"code":-32700,"message":format!("Parse error: {e}")}}),
                )
                .await;
                continue;
            }
        };

        let id = msg.get("id").cloned();
        let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = msg.get("params").cloned().unwrap_or(json!({}));

        // Notifications carry no id and must never be answered.
        if id.is_none() {
            if method == "notifications/cancelled" {
                eprintln!("[mcp] cancelled");
            }
            continue;
        }
        let id = id.unwrap();

        let reply = match method {
            "initialize" => json!({
                "jsonrpc": "2.0", "id": id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": { "name": "vw-agent-broker", "version": env!("CARGO_PKG_VERSION") }
                }
            }),
            "ping" => json!({"jsonrpc":"2.0","id":id,"result":{}}),
            "tools/list" => json!({
                "jsonrpc":"2.0","id":id,
                "result": { "tools": tool_defs() }
            }),
            "tools/call" => {
                let name = params
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string();
                let args = params.get("arguments").cloned().unwrap_or(json!({}));
                match call_tool(&client, &name, &args).await {
                    Ok(text) => json!({
                        "jsonrpc":"2.0","id":id,
                        "result": {"content":[{"type":"text","text":text}],"isError":false}
                    }),
                    Err(e) => json!({
                        "jsonrpc":"2.0","id":id,
                        "result": {"content":[{"type":"text","text":e}],"isError":true}
                    }),
                }
            }
            other => json!({
                "jsonrpc":"2.0","id":id,
                "error":{"code":-32601,"message":format!("Unbekannte Methode: {other}")}
            }),
        };
        write_msg(&mut stdout, reply).await;
    }
    Ok(())
}

async fn call_tool(client: &Client, name: &str, args: &Value) -> Result<String, String> {
    let needle = || -> Result<String, String> {
        args.get("name_or_id")
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.to_string())
            .ok_or_else(|| "Parameter name_or_id fehlt".to_string())
    };
    let timeout = args
        .get("timeout_seconds")
        .and_then(|v| v.as_u64())
        .unwrap_or(DEFAULT_TIMEOUT_SECS)
        .clamp(5, 900);

    match name {
        "list_credentials" => {
            let (code, body) = client.get("/v1/items").await?;
            if code != 200 {
                return Err(err_text(code, &body));
            }
            Ok(serde_json::to_string_pretty(&body).unwrap_or_else(|_| body.to_string()))
        }
        "get_credential" => {
            let fields: Vec<String> = args
                .get("fields")
                .and_then(|f| f.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .filter(|v: &Vec<String>| !v.is_empty())
                .unwrap_or_else(|| vec!["password".to_string()]);
            let out = client.get_credential(&needle()?, fields, timeout).await?;
            Ok(serde_json::to_string_pretty(&out).unwrap_or_else(|_| out.to_string()))
        }
        "request_totp" => {
            let out = client
                .get_credential(&needle()?, vec!["totp".to_string()], timeout)
                .await?;
            Ok(serde_json::to_string_pretty(&out).unwrap_or_else(|_| out.to_string()))
        }
        other => Err(format!("Unbekanntes Tool: {other}")),
    }
}

async fn write_msg(out: &mut tokio::io::Stdout, v: Value) {
    let mut s = v.to_string();
    s.push('\n');
    if let Err(e) = out.write_all(s.as_bytes()).await {
        eprintln!("[mcp] stdout Fehler: {e}");
        return;
    }
    let _ = out.flush().await;
}
