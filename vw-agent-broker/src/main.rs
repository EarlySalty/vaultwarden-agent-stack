//! vw-agent-broker - policy broker between AI agents and a self-hosted Vaultwarden.
//!
//! Subcommands:
//!   broker serve                 REST API + dashboard
//!   broker mcp                   MCP server over stdio (proxies the REST API)
//!   broker --create-token NAME   create an agent token and print it once

mod admin;
mod api;
mod app;
mod bw;
mod config;
mod db;
mod mcp;
mod ntfy;
mod policy;

use std::sync::Arc;
use std::time::Duration;

use app::{new_secret_hex, sha256_hex, AppState, Shared};
use config::Config;
use db::Db;
use policy::Policy;

const USAGE: &str = r#"vw-agent-broker

Aufrufe:
  broker serve [--config DATEI]
      Startet REST-API und Dashboard.

  broker mcp
      MCP-Server ueber stdio. Erwartet BROKER_URL und BROKER_TOKEN
      als Umgebungsvariablen.

  broker --create-token NAME [--config DATEI]
         [--collections ID1,ID2] [--max-policy auto|ask|deny]
      Legt ein Agent-Token an und gibt es EINMALIG aus.

Optionen:
  --config DATEI   Pfad zur config.toml (Standard: /etc/broker/config.toml
                   bzw. $BROKER_CONFIG)
  -h, --help       Diese Hilfe
"#;

struct Args {
    cmd: String,
    config: String,
    create_token: Option<String>,
    collections: Vec<String>,
    max_policy: Option<Policy>,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        cmd: String::new(),
        config: std::env::var("BROKER_CONFIG")
            .unwrap_or_else(|_| "/etc/broker/config.toml".to_string()),
        create_token: None,
        collections: Vec::new(),
        max_policy: None,
    };
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < argv.len() {
        let arg = argv[i].as_str();
        let next = |i: &mut usize, name: &str| -> Result<String, String> {
            *i += 1;
            argv.get(*i)
                .cloned()
                .ok_or_else(|| format!("{name} erwartet einen Wert"))
        };
        match arg {
            "serve" | "mcp" => a.cmd = arg.to_string(),
            "--config" | "-c" => a.config = next(&mut i, "--config")?,
            "--create-token" => a.create_token = Some(next(&mut i, "--create-token")?),
            "--collections" => {
                a.collections = next(&mut i, "--collections")?
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            }
            "--max-policy" => {
                let v = next(&mut i, "--max-policy")?;
                a.max_policy = Some(
                    Policy::parse(&v).ok_or("--max-policy muss auto, ask oder deny sein")?,
                );
            }
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            other => return Err(format!("unbekanntes Argument: {other}")),
        }
        i += 1;
    }
    if a.cmd.is_empty() && a.create_token.is_none() {
        a.cmd = "serve".into();
    }
    Ok(a)
}

#[tokio::main]
async fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Fehler: {e}\n\n{USAGE}");
            std::process::exit(2);
        }
    };

    // MCP speaks JSON-RPC on stdout - every log line must go to stderr.
    let to_stderr = args.cmd == "mcp";
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into());
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if to_stderr {
        builder.with_writer(std::io::stderr).init();
    } else {
        builder.init();
    }

    if args.cmd == "mcp" {
        if let Err(e) = mcp::run().await {
            eprintln!("MCP-Fehler: {e}");
            std::process::exit(1);
        }
        return;
    }

    let cfg = match Config::load(&args.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Konfigurationsfehler: {e}");
            std::process::exit(2);
        }
    };
    let db = match Db::open(&cfg.db_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Datenbank {} nicht nutzbar: {e}", cfg.db_path);
            std::process::exit(1);
        }
    };

    if let Some(name) = args.create_token {
        let secret = new_secret_hex();
        match db.create_token(
            &name,
            &sha256_hex(&secret),
            Some(&args.collections),
            args.max_policy,
        ) {
            Ok(id) => {
                db.audit(
                    "cli",
                    "token_create",
                    Some(&name),
                    None,
                    None,
                    "ok",
                    Some(&format!("id={id}")),
                );
                println!("Token \"{name}\" angelegt (id {id}).");
                println!("Einmalige Ausgabe - jetzt sichern:\n");
                println!("  {secret}\n");
                println!("Verwendung:  Authorization: Bearer {secret}");
            }
            Err(e) => {
                eprintln!("Token konnte nicht angelegt werden: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    serve(cfg, db).await;
}

async fn serve(cfg: Config, db: Db) {
    let bind = cfg.bind.clone();
    let sync_interval = cfg.sync_interval;
    let state: Shared = Arc::new(AppState::new(cfg, db));

    // Lock check + sync, at start and then periodically. The sidecar comes up
    // locked by design, so this also fires the one-time "please unlock" push.
    {
        let st = state.clone();
        tokio::spawn(async move {
            // Give the bw sidecar a moment to finish its login.
            tokio::time::sleep(Duration::from_secs(3)).await;
            // 0 disables the periodic sync, but the lock state is still watched.
            let period = if sync_interval > 0 { sync_interval } else { 60 };
            let mut tick = tokio::time::interval(Duration::from_secs(period.max(5)));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                let status = app::refresh_lock_state(&st).await;
                if status != "unlocked" {
                    // Syncing a locked vault cannot work - wait for the unlock.
                    tracing::warn!("bw-Tresor ist {status} - warte auf Entsperren im Dashboard");
                    continue;
                }
                if sync_interval > 0 {
                    if let Err(e) = st.bw.sync().await {
                        tracing::warn!("bw sync fehlgeschlagen: {e}");
                    }
                }
            }
        });
    }

    {
        let st = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                let _ = st.db.expire_stale();
                let _ = st.db.purge_expired_rules();
                // Decided requests older than 7 days; audit keeps the history.
                let _ = st.db.purge_old_requests(7 * 86_400);
            }
        });
    }

    let router = axum::Router::new()
        .merge(api::routes())
        .merge(admin::routes(state.clone()))
        .with_state(state.clone());

    let listener = match tokio::net::TcpListener::bind(&bind).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Kann nicht an {bind} binden: {e}");
            std::process::exit(1);
        }
    };
    tracing::info!("Broker laeuft auf http://{bind} (Dashboard: /admin)");
    state
        .db
        .audit("system", "start", None, None, None, "ok", Some(&bind));

    if let Err(e) = axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        tracing::error!("Server beendet: {e}");
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
    tracing::info!("Beende ...");
}
