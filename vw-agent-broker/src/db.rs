//! SQLite persistence: agent tokens, approval requests, remember rules, audit log.
//!
//! Note: credential VALUES are never written here. Only metadata.

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::sync::Mutex;

use crate::policy::Policy;

pub const ST_PENDING: &str = "pending";
pub const ST_APPROVED: &str = "approved";
pub const ST_DENIED: &str = "denied";
pub const ST_EXPIRED: &str = "expired";
pub const ST_DELIVERED: &str = "delivered";

pub struct Db {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenRow {
    pub id: i64,
    pub name: String,
    /// None = all collections the broker account can see.
    pub allowed_collections: Option<Vec<String>>,
    pub max_policy: Option<Policy>,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RequestRow {
    pub id: String,
    pub token_id: i64,
    pub agent: String,
    pub item_id: String,
    pub item_name: String,
    pub fields: Vec<String>,
    pub status: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub decided_at: Option<i64>,
    pub decided_by: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleRow {
    pub id: i64,
    pub item_id: String,
    pub item_name: String,
    pub token_id: i64,
    pub agent: String,
    /// None = permanent.
    pub expires_at: Option<i64>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditRow {
    pub id: i64,
    pub ts: i64,
    pub actor: String,
    pub action: String,
    pub agent: Option<String>,
    pub item_id: Option<String>,
    pub item_name: Option<String>,
    pub result: String,
    pub detail: Option<String>,
}

pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

impl Db {
    pub fn open(path: &str) -> rusqlite::Result<Db> {
        if let Some(parent) = std::path::Path::new(path).parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;
            PRAGMA busy_timeout = 5000;

            CREATE TABLE IF NOT EXISTS tokens (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                name                TEXT NOT NULL UNIQUE,
                token_hash          TEXT NOT NULL UNIQUE,
                allowed_collections TEXT,
                max_policy          TEXT,
                created_at          INTEGER NOT NULL,
                last_used_at        INTEGER,
                revoked_at          INTEGER
            );

            CREATE TABLE IF NOT EXISTS requests (
                id          TEXT PRIMARY KEY,
                token_id    INTEGER NOT NULL,
                agent       TEXT NOT NULL,
                item_id     TEXT NOT NULL,
                item_name   TEXT NOT NULL,
                fields      TEXT NOT NULL,
                status      TEXT NOT NULL,
                created_at  INTEGER NOT NULL,
                expires_at  INTEGER NOT NULL,
                decided_at  INTEGER,
                decided_by  TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_requests_status ON requests(status, created_at DESC);

            CREATE TABLE IF NOT EXISTS rules (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                item_id     TEXT NOT NULL,
                item_name   TEXT NOT NULL DEFAULT '',
                token_id    INTEGER NOT NULL,
                agent       TEXT NOT NULL DEFAULT '',
                expires_at  INTEGER,
                created_at  INTEGER NOT NULL,
                UNIQUE(item_id, token_id)
            );

            CREATE TABLE IF NOT EXISTS audit (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ts         INTEGER NOT NULL,
                actor      TEXT NOT NULL,
                action     TEXT NOT NULL,
                agent      TEXT,
                item_id    TEXT,
                item_name  TEXT,
                result     TEXT NOT NULL,
                detail     TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts DESC);
            "#,
        )?;
        Ok(Db {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        // A poisoned mutex means a previous DB call panicked; recovering the
        // guard is safe here because every statement is self-contained.
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    // ---------------------------------------------------------------- tokens

    pub fn create_token(
        &self,
        name: &str,
        token_hash: &str,
        allowed_collections: Option<&[String]>,
        max_policy: Option<Policy>,
    ) -> rusqlite::Result<i64> {
        let cols = allowed_collections
            .filter(|c| !c.is_empty())
            .map(|c| serde_json::to_string(c).unwrap_or_else(|_| "[]".into()));
        let c = self.lock();
        c.execute(
            "INSERT INTO tokens (name, token_hash, allowed_collections, max_policy, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                name,
                token_hash,
                cols,
                max_policy.map(|p| p.as_str().to_string()),
                now()
            ],
        )?;
        Ok(c.last_insert_rowid())
    }

    pub fn token_by_hash(&self, hash: &str) -> rusqlite::Result<Option<TokenRow>> {
        let c = self.lock();
        c.query_row(
            "SELECT id, name, allowed_collections, max_policy, created_at, last_used_at, revoked_at
             FROM tokens WHERE token_hash = ?1",
            params![hash],
            map_token,
        )
        .optional()
    }

    pub fn token_by_id(&self, id: i64) -> rusqlite::Result<Option<TokenRow>> {
        let c = self.lock();
        c.query_row(
            "SELECT id, name, allowed_collections, max_policy, created_at, last_used_at, revoked_at
             FROM tokens WHERE id = ?1",
            params![id],
            map_token,
        )
        .optional()
    }

    pub fn list_tokens(&self) -> rusqlite::Result<Vec<TokenRow>> {
        let c = self.lock();
        let mut st = c.prepare(
            "SELECT id, name, allowed_collections, max_policy, created_at, last_used_at, revoked_at
             FROM tokens ORDER BY id DESC",
        )?;
        let rows = st.query_map([], map_token)?;
        rows.collect()
    }

    pub fn touch_token(&self, id: i64) {
        let c = self.lock();
        let _ = c.execute(
            "UPDATE tokens SET last_used_at = ?1 WHERE id = ?2",
            params![now(), id],
        );
    }

    pub fn revoke_token(&self, id: i64) -> rusqlite::Result<usize> {
        let c = self.lock();
        c.execute(
            "UPDATE tokens SET revoked_at = ?1 WHERE id = ?2 AND revoked_at IS NULL",
            params![now(), id],
        )
    }

    // -------------------------------------------------------------- requests

    pub fn create_request(&self, r: &RequestRow) -> rusqlite::Result<()> {
        let c = self.lock();
        c.execute(
            "INSERT INTO requests (id, token_id, agent, item_id, item_name, fields, status, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                r.id,
                r.token_id,
                r.agent,
                r.item_id,
                r.item_name,
                serde_json::to_string(&r.fields).unwrap_or_else(|_| "[]".into()),
                r.status,
                r.created_at,
                r.expires_at
            ],
        )?;
        Ok(())
    }

    pub fn request(&self, id: &str) -> rusqlite::Result<Option<RequestRow>> {
        let c = self.lock();
        c.query_row(
            "SELECT id, token_id, agent, item_id, item_name, fields, status, created_at, expires_at, decided_at, decided_by
             FROM requests WHERE id = ?1",
            params![id],
            map_request,
        )
        .optional()
    }

    pub fn list_requests(&self, only_pending: bool, limit: i64) -> rusqlite::Result<Vec<RequestRow>> {
        let c = self.lock();
        let sql = if only_pending {
            "SELECT id, token_id, agent, item_id, item_name, fields, status, created_at, expires_at, decided_at, decided_by
             FROM requests WHERE status = 'pending' ORDER BY created_at DESC LIMIT ?1"
        } else {
            "SELECT id, token_id, agent, item_id, item_name, fields, status, created_at, expires_at, decided_at, decided_by
             FROM requests ORDER BY created_at DESC LIMIT ?1"
        };
        let mut st = c.prepare(sql)?;
        let rows = st.query_map(params![limit], map_request)?;
        rows.collect()
    }

    /// Atomically move a request out of `pending`. Returns false if it was
    /// already decided or expired - this is what makes the ntfy links single-use.
    pub fn decide_request(&self, id: &str, status: &str, by: &str) -> rusqlite::Result<bool> {
        let c = self.lock();
        let n = c.execute(
            "UPDATE requests SET status = ?1, decided_at = ?2, decided_by = ?3
             WHERE id = ?4 AND status = 'pending' AND expires_at > ?2",
            params![status, now(), by, id],
        )?;
        Ok(n == 1)
    }

    /// Mark an approved request as delivered. False if it was already consumed.
    pub fn mark_delivered(&self, id: &str) -> rusqlite::Result<bool> {
        let c = self.lock();
        let n = c.execute(
            "UPDATE requests SET status = ?1 WHERE id = ?2 AND status = 'approved'",
            params![ST_DELIVERED, id],
        )?;
        Ok(n == 1)
    }

    /// Flag timed-out requests. Called lazily on read paths and by the janitor.
    pub fn expire_stale(&self) -> rusqlite::Result<usize> {
        let c = self.lock();
        c.execute(
            "UPDATE requests SET status = ?1 WHERE status = 'pending' AND expires_at <= ?2",
            params![ST_EXPIRED, now()],
        )
    }

    /// Keep the table small; audit keeps the long-term history.
    pub fn purge_old_requests(&self, older_than_secs: i64) -> rusqlite::Result<usize> {
        let c = self.lock();
        c.execute(
            "DELETE FROM requests WHERE status <> 'pending' AND created_at < ?1",
            params![now() - older_than_secs],
        )
    }

    // ----------------------------------------------------------------- rules

    pub fn upsert_rule(
        &self,
        item_id: &str,
        item_name: &str,
        token_id: i64,
        agent: &str,
        expires_at: Option<i64>,
    ) -> rusqlite::Result<()> {
        let c = self.lock();
        c.execute(
            "INSERT INTO rules (item_id, item_name, token_id, agent, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(item_id, token_id)
             DO UPDATE SET expires_at = excluded.expires_at,
                           created_at = excluded.created_at,
                           item_name  = excluded.item_name",
            params![item_id, item_name, token_id, agent, expires_at, now()],
        )?;
        Ok(())
    }

    /// True if a non-expired remember rule exists for this pair.
    pub fn rule_active(&self, item_id: &str, token_id: i64) -> rusqlite::Result<bool> {
        let c = self.lock();
        let n: i64 = c.query_row(
            "SELECT COUNT(*) FROM rules
             WHERE item_id = ?1 AND token_id = ?2
               AND (expires_at IS NULL OR expires_at > ?3)",
            params![item_id, token_id, now()],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    pub fn list_rules(&self) -> rusqlite::Result<Vec<RuleRow>> {
        let c = self.lock();
        let mut st = c.prepare(
            "SELECT id, item_id, item_name, token_id, agent, expires_at, created_at
             FROM rules ORDER BY id DESC",
        )?;
        let rows = st.query_map([], |r| {
            Ok(RuleRow {
                id: r.get(0)?,
                item_id: r.get(1)?,
                item_name: r.get(2)?,
                token_id: r.get(3)?,
                agent: r.get(4)?,
                expires_at: r.get(5)?,
                created_at: r.get(6)?,
            })
        })?;
        rows.collect()
    }

    pub fn delete_rule(&self, id: i64) -> rusqlite::Result<usize> {
        let c = self.lock();
        c.execute("DELETE FROM rules WHERE id = ?1", params![id])
    }

    pub fn purge_expired_rules(&self) -> rusqlite::Result<usize> {
        let c = self.lock();
        c.execute(
            "DELETE FROM rules WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            params![now()],
        )
    }

    // ----------------------------------------------------------------- audit

    #[allow(clippy::too_many_arguments)]
    pub fn audit(
        &self,
        actor: &str,
        action: &str,
        agent: Option<&str>,
        item_id: Option<&str>,
        item_name: Option<&str>,
        result: &str,
        detail: Option<&str>,
    ) {
        let c = self.lock();
        if let Err(e) = c.execute(
            "INSERT INTO audit (ts, actor, action, agent, item_id, item_name, result, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![now(), actor, action, agent, item_id, item_name, result, detail],
        ) {
            tracing::error!("audit insert failed: {e}");
        }
    }

    pub fn list_audit(&self, limit: i64) -> rusqlite::Result<Vec<AuditRow>> {
        let c = self.lock();
        let mut st = c.prepare(
            "SELECT id, ts, actor, action, agent, item_id, item_name, result, detail
             FROM audit ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = st.query_map(params![limit], |r| {
            Ok(AuditRow {
                id: r.get(0)?,
                ts: r.get(1)?,
                actor: r.get(2)?,
                action: r.get(3)?,
                agent: r.get(4)?,
                item_id: r.get(5)?,
                item_name: r.get(6)?,
                result: r.get(7)?,
                detail: r.get(8)?,
            })
        })?;
        rows.collect()
    }
}

fn map_token(r: &rusqlite::Row<'_>) -> rusqlite::Result<TokenRow> {
    let cols: Option<String> = r.get(2)?;
    let max: Option<String> = r.get(3)?;
    let revoked: Option<i64> = r.get(6)?;
    Ok(TokenRow {
        id: r.get(0)?,
        name: r.get(1)?,
        allowed_collections: cols.and_then(|s| serde_json::from_str(&s).ok()),
        max_policy: max.as_deref().and_then(Policy::parse),
        created_at: r.get(4)?,
        last_used_at: r.get(5)?,
        revoked: revoked.is_some(),
    })
}

fn map_request(r: &rusqlite::Row<'_>) -> rusqlite::Result<RequestRow> {
    let fields: String = r.get(5)?;
    Ok(RequestRow {
        id: r.get(0)?,
        token_id: r.get(1)?,
        agent: r.get(2)?,
        item_id: r.get(3)?,
        item_name: r.get(4)?,
        fields: serde_json::from_str(&fields).unwrap_or_default(),
        status: r.get(6)?,
        created_at: r.get(7)?,
        expires_at: r.get(8)?,
        decided_at: r.get(9)?,
        decided_by: r.get(10)?,
    })
}
