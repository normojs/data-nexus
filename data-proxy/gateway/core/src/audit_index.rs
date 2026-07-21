//! B06: SQLite side-index for audit events.
//!
//! The hot path still only `try_send`s; the audit worker inserts into this index
//! after dequeuing. Admin `GET /admin/audit/events` queries the index when
//! configured so it does not scan full JSONL or rely solely on the in-memory
//! ring buffer.
//!
//! Enable with non-empty `security.audit.index_path`. Empty path = off.

use crate::audit::AuditEvent;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// H05: multi-process writers share one SQLite file (WAL). Wait up to this long
/// for locks before failing an insert/query.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const BUSY_RETRIES: u32 = 8;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS audit_events (
    event_id    TEXT PRIMARY KEY NOT NULL,
    ts_unix_ms  INTEGER NOT NULL,
    decision    TEXT,
    subject_id  TEXT,
    service     TEXT,
    action      TEXT,
    listener    TEXT,
    rule        TEXT,
    outcome     TEXT,
    payload     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts_unix_ms DESC);
CREATE INDEX IF NOT EXISTS idx_audit_decision_ts ON audit_events(decision, ts_unix_ms DESC);
CREATE INDEX IF NOT EXISTS idx_audit_subject_ts ON audit_events(subject_id, ts_unix_ms DESC);
CREATE INDEX IF NOT EXISTS idx_audit_service_ts ON audit_events(service, ts_unix_ms DESC);
CREATE INDEX IF NOT EXISTS idx_audit_outcome_ts ON audit_events(outcome, ts_unix_ms DESC);
CREATE INDEX IF NOT EXISTS idx_audit_listener_ts ON audit_events(listener, ts_unix_ms DESC);
"#;

/// Filter for Admin / index queries (B06).
#[derive(Debug, Clone, Default)]
pub struct AuditQueryFilter {
    pub decision: Option<String>,
    pub subject_id: Option<String>,
    pub service: Option<String>,
    pub event_id: Option<String>,
    /// F32: filter by effective audit_level (L0/L1/L2), case-insensitive.
    pub audit_level: Option<String>,
    /// UI17: filter by outcome column (`security_deny`, `ok`, portal_*, …).
    pub outcome: Option<String>,
    /// UI19: filter by frontend listener name (index column).
    pub listener: Option<String>,
    /// Inclusive lower bound on `ts_unix_ms`.
    pub from_ms: Option<u64>,
    /// Inclusive upper bound on `ts_unix_ms`.
    pub to_ms: Option<u64>,
    pub limit: usize,
}

impl AuditQueryFilter {
    pub fn limit_clamped(&self) -> usize {
        self.limit.clamp(1, 1000)
    }
}

pub struct AuditIndex {
    path: PathBuf,
    conn: Mutex<Connection>,
    inserted: AtomicU64,
    errors: AtomicU64,
    pruned: AtomicU64,
    /// Live row count (maintained on insert/prune; avoids COUNT(*) on stats).
    rows: AtomicU64,
}

impl AuditIndex {
    /// Open (or create) a SQLite index at `path`. Parent dirs are created.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    format!("create audit index dir {}: {e}", parent.display())
                })?;
            }
        }
        let conn = Connection::open(&path)
            .map_err(|e| format!("open audit index {}: {e}", path.display()))?;
        // H05: multi-instance / multi-worker writers on shared disk.
        // WAL allows concurrent readers; busy_timeout backs off on writer locks.
        conn.busy_timeout(BUSY_TIMEOUT)
            .map_err(|e| format!("busy_timeout audit index: {e}"))?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA temp_store=MEMORY;
             PRAGMA foreign_keys=OFF;",
        )
        .map_err(|e| format!("pragma audit index: {e}"))?;
        conn.execute_batch(SCHEMA)
            .map_err(|e| format!("schema audit index: {e}"))?;
        let existing_rows: u64 = conn
            .query_row("SELECT COUNT(*) FROM audit_events", [], |r| r.get::<_, i64>(0))
            .map(|n| n as u64)
            .unwrap_or(0);
        Ok(Self {
            path,
            conn: Mutex::new(conn),
            inserted: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            pruned: AtomicU64::new(0),
            rows: AtomicU64::new(existing_rows),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn inserted(&self) -> u64 {
        self.inserted.load(Ordering::Relaxed)
    }

    pub fn errors(&self) -> u64 {
        self.errors.load(Ordering::Relaxed)
    }

    pub fn pruned(&self) -> u64 {
        self.pruned.load(Ordering::Relaxed)
    }

    /// O(1) row estimate maintained by insert/prune (refreshed once at open).
    pub fn row_count(&self) -> u64 {
        self.rows.load(Ordering::Relaxed)
    }

    /// Insert or replace one event. Failures are counted and logged by the caller.
    pub fn insert(&self, event: &AuditEvent) -> Result<(), String> {
        let event_id = event
            .event_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_owned())
            .unwrap_or_else(|| format!("ae-missing-{}", now_unix_ms()));
        let ts = event.ts_unix_ms.unwrap_or_else(now_unix_ms) as i64;
        let payload = serde_json::to_string(event)
            .map_err(|e| format!("serialize audit event: {e}"))?;

        let conn = self
            .conn
            .lock()
            .map_err(|_| "audit index lock poisoned".to_string())?;
        let existed: bool = with_busy_retry("probe audit index", || {
            conn.query_row(
                "SELECT 1 FROM audit_events WHERE event_id = ?1",
                params![event_id],
                |_| Ok(true),
            )
            .optional()
        })?
        .unwrap_or(false);
        with_busy_retry("insert audit index", || {
            conn.execute(
                r#"
                INSERT INTO audit_events (
                    event_id, ts_unix_ms, decision, subject_id, service,
                    action, listener, rule, outcome, payload
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                ON CONFLICT(event_id) DO UPDATE SET
                    ts_unix_ms=excluded.ts_unix_ms,
                    decision=excluded.decision,
                    subject_id=excluded.subject_id,
                    service=excluded.service,
                    action=excluded.action,
                    listener=excluded.listener,
                    rule=excluded.rule,
                    outcome=excluded.outcome,
                    payload=excluded.payload
                "#,
                params![
                    event_id,
                    ts,
                    event.decision.as_deref(),
                    event.subject_id.as_deref(),
                    event.service.as_deref(),
                    event.action.as_deref(),
                    event.listener.as_deref(),
                    event.rule.as_deref(),
                    event.outcome.as_deref(),
                    payload,
                ],
            )
        })?;
        self.inserted.fetch_add(1, Ordering::Relaxed);
        if !existed {
            self.rows.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn query(&self, filter: &AuditQueryFilter) -> Result<Vec<AuditEvent>, String> {
        let limit = filter.limit_clamped() as i64;
        let mut sql = String::from(
            "SELECT payload FROM audit_events WHERE 1=1",
        );
        let mut binds: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(ref id) = filter.event_id {
            sql.push_str(" AND event_id = ?");
            binds.push(Box::new(id.clone()));
        }
        if let Some(ref d) = filter.decision {
            sql.push_str(" AND decision = ?");
            binds.push(Box::new(d.clone()));
        }
        if let Some(ref s) = filter.subject_id {
            sql.push_str(" AND subject_id = ?");
            binds.push(Box::new(s.clone()));
        }
        if let Some(ref s) = filter.service {
            sql.push_str(" AND service = ?");
            binds.push(Box::new(s.clone()));
        }
        if let Some(ref o) = filter.outcome {
            sql.push_str(" AND outcome = ?");
            binds.push(Box::new(o.clone()));
        }
        if let Some(ref l) = filter.listener {
            sql.push_str(" AND listener = ?");
            binds.push(Box::new(l.clone()));
        }
        if let Some(from) = filter.from_ms {
            sql.push_str(" AND ts_unix_ms >= ?");
            binds.push(Box::new(from as i64));
        }
        if let Some(to) = filter.to_ms {
            sql.push_str(" AND ts_unix_ms <= ?");
            binds.push(Box::new(to as i64));
        }
        if let Some(ref lvl) = filter.audit_level {
            // Stored on payload JSON (F32); avoid schema migration for older index files.
            sql.push_str(" AND lower(coalesce(json_extract(payload, '$.audit_level'), '')) = lower(?)");
            binds.push(Box::new(lvl.clone()));
        }
        sql.push_str(" ORDER BY ts_unix_ms DESC LIMIT ?");
        binds.push(Box::new(limit));

        let conn = self
            .conn
            .lock()
            .map_err(|_| "audit index lock poisoned".to_string())?;
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| format!("prepare audit query: {e}"))?;
        let param_refs: Vec<&dyn rusqlite::ToSql> = binds.iter().map(|b| b.as_ref()).collect();
        let rows = stmt
            .query_map(param_refs.as_slice(), |row| {
                let payload: String = row.get(0)?;
                Ok(payload)
            })
            .map_err(|e| format!("query audit index: {e}"))?;

        let mut out = Vec::new();
        for row in rows {
            let payload = row.map_err(|e| format!("row audit index: {e}"))?;
            match serde_json::from_str::<AuditEvent>(&payload) {
                Ok(ev) => out.push(ev),
                Err(e) => {
                    tracing::warn!(
                        target: "data_nexus::audit",
                        error = %e,
                        "skip corrupt audit index payload"
                    );
                }
            }
        }
        Ok(out)
    }

    pub fn get_by_id(&self, event_id: &str) -> Result<Option<AuditEvent>, String> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| "audit index lock poisoned".to_string())?;
        let payload: Option<String> = conn
            .query_row(
                "SELECT payload FROM audit_events WHERE event_id = ?1",
                params![event_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| format!("get audit index: {e}"))?;
        match payload {
            Some(p) => serde_json::from_str(&p)
                .map(Some)
                .map_err(|e| format!("decode audit index: {e}")),
            None => Ok(None),
        }
    }

    /// Delete rows older than `retain_days`. Returns number of deleted rows.
    pub fn prune_older_than_days(&self, retain_days: u32) -> u64 {
        if retain_days == 0 {
            return 0;
        }
        let cutoff = now_unix_ms().saturating_sub(u64::from(retain_days) * 86_400_000) as i64;
        let Ok(conn) = self.conn.lock() else {
            return 0;
        };
        match conn.execute(
            "DELETE FROM audit_events WHERE ts_unix_ms < ?1",
            params![cutoff],
        ) {
            Ok(n) => {
                let n = n as u64;
                if n > 0 {
                    self.pruned.fetch_add(n, Ordering::Relaxed);
                    // Saturating sub on atomic rows.
                    let mut cur = self.rows.load(Ordering::Relaxed);
                    loop {
                        let next = cur.saturating_sub(n);
                        match self.rows.compare_exchange_weak(
                            cur,
                            next,
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                        ) {
                            Ok(_) => break,
                            Err(actual) => cur = actual,
                        }
                    }
                }
                n
            }
            Err(e) => {
                tracing::warn!(
                    target: "data_nexus::audit",
                    error = %e,
                    "audit index prune failed"
                );
                0
            }
        }
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Retry on SQLITE_BUSY / locked (H05 multi-writer). `busy_timeout` already waits
/// inside SQLite; this covers residual races between probe + insert.
fn with_busy_retry<T, F>(label: &str, mut f: F) -> Result<T, String>
where
    F: FnMut() -> Result<T, rusqlite::Error>,
{
    let mut attempt = 0u32;
    loop {
        match f() {
            Ok(v) => return Ok(v),
            Err(e) => {
                let busy = matches!(
                    e.sqlite_error_code(),
                    Some(rusqlite::ErrorCode::DatabaseBusy)
                        | Some(rusqlite::ErrorCode::DatabaseLocked)
                );
                if busy && attempt < BUSY_RETRIES {
                    attempt += 1;
                    // Exponential-ish backoff: 1,2,4,8… ms capped.
                    let ms = (1u64 << attempt.min(6)).min(50);
                    thread::sleep(Duration::from_millis(ms));
                    continue;
                }
                return Err(format!("{label}: {e}"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_path(tag: &str) -> PathBuf {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        std::env::temp_dir().join(format!("dn-audit-idx-{tag}-{ms}.sqlite"))
    }

    fn sample(decision: &str, subject: &str, service: &str, ts: u64) -> AuditEvent {
        AuditEvent {
            event_id: Some(format!("ae-{decision}-{subject}-{ts}")),
            ts_unix_ms: Some(ts),
            decision: Some(decision.into()),
            subject_id: Some(subject.into()),
            service: Some(service.into()),
            action: Some("query".into()),
            outcome: Some("ok".into()),
            ..AuditEvent::default()
        }
    }

    #[test]
    fn insert_and_filter_by_decision_subject_service() {
        let path = tmp_path("filter");
        let idx = AuditIndex::open(&path).unwrap();
        idx.insert(&sample("deny", "alice", "orders", 1000)).unwrap();
        idx.insert(&sample("execute", "alice", "orders", 1001))
            .unwrap();
        idx.insert(&sample("deny", "bob", "orders", 1002)).unwrap();
        idx.insert(&sample("deny", "alice", "billing", 1003))
            .unwrap();

        let denies = idx
            .query(&AuditQueryFilter {
                decision: Some("deny".into()),
                subject_id: Some("alice".into()),
                service: Some("orders".into()),
                limit: 10,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(denies.len(), 1);
        assert_eq!(denies[0].subject_id.as_deref(), Some("alice"));
        assert_eq!(denies[0].service.as_deref(), Some("orders"));

        let by_id = idx
            .get_by_id("ae-deny-alice-1000")
            .unwrap()
            .expect("row");
        assert_eq!(by_id.decision.as_deref(), Some("deny"));
        assert_eq!(idx.row_count(), 4);
        assert_eq!(idx.inserted(), 4);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn time_range_and_order_desc() {
        let path = tmp_path("range");
        let idx = AuditIndex::open(&path).unwrap();
        for i in 0..5 {
            idx.insert(&sample("execute", "u", "svc", 1000 + i)).unwrap();
        }
        let mid = idx
            .query(&AuditQueryFilter {
                from_ms: Some(1001),
                to_ms: Some(1003),
                limit: 10,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(mid.len(), 3);
        // Newest first.
        assert_eq!(mid[0].ts_unix_ms, Some(1003));
        assert_eq!(mid[2].ts_unix_ms, Some(1001));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn prune_by_age() {
        let path = tmp_path("prune");
        let idx = AuditIndex::open(&path).unwrap();
        let old_ts = now_unix_ms().saturating_sub(10 * 86_400_000);
        idx.insert(&sample("deny", "old", "s", old_ts)).unwrap();
        idx.insert(&sample("deny", "new", "s", now_unix_ms()))
            .unwrap();
        // retain_days=1 drops the 10-day-old row.
        let n = idx.prune_older_than_days(1);
        assert_eq!(n, 1);
        assert_eq!(idx.row_count(), 1);
        let left = idx
            .query(&AuditQueryFilter {
                decision: Some("deny".into()),
                limit: 10,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(left[0].subject_id.as_deref(), Some("new"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn upsert_same_event_id() {
        let path = tmp_path("upsert");
        let idx = AuditIndex::open(&path).unwrap();
        let mut e = sample("deny", "alice", "orders", 1);
        e.event_id = Some("same".into());
        idx.insert(&e).unwrap();
        e.outcome = Some("updated".into());
        e.ts_unix_ms = Some(2);
        idx.insert(&e).unwrap();
        assert_eq!(idx.row_count(), 1);
        let got = idx.get_by_id("same").unwrap().unwrap();
        assert_eq!(got.outcome.as_deref(), Some("updated"));
        assert_eq!(got.ts_unix_ms, Some(2));
        let _ = std::fs::remove_file(&path);
    }

    /// H05: two AuditIndex handles on the same file (multi-process / multi-worker).
    #[test]
    fn h05_two_handles_share_wal_file() {
        let path = tmp_path("h05-mp");
        let a = AuditIndex::open(&path).unwrap();
        let b = AuditIndex::open(&path).unwrap();
        a.insert(&sample("deny", "a", "svc", 10)).unwrap();
        b.insert(&sample("execute", "b", "svc", 11)).unwrap();
        // Cross-read: each handle sees the other's rows.
        let from_a = a
            .query(&AuditQueryFilter {
                limit: 10,
                ..Default::default()
            })
            .unwrap();
        let from_b = b
            .query(&AuditQueryFilter {
                limit: 10,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(from_a.len(), 2);
        assert_eq!(from_b.len(), 2);
        assert!(a.get_by_id("ae-execute-b-11").unwrap().is_some());
        assert!(b.get_by_id("ae-deny-a-10").unwrap().is_some());
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn filter_by_audit_level_json_extract() {
        let dir = std::env::temp_dir().join(format!("dn-audit-lvl-{}", now_unix_ms()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("idx.sqlite");
        let idx = AuditIndex::open(&path).unwrap();
        let mut e0 = sample("deny", "alice", "orders", 1000);
        e0.audit_level = Some("L0".into());
        e0.event_id = Some("ae-l0".into());
        idx.insert(&e0).unwrap();
        let mut e2 = sample("deny", "alice", "orders", 1001);
        e2.audit_level = Some("L2".into());
        e2.event_id = Some("ae-l2".into());
        idx.insert(&e2).unwrap();

        let only_l2 = idx
            .query(&AuditQueryFilter {
                audit_level: Some("l2".into()),
                limit: 10,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(only_l2.len(), 1);
        assert_eq!(only_l2[0].event_id.as_deref(), Some("ae-l2"));
        assert_eq!(only_l2[0].audit_level.as_deref(), Some("L2"));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn filter_by_outcome_column() {
        let path = tmp_path("outcome");
        let idx = AuditIndex::open(&path).unwrap();
        let mut deny = sample("deny", "a", "s", 1000);
        deny.outcome = Some("security_deny".into());
        deny.event_id = Some("ae-out-deny".into());
        idx.insert(&deny).unwrap();
        let mut ok = sample("execute", "a", "s", 1001);
        ok.outcome = Some("ok".into());
        ok.event_id = Some("ae-out-ok".into());
        idx.insert(&ok).unwrap();
        let mut portal = sample("execute", "a", "s", 1002);
        portal.outcome = Some("portal_query".into());
        portal.event_id = Some("ae-out-portal".into());
        idx.insert(&portal).unwrap();

        let only_deny = idx
            .query(&AuditQueryFilter {
                outcome: Some("security_deny".into()),
                limit: 10,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(only_deny.len(), 1, "{only_deny:?}");
        assert_eq!(only_deny[0].outcome.as_deref(), Some("security_deny"));
        assert_eq!(only_deny[0].event_id.as_deref(), Some("ae-out-deny"));

        let only_portal = idx
            .query(&AuditQueryFilter {
                outcome: Some("portal_query".into()),
                limit: 10,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(only_portal.len(), 1);
        assert_eq!(only_portal[0].event_id.as_deref(), Some("ae-out-portal"));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn filter_by_listener_column() {
        let path = tmp_path("listener");
        let idx = AuditIndex::open(&path).unwrap();
        let mut a = sample("deny", "u", "orders", 1000);
        a.listener = Some("orders-mysql".into());
        a.event_id = Some("ae-lsn-a".into());
        idx.insert(&a).unwrap();
        let mut b = sample("execute", "u", "orders", 1001);
        b.listener = Some("orders-pg".into());
        b.event_id = Some("ae-lsn-b".into());
        idx.insert(&b).unwrap();
        let mut c = sample("deny", "u", "billing", 1002);
        c.listener = Some("orders-mysql".into());
        c.event_id = Some("ae-lsn-c".into());
        idx.insert(&c).unwrap();

        let only_mysql = idx
            .query(&AuditQueryFilter {
                listener: Some("orders-mysql".into()),
                limit: 10,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(only_mysql.len(), 2, "{only_mysql:?}");
        assert!(only_mysql.iter().all(|e| e.listener.as_deref() == Some("orders-mysql")));

        let only_pg = idx
            .query(&AuditQueryFilter {
                listener: Some("orders-pg".into()),
                limit: 10,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(only_pg.len(), 1);
        assert_eq!(only_pg[0].event_id.as_deref(), Some("ae-lsn-b"));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

}
