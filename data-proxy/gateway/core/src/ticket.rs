//! Approval tickets for high-risk SQL (S5) + dual-control vault (F18).
//!
//! Tickets are **not** a full BPM. External systems (or Admin API) mint a short-lived
//! ticket bound to subject + SQL fingerprint; the data-plane embeds
//! `/*dn_ticket:<id>*/` (or `/* data_nexus_ticket: <id> */`) in the SQL text.
//!
//! **F18 dual control**: when `dual_control=true`, issue creates a **pending** ticket.
//! A second person (≠ issuer) must `approve` before the data plane can `consume` it.
//!
//! **H05**: optional file backend (`security.state.backend=file`) persists tickets as
//! JSON so multiple gateway processes on shared storage can share ticket state.
//! With `security.state.ticket_encrypt_key` the file is AES-GCM sealed (sql_sample
//! and metadata at rest).

use crate::state_crypto::{
    decode_maybe_encrypted, encrypt_blob, parse_encrypt_key,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;

static GLOBAL: OnceLock<Arc<TicketStore>> = OnceLock::new();

const TICKET_ENC_MAGIC: &str = "DNTICKET1:";

/// Process-wide ticket store (memory or file-backed per install).
pub fn global_ticket_store() -> Arc<TicketStore> {
    GLOBAL
        .get_or_init(|| Arc::new(TicketStore::new()))
        .clone()
}

/// H05: install / reconfigure ticket store backend. Safe to call on reload.
///
/// `encrypt_key_hex`: empty → plaintext JSON; 64 hex → AES-256-GCM envelope.
pub fn install_ticket_store(
    backend: &str,
    path: &str,
    encrypt_key_hex: &str,
) -> Result<Arc<TicketStore>, String> {
    let key = parse_encrypt_key(encrypt_key_hex)?;
    let store = match backend.trim().to_ascii_lowercase().as_str() {
        "memory" | "" => Arc::new(TicketStore::new()),
        "file" => Arc::new(TicketStore::with_file(PathBuf::from(path), key)?),
        other => {
            return Err(format!(
                "ticket store backend '{other}' not supported (use memory or file)"
            ))
        }
    };
    // OnceLock cannot replace; if already set, reconfigure in place.
    if let Some(existing) = GLOBAL.get() {
        existing.reconfigure_from(&store)?;
        return Ok(existing.clone());
    }
    let _ = GLOBAL.set(store.clone());
    Ok(store)
}

/// Lifecycle status for dual-control tickets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    /// Waiting for a second approver (dual_control only).
    Pending,
    /// Usable by the data plane (default for non-dual tickets).
    #[default]
    Active,
    /// Explicitly rejected; never consumable.
    Rejected,
}

impl TicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ticket {
    pub id: String,
    pub ticket_type: String,
    pub subject_id: String,
    /// Normalized SQL fingerprint this ticket authorizes.
    pub sql_fingerprint: String,
    /// Optional raw SQL snapshot (admin only; not required for match).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sql_sample: Option<String>,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub max_uses: u32,
    pub uses: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// When true, ticket starts as [`TicketStatus::Pending`] until a second person approves.
    #[serde(default)]
    pub dual_control: bool,
    #[serde(default)]
    pub status: TicketStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejected_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reject_reason: Option<String>,
}

impl Ticket {
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms > self.expires_at_unix_ms
    }

    pub fn remaining_uses(&self) -> u32 {
        self.max_uses.saturating_sub(self.uses)
    }

    pub fn is_consumable(&self, now_ms: u64) -> Result<(), String> {
        if self.is_expired(now_ms) {
            return Err(format!("ticket '{}' expired", self.id));
        }
        match self.status {
            TicketStatus::Active => {}
            TicketStatus::Pending => {
                return Err(format!(
                    "ticket '{}' is pending dual-control approval (POST /admin/tickets/{}/approve)",
                    self.id, self.id
                ));
            }
            TicketStatus::Rejected => {
                return Err(format!("ticket '{}' was rejected", self.id));
            }
        }
        if self.remaining_uses() == 0 {
            return Err(format!("ticket '{}' has no remaining uses", self.id));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueTicketRequest {
    pub subject_id: String,
    pub sql: String,
    #[serde(default = "default_ticket_type")]
    pub ticket_type: String,
    /// Validity window in seconds (default 600).
    #[serde(default = "default_ttl_secs")]
    pub ttl_secs: u64,
    #[serde(default = "default_max_uses")]
    pub max_uses: u32,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub issued_by: Option<String>,
    /// F18: require a second person to approve before the ticket is consumable.
    #[serde(default)]
    pub dual_control: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ApproveTicketRequest {
    /// Approver identity (admin subject). Must differ from issuer.
    #[serde(default)]
    pub approved_by: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RejectTicketRequest {
    #[serde(default)]
    pub rejected_by: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

fn default_ticket_type() -> String {
    "high_risk".into()
}
fn default_ttl_secs() -> u64 {
    600
}
fn default_max_uses() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct TicketFile {
    tickets: Vec<Ticket>,
}

#[derive(Debug)]
pub struct TicketStore {
    inner: Mutex<HashMap<String, Ticket>>,
    seq: AtomicU64,
    /// H05: optional JSON file path for durable shared state.
    path: Mutex<Option<PathBuf>>,
    /// H05: AES-256 key for sealed file (None = plaintext).
    encrypt_key: Mutex<Option<[u8; 32]>>,
}

impl TicketStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            seq: AtomicU64::new(1),
            path: Mutex::new(None),
            encrypt_key: Mutex::new(None),
        }
    }

    pub fn with_file(path: PathBuf, encrypt_key: Option<[u8; 32]>) -> Result<Self, String> {
        let store = Self {
            inner: Mutex::new(HashMap::new()),
            seq: AtomicU64::new(1),
            path: Mutex::new(Some(path.clone())),
            encrypt_key: Mutex::new(encrypt_key),
        };
        store.load_from_disk()?;
        Ok(store)
    }

    /// Replace in-memory map from another store (used when GLOBAL already installed).
    fn reconfigure_from(&self, other: &TicketStore) -> Result<(), String> {
        let map = other.inner.lock().map_err(|e| e.to_string())?.clone();
        let path = other.path.lock().map_err(|e| e.to_string())?.clone();
        let key = *other.encrypt_key.lock().map_err(|e| e.to_string())?;
        let seq = other.seq.load(Ordering::Relaxed);
        *self.inner.lock().map_err(|e| e.to_string())? = map;
        *self.path.lock().map_err(|e| e.to_string())? = path;
        *self.encrypt_key.lock().map_err(|e| e.to_string())? = key;
        self.seq.store(seq, Ordering::Relaxed);
        Ok(())
    }

    fn load_from_disk(&self) -> Result<(), String> {
        let path = self.path.lock().map_err(|e| e.to_string())?.clone();
        let Some(path) = path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        if !path.exists() {
            // Create empty file under exclusive lock.
            let lock = open_state_lock(&path)?;
            lock.lock_exclusive().map_err(|e| e.to_string())?;
            self.write_file_locked(&path, &HashMap::new())?;
            let _ = lock.unlock();
            return Ok(());
        }
        let lock = open_state_lock(&path)?;
        lock.lock_shared().map_err(|e| e.to_string())?;
        let mut file = File::open(&path).map_err(|e| e.to_string())?;
        let mut raw = String::new();
        file.read_to_string(&mut raw).map_err(|e| e.to_string())?;
        let _ = lock.unlock();
        if raw.trim().is_empty() {
            return Ok(());
        }
        let key = *self.encrypt_key.lock().map_err(|e| e.to_string())?;
        let bytes = decode_maybe_encrypted(TICKET_ENC_MAGIC, &raw, key.as_ref())?;
        let file: TicketFile = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        let mut map = HashMap::new();
        let mut max_seq = 1u64;
        for t in file.tickets {
            if let Some(n) = t.id.rsplit('-').next().and_then(|s| s.parse::<u64>().ok()) {
                max_seq = max_seq.max(n + 1);
            }
            map.insert(t.id.clone(), t);
        }
        self.seq.store(max_seq, Ordering::Relaxed);
        *self.inner.lock().map_err(|e| e.to_string())? = map;
        Ok(())
    }

    fn persist(&self) -> Result<(), String> {
        let guard = self.inner.lock().map_err(|e| e.to_string())?;
        self.persist_unlocked(&guard)
    }

    fn persist_unlocked(&self, map: &HashMap<String, Ticket>) -> Result<(), String> {
        let path = self.path.lock().map_err(|e| e.to_string())?.clone();
        let Some(path) = path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        // Exclusive lock for multi-process writers on shared disk (H05).
        let lock = open_state_lock(&path)?;
        lock.lock_exclusive().map_err(|e| e.to_string())?;
        self.write_file_locked(&path, map)?;
        let _ = lock.unlock();
        Ok(())
    }

    fn write_file_locked(
        &self,
        path: &std::path::Path,
        map: &HashMap<String, Ticket>,
    ) -> Result<(), String> {
        let mut tickets: Vec<Ticket> = map.values().cloned().collect();
        tickets.sort_by(|a, b| b.issued_at_unix_ms.cmp(&a.issued_at_unix_ms));
        let file = TicketFile { tickets };
        let plain = serde_json::to_vec_pretty(&file).map_err(|e| e.to_string())?;
        let key = *self.encrypt_key.lock().map_err(|e| e.to_string())?;
        let data = if let Some(key) = key {
            encrypt_blob(TICKET_ENC_MAGIC, &key, &plain)?
        } else {
            plain
        };
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, data).map_err(|e| e.to_string())?;
        fs::rename(&tmp, path).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn issue(&self, req: IssueTicketRequest) -> Ticket {
        let now = now_unix_ms();
        let id = format!(
            "tkt-{}-{}",
            now,
            self.seq.fetch_add(1, Ordering::Relaxed)
        );
        let fp = sql_fingerprint(&req.sql);
        let dual = req.dual_control;
        let ticket = Ticket {
            id: id.clone(),
            ticket_type: if req.ticket_type.trim().is_empty() {
                default_ticket_type()
            } else {
                req.ticket_type
            },
            subject_id: req.subject_id,
            sql_fingerprint: fp,
            sql_sample: Some(strip_ticket_comment(&req.sql)),
            issued_at_unix_ms: now,
            expires_at_unix_ms: now.saturating_add(req.ttl_secs.saturating_mul(1000)),
            max_uses: req.max_uses.max(1),
            uses: 0,
            issued_by: req.issued_by,
            note: req.note,
            dual_control: dual,
            status: if dual {
                TicketStatus::Pending
            } else {
                TicketStatus::Active
            },
            approved_by: None,
            approved_at_unix_ms: None,
            rejected_by: None,
            reject_reason: None,
        };
        {
            let mut guard = self.inner.lock().expect("ticket lock");
            guard.insert(id, ticket.clone());
        }
        let _ = self.persist();
        ticket
    }

    pub fn get(&self, id: &str) -> Option<Ticket> {
        self.inner.lock().ok()?.get(id).cloned()
    }

    pub fn list(&self, limit: usize) -> Vec<Ticket> {
        let guard = self.inner.lock().expect("ticket lock");
        let mut v: Vec<_> = guard.values().cloned().collect();
        v.sort_by(|a, b| b.issued_at_unix_ms.cmp(&a.issued_at_unix_ms));
        v.truncate(limit.clamp(1, 500));
        v
    }

    /// Second-person approval for dual-control tickets.
    ///
    /// Rules:
    /// - ticket must exist, not expired, status = pending, dual_control = true
    /// - approver must be non-empty
    /// - approver must not equal issuer (case-insensitive)
    pub fn approve(&self, ticket_id: &str, approved_by: &str) -> Result<Ticket, String> {
        let approver = approved_by.trim();
        if approver.is_empty() {
            return Err("approved_by is required".into());
        }
        let now = now_unix_ms();
        let mut guard = self.inner.lock().expect("ticket lock");
        let ticket = guard
            .get_mut(ticket_id)
            .ok_or_else(|| format!("ticket '{ticket_id}' not found"))?;
        if ticket.is_expired(now) {
            return Err(format!("ticket '{ticket_id}' expired"));
        }
        if !ticket.dual_control {
            return Err(format!(
                "ticket '{ticket_id}' is not dual-control (already active on issue)"
            ));
        }
        match ticket.status {
            TicketStatus::Pending => {}
            TicketStatus::Active => {
                return Err(format!("ticket '{ticket_id}' is already active"));
            }
            TicketStatus::Rejected => {
                return Err(format!("ticket '{ticket_id}' was rejected"));
            }
        }
        if let Some(issuer) = ticket.issued_by.as_deref() {
            if issuer.eq_ignore_ascii_case(approver) {
                return Err(format!(
                    "ticket '{ticket_id}' dual-control: approver must differ from issuer '{issuer}'"
                ));
            }
        }
        ticket.status = TicketStatus::Active;
        ticket.approved_by = Some(approver.to_owned());
        ticket.approved_at_unix_ms = Some(now);
        let out = ticket.clone();
        drop(guard);
        let _ = self.persist();
        Ok(out)
    }

    /// Reject a pending dual-control ticket (or any unused ticket).
    pub fn reject(
        &self,
        ticket_id: &str,
        rejected_by: &str,
        reason: Option<String>,
    ) -> Result<Ticket, String> {
        let rejector = rejected_by.trim();
        if rejector.is_empty() {
            return Err("rejected_by is required".into());
        }
        let mut guard = self.inner.lock().expect("ticket lock");
        let ticket = guard
            .get_mut(ticket_id)
            .ok_or_else(|| format!("ticket '{ticket_id}' not found"))?;
        if ticket.uses > 0 {
            return Err(format!(
                "ticket '{ticket_id}' already consumed and cannot be rejected"
            ));
        }
        match ticket.status {
            TicketStatus::Rejected => {
                return Err(format!("ticket '{ticket_id}' already rejected"));
            }
            TicketStatus::Pending | TicketStatus::Active => {}
        }
        ticket.status = TicketStatus::Rejected;
        ticket.rejected_by = Some(rejector.to_owned());
        ticket.reject_reason = reason;
        let out = ticket.clone();
        drop(guard);
        let _ = self.persist();
        Ok(out)
    }

    /// H03: alias of reject for active/pending unused tickets (explicit revoke wording).
    pub fn revoke(
        &self,
        ticket_id: &str,
        revoked_by: &str,
        reason: Option<String>,
    ) -> Result<Ticket, String> {
        self.reject(ticket_id, revoked_by, reason)
    }

    /// Drop expired tickets; returns count removed.
    pub fn prune_expired(&self) -> usize {
        let now = now_unix_ms();
        let mut guard = self.inner.lock().expect("ticket lock");
        let before = guard.len();
        guard.retain(|_, t| !t.is_expired(now));
        let removed = before.saturating_sub(guard.len());
        drop(guard);
        if removed > 0 {
            let _ = self.persist();
        }
        removed
    }

    /// Validate and consume one use. Returns Ok(ticket) or Err(reason).
    /// Dual-control tickets must be **active** (approved) before consume succeeds.
    pub fn consume(
        &self,
        ticket_id: &str,
        subject_id: &str,
        sql: &str,
        expected_type: Option<&str>,
    ) -> Result<Ticket, String> {
        let now = now_unix_ms();
        let fp = sql_fingerprint(sql);
        let mut guard = self.inner.lock().expect("ticket lock");
        let ticket = guard
            .get_mut(ticket_id)
            .ok_or_else(|| format!("ticket '{ticket_id}' not found"))?;
        ticket.is_consumable(now)?;
        if !ticket.subject_id.eq_ignore_ascii_case(subject_id) {
            return Err(format!(
                "ticket '{ticket_id}' subject mismatch (expected {}, got {subject_id})",
                ticket.subject_id
            ));
        }
        if let Some(tt) = expected_type {
            if !tt.is_empty() && !ticket.ticket_type.eq_ignore_ascii_case(tt) {
                return Err(format!(
                    "ticket '{ticket_id}' type mismatch (expected {tt}, got {})",
                    ticket.ticket_type
                ));
            }
        }
        if ticket.sql_fingerprint != fp {
            return Err(format!(
                "ticket '{ticket_id}' SQL fingerprint mismatch (re-issue for this statement)"
            ));
        }
        ticket.uses += 1;
        let out = ticket.clone();
        drop(guard);
        let _ = self.persist();
        Ok(out)
    }
}

impl Default for TicketStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Normalize SQL for ticket binding: strip ticket comments, collapse space, lower-case.
pub fn sql_fingerprint(sql: &str) -> String {
    let stripped = strip_ticket_comment(sql);
    let mut out = String::with_capacity(stripped.len());
    let mut prev_space = false;
    for ch in stripped.chars() {
        if ch.is_whitespace() {
            if !prev_space && !out.is_empty() {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(ch.to_ascii_lowercase());
            prev_space = false;
        }
    }
    out.trim().trim_end_matches(';').trim().to_owned()
}

/// Extract ticket id from SQL comment forms:
/// - `/*dn_ticket:ID*/`
/// - `/* data_nexus_ticket: ID */`
/// - `/*+ dn_ticket=ID */`
pub fn extract_ticket_id(sql: &str) -> Option<String> {
    let s = sql.trim_start();
    if !s.starts_with("/*") {
        return None;
    }
    let end = s.find("*/")?;
    let body = s[2..end].trim();
    // strip optional leading +
    let body = body.trim_start_matches('+').trim();
    let lower = body.to_ascii_lowercase();
    for prefix in ["dn_ticket:", "data_nexus_ticket:", "dn_ticket="] {
        if let Some(_rest) = lower.strip_prefix(prefix) {
            // recover original casing from body
            let idx = prefix.len();
            let id = body[idx..].trim().split_whitespace().next()?.to_owned();
            if !id.is_empty() {
                return Some(id);
            }
        }
    }
    // key=value form with spaces: dn_ticket = ID
    if let Some(pos) = lower.find("dn_ticket") {
        let after = body[pos + "dn_ticket".len()..].trim_start();
        let after = after.trim_start_matches([':', '=']).trim_start();
        let id = after.split_whitespace().next()?.to_owned();
        if !id.is_empty() {
            return Some(id);
        }
    }
    None
}

pub fn strip_ticket_comment(sql: &str) -> String {
    let s = sql.trim_start();
    if s.starts_with("/*") {
        if let Some(end) = s.find("*/") {
            let body = s[2..end].to_ascii_lowercase();
            if body.contains("dn_ticket") || body.contains("data_nexus_ticket") {
                return s[end + 2..].trim_start().to_owned();
            }
        }
    }
    sql.to_owned()
}

/// Heuristic: UPDATE/DELETE without WHERE (top-level).
pub fn is_write_without_where(sql: &str) -> bool {
    let s = strip_ticket_comment(sql);
    let upper = s.trim_start().to_ascii_uppercase();
    if !(upper.starts_with("UPDATE") || upper.starts_with("DELETE")) {
        return false;
    }
    // crude top-level WHERE search (ignore nested parens lightly)
    !contains_top_level_keyword(&s, "WHERE")
}

fn contains_top_level_keyword(sql: &str, keyword: &str) -> bool {
    let upper = sql.to_ascii_uppercase();
    let key = keyword.to_ascii_uppercase();
    let bytes = upper.as_bytes();
    let key_b = key.as_bytes();
    let mut depth = 0i32;
    let mut i = 0usize;
    while i + key_b.len() <= bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ if depth == 0 && bytes[i..].starts_with(key_b) => {
                let before_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
                let after = i + key_b.len();
                let after_ok = after >= bytes.len() || !bytes[after].is_ascii_alphanumeric();
                if before_ok && after_ok {
                    return true;
                }
            }
            _ => {}
        }
        i += 1;
    }
    false
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}


/// Sidecar lock file next to the JSON state file (H05 multi-process).
fn open_state_lock(path: &std::path::Path) -> Result<File, String> {
    let lock_path = path.with_extension("json.lock");
    OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(lock_path)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_ignores_ticket_comment_and_case() {
        let a = sql_fingerprint("/*dn_ticket:t1*/ SELECT Id FROM T;");
        let b = sql_fingerprint("select id from t");
        assert_eq!(a, b);
    }

    #[test]
    fn extract_ticket_variants() {
        assert_eq!(
            extract_ticket_id("/*dn_ticket:abc-1*/ SELECT 1").as_deref(),
            Some("abc-1")
        );
        assert_eq!(
            extract_ticket_id("/* data_nexus_ticket: xyz */ SELECT 1").as_deref(),
            Some("xyz")
        );
    }

    #[test]
    fn write_without_where_detects() {
        assert!(is_write_without_where("UPDATE employees SET salary=1"));
        assert!(!is_write_without_where("UPDATE employees SET salary=1 WHERE id=1"));
        assert!(is_write_without_where("DELETE FROM employees"));
        assert!(!is_write_without_where("DELETE FROM employees WHERE id=1"));
    }

    #[test]
    fn issue_and_consume() {
        let store = TicketStore::new();
        let t = store.issue(IssueTicketRequest {
            subject_id: "root".into(),
            sql: "DROP TABLE smoke_t".into(),
            ticket_type: "ddl".into(),
            ttl_secs: 60,
            max_uses: 1,
            note: None,
            issued_by: Some("admin".into()),
            dual_control: false,
        });
        assert_eq!(t.status, TicketStatus::Active);
        assert!(!t.dual_control);
        let sql = format!("/*dn_ticket:{}*/ DROP TABLE smoke_t", t.id);
        store
            .consume(&t.id, "root", &sql, Some("ddl"))
            .expect("consume");
        assert!(store.consume(&t.id, "root", &sql, Some("ddl")).is_err());
    }

    #[test]
    fn dual_control_requires_second_approver() {
        let store = TicketStore::new();
        let t = store.issue(IssueTicketRequest {
            subject_id: "root".into(),
            sql: "DROP TABLE vault_t".into(),
            ticket_type: "ddl".into(),
            ttl_secs: 120,
            max_uses: 1,
            note: Some("dual".into()),
            issued_by: Some("issuer-alice".into()),
            dual_control: true,
        });
        assert_eq!(t.status, TicketStatus::Pending);
        assert!(t.dual_control);

        let sql = format!("/*dn_ticket:{}*/ DROP TABLE vault_t", t.id);
        let err = store
            .consume(&t.id, "root", &sql, Some("ddl"))
            .expect_err("pending must not consume");
        assert!(
            err.to_ascii_lowercase().contains("pending")
                || err.to_ascii_lowercase().contains("dual"),
            "err={err}"
        );

        // Self-approve blocked.
        let self_err = store
            .approve(&t.id, "issuer-alice")
            .expect_err("self-approve");
        assert!(
            self_err.to_ascii_lowercase().contains("differ")
                || self_err.to_ascii_lowercase().contains("issuer"),
            "err={self_err}"
        );

        let approved = store.approve(&t.id, "approver-bob").expect("approve");
        assert_eq!(approved.status, TicketStatus::Active);
        assert_eq!(approved.approved_by.as_deref(), Some("approver-bob"));

        store
            .consume(&t.id, "root", &sql, Some("ddl"))
            .expect("consume after approve");
    }

    #[test]
    fn dual_control_reject_blocks_consume() {
        let store = TicketStore::new();
        let t = store.issue(IssueTicketRequest {
            subject_id: "root".into(),
            sql: "TRUNCATE TABLE t".into(),
            ticket_type: "ddl".into(),
            ttl_secs: 60,
            max_uses: 1,
            note: None,
            issued_by: Some("alice".into()),
            dual_control: true,
        });
        store
            .reject(&t.id, "bob", Some("too risky".into()))
            .expect("reject");
        let sql = format!("/*dn_ticket:{}*/ TRUNCATE TABLE t", t.id);
        let err = store
            .consume(&t.id, "root", &sql, Some("ddl"))
            .expect_err("rejected");
        assert!(err.to_ascii_lowercase().contains("reject"), "err={err}");
    }

    #[test]
    fn dual_control_issuer_may_self_reject() {
        // Unlike approve, reject does not require a second person — issuer can withdraw.
        let store = TicketStore::new();
        let t = store.issue(IssueTicketRequest {
            subject_id: "root".into(),
            sql: "DROP TABLE t".into(),
            ticket_type: "ddl".into(),
            ttl_secs: 60,
            max_uses: 1,
            note: None,
            issued_by: Some("alice".into()),
            dual_control: true,
        });
        let rejected = store
            .reject(&t.id, "alice", Some("issuer withdraw".into()))
            .expect("issuer self-reject");
        assert_eq!(rejected.status, TicketStatus::Rejected);
        assert_eq!(rejected.rejected_by.as_deref(), Some("alice"));
        let sql = format!("/*dn_ticket:{}*/ DROP TABLE t", t.id);
        let err = store
            .consume(&t.id, "root", &sql, Some("ddl"))
            .expect_err("rejected");
        assert!(err.to_ascii_lowercase().contains("reject"), "err={err}");
    }

    #[test]
    fn h05_ticket_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!("dn-h05-tkt-{}", now_unix_ms()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("tickets.json");
        let store = TicketStore::with_file(path.clone(), None).unwrap();
        let t = store.issue(IssueTicketRequest {
            subject_id: "alice".into(),
            sql: "DELETE FROM t".into(),
            ticket_type: "high_risk".into(),
            ttl_secs: 600,
            max_uses: 1,
            note: None,
            issued_by: Some("admin".into()),
            dual_control: false,
        });
        drop(store);
        let store2 = TicketStore::with_file(path, None).unwrap();
        let got = store2.get(&t.id).expect("reloaded");
        assert_eq!(got.subject_id, "alice");
        assert_eq!(got.sql_fingerprint, t.sql_fingerprint);
        let _ = std::fs::remove_dir_all(&dir);
    }


    #[test]
    fn h05_ticket_file_lock_serializes_writes() {
        let dir = std::env::temp_dir().join(format!("dn-h05-lock-{}", now_unix_ms()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("tickets.json");
        let a = TicketStore::with_file(path.clone(), None).unwrap();
        let b = TicketStore::with_file(path.clone(), None).unwrap();
        let t1 = a.issue(IssueTicketRequest {
            subject_id: "a".into(),
            sql: "SELECT 1".into(),
            ticket_type: "high_risk".into(),
            ttl_secs: 600,
            max_uses: 1,
            note: None,
            issued_by: None,
            dual_control: false,
        });
        let t2 = b.issue(IssueTicketRequest {
            subject_id: "b".into(),
            sql: "SELECT 2".into(),
            ticket_type: "high_risk".into(),
            ttl_secs: 600,
            max_uses: 1,
            note: None,
            issued_by: None,
            dual_control: false,
        });
        // Last exclusive write wins for full-file replace semantics; both must succeed
        // without panicking under lock. Reload sees a consistent JSON file.
        let c = TicketStore::with_file(path, None).unwrap();
        let list = c.list(10);
        assert!(!list.is_empty());
        // At least the last writer's ticket is present.
        assert!(c.get(&t1.id).is_some() || c.get(&t2.id).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn h05_ticket_encrypted_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!("dn-h05-tkt-enc-{}", now_unix_ms()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("tickets.json");
        let key_hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let key = parse_encrypt_key(key_hex).unwrap();
        let store = TicketStore::with_file(path.clone(), key).unwrap();
        let t = store.issue(IssueTicketRequest {
            subject_id: "alice".into(),
            sql: "DELETE FROM secret_table WHERE id=1".into(),
            ticket_type: "high_risk".into(),
            ttl_secs: 600,
            max_uses: 1,
            note: Some("sensitive".into()),
            issued_by: Some("admin".into()),
            dual_control: false,
        });
        drop(store);
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.starts_with(TICKET_ENC_MAGIC));
        assert!(!raw.contains("secret_table"));
        assert!(!raw.contains("alice"));

        let store2 = TicketStore::with_file(path.clone(), key).unwrap();
        let got = store2.get(&t.id).expect("reloaded");
        assert_eq!(got.subject_id, "alice");
        assert_eq!(got.sql_fingerprint, t.sql_fingerprint);
        assert!(got.sql_sample.as_deref().unwrap_or("").contains("secret_table"));

        assert!(TicketStore::with_file(path.clone(), None).is_err());
        let bad = parse_encrypt_key(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        .unwrap();
        assert!(TicketStore::with_file(path, bad).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}