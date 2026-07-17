//! Approval tickets for high-risk SQL (S5) + dual-control vault (F18).
//!
//! Tickets are **not** a full BPM. External systems (or Admin API) mint a short-lived
//! ticket bound to subject + SQL fingerprint; the data-plane embeds
//! `/*dn_ticket:<id>*/` (or `/* data_nexus_ticket: <id> */`) in the SQL text.
//!
//! **F18 dual control**: when `dual_control=true`, issue creates a **pending** ticket.
//! A second person (≠ issuer) must `approve` before the data plane can `consume` it.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

static GLOBAL: OnceLock<Arc<TicketStore>> = OnceLock::new();

/// Process-wide ticket store.
pub fn global_ticket_store() -> Arc<TicketStore> {
    GLOBAL
        .get_or_init(|| Arc::new(TicketStore::new()))
        .clone()
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

#[derive(Debug)]
pub struct TicketStore {
    inner: Mutex<HashMap<String, Ticket>>,
    seq: AtomicU64,
}

impl TicketStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            seq: AtomicU64::new(1),
        }
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
        self.inner
            .lock()
            .expect("ticket lock")
            .insert(id, ticket.clone());
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
        Ok(ticket.clone())
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
        Ok(ticket.clone())
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
        before.saturating_sub(guard.len())
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
        Ok(ticket.clone())
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
}
