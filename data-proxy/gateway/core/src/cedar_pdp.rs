//! Optional Cedar PDP (F26) + policy hot-reload (epoch / keep-old) + entity attrs (F29).
//!
//! Compiled only with `--features security-cedar`. Evaluates **table + action**
//! authorization using [Cedar](https://www.cedarpolicy.com/) policies loaded from
//! `security.pdp.policy_dir`. Column masks, row filters, tickets, and time rules
//! remain on the Local path and are composed after Cedar allows the statement.
//!
//! Entity model:
//! - principal: `User::"<subject_id>"` with optional attrs `tenant`, `clearance`, `roles`
//! - action: `Action::"select|insert|update|delete|ddl|tcl|other"`
//! - resource: `Table::"<table>"` with optional attrs `tenant`, `clearance`, `classification`
//!
//! Attr directories come from static config (`security.pdp.subject_attrs` /
//! `security.pdp.table_attrs`). Empty directories keep F26 behaviour (`Entities::empty()`
//! is still valid for uid-only policies).
//!
//! Empty object set (e.g. `SELECT 1`) uses resource `Table::"__none__"`.
//!
//! Hot-reload: process-wide [`CedarPolicyStore`] holds an epoch'd snapshot.
//! `reload_from_dir` validates on a side buffer and only swaps on success
//! (admin reload / `POST /admin/security/cedar/reload` semantics).

#![cfg(feature = "security-cedar")]

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use cedar_policy::{
    Authorizer, Context, Decision, Entities, Entity, EntityUid, PolicySet, Request,
    RestrictedExpression,
};
use tracing::info;

use crate::security::{SecuritySubjectAttrConfig, SecurityTableAttrConfig};
use crate::{GatewayError, GatewayResult, StatementAction};

static GLOBAL: OnceLock<Arc<CedarPolicyStore>> = OnceLock::new();

/// Process-wide Cedar store (shared by all listeners / portal).
pub fn global_cedar_store() -> Option<Arc<CedarPolicyStore>> {
    GLOBAL.get().cloned()
}

/// Install store if missing, then load `policy_dir` (keep-old if already loaded and load fails).
pub fn install_cedar_store(policy_dir: &str) -> GatewayResult<Arc<CedarPolicyStore>> {
    let store = GLOBAL
        .get_or_init(|| Arc::new(CedarPolicyStore::empty()))
        .clone();
    store.reload_from_dir(policy_dir)?;
    Ok(store)
}

/// Force reload of the global store from `policy_dir`. Keep-old on failure if a
/// previous snapshot exists.
pub fn reload_global_cedar(policy_dir: &str) -> GatewayResult<CedarReloadInfo> {
    let store = GLOBAL
        .get_or_init(|| Arc::new(CedarPolicyStore::empty()))
        .clone();
    store.reload_from_dir(policy_dir)
}

/// Result of a successful Cedar reload (or no-op when content unchanged).
#[derive(Debug, Clone, serde::Serialize)]
pub struct CedarReloadInfo {
    pub epoch: u64,
    pub source: String,
    pub files: usize,
    pub policy_count: usize,
    pub loaded_at_unix_ms: u64,
    /// True when the swap advanced the epoch (content changed).
    pub swapped: bool,
}

/// Status snapshot for Admin API.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CedarStatus {
    pub installed: bool,
    pub epoch: u64,
    pub source: String,
    pub files: usize,
    pub policy_count: usize,
    pub loaded_at_unix_ms: u64,
    pub ready: bool,
}

#[derive(Debug, Clone)]
struct CedarSnapshot {
    policies: Arc<PolicySet>,
    source: String,
    files: usize,
    policy_count: usize,
    loaded_at_unix_ms: u64,
    /// Concatenated source fingerprint for cheap no-op reload.
    content_fp: u64,
}

impl CedarSnapshot {
    fn empty() -> Self {
        Self {
            policies: Arc::new(PolicySet::new()),
            source: String::new(),
            files: 0,
            policy_count: 0,
            loaded_at_unix_ms: 0,
            content_fp: 0,
        }
    }
}

/// Shared, epoch'd Cedar policy set (lock for write; readers take Arc snapshot).
#[derive(Debug)]
pub struct CedarPolicyStore {
    inner: RwLock<CedarSnapshot>,
    epoch: AtomicU64,
    authorizer: Authorizer,
}

impl CedarPolicyStore {
    fn empty() -> Self {
        Self {
            inner: RwLock::new(CedarSnapshot::empty()),
            epoch: AtomicU64::new(0),
            authorizer: Authorizer::new(),
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    pub fn status(&self) -> CedarStatus {
        let snap = self.inner.read().expect("cedar store").clone();
        CedarStatus {
            installed: true,
            epoch: self.epoch(),
            source: snap.source,
            files: snap.files,
            policy_count: snap.policy_count,
            loaded_at_unix_ms: snap.loaded_at_unix_ms,
            ready: snap.files > 0 && snap.policy_count > 0,
        }
    }

    pub fn is_ready(&self) -> bool {
        let snap = self.inner.read().expect("cedar store");
        snap.files > 0 && !snap.source.is_empty()
    }

    /// Load and validate policies from disk; swap only on success.
    ///
    /// If a previous good snapshot exists and the new load fails, the error is
    /// returned and the old snapshot remains (keep-old).
    pub fn reload_from_dir(&self, policy_dir: &str) -> GatewayResult<CedarReloadInfo> {
        let loaded = load_dir_snapshot(policy_dir);
        match loaded {
            Ok(new_snap) => {
                let mut guard = self.inner.write().expect("cedar store");
                let same = guard.files > 0 && guard.content_fp == new_snap.content_fp;
                if same {
                    return Ok(CedarReloadInfo {
                        epoch: self.epoch(),
                        source: guard.source.clone(),
                        files: guard.files,
                        policy_count: guard.policy_count,
                        loaded_at_unix_ms: guard.loaded_at_unix_ms,
                        swapped: false,
                    });
                }
                *guard = new_snap;
                let epoch = self.epoch.fetch_add(1, Ordering::AcqRel) + 1;
                info!(
                    target: "data_nexus::security",
                    epoch,
                    policy_dir = %guard.source,
                    files = guard.files,
                    policy_count = guard.policy_count,
                    "cedar PDP snapshot swapped"
                );
                Ok(CedarReloadInfo {
                    epoch,
                    source: guard.source.clone(),
                    files: guard.files,
                    policy_count: guard.policy_count,
                    loaded_at_unix_ms: guard.loaded_at_unix_ms,
                    swapped: true,
                })
            }
            Err(e) => {
                let ready = self.is_ready();
                if ready {
                    // keep-old
                    return Err(GatewayError::Configuration(format!(
                        "cedar reload failed (kept previous epoch {}): {e}",
                        self.epoch()
                    )));
                }
                Err(e)
            }
        }
    }

    /// Load from in-memory Cedar text (tests / fixtures). Keep-old on parse failure.
    pub fn reload_from_str(&self, source: &str, text: &str) -> GatewayResult<CedarReloadInfo> {
        let policies = match PolicySet::from_str(text) {
            Ok(p) => p,
            Err(e) => {
                let msg = format!("invalid Cedar policies ({source}): {e}");
                if self.is_ready() {
                    return Err(GatewayError::Configuration(format!(
                        "cedar reload failed (kept previous epoch {}): {msg}",
                        self.epoch()
                    )));
                }
                return Err(GatewayError::Configuration(msg));
            }
        };
        let policy_count = policies.policies().count();
        let content_fp = fnv1a64(text.as_bytes());
        let new_snap = CedarSnapshot {
            policies: Arc::new(policies),
            source: source.to_owned(),
            files: 1,
            policy_count,
            loaded_at_unix_ms: now_unix_ms(),
            content_fp,
        };
        let mut guard = self.inner.write().expect("cedar store");
        let same = guard.files > 0 && guard.content_fp == new_snap.content_fp;
        if same {
            return Ok(CedarReloadInfo {
                epoch: self.epoch(),
                source: guard.source.clone(),
                files: guard.files,
                policy_count: guard.policy_count,
                loaded_at_unix_ms: guard.loaded_at_unix_ms,
                swapped: false,
            });
        }
        *guard = new_snap;
        let epoch = self.epoch.fetch_add(1, Ordering::AcqRel) + 1;
        Ok(CedarReloadInfo {
            epoch,
            source: guard.source.clone(),
            files: guard.files,
            policy_count: guard.policy_count,
            loaded_at_unix_ms: guard.loaded_at_unix_ms,
            swapped: true,
        })
    }

    fn with_policies<R>(&self, f: impl FnOnce(&PolicySet) -> R) -> Result<R, String> {
        let guard = self.inner.read().map_err(|_| "cedar store poisoned".to_owned())?;
        if guard.files == 0 {
            return Err("cedar PDP has no loaded policies".into());
        }
        Ok(f(&guard.policies))
    }

    pub fn is_allowed(
        &self,
        subject_id: &str,
        action: StatementAction,
        table: &str,
    ) -> Result<bool, String> {
        self.is_allowed_with_attrs(subject_id, action, table, &[], &[])
    }

    /// F29: authorize with optional static subject/table attribute directories.
    pub fn is_allowed_with_attrs(
        &self,
        subject_id: &str,
        action: StatementAction,
        table: &str,
        subject_attrs: &[SecuritySubjectAttrConfig],
        table_attrs: &[SecurityTableAttrConfig],
    ) -> Result<bool, String> {
        let principal = entity_uid("User", &sanitize_id(subject_id))?;
        let action_uid = entity_uid("Action", action.as_str())?;
        let resource = entity_uid("Table", &sanitize_id(table))?;
        let request = Request::new(
            principal.clone(),
            action_uid,
            resource.clone(),
            Context::empty(),
            None,
        )
        .map_err(|e| format!("cedar request: {e}"))?;
        let entities = build_entities(
            subject_id,
            table,
            &principal,
            &resource,
            subject_attrs,
            table_attrs,
        )?;
        self.with_policies(|policies| {
            let response = self.authorizer.is_authorized(&request, policies, &entities);
            response.decision() == Decision::Allow
        })
    }

    pub fn authorize_tables(
        &self,
        subject_id: &str,
        action: StatementAction,
        tables: &[String],
    ) -> Result<(), String> {
        self.authorize_tables_with_attrs(subject_id, action, tables, &[], &[])
    }

    /// F29: authorize each table with entity attributes.
    pub fn authorize_tables_with_attrs(
        &self,
        subject_id: &str,
        action: StatementAction,
        tables: &[String],
        subject_attrs: &[SecuritySubjectAttrConfig],
        table_attrs: &[SecurityTableAttrConfig],
    ) -> Result<(), String> {
        if tables.is_empty() {
            if self.is_allowed_with_attrs(
                subject_id,
                action,
                "__none__",
                subject_attrs,
                table_attrs,
            )? {
                return Ok(());
            }
            return Err(format!(
                "cedar deny: subject '{subject_id}' action '{}' on empty object set",
                action.as_str()
            ));
        }
        for table in tables {
            let bare = bare_table_name(table);
            if !self.is_allowed_with_attrs(
                subject_id,
                action,
                bare,
                subject_attrs,
                table_attrs,
            )? {
                return Err(format!(
                    "cedar deny: subject '{subject_id}' action '{}' on table '{bare}'",
                    action.as_str()
                ));
            }
        }
        Ok(())
    }
}

/// Cheap handle used by [`crate::LocalPdp`] (clones share the global store).
#[derive(Debug, Clone)]
pub struct CedarEngine {
    store: Arc<CedarPolicyStore>,
    /// F29: static attr directories cloned from `security.pdp` at load/reload time.
    subject_attrs: Arc<Vec<SecuritySubjectAttrConfig>>,
    table_attrs: Arc<Vec<SecurityTableAttrConfig>>,
}

impl CedarEngine {
    pub fn from_store(store: Arc<CedarPolicyStore>) -> Self {
        Self {
            store,
            subject_attrs: Arc::new(Vec::new()),
            table_attrs: Arc::new(Vec::new()),
        }
    }

    pub fn with_attr_dirs(
        mut self,
        subject_attrs: Vec<SecuritySubjectAttrConfig>,
        table_attrs: Vec<SecurityTableAttrConfig>,
    ) -> Self {
        self.subject_attrs = Arc::new(subject_attrs);
        self.table_attrs = Arc::new(table_attrs);
        self
    }

    pub fn store(&self) -> &Arc<CedarPolicyStore> {
        &self.store
    }

    pub fn epoch(&self) -> u64 {
        self.store.epoch()
    }

    pub fn source(&self) -> String {
        self.store.inner.read().expect("cedar store").source.clone()
    }

    /// Load every `*.cedar` file under `policy_dir` into the **global** store.
    pub fn load_dir(policy_dir: &str) -> GatewayResult<Self> {
        let store = install_cedar_store(policy_dir)?;
        Ok(Self::from_store(store))
    }

    /// Parse policies from an in-memory string into a **private** store (tests).
    pub fn from_str_policies(source: &str, text: &str) -> GatewayResult<Self> {
        let store = Arc::new(CedarPolicyStore::empty());
        store.reload_from_str(source, text)?;
        Ok(Self::from_store(store))
    }

    pub fn is_allowed(
        &self,
        subject_id: &str,
        action: StatementAction,
        table: &str,
    ) -> Result<bool, String> {
        self.store.is_allowed_with_attrs(
            subject_id,
            action,
            table,
            &self.subject_attrs,
            &self.table_attrs,
        )
    }

    pub fn authorize_tables(
        &self,
        subject_id: &str,
        action: StatementAction,
        tables: &[String],
    ) -> Result<(), String> {
        self.store.authorize_tables_with_attrs(
            subject_id,
            action,
            tables,
            &self.subject_attrs,
            &self.table_attrs,
        )
    }
}

fn load_dir_snapshot(policy_dir: &str) -> GatewayResult<CedarSnapshot> {
    let dir = Path::new(policy_dir);
    if !dir.is_dir() {
        return Err(GatewayError::Configuration(format!(
            "security.pdp.policy_dir '{policy_dir}' is not a directory"
        )));
    }
    let mut merged = String::new();
    let mut files = 0usize;
    let mut entries: Vec<_> = fs::read_dir(dir)
        .map_err(|e| {
            GatewayError::Configuration(format!(
                "security.pdp.policy_dir '{policy_dir}' read error: {e}"
            ))
        })?
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("cedar") {
            continue;
        }
        let text = fs::read_to_string(&path).map_err(|e| {
            GatewayError::Configuration(format!(
                "failed to read cedar policy {}: {e}",
                path.display()
            ))
        })?;
        merged.push_str(&text);
        if !merged.ends_with('\n') {
            merged.push('\n');
        }
        files += 1;
    }
    if files == 0 {
        return Err(GatewayError::Configuration(format!(
            "security.pdp.policy_dir '{policy_dir}' has no *.cedar files"
        )));
    }
    let policies = PolicySet::from_str(&merged).map_err(|e| {
        GatewayError::Configuration(format!(
            "invalid Cedar policies in '{policy_dir}': {e}"
        ))
    })?;
    let policy_count = policies.policies().count();
    let content_fp = fnv1a64(merged.as_bytes());
    info!(
        target: "data_nexus::security",
        policy_dir = %policy_dir,
        files,
        policy_count,
        "cedar PDP loaded (validated)"
    );
    Ok(CedarSnapshot {
        policies: Arc::new(policies),
        source: policy_dir.to_owned(),
        files,
        policy_count,
        loaded_at_unix_ms: now_unix_ms(),
        content_fp,
    })
}

/// Resolve Cedar engine from config fields (feature-gated caller).
pub fn try_load_from_config(policy_dir: &str) -> GatewayResult<Option<CedarEngine>> {
    if policy_dir.trim().is_empty() {
        return Err(GatewayError::Configuration(
            "security.pdp.backend=cedar requires non-empty security.pdp.policy_dir".into(),
        ));
    }
    Ok(Some(CedarEngine::load_dir(policy_dir.trim())?))
}

/// F29: load policies + static entity attribute directories from full PDP config.
pub fn try_load_from_pdp_config(
    pdp: &crate::security::SecurityPdpConfig,
) -> GatewayResult<Option<CedarEngine>> {
    let eng = try_load_from_config(&pdp.policy_dir)?;
    Ok(eng.map(|e| e.with_attr_dirs(pdp.subject_attrs.clone(), pdp.table_attrs.clone())))
}

fn entity_uid(ty: &str, id: &str) -> Result<EntityUid, String> {
    let s = format!(r#"{ty}::"{id}""#);
    EntityUid::from_str(&s).map_err(|e| format!("entity uid {s}: {e}"))
}

fn sanitize_id(raw: &str) -> String {
    raw.replace('\\', "\\\\").replace('"', "\\\"")
}

fn bare_table_name(qualified: &str) -> &str {
    qualified
        .rsplit(['.', '/'])
        .next()
        .unwrap_or(qualified)
        .trim_matches('`')
        .trim_matches('"')
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// F29: build Entities for one request (principal + resource). Empty attrs → empty Entities.
fn build_entities(
    subject_id: &str,
    table: &str,
    principal: &EntityUid,
    resource: &EntityUid,
    subject_attrs: &[SecuritySubjectAttrConfig],
    table_attrs: &[SecurityTableAttrConfig],
) -> Result<Entities, String> {
    let subj = find_subject_attrs(subject_id, subject_attrs);
    let tbl = find_table_attrs(table, table_attrs);
    if subj.is_none() && tbl.is_none() {
        // Preserve F26 behaviour for uid-only policies.
        return Ok(Entities::empty());
    }

    let mut entities = Vec::with_capacity(2);
    let mut user_attrs = HashMap::new();
    if let Some(s) = subj {
        if !s.tenant.is_empty() {
            user_attrs.insert("tenant".into(), string_attr(&s.tenant)?);
        }
        if !s.clearance.is_empty() {
            user_attrs.insert("clearance".into(), string_attr(&s.clearance)?);
        }
        if !s.roles.is_empty() {
            user_attrs.insert("roles".into(), set_string_attr(&s.roles)?);
        }
    }
    entities.push(
        Entity::new(principal.clone(), user_attrs, HashSet::new())
            .map_err(|e| format!("cedar User entity: {e}"))?,
    );

    let mut table_map = HashMap::new();
    if let Some(t) = tbl {
        if !t.tenant.is_empty() {
            table_map.insert("tenant".into(), string_attr(&t.tenant)?);
        }
        if !t.clearance.is_empty() {
            table_map.insert("clearance".into(), string_attr(&t.clearance)?);
        }
        if !t.classification.is_empty() {
            table_map.insert("classification".into(), string_attr(&t.classification)?);
        }
    }
    entities.push(
        Entity::new(resource.clone(), table_map, HashSet::new())
            .map_err(|e| format!("cedar Table entity: {e}"))?,
    );

    Entities::from_entities(entities, None).map_err(|e| format!("cedar entities: {e}"))
}

fn find_subject_attrs<'a>(
    subject_id: &str,
    dirs: &'a [SecuritySubjectAttrConfig],
) -> Option<&'a SecuritySubjectAttrConfig> {
    dirs.iter()
        .find(|s| s.subject_id.eq_ignore_ascii_case(subject_id))
}

fn find_table_attrs<'a>(
    table: &str,
    dirs: &'a [SecurityTableAttrConfig],
) -> Option<&'a SecurityTableAttrConfig> {
    let bare = bare_table_name(table);
    dirs.iter()
        .find(|t| t.table.eq_ignore_ascii_case(bare) || t.table.eq_ignore_ascii_case(table))
}

fn string_attr(value: &str) -> Result<RestrictedExpression, String> {
    // RestrictedExpression string literal needs JSON-style quotes.
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    RestrictedExpression::from_str(&format!("\"{escaped}\""))
        .map_err(|e| format!("cedar string attr: {e}"))
}

fn set_string_attr(values: &[String]) -> Result<RestrictedExpression, String> {
    let mut parts = Vec::with_capacity(values.len());
    for v in values {
        let escaped = v.replace('\\', "\\\\").replace('"', "\\\"");
        parts.push(format!("\"{escaped}\""));
    }
    let lit = format!("[{}]", parts.join(", "));
    RestrictedExpression::from_str(&lit).map_err(|e| format!("cedar set attr: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StatementAction;

    const FIXTURE: &str = r#"
permit (
  principal,
  action == Action::"select",
  resource
)
when { resource != Table::"secret_tokens" };

permit (
  principal,
  action == Action::"select",
  resource == Table::"__none__"
);

forbid (
  principal,
  action,
  resource
)
when { resource == Table::"secret_tokens" };

permit (
  principal,
  action == Action::"insert",
  resource == Table::"orders"
);
"#;

    const FIXTURE_ALLOW_SECRET: &str = r#"
permit (principal, action == Action::"select", resource);
permit (principal, action == Action::"select", resource == Table::"__none__");
"#;

    #[test]
    fn select_allowed_on_orders() {
        let eng = CedarEngine::from_str_policies("fixture", FIXTURE).unwrap();
        assert!(eng
            .is_allowed("alice", StatementAction::Select, "orders")
            .unwrap());
    }

    /// F29: clearance / tenant attributes gate select on secret classification tables.
    const FIXTURE_ATTRS: &str = r#"
// Default allow select on non-secret tables (uid-only path still works without attrs).
permit (
  principal,
  action == Action::"select",
  resource
)
when { resource != Table::"payroll" && resource != Table::"secret_tokens" };

permit (
  principal,
  action == Action::"select",
  resource == Table::"__none__"
);

// Attribute gate: only clearance >= secret may read payroll.
permit (
  principal,
  action == Action::"select",
  resource
)
when {
  resource == Table::"payroll" &&
  principal has clearance &&
  principal.clearance == "secret" &&
  principal has tenant &&
  resource has tenant &&
  principal.tenant == resource.tenant
};

forbid (
  principal,
  action,
  resource
)
when { resource == Table::"secret_tokens" };
"#;

    #[test]
    fn f29_attr_allow_same_tenant_secret_clearance() {
        let eng = CedarEngine::from_str_policies("attrs", FIXTURE_ATTRS)
            .unwrap()
            .with_attr_dirs(
                vec![SecuritySubjectAttrConfig {
                    subject_id: "alice".into(),
                    tenant: "acme".into(),
                    clearance: "secret".into(),
                    roles: vec!["analyst".into()],
                }],
                vec![SecurityTableAttrConfig {
                    table: "payroll".into(),
                    tenant: "acme".into(),
                    clearance: "secret".into(),
                    classification: "pii".into(),
                }],
            );
        assert!(
            eng.is_allowed("alice", StatementAction::Select, "payroll")
                .unwrap(),
            "same tenant + secret clearance should allow"
        );
        assert!(
            eng.is_allowed("alice", StatementAction::Select, "orders")
                .unwrap(),
            "non-attr tables still allowed"
        );
    }

    #[test]
    fn f29_attr_deny_low_clearance_or_wrong_tenant() {
        let eng = CedarEngine::from_str_policies("attrs", FIXTURE_ATTRS)
            .unwrap()
            .with_attr_dirs(
                vec![
                    SecuritySubjectAttrConfig {
                        subject_id: "bob".into(),
                        tenant: "acme".into(),
                        clearance: "internal".into(),
                        roles: vec![],
                    },
                    SecuritySubjectAttrConfig {
                        subject_id: "carol".into(),
                        tenant: "other".into(),
                        clearance: "secret".into(),
                        roles: vec![],
                    },
                ],
                vec![SecurityTableAttrConfig {
                    table: "payroll".into(),
                    tenant: "acme".into(),
                    clearance: "secret".into(),
                    classification: "pii".into(),
                }],
            );
        assert!(
            !eng.is_allowed("bob", StatementAction::Select, "payroll")
                .unwrap(),
            "internal clearance must not read secret table"
        );
        assert!(
            !eng.is_allowed("carol", StatementAction::Select, "payroll")
                .unwrap(),
            "wrong tenant must not read even with secret clearance"
        );
        // Unknown subject (no attrs) also denied by attr policy.
        assert!(
            !eng.is_allowed("nobody", StatementAction::Select, "payroll")
                .unwrap()
        );
    }

    #[test]
    fn f29_uid_only_policies_still_work_without_attr_dirs() {
        // Empty attr dirs → Entities::empty(); FIXTURE uid-only policies unchanged.
        let eng = CedarEngine::from_str_policies("fixture", FIXTURE).unwrap();
        assert!(eng
            .is_allowed("alice", StatementAction::Select, "orders")
            .unwrap());
        assert!(!eng
            .is_allowed("alice", StatementAction::Select, "secret_tokens")
            .unwrap());
    }

    /// F29 vs Local: same intent expressed two ways — Local deny-table vs Cedar attr gate.
    #[test]
    fn f29_local_contrast_table_deny_matches_cedar_attr_deny() {
        use crate::pdp::{LocalPdp, Subject};
        use crate::security::{SecurityPolicyConfig, SecurityRuleConfig};
        use crate::{GatewayCommand, HeuristicDialectParser};

        // Local: explicit deny on payroll for everyone.
        let mut local_cfg = SecurityPolicyConfig::default();
        local_cfg.enabled = true;
        local_cfg.rules.push(SecurityRuleConfig {
            name: "deny-payroll".into(),
            effect: "deny".into(),
            actions: vec!["select".into()],
            tables: vec!["payroll".into()],
            columns: vec![],
            subjects: vec![],
            row_filter: None,
        });
        // Allow other selects so only payroll is the contrast point.
        local_cfg.rules.push(SecurityRuleConfig {
            name: "allow-select".into(),
            effect: "allow".into(),
            actions: vec!["select".into()],
            tables: vec!["*".into()],
            columns: vec![],
            subjects: vec![],
            row_filter: None,
        });
        let local = LocalPdp::from_config_isolated(&local_cfg).expect("local pdp");
        let subject = Subject::from_protocol_user(Some("bob"), Some("orders"));
        let dialect = HeuristicDialectParser::mysql();
        let cmd = GatewayCommand::Query {
            sql: "SELECT id FROM payroll".into(),
        };
        let local_dec = local.authorize_command(&subject, "orders", &cmd, &dialect);
        assert!(
            local_dec.is_deny(),
            "local should deny payroll: {local_dec:?}"
        );

        // Cedar attr path: bob lacks secret clearance → deny payroll (same outcome).
        let eng = CedarEngine::from_str_policies("attrs", FIXTURE_ATTRS)
            .unwrap()
            .with_attr_dirs(
                vec![SecuritySubjectAttrConfig {
                    subject_id: "bob".into(),
                    tenant: "acme".into(),
                    clearance: "internal".into(),
                    roles: vec![],
                }],
                vec![SecurityTableAttrConfig {
                    table: "payroll".into(),
                    tenant: "acme".into(),
                    clearance: "secret".into(),
                    classification: "pii".into(),
                }],
            );
        assert!(
            !eng.is_allowed("bob", StatementAction::Select, "payroll")
                .unwrap(),
            "cedar attr path should deny like Local table deny"
        );
    }

    #[test]
    fn select_denied_on_secret() {
        let eng = CedarEngine::from_str_policies("fixture", FIXTURE).unwrap();
        assert!(!eng
            .is_allowed("alice", StatementAction::Select, "secret_tokens")
            .unwrap());
        let err = eng
            .authorize_tables(
                "alice",
                StatementAction::Select,
                &["secret_tokens".into()],
            )
            .unwrap_err();
        assert!(err.contains("secret_tokens"), "{err}");
    }

    #[test]
    fn empty_tables_select_allowed() {
        let eng = CedarEngine::from_str_policies("fixture", FIXTURE).unwrap();
        eng.authorize_tables("alice", StatementAction::Select, &[])
            .unwrap();
    }

    #[test]
    fn insert_only_orders() {
        let eng = CedarEngine::from_str_policies("fixture", FIXTURE).unwrap();
        assert!(eng
            .is_allowed("bob", StatementAction::Insert, "orders")
            .unwrap());
        assert!(!eng
            .is_allowed("bob", StatementAction::Insert, "employees")
            .unwrap());
    }

    #[test]
    fn hot_reload_swaps_and_keep_old_on_bad() {
        let store = Arc::new(CedarPolicyStore::empty());
        let eng = CedarEngine::from_store(store.clone());
        let info1 = store.reload_from_str("t1", FIXTURE).unwrap();
        assert!(info1.swapped);
        assert_eq!(info1.epoch, 1);
        assert!(!eng
            .is_allowed("alice", StatementAction::Select, "secret_tokens")
            .unwrap());

        // Bad policy text → keep-old
        let err = store
            .reload_from_str("bad", "this is not cedar {{{")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("kept previous") || err.contains("invalid"),
            "{err}"
        );
        assert_eq!(store.epoch(), 1);
        assert!(!eng
            .is_allowed("alice", StatementAction::Select, "secret_tokens")
            .unwrap());

        // Good more-permissive swap
        let info2 = store.reload_from_str("t2", FIXTURE_ALLOW_SECRET).unwrap();
        assert!(info2.swapped);
        assert_eq!(info2.epoch, 2);
        assert!(eng
            .is_allowed("alice", StatementAction::Select, "secret_tokens")
            .unwrap());
    }

    #[test]
    fn reload_same_content_no_epoch_bump() {
        let store = Arc::new(CedarPolicyStore::empty());
        store.reload_from_str("t", FIXTURE).unwrap();
        let e1 = store.epoch();
        // from_str path always swaps today; use same content via second reload_from_str
        // (content_fp path is for load_dir). For str, always swapped — document that.
        // Directory path: write temp dir twice.
        let dir = std::env::temp_dir().join(format!("dn-cedar-{}", now_unix_ms()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("p.cedar");
        fs::write(&path, FIXTURE).unwrap();
        let store2 = Arc::new(CedarPolicyStore::empty());
        let i1 = store2.reload_from_dir(dir.to_str().unwrap()).unwrap();
        assert!(i1.swapped);
        let i2 = store2.reload_from_dir(dir.to_str().unwrap()).unwrap();
        assert!(!i2.swapped);
        assert_eq!(i1.epoch, i2.epoch);
        let _ = fs::remove_dir_all(dir);
        let _ = e1;
    }
}
