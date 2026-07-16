//! Optional Cedar PDP (F26).
//!
//! Compiled only with `--features security-cedar`. Evaluates **table + action**
//! authorization using [Cedar](https://www.cedarpolicy.com/) policies loaded from
//! `security.pdp.policy_dir`. Column masks, row filters, tickets, and time rules
//! remain on the Local path and are composed after Cedar allows the statement.
//!
//! Entity model (MVP):
//! - principal: `User::"<subject_id>"`
//! - action: `Action::"select|insert|update|delete|ddl|tcl|other"`
//! - resource: `Table::"<table>"` (bare name, lower-case recommended in policies)
//!
//! Empty object set (e.g. `SELECT 1`) uses resource `Table::"__none__"`.

#![cfg(feature = "security-cedar")]

use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use cedar_policy::{Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request};
use tracing::info;

use crate::{GatewayError, GatewayResult, StatementAction};

/// Compiled Cedar policy set + authorizer (cheap to Arc-share).
#[derive(Debug, Clone)]
pub struct CedarEngine {
    policies: Arc<PolicySet>,
    authorizer: Authorizer,
    source: String,
}

impl CedarEngine {
    /// Load every `*.cedar` file under `policy_dir` (non-recursive) into one PolicySet.
    pub fn load_dir(policy_dir: &str) -> GatewayResult<Self> {
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
        info!(
            target: "data_nexus::security",
            policy_dir = %policy_dir,
            files,
            "cedar PDP loaded"
        );
        Ok(Self {
            policies: Arc::new(policies),
            authorizer: Authorizer::new(),
            source: policy_dir.to_owned(),
        })
    }

    /// Parse policies from an in-memory string (tests / fixtures).
    pub fn from_str_policies(source: &str, text: &str) -> GatewayResult<Self> {
        let policies = PolicySet::from_str(text).map_err(|e| {
            GatewayError::Configuration(format!("invalid Cedar policies ({source}): {e}"))
        })?;
        Ok(Self {
            policies: Arc::new(policies),
            authorizer: Authorizer::new(),
            source: source.to_owned(),
        })
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    /// Authorize subject + action against one table resource.
    pub fn is_allowed(
        &self,
        subject_id: &str,
        action: StatementAction,
        table: &str,
    ) -> Result<bool, String> {
        let principal = entity_uid("User", &sanitize_id(subject_id))?;
        let action_uid = entity_uid("Action", action.as_str())?;
        let resource = entity_uid("Table", &sanitize_id(table))?;
        let request = Request::new(principal, action_uid, resource, Context::empty(), None)
            .map_err(|e| format!("cedar request: {e}"))?;
        let response = self
            .authorizer
            .is_authorized(&request, &self.policies, &Entities::empty());
        Ok(response.decision() == Decision::Allow)
    }

    /// Authorize a statement: every referenced table must be allowed.
    /// Empty tables → resource `Table::"__none__"`.
    pub fn authorize_tables(
        &self,
        subject_id: &str,
        action: StatementAction,
        tables: &[String],
    ) -> Result<(), String> {
        if tables.is_empty() {
            if self.is_allowed(subject_id, action, "__none__")? {
                return Ok(());
            }
            return Err(format!(
                "cedar deny: subject '{subject_id}' action '{}' on empty object set",
                action.as_str()
            ));
        }
        for table in tables {
            let bare = bare_table_name(table);
            if !self.is_allowed(subject_id, action, bare)? {
                return Err(format!(
                    "cedar deny: subject '{subject_id}' action '{}' on table '{bare}'",
                    action.as_str()
                ));
            }
        }
        Ok(())
    }
}

fn entity_uid(ty: &str, id: &str) -> Result<EntityUid, String> {
    // Cedar string entity ids: Type::"id"
    let s = format!(r#"{ty}::"{id}""#);
    EntityUid::from_str(&s).map_err(|e| format!("entity uid {s}: {e}"))
}

fn sanitize_id(raw: &str) -> String {
    // Escape embedded quotes for Cedar string entity syntax.
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

/// Resolve Cedar engine from config fields (feature-gated caller).
pub fn try_load_from_config(policy_dir: &str) -> GatewayResult<Option<CedarEngine>> {
    if policy_dir.trim().is_empty() {
        return Err(GatewayError::Configuration(
            "security.pdp.backend=cedar requires non-empty security.pdp.policy_dir".into(),
        ));
    }
    Ok(Some(CedarEngine::load_dir(policy_dir.trim())?))
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

    #[test]
    fn select_allowed_on_orders() {
        let eng = CedarEngine::from_str_policies("fixture", FIXTURE).unwrap();
        assert!(eng
            .is_allowed("alice", StatementAction::Select, "orders")
            .unwrap());
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
}
