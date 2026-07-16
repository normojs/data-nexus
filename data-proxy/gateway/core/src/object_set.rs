//! SQL object access set for fine-grained PDP (S2).
//!
//! Extraction lives in `runtime_gateway` (parser crates). Core only holds the
//! protocol-neutral types consumed by Local PDP and rewrite.

use crate::pdp::StatementAction;
use serde::{Deserialize, Serialize};

/// How `SELECT *` / `t.*` is treated when column ACL is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum StarPolicy {
    /// Deny any query whose projection contains `*` / `table.*` when column
    /// rules apply to the involved tables (safest without schema expansion).
    #[default]
    Deny,
    /// Leave wildcards as-is; column denials only apply to explicit columns.
    Allow,
}

impl StarPolicy {
    pub fn from_config(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "allow" => Self::Allow,
            _ => Self::Deny,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Allow => "allow",
        }
    }
}

/// One table (and optional columns) touched by a statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectAccess {
    pub schema: Option<String>,
    pub table: String,
    /// Projection / write columns (bare or `table.col`). Empty when unknown.
    pub columns: Vec<String>,
    pub op: StatementAction,
    /// True when the statement projection includes `*` or `table.*`.
    pub has_wildcard: bool,
}

impl ObjectAccess {
    pub fn new(table: impl Into<String>, op: StatementAction) -> Self {
        Self {
            schema: None,
            table: table.into(),
            columns: Vec::new(),
            op,
            has_wildcard: false,
        }
    }

    pub fn with_schema(mut self, schema: Option<String>) -> Self {
        self.schema = schema;
        self
    }

    pub fn qualified_table(&self) -> String {
        match &self.schema {
            Some(s) if !s.is_empty() => format!("{}.{}", s, self.table),
            _ => self.table.clone(),
        }
    }

    /// Bare column name (last segment), lowercased for matching.
    pub fn bare_columns(&self) -> impl Iterator<Item = String> + '_ {
        self.columns.iter().map(|c| {
            c.rsplit('.')
                .next()
                .unwrap_or(c.as_str())
                .trim_matches('`')
                .trim_matches('"')
                .to_ascii_lowercase()
        })
    }
}

/// All objects referenced by one SQL command.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ObjectSet {
    pub objects: Vec<ObjectAccess>,
    /// True when SQL could not be fully parsed into an object set.
    pub parse_failed: bool,
    /// True when extraction used heuristic fallback (S1 table scan).
    pub heuristic: bool,
}

impl ObjectSet {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn parse_failed() -> Self {
        Self {
            objects: Vec::new(),
            parse_failed: true,
            heuristic: false,
        }
    }

    pub fn tables(&self) -> Vec<String> {
        let mut out = Vec::new();
        for obj in &self.objects {
            let q = obj.qualified_table();
            if !out.iter().any(|t: &String| t.eq_ignore_ascii_case(&q)) {
                out.push(q);
            }
            if !out
                .iter()
                .any(|t: &String| t.eq_ignore_ascii_case(&obj.table))
            {
                out.push(obj.table.clone());
            }
        }
        out
    }

    pub fn has_wildcard(&self) -> bool {
        self.objects.iter().any(|o| o.has_wildcard)
    }

    pub fn primary_action(&self) -> Option<StatementAction> {
        self.objects.first().map(|o| o.op)
    }
}

/// Result of applying column ACL (S2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColumnAclOutcome {
    /// No column rules matched; leave SQL unchanged.
    Unchanged,
    /// Explicit columns stripped; use rewritten SQL.
    Rewrite { sql: String },
    /// Cannot safely enforce (e.g. wildcard under deny star policy).
    Deny { rule: String, message: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qualified_table_and_bare_columns() {
        let mut obj = ObjectAccess::new("users", StatementAction::Select)
            .with_schema(Some("public".into()));
        obj.columns = vec!["public.users.id".into(), "email".into()];
        assert_eq!(obj.qualified_table(), "public.users");
        let bare: Vec<_> = obj.bare_columns().collect();
        assert_eq!(bare, vec!["id".to_string(), "email".to_string()]);
    }

    #[test]
    fn star_policy_from_config() {
        assert_eq!(StarPolicy::from_config("allow"), StarPolicy::Allow);
        assert_eq!(StarPolicy::from_config("deny"), StarPolicy::Deny);
        assert_eq!(StarPolicy::from_config(""), StarPolicy::Deny);
    }
}
