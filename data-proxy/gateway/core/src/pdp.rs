//! Local PDP for data-plane access control (S1 MVP).
//!
//! Evaluates `SecurityPolicyConfig.rules` against subject + statement action +
//! best-effort table names. Full AST ObjectSet is S2.

use crate::{
    CommandSummary, DialectParser, GatewayCommand, SecurityPolicyConfig, SecurityRuleConfig,
};

/// Data-plane identity (not Admin JWT).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    pub subject_id: String,
    pub db_user: Option<String>,
    pub database: Option<String>,
}

impl Subject {
    /// Bind from protocol session user (source: `protocol_user`).
    pub fn from_protocol_user(user: Option<&str>, database: Option<&str>) -> Self {
        let db_user = user.map(|u| u.to_owned());
        let subject_id = db_user
            .clone()
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| "anonymous".into());
        Self {
            subject_id,
            db_user,
            database: database.map(|d| d.to_owned()),
        }
    }
}

/// Coarse statement class for rule matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementAction {
    Select,
    Insert,
    Update,
    Delete,
    Ddl,
    Tcl,
    Other,
}

impl StatementAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Select => "select",
            Self::Insert => "insert",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Ddl => "ddl",
            Self::Tcl => "tcl",
            Self::Other => "other",
        }
    }

    pub fn from_keyword(keyword: &str) -> Self {
        let k = keyword.trim().to_ascii_uppercase();
        match k.as_str() {
            "SELECT" | "WITH" | "VALUES" | "TABLE" | "SHOW" | "EXPLAIN" | "DESCRIBE" | "DESC" => {
                Self::Select
            }
            "INSERT" | "REPLACE" => Self::Insert,
            "UPDATE" => Self::Update,
            "DELETE" => Self::Delete,
            "CREATE" | "ALTER" | "DROP" | "TRUNCATE" | "RENAME" | "COMMENT" => Self::Ddl,
            "BEGIN" | "START" | "COMMIT" | "ROLLBACK" | "SAVEPOINT" | "RELEASE" => Self::Tcl,
            _ => Self::Other,
        }
    }
}

/// Input to a single PDP evaluation.
#[derive(Debug, Clone)]
pub struct AccessRequest<'a> {
    pub subject: &'a Subject,
    pub service: &'a str,
    pub action: StatementAction,
    pub tables: Vec<String>,
    pub sql: Option<&'a str>,
}

/// Local policy decision (S1: allow / deny only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityDecision {
    Allow,
    Deny { rule: String, message: String },
}

impl SecurityDecision {
    pub fn is_deny(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }
}

/// Compiled local PDP snapshot (cheap to clone via Arc at runtime).
#[derive(Debug, Clone)]
pub struct LocalPdp {
    fail_closed: bool,
    rules: Vec<SecurityRuleConfig>,
}

impl LocalPdp {
    /// Build PDP when security is enabled; `None` when disabled (fast path).
    pub fn from_config(config: &SecurityPolicyConfig) -> Option<Self> {
        if !config.enabled {
            return None;
        }
        Some(Self {
            fail_closed: config.fail_closed,
            rules: config.rules.clone(),
        })
    }

    pub fn fail_closed(&self) -> bool {
        self.fail_closed
    }

    pub fn rules(&self) -> &[SecurityRuleConfig] {
        &self.rules
    }

    pub fn evaluate(&self, request: &AccessRequest<'_>) -> SecurityDecision {
        for rule in &self.rules {
            if !rule_matches(rule, request) {
                continue;
            }
            match rule.effect.to_ascii_lowercase().as_str() {
                "deny" => {
                    return SecurityDecision::Deny {
                        rule: rule.name.clone(),
                        message: format!(
                            "security policy '{}' denied {} on service '{}'",
                            rule.name,
                            request.action.as_str(),
                            request.service
                        ),
                    };
                }
                "allow" => return SecurityDecision::Allow,
                _ => continue,
            }
        }
        SecurityDecision::Allow
    }

    /// Classify command + extract tables; on failure apply fail_closed.
    pub fn authorize_command(
        &self,
        subject: &Subject,
        service: &str,
        command: &GatewayCommand,
        dialect: &dyn DialectParser,
    ) -> SecurityDecision {
        match command {
            GatewayCommand::Ping | GatewayCommand::Quit | GatewayCommand::CloseStatement { .. } => {
                SecurityDecision::Allow
            }
            GatewayCommand::Begin | GatewayCommand::Commit | GatewayCommand::Rollback => {
                let request = AccessRequest {
                    subject,
                    service,
                    action: StatementAction::Tcl,
                    tables: Vec::new(),
                    sql: None,
                };
                self.evaluate(&request)
            }
            GatewayCommand::UseDatabase { database } => {
                let request = AccessRequest {
                    subject,
                    service,
                    action: StatementAction::Other,
                    tables: vec![database.clone()],
                    sql: None,
                };
                self.evaluate(&request)
            }
            GatewayCommand::Execute { .. } => {
                // Prepared execute has no SQL here; S1 allow (S2 can track prepare cache).
                if self.fail_closed {
                    SecurityDecision::Deny {
                        rule: "fail_closed".into(),
                        message: "security policy deny: prepared EXECUTE not classified (fail_closed)"
                            .into(),
                    }
                } else {
                    SecurityDecision::Allow
                }
            }
            GatewayCommand::Query { sql } | GatewayCommand::Prepare { sql } => {
                let keyword = dialect.leading_keyword(sql);
                let action = match keyword.as_deref() {
                    Some(k) => StatementAction::from_keyword(k),
                    None => {
                        if self.fail_closed {
                            return SecurityDecision::Deny {
                                rule: "fail_closed".into(),
                                message: "security policy deny: empty or unparseable SQL (fail_closed)"
                                    .into(),
                            };
                        }
                        StatementAction::Other
                    }
                };
                let tables = extract_table_names(sql);
                let request = AccessRequest {
                    subject,
                    service,
                    action,
                    tables,
                    sql: Some(sql.as_str()),
                };
                self.evaluate(&request)
            }
        }
    }
}

fn rule_matches(rule: &SecurityRuleConfig, request: &AccessRequest<'_>) -> bool {
    if !rule.subjects.is_empty() {
        let sid = request.subject.subject_id.as_str();
        let matched = rule
            .subjects
            .iter()
            .any(|pattern| glob_match(pattern, sid));
        if !matched {
            return false;
        }
    }

    if !rule.actions.is_empty() {
        let action = request.action.as_str();
        let matched = rule.actions.iter().any(|a| {
            let a = a.to_ascii_lowercase();
            a == action
                || a == "*"
                || (a == "write" && matches!(
                    request.action,
                    StatementAction::Insert
                        | StatementAction::Update
                        | StatementAction::Delete
                        | StatementAction::Ddl
                ))
                || (a == "read" && request.action == StatementAction::Select)
                || (a == "dml"
                    && matches!(
                        request.action,
                        StatementAction::Insert
                            | StatementAction::Update
                            | StatementAction::Delete
                    ))
        });
        if !matched {
            return false;
        }
    }

    if !rule.tables.is_empty() {
        if request.tables.is_empty() {
            // Rule requires tables but none extracted → no match (avoid false deny on SELECT 1).
            return false;
        }
        let matched = request.tables.iter().any(|table| {
            rule.tables
                .iter()
                .any(|pattern| table_glob_match(pattern, table))
        });
        if !matched {
            return false;
        }
    }

    // Optional service filter via rule name convention is not used; rules apply to all services.
    let _ = request.service;
    true
}

fn table_glob_match(pattern: &str, table: &str) -> bool {
    let table = table.trim_matches('`').trim_matches('"').trim_matches('\'');
    if glob_match(pattern, table) {
        return true;
    }
    // Match bare name against last segment: schema.table / catalog.schema.table
    if let Some(base) = table.rsplit('.').next() {
        if base != table && glob_match(pattern, base) {
            return true;
        }
        // Patterns like *.*.secret_*
        if glob_match(pattern, table) {
            return true;
        }
    }
    // Pattern may be only the leaf: secret_*
    if let Some(leaf) = pattern.rsplit('.').next() {
        if leaf != pattern {
            if let Some(base) = table.rsplit('.').next() {
                return glob_match(leaf, base);
            }
        }
    }
    false
}

/// Glob with `*` (any run) and `?` (one char). Case-insensitive for SQL ids.
fn glob_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let value = value.to_ascii_lowercase();
    glob_match_bytes(pattern.as_bytes(), value.as_bytes())
}

fn glob_match_bytes(pattern: &[u8], value: &[u8]) -> bool {
    let (mut pi, mut vi) = (0usize, 0usize);
    let mut star_p = None;
    let mut star_v = 0usize;
    while vi < value.len() {
        if pi < pattern.len() && (pattern[pi] == b'?' || pattern[pi] == value[vi]) {
            pi += 1;
            vi += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star_p = Some(pi);
            star_v = vi;
            pi += 1;
        } else if let Some(sp) = star_p {
            pi = sp + 1;
            star_v += 1;
            vi = star_v;
        } else {
            return false;
        }
    }
    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }
    pi == pattern.len()
}

/// Best-effort table name extraction for S1 (not a full SQL parser).
pub fn extract_table_names(sql: &str) -> Vec<String> {
    let mut tables = Vec::new();
    let upper = sql.to_ascii_uppercase();
    let bytes = sql.as_bytes();
    let upper_bytes = upper.as_bytes();

    for keyword in [
        " FROM ",
        " JOIN ",
        " INTO ",
        " UPDATE ",
        " TABLE ",
        "\nFROM ",
        "\nJOIN ",
        "\nINTO ",
        "\nUPDATE ",
        "\nTABLE ",
    ] {
        let mut start = 0usize;
        let key = keyword.as_bytes();
        while let Some(rel) = find_slice(&upper_bytes[start..], key) {
            let after = start + rel + key.len();
            if let Some(name) = next_sql_ident(&sql[after..]) {
                push_unique(&mut tables, name);
            }
            start = after;
        }
    }

    // Leading UPDATE/INSERT without preceding space variants already handled;
    // also catch "UPDATE t SET" at start.
    let trimmed = sql.trim_start();
    let trimmed_upper = trimmed.to_ascii_uppercase();
    for prefix in ["UPDATE ", "INSERT INTO ", "DELETE FROM ", "TRUNCATE TABLE ", "TRUNCATE "] {
        if let Some(rest) = trimmed_upper.strip_prefix(prefix) {
            let offset = prefix.len();
            if let Some(name) = next_sql_ident(&trimmed[offset..offset + rest.len().min(trimmed.len() - offset)]) {
                push_unique(&mut tables, name);
            }
        }
    }

    let _ = bytes;
    tables
}

fn find_slice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn next_sql_ident(input: &str) -> Option<String> {
    let s = input.trim_start();
    if s.is_empty() {
        return None;
    }
    let mut chars = s.chars().peekable();
    let mut out = String::new();
    // optional quoted ident
    match chars.peek().copied() {
        Some('`') | Some('"') | Some('\'') => {
            let q = chars.next()?;
            for c in chars.by_ref() {
                if c == q {
                    break;
                }
                out.push(c);
            }
        }
        Some(c) if c.is_ascii_alphanumeric() || c == '_' || c == '$' => {
            out.push(c);
            chars.next();
            for c in chars.by_ref() {
                if c.is_ascii_alphanumeric() || c == '_' || c == '$' || c == '.' {
                    out.push(c);
                } else {
                    break;
                }
            }
        }
        _ => return None,
    }
    let name = out.trim().trim_matches('.').to_owned();
    if name.is_empty()
        || matches!(
            name.to_ascii_uppercase().as_str(),
            "SELECT" | "WHERE" | "SET" | "VALUES" | "ON" | "AS" | "LEFT" | "RIGHT" | "INNER" | "OUTER" | "CROSS" | "ONLY"
        )
    {
        return None;
    }
    Some(name)
}

fn push_unique(tables: &mut Vec<String>, name: String) {
    if !tables.iter().any(|t| t.eq_ignore_ascii_case(&name)) {
        tables.push(name);
    }
}

/// Helper for tests / callers using CommandSummary.
pub fn sql_from_command(command: &GatewayCommand) -> Option<&str> {
    match command {
        GatewayCommand::Query { sql } | GatewayCommand::Prepare { sql } => Some(sql.as_str()),
        _ => None,
    }
}

pub fn action_from_command(command: &GatewayCommand, dialect: &dyn DialectParser) -> StatementAction {
    match command {
        GatewayCommand::Begin | GatewayCommand::Commit | GatewayCommand::Rollback => {
            StatementAction::Tcl
        }
        GatewayCommand::Query { sql } | GatewayCommand::Prepare { sql } => dialect
            .leading_keyword(sql)
            .map(|k| StatementAction::from_keyword(&k))
            .unwrap_or(StatementAction::Other),
        GatewayCommand::UseDatabase { .. } => StatementAction::Other,
        _ => StatementAction::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HeuristicDialectParser, ProtocolKind};

    fn pdp_with(rules: Vec<SecurityRuleConfig>) -> LocalPdp {
        LocalPdp {
            fail_closed: true,
            rules,
        }
    }

    fn subject(user: &str) -> Subject {
        Subject::from_protocol_user(Some(user), Some("orders"))
    }

    #[test]
    fn disabled_config_yields_no_pdp() {
        let cfg = SecurityPolicyConfig::default();
        assert!(LocalPdp::from_config(&cfg).is_none());
    }

    #[test]
    fn deny_secret_table_select() {
        let pdp = pdp_with(vec![SecurityRuleConfig {
            name: "deny-secret".into(),
            effect: "deny".into(),
            actions: vec!["select".into()],
            tables: vec!["secret_*".into()],
            subjects: vec![],
        }]);
        let sub = subject("app");
        let dialect = HeuristicDialectParser::new(ProtocolKind::MySql);
        let cmd = GatewayCommand::Query {
            sql: "SELECT * FROM secret_tokens WHERE id=1".into(),
        };
        assert!(pdp
            .authorize_command(&sub, "orders", &cmd, &dialect)
            .is_deny());
    }

    #[test]
    fn allow_when_table_not_matched() {
        let pdp = pdp_with(vec![SecurityRuleConfig {
            name: "deny-secret".into(),
            effect: "deny".into(),
            actions: vec!["select".into()],
            tables: vec!["secret_*".into()],
            subjects: vec![],
        }]);
        let sub = subject("app");
        let dialect = HeuristicDialectParser::new(ProtocolKind::MySql);
        let cmd = GatewayCommand::Query {
            sql: "SELECT 1".into(),
        };
        assert_eq!(
            pdp.authorize_command(&sub, "orders", &cmd, &dialect),
            SecurityDecision::Allow
        );
    }

    #[test]
    fn deny_ddl_for_subject() {
        let pdp = pdp_with(vec![SecurityRuleConfig {
            name: "no-ddl-analyst".into(),
            effect: "deny".into(),
            actions: vec!["ddl".into()],
            tables: vec![],
            subjects: vec!["analyst".into()],
        }]);
        let sub = subject("analyst");
        let dialect = HeuristicDialectParser::new(ProtocolKind::PostgreSql);
        let cmd = GatewayCommand::Query {
            sql: "CREATE TABLE t (id int)".into(),
        };
        assert!(pdp
            .authorize_command(&sub, "analytics", &cmd, &dialect)
            .is_deny());
        let app = subject("app");
        assert_eq!(
            pdp.authorize_command(&app, "analytics", &cmd, &dialect),
            SecurityDecision::Allow
        );
    }

    #[test]
    fn extract_from_join() {
        let tables = extract_table_names(
            "SELECT a.id FROM orders a JOIN order_items b ON a.id=b.order_id",
        );
        assert!(tables.iter().any(|t| t.eq_ignore_ascii_case("orders")));
        assert!(tables.iter().any(|t| t.eq_ignore_ascii_case("order_items")));
    }

    #[test]
    fn glob_star() {
        assert!(glob_match("secret_*", "secret_tokens"));
        assert!(!glob_match("secret_*", "public_tokens"));
        assert!(glob_match("*.secret_*", "app.secret_keys"));
    }

    #[test]
    fn subject_anonymous_when_missing_user() {
        let s = Subject::from_protocol_user(None, None);
        assert_eq!(s.subject_id, "anonymous");
    }

    #[test]
    fn command_summary_not_required_for_authorize() {
        let _ = CommandSummary::from_command(&GatewayCommand::Ping);
    }
}
