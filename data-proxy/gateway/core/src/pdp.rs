//! Local PDP for data-plane access control (S1 table/statement + S2 columns).
//!
//! Evaluates `SecurityPolicyConfig.rules` against subject + statement action +
//! tables, and optionally column ACL against an [`ObjectSet`] provided by the
//! runtime extractor.

use crate::object_set::{ColumnAclOutcome, ObjectSet, StarPolicy};
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
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
    /// Bare column names already known (from ObjectSet); empty for table-only.
    pub columns: Vec<String>,
    pub sql: Option<&'a str>,
}

/// Local policy decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityDecision {
    Allow,
    /// Allow with SQL rewrite obligation (column strip).
    AllowRewrite { sql: String },
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
    star_policy: StarPolicy,
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
            star_policy: StarPolicy::from_config(&config.star_policy),
            rules: config.rules.clone(),
        })
    }

    pub fn fail_closed(&self) -> bool {
        self.fail_closed
    }

    pub fn star_policy(&self) -> StarPolicy {
        self.star_policy
    }

    pub fn rules(&self) -> &[SecurityRuleConfig] {
        &self.rules
    }

    pub fn has_column_rules(&self) -> bool {
        self.rules.iter().any(|r| !r.columns.is_empty())
    }

    pub fn evaluate(&self, request: &AccessRequest<'_>) -> SecurityDecision {
        for rule in &self.rules {
            // Column-only rules are handled in `evaluate_column_acl`.
            if !rule.columns.is_empty() {
                continue;
            }
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

    /// Table/statement authorize using heuristic table extraction (S1 path).
    pub fn authorize_command(
        &self,
        subject: &Subject,
        service: &str,
        command: &GatewayCommand,
        dialect: &dyn DialectParser,
    ) -> SecurityDecision {
        self.authorize_command_with_objects(subject, service, command, dialect, None)
    }

    /// Authorize with optional AST-derived [`ObjectSet`] (S2).
    ///
    /// When `objects` is `Some`, table names and column ACL use that set.
    /// When `None`, falls back to S1 heuristic table extraction.
    pub fn authorize_command_with_objects(
        &self,
        subject: &Subject,
        service: &str,
        command: &GatewayCommand,
        dialect: &dyn DialectParser,
        objects: Option<&ObjectSet>,
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
                    columns: Vec::new(),
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
                    columns: Vec::new(),
                    sql: None,
                };
                self.evaluate(&request)
            }
            GatewayCommand::Execute { .. } => {
                if self.fail_closed {
                    SecurityDecision::Deny {
                        rule: "fail_closed".into(),
                        message:
                            "security policy deny: prepared EXECUTE not classified (fail_closed)"
                                .into(),
                    }
                } else {
                    SecurityDecision::Allow
                }
            }
            GatewayCommand::Query { sql } | GatewayCommand::Prepare { sql } => {
                // Hard-deny only when extraction failed *and* produced no usable objects.
                // Heuristic recoveries may set `parse_failed` with tables still present.
                if let Some(set) = objects {
                    if set.parse_failed && set.objects.is_empty() && self.fail_closed {
                        return SecurityDecision::Deny {
                            rule: "fail_closed".into(),
                            message:
                                "security policy deny: SQL object extraction failed (fail_closed)"
                                    .into(),
                        };
                    }
                }

                let keyword = dialect.leading_keyword(sql);
                let action = match keyword.as_deref() {
                    Some(k) => StatementAction::from_keyword(k),
                    None => {
                        if self.fail_closed {
                            return SecurityDecision::Deny {
                                rule: "fail_closed".into(),
                                message:
                                    "security policy deny: empty or unparseable SQL (fail_closed)"
                                        .into(),
                            };
                        }
                        StatementAction::Other
                    }
                };

                let (tables, columns) = if let Some(set) = objects {
                    if set.parse_failed && !set.objects.is_empty() {
                        // partial — still use objects
                        (set.tables(), collect_bare_columns(set))
                    } else if set.parse_failed {
                        (extract_table_names(sql), Vec::new())
                    } else {
                        (set.tables(), collect_bare_columns(set))
                    }
                } else {
                    (extract_table_names(sql), Vec::new())
                };

                let request = AccessRequest {
                    subject,
                    service,
                    action,
                    tables,
                    columns: columns.clone(),
                    sql: Some(sql.as_str()),
                };

                let table_decision = self.evaluate(&request);
                if table_decision.is_deny() {
                    return table_decision;
                }

                // Column ACL only when rules mention columns and we have an object set.
                if self.has_column_rules() {
                    if let Some(set) = objects {
                        if !set.parse_failed || !set.objects.is_empty() {
                            match self.evaluate_column_acl(subject, service, action, set, sql) {
                                ColumnAclOutcome::Unchanged => {}
                                ColumnAclOutcome::Rewrite { sql: rewritten } => {
                                    return SecurityDecision::AllowRewrite { sql: rewritten };
                                }
                                ColumnAclOutcome::Deny { rule, message } => {
                                    return SecurityDecision::Deny { rule, message };
                                }
                            }
                        } else if self.fail_closed {
                            return SecurityDecision::Deny {
                                rule: "fail_closed".into(),
                                message: "security policy deny: column ACL requires parseable SQL (fail_closed)"
                                    .into(),
                            };
                        }
                    }
                }

                SecurityDecision::Allow
            }
        }
    }

    /// Apply column deny rules: strip columns from SELECT when possible, else deny.
    pub fn evaluate_column_acl(
        &self,
        subject: &Subject,
        service: &str,
        action: StatementAction,
        objects: &ObjectSet,
        sql: &str,
    ) -> ColumnAclOutcome {
        let mut denied_columns: Vec<(String, String)> = Vec::new(); // (rule, column)

        for rule in &self.rules {
            if rule.columns.is_empty() {
                continue;
            }
            if !subject_matches(rule, subject) {
                continue;
            }
            if !action_matches(rule, action) {
                continue;
            }

            for obj in &objects.objects {
                if !table_matches_rule(rule, obj) {
                    continue;
                }

                if obj.has_wildcard {
                    if self.star_policy == StarPolicy::Deny
                        && rule.effect.eq_ignore_ascii_case("deny")
                    {
                        return ColumnAclOutcome::Deny {
                            rule: rule.name.clone(),
                            message: format!(
                                "security policy '{}' denies wildcard projection on table '{}' (star_policy=deny); list columns explicitly",
                                rule.name,
                                obj.qualified_table()
                            ),
                        };
                    }
                    // star_policy=allow: skip wildcard; only explicit columns below.
                }

                for col in obj.bare_columns() {
                    if column_matches_rule(rule, &col, &obj.table) {
                        match rule.effect.to_ascii_lowercase().as_str() {
                            "deny" => denied_columns.push((rule.name.clone(), col)),
                            "allow" => {}
                            _ => {}
                        }
                    }
                }
            }
        }

        if denied_columns.is_empty() {
            return ColumnAclOutcome::Unchanged;
        }

        // Only attempt rewrite for SELECT with explicit columns.
        if action == StatementAction::Select && !objects.has_wildcard() {
            match rewrite_select_strip_columns(sql, &denied_columns) {
                Some(rewritten) if rewritten != sql => {
                    return ColumnAclOutcome::Rewrite { sql: rewritten };
                }
                Some(_) => {
                    // All columns stripped or rewrite produced empty projection.
                    let (rule, col) = &denied_columns[0];
                    return ColumnAclOutcome::Deny {
                        rule: rule.clone(),
                        message: format!(
                            "security policy '{rule}' denied column '{col}' on service '{service}' (empty projection after strip)"
                        ),
                    };
                }
                None => {
                    let (rule, col) = &denied_columns[0];
                    return ColumnAclOutcome::Deny {
                        rule: rule.clone(),
                        message: format!(
                            "security policy '{rule}' denied column '{col}' on service '{service}' (rewrite not possible)"
                        ),
                    };
                }
            }
        }

        let (rule, col) = &denied_columns[0];
        ColumnAclOutcome::Deny {
            rule: rule.clone(),
            message: format!(
                "security policy '{rule}' denied column '{col}' for {} on service '{service}'",
                action.as_str()
            ),
        }
    }
}

fn collect_bare_columns(set: &ObjectSet) -> Vec<String> {
    let mut out = Vec::new();
    for obj in &set.objects {
        for c in obj.bare_columns() {
            if !out.iter().any(|x: &String| x == &c) {
                out.push(c);
            }
        }
    }
    out
}

fn subject_matches(rule: &SecurityRuleConfig, subject: &Subject) -> bool {
    if rule.subjects.is_empty() {
        return true;
    }
    let sid = subject.subject_id.as_str();
    rule.subjects
        .iter()
        .any(|pattern| glob_match(pattern, sid))
}

fn action_matches(rule: &SecurityRuleConfig, action: StatementAction) -> bool {
    if rule.actions.is_empty() {
        return true;
    }
    let action_s = action.as_str();
    rule.actions.iter().any(|a| {
        let a = a.to_ascii_lowercase();
        a == action_s
            || a == "*"
            || (a == "write"
                && matches!(
                    action,
                    StatementAction::Insert
                        | StatementAction::Update
                        | StatementAction::Delete
                        | StatementAction::Ddl
                ))
            || (a == "read" && action == StatementAction::Select)
            || (a == "dml"
                && matches!(
                    action,
                    StatementAction::Insert | StatementAction::Update | StatementAction::Delete
                ))
    })
}

fn table_matches_rule(
    rule: &SecurityRuleConfig,
    obj: &crate::object_set::ObjectAccess,
) -> bool {
    if rule.tables.is_empty() {
        return true;
    }
    let qualified = obj.qualified_table();
    rule.tables.iter().any(|pattern| {
        table_glob_match(pattern, &qualified) || table_glob_match(pattern, &obj.table)
    })
}

fn column_matches_rule(rule: &SecurityRuleConfig, bare_col: &str, table: &str) -> bool {
    rule.columns.iter().any(|pattern| {
        let p = pattern.trim();
        if p.contains('.') {
            // table.col or *.col
            let mut parts = p.rsplitn(2, '.');
            let col_pat = parts.next().unwrap_or("");
            let tbl_pat = parts.next().unwrap_or("*");
            glob_match(col_pat, bare_col)
                && (tbl_pat == "*" || glob_match(tbl_pat, table))
        } else {
            glob_match(p, bare_col)
        }
    })
}

fn rule_matches(rule: &SecurityRuleConfig, request: &AccessRequest<'_>) -> bool {
    if !subject_matches(rule, request.subject) {
        return false;
    }
    if !action_matches(rule, request.action) {
        return false;
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
pub(crate) fn glob_match(pattern: &str, value: &str) -> bool {
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

/// Best-effort table name extraction for S1 / parse fallback (not a full SQL parser).
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

    let trimmed = sql.trim_start();
    let trimmed_upper = trimmed.to_ascii_uppercase();
    for prefix in [
        "UPDATE ",
        "INSERT INTO ",
        "DELETE FROM ",
        "TRUNCATE TABLE ",
        "TRUNCATE ",
    ] {
        if let Some(rest) = trimmed_upper.strip_prefix(prefix) {
            let offset = prefix.len();
            if let Some(name) = next_sql_ident(
                &trimmed[offset..offset + rest.len().min(trimmed.len() - offset)],
            ) {
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
            "SELECT"
                | "WHERE"
                | "SET"
                | "VALUES"
                | "ON"
                | "AS"
                | "LEFT"
                | "RIGHT"
                | "INNER"
                | "OUTER"
                | "CROSS"
                | "ONLY"
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

/// Strip denied columns from a simple SELECT list (heuristic, no full AST rewrite).
///
/// Returns `None` when the SQL shape is not a simple SELECT list rewrite target.
/// Returns `Some` rewritten SQL (may have empty projection → caller should deny).
fn rewrite_select_strip_columns(sql: &str, denied: &[(String, String)]) -> Option<String> {
    if denied.is_empty() {
        return Some(sql.to_owned());
    }
    let trimmed = sql.trim_start();
    let upper = trimmed.to_ascii_uppercase();
    if !upper.starts_with("SELECT") {
        return None;
    }
    let after_select = trimmed[6..].trim_start();
    // Optional DISTINCT
    let after_select = if after_select.to_ascii_uppercase().starts_with("DISTINCT") {
        after_select[8..].trim_start()
    } else {
        after_select
    };

    let from_idx = find_top_level_keyword(after_select, "FROM")?;
    let select_list = after_select[..from_idx].trim();
    let rest = &after_select[from_idx..]; // starts with FROM ...

    if select_list == "*" || select_list.ends_with(".*") {
        return None;
    }

    let parts = split_select_list(select_list);
    if parts.is_empty() {
        return None;
    }

    let denied_names: Vec<String> = denied.iter().map(|(_, c)| c.to_ascii_lowercase()).collect();
    let kept: Vec<&str> = parts
        .iter()
        .copied()
        .filter(|part| {
            let bare = select_item_bare_name(part);
            !denied_names.iter().any(|d| d == &bare)
        })
        .collect();

    if kept.is_empty() {
        // Signal empty projection with a sentinel rewrite the caller treats as deny.
        return Some(format!("SELECT {rest}"));
    }

    let new_list = kept.join(", ");
    // Preserve leading whitespace / casing of SELECT keyword region lightly.
    let prefix_end = sql.len() - trimmed.len();
    let mut out = String::new();
    out.push_str(&sql[..prefix_end]);
    out.push_str("SELECT ");
    if upper[6..].trim_start().starts_with("DISTINCT") {
        out.push_str("DISTINCT ");
    }
    out.push_str(&new_list);
    out.push(' ');
    out.push_str(rest.trim_start());
    Some(out)
}

fn find_top_level_keyword(sql: &str, keyword: &str) -> Option<usize> {
    let upper = sql.to_ascii_uppercase();
    let key = keyword.to_ascii_uppercase();
    let bytes = upper.as_bytes();
    let key_bytes = key.as_bytes();
    let mut depth = 0i32;
    let mut in_single = false;
    let mut in_double = false;
    let mut in_back = false;
    let mut i = 0usize;
    while i + key_bytes.len() <= bytes.len() {
        let c = bytes[i];
        if in_single {
            if c == b'\'' {
                in_single = false;
            }
            i += 1;
            continue;
        }
        if in_double {
            if c == b'"' {
                in_double = false;
            }
            i += 1;
            continue;
        }
        if in_back {
            if c == b'`' {
                in_back = false;
            }
            i += 1;
            continue;
        }
        match c {
            b'\'' => in_single = true,
            b'"' => in_double = true,
            b'`' => in_back = true,
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ => {
                if depth == 0 && bytes[i..].starts_with(key_bytes) {
                    let before_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
                    let after = i + key_bytes.len();
                    let after_ok = after >= bytes.len() || !bytes[after].is_ascii_alphanumeric();
                    if before_ok && after_ok {
                        return Some(i);
                    }
                }
            }
        }
        i += 1;
    }
    None
}

fn split_select_list(list: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut depth = 0i32;
    let mut in_single = false;
    let mut in_double = false;
    let mut in_back = false;
    let bytes = list.as_bytes();
    for (i, &c) in bytes.iter().enumerate() {
        if in_single {
            if c == b'\'' {
                in_single = false;
            }
            continue;
        }
        if in_double {
            if c == b'"' {
                in_double = false;
            }
            continue;
        }
        if in_back {
            if c == b'`' {
                in_back = false;
            }
            continue;
        }
        match c {
            b'\'' => in_single = true,
            b'"' => in_double = true,
            b'`' => in_back = true,
            b'(' => depth += 1,
            b')' => depth -= 1,
            b',' if depth == 0 => {
                let part = list[start..i].trim();
                if !part.is_empty() {
                    parts.push(part);
                }
                start = i + 1;
            }
            _ => {}
        }
    }
    let part = list[start..].trim();
    if !part.is_empty() {
        parts.push(part);
    }
    parts
}

fn select_item_bare_name(item: &str) -> String {
    // take last identifier before AS alias or end
    let upper = item.to_ascii_uppercase();
    let expr = if let Some(idx) = find_top_level_keyword(item, "AS") {
        item[..idx].trim()
    } else {
        // trailing alias without AS: "col alias"
        let tokens: Vec<&str> = item.split_whitespace().collect();
        if tokens.len() >= 2 && !tokens[0].contains('(') {
            tokens[0]
        } else {
            item.trim()
        }
    };
    let _ = upper;
    let bare = expr
        .rsplit('.')
        .next()
        .unwrap_or(expr)
        .trim_matches('`')
        .trim_matches('"')
        .trim_matches('\'');
    bare.to_ascii_lowercase()
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
    use crate::object_set::{ObjectAccess, ObjectSet};
    use crate::{HeuristicDialectParser, ProtocolKind};

    fn pdp_with(rules: Vec<SecurityRuleConfig>) -> LocalPdp {
        LocalPdp {
            fail_closed: true,
            star_policy: StarPolicy::Deny,
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
            columns: vec![],
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
            columns: vec![],
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
            columns: vec![],
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

    #[test]
    fn column_deny_rewrites_select_list() {
        let pdp = pdp_with(vec![SecurityRuleConfig {
            name: "deny-salary".into(),
            effect: "deny".into(),
            actions: vec!["select".into()],
            tables: vec!["employees".into()],
            columns: vec!["salary".into(), "ssn".into()],
            subjects: vec![],
        }]);
        let mut set = ObjectSet::empty();
        let mut obj = ObjectAccess::new("employees", StatementAction::Select);
        obj.columns = vec!["id".into(), "name".into(), "salary".into()];
        set.objects.push(obj);

        let sub = subject("app");
        let dialect = HeuristicDialectParser::mysql();
        let cmd = GatewayCommand::Query {
            sql: "SELECT id, name, salary FROM employees".into(),
        };
        match pdp.authorize_command_with_objects(&sub, "hr", &cmd, &dialect, Some(&set)) {
            SecurityDecision::AllowRewrite { sql } => {
                assert!(sql.to_ascii_lowercase().contains("id"));
                assert!(sql.to_ascii_lowercase().contains("name"));
                assert!(!sql.to_ascii_lowercase().contains("salary"));
            }
            other => panic!("expected rewrite, got {other:?}"),
        }
    }

    #[test]
    fn column_deny_wildcard_with_star_policy_deny() {
        let pdp = pdp_with(vec![SecurityRuleConfig {
            name: "deny-salary".into(),
            effect: "deny".into(),
            actions: vec!["select".into()],
            tables: vec!["employees".into()],
            columns: vec!["salary".into()],
            subjects: vec![],
        }]);
        let mut set = ObjectSet::empty();
        let mut obj = ObjectAccess::new("employees", StatementAction::Select);
        obj.has_wildcard = true;
        set.objects.push(obj);
        let sub = subject("app");
        let dialect = HeuristicDialectParser::mysql();
        let cmd = GatewayCommand::Query {
            sql: "SELECT * FROM employees".into(),
        };
        assert!(pdp
            .authorize_command_with_objects(&sub, "hr", &cmd, &dialect, Some(&set))
            .is_deny());
    }

    #[test]
    fn parse_failed_fail_closed() {
        let pdp = pdp_with(vec![SecurityRuleConfig {
            name: "deny-secret".into(),
            effect: "deny".into(),
            actions: vec!["select".into()],
            tables: vec!["secret_*".into()],
            columns: vec![],
            subjects: vec![],
        }]);
        let set = ObjectSet::parse_failed();
        let sub = subject("app");
        let dialect = HeuristicDialectParser::mysql();
        let cmd = GatewayCommand::Query {
            sql: "SELECT !!!".into(),
        };
        assert!(pdp
            .authorize_command_with_objects(&sub, "orders", &cmd, &dialect, Some(&set))
            .is_deny());
    }

    #[test]
    fn rewrite_strips_multiple_columns() {
        let denied = vec![
            ("r".into(), "salary".into()),
            ("r".into(), "ssn".into()),
        ];
        let sql = "SELECT id, salary, name, ssn FROM employees WHERE id=1";
        let out = rewrite_select_strip_columns(sql, &denied).unwrap();
        let lower = out.to_ascii_lowercase();
        assert!(lower.contains("id"));
        assert!(lower.contains("name"));
        assert!(!lower.contains("salary"));
        assert!(!lower.contains("ssn"));
        assert!(lower.contains("from employees"));
    }
}
