use serde::{Deserialize, Serialize};

use crate::{
    map_column_type, Column, DialectParser, GatewayCommand, GatewayError, GatewayResponse,
    GatewayResult, ProtocolKind,
};

/// Controlled cross-protocol translation policy.
///
/// Default is disabled. When enabled, only an explicitly supported SQL subset
/// may cross dialects; everything else fails with a clear error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranslationPolicyConfig {
    pub name: String,
    /// Must be true to allow cross-protocol access.
    #[serde(default)]
    pub enabled: bool,
    pub frontend_protocol: ProtocolKind,
    pub backend_protocol: ProtocolKind,
    /// Allowed statement kinds for this direction. Empty means default subset.
    #[serde(default)]
    pub allowed_statements: Vec<TranslationStatementKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TranslationStatementKind {
    Select,
    Insert,
    Update,
    Delete,
}

impl TranslationStatementKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Select => "select",
            Self::Insert => "insert",
            Self::Update => "update",
            Self::Delete => "delete",
        }
    }

    pub fn from_keyword(keyword: &str) -> Option<Self> {
        match keyword {
            "SELECT" | "WITH" | "VALUES" | "TABLE" | "SHOW" | "EXPLAIN" | "DESCRIBE" | "DESC" => {
                Some(Self::Select)
            }
            "INSERT" => Some(Self::Insert),
            "UPDATE" => Some(Self::Update),
            "DELETE" => Some(Self::Delete),
            _ => None,
        }
    }
}

impl Default for TranslationPolicyConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            enabled: false,
            frontend_protocol: ProtocolKind::MySql,
            backend_protocol: ProtocolKind::PostgreSql,
            allowed_statements: default_allowed_statements(),
        }
    }
}

pub fn default_allowed_statements() -> Vec<TranslationStatementKind> {
    vec![
        TranslationStatementKind::Select,
        TranslationStatementKind::Insert,
        TranslationStatementKind::Update,
        TranslationStatementKind::Delete,
    ]
}

/// Validate a full gateway command for a cross-protocol hop.
///
/// Prepared statements are rejected. Query SQL is checked against the subset
/// and optionally rewritten for the backend dialect.
pub fn prepare_cross_protocol_command(
    policy: &TranslationPolicyConfig,
    command: GatewayCommand,
    dialect: &dyn DialectParser,
) -> GatewayResult<GatewayCommand> {
    match command {
        GatewayCommand::Prepare { .. }
        | GatewayCommand::Execute { .. }
        | GatewayCommand::CloseStatement { .. } => Err(GatewayError::Unsupported(format!(
            "translation policy '{}': prepared statements are not supported for {} -> {}",
            policy.name, policy.frontend_protocol, policy.backend_protocol
        ))),
        GatewayCommand::Query { sql } => {
            check_translation_sql(policy, &sql, dialect)?;
            let rewritten = rewrite_sql_for_backend(
                &sql,
                &policy.frontend_protocol,
                &policy.backend_protocol,
            )?;
            Ok(GatewayCommand::Query { sql: rewritten })
        }
        GatewayCommand::UseDatabase { .. }
        | GatewayCommand::Begin
        | GatewayCommand::Commit
        | GatewayCommand::Rollback
        | GatewayCommand::Ping
        | GatewayCommand::Quit => Ok(command),
    }
}

/// Map resultset column types from backend dialect to frontend dialect.
pub fn map_response_types(
    response: GatewayResponse,
    backend: &ProtocolKind,
    frontend: &ProtocolKind,
) -> GatewayResponse {
    if backend == frontend {
        return response;
    }
    match response {
        GatewayResponse::ResultSet { columns, rows } => {
            let columns = columns
                .into_iter()
                .map(|column| Column {
                    name: column.name,
                    data_type: map_column_type(&column.data_type, backend, frontend),
                })
                .collect();
            GatewayResponse::ResultSet { columns, rows }
        }
        other => other,
    }
}

/// Validate and classify one SQL statement for a cross-protocol hop.
pub fn check_translation_sql(
    policy: &TranslationPolicyConfig,
    sql: &str,
    dialect: &dyn DialectParser,
) -> GatewayResult<TranslationStatementKind> {
    if !policy.enabled {
        return Err(GatewayError::Configuration(format!(
            "translation policy '{}' is disabled; cross-protocol access is not allowed",
            policy.name
        )));
    }
    if policy.frontend_protocol == policy.backend_protocol {
        return Err(GatewayError::Configuration(format!(
            "translation policy '{}' has identical frontend/backend protocol '{}'",
            policy.name, policy.frontend_protocol
        )));
    }
    if dialect.dialect() != policy.frontend_protocol {
        return Err(GatewayError::Configuration(format!(
            "translation policy '{}' expects frontend protocol '{}', got '{:?}'",
            policy.name,
            policy.frontend_protocol,
            dialect.dialect()
        )));
    }

    let upper = sql.trim_start().to_ascii_uppercase();
    reject_unsupported_constructs(policy, &upper)?;

    let keyword = dialect.leading_keyword(sql).ok_or_else(|| {
        GatewayError::Unsupported(format!(
            "translation policy '{}': empty or unparseable SQL is not supported for {} -> {}",
            policy.name, policy.frontend_protocol, policy.backend_protocol
        ))
    })?;

    let kind = TranslationStatementKind::from_keyword(&keyword).ok_or_else(|| {
        GatewayError::Unsupported(format!(
            "translation policy '{}': statement kind '{}' is not in the supported subset for {} -> {} (allowed: {})",
            policy.name,
            keyword,
            policy.frontend_protocol,
            policy.backend_protocol,
            format_allowed(policy)
        ))
    })?;

    let allowed = if policy.allowed_statements.is_empty() {
        default_allowed_statements()
    } else {
        policy.allowed_statements.clone()
    };
    if !allowed.contains(&kind) {
        return Err(GatewayError::Unsupported(format!(
            "translation policy '{}': '{}' is not allowed (allowed: {})",
            policy.name,
            kind.as_str(),
            format_allowed(policy)
        )));
    }

    Ok(kind)
}

/// Conservative SQL rewrite for the supported subset.
///
/// Only applies known-safe mechanical transforms. Unsupported vendor syntax is
/// rejected earlier by [`check_translation_sql`].
pub fn rewrite_sql_for_backend(
    sql: &str,
    frontend: &ProtocolKind,
    backend: &ProtocolKind,
) -> GatewayResult<String> {
    if frontend == backend {
        return Ok(sql.to_owned());
    }

    match (frontend, backend) {
        (ProtocolKind::MySql, ProtocolKind::PostgreSql) => Ok(rewrite_mysql_to_postgresql(sql)),
        (ProtocolKind::PostgreSql, ProtocolKind::MySql) => Ok(rewrite_postgresql_to_mysql(sql)),
        _ => Ok(sql.to_owned()),
    }
}

fn rewrite_mysql_to_postgresql(sql: &str) -> String {
    let mut out = convert_backticks_to_double_quotes(sql);
    out = replace_ifnull_with_coalesce(&out);
    out = rewrite_mysql_limit_offset(&out);
    out
}

fn rewrite_postgresql_to_mysql(sql: &str) -> String {
    // Double-quoted identifiers are valid in MySQL ANSI_QUOTES mode; keep them.
    // COALESCE is portable. LIMIT/OFFSET form is portable when already standard.
    sql.to_owned()
}

fn convert_backticks_to_double_quotes(sql: &str) -> String {
    let bytes = sql.as_bytes();
    let mut out = String::with_capacity(sql.len());
    let mut i = 0;
    let mut in_single = false;
    let mut in_double = false;

    while i < bytes.len() {
        let c = bytes[i] as char;
        if in_single {
            out.push(c);
            if c == '\'' {
                if i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                    out.push('\'');
                    i += 2;
                    continue;
                }
                in_single = false;
            }
            i += 1;
            continue;
        }
        if in_double {
            out.push(c);
            if c == '"' {
                if i + 1 < bytes.len() && bytes[i + 1] == b'"' {
                    out.push('"');
                    i += 2;
                    continue;
                }
                in_double = false;
            }
            i += 1;
            continue;
        }

        match c {
            '\'' => {
                in_single = true;
                out.push(c);
                i += 1;
            }
            '"' => {
                in_double = true;
                out.push(c);
                i += 1;
            }
            '`' => {
                // Convert `ident` -> "ident", doubling internal double-quotes.
                i += 1;
                out.push('"');
                while i < bytes.len() {
                    let ch = bytes[i] as char;
                    if ch == '`' {
                        if i + 1 < bytes.len() && bytes[i + 1] == b'`' {
                            out.push('`');
                            i += 2;
                            continue;
                        }
                        i += 1;
                        break;
                    }
                    if ch == '"' {
                        out.push('"');
                        out.push('"');
                    } else {
                        out.push(ch);
                    }
                    i += 1;
                }
                out.push('"');
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

fn replace_ifnull_with_coalesce(sql: &str) -> String {
    // Case-insensitive IFNULL( -> COALESCE(
    let upper = sql.to_ascii_uppercase();
    let mut out = String::with_capacity(sql.len());
    let mut i = 0;
    let bytes = sql.as_bytes();
    let upper_bytes = upper.as_bytes();

    while i < bytes.len() {
        if i + 6 < bytes.len()
            && &upper_bytes[i..i + 6] == b"IFNULL"
            && (i == 0 || !is_ident_byte(upper_bytes[i - 1]))
            && !is_ident_byte(upper_bytes[i + 6])
        {
            // Skip optional whitespace then require '('
            let mut j = i + 6;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'(' {
                out.push_str("COALESCE");
                out.push_str(&sql[i + 6..j]);
                out.push('(');
                i = j + 1;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Rewrite MySQL `LIMIT offset, count` to `LIMIT count OFFSET offset`.
fn rewrite_mysql_limit_offset(sql: &str) -> String {
    let upper = sql.to_ascii_uppercase();
    let Some(limit_pos) = find_keyword(&upper, "LIMIT") else {
        return sql.to_owned();
    };

    let after_limit = limit_pos + 5;
    let rest = sql[after_limit..].trim_start();

    // Already OFFSET form or bare LIMIT n
    let upper_rest = rest.to_ascii_uppercase();
    if upper_rest.contains("OFFSET") {
        return sql.to_owned();
    }

    // Match: number , number
    let mut idx = 0;
    let chars: Vec<char> = rest.chars().collect();
    while idx < chars.len() && chars[idx].is_ascii_digit() {
        idx += 1;
    }
    if idx == 0 {
        return sql.to_owned();
    }
    let offset_end = idx;
    while idx < chars.len() && chars[idx].is_ascii_whitespace() {
        idx += 1;
    }
    if idx >= chars.len() || chars[idx] != ',' {
        return sql.to_owned();
    }
    idx += 1;
    while idx < chars.len() && chars[idx].is_ascii_whitespace() {
        idx += 1;
    }
    let count_start = idx;
    while idx < chars.len() && chars[idx].is_ascii_digit() {
        idx += 1;
    }
    if idx == count_start {
        return sql.to_owned();
    }
    let count_end = idx;
    // Trailing must not start another identifier digit glued
    let offset = chars[..offset_end].iter().collect::<String>();
    let count = chars[count_start..count_end].iter().collect::<String>();
    let tail: String = chars[count_end..].iter().collect();

    // Prefix ends before the original LIMIT keyword.
    format!(
        "{}LIMIT {} OFFSET {}{}",
        &sql[..limit_pos],
        count,
        offset,
        tail
    )
}

fn find_keyword(upper_sql: &str, keyword: &str) -> Option<usize> {
    let mut i = 0;
    let bytes = upper_sql.as_bytes();
    let key = keyword.as_bytes();
    while i + key.len() <= bytes.len() {
        if &bytes[i..i + key.len()] == key {
            let before_ok = i == 0 || !is_ident_byte(bytes[i - 1]);
            let after = i + key.len();
            let after_ok = after >= bytes.len() || !is_ident_byte(bytes[after]);
            if before_ok && after_ok {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn format_allowed(policy: &TranslationPolicyConfig) -> String {
    let allowed = if policy.allowed_statements.is_empty() {
        default_allowed_statements()
    } else {
        policy.allowed_statements.clone()
    };
    allowed.iter().map(|k| k.as_str()).collect::<Vec<_>>().join(", ")
}

fn reject_unsupported_constructs(
    policy: &TranslationPolicyConfig,
    upper_sql: &str,
) -> GatewayResult<()> {
    let forbidden = [
        ("CREATE ", "DDL CREATE"),
        ("ALTER ", "DDL ALTER"),
        ("DROP ", "DDL DROP"),
        ("TRUNCATE ", "DDL TRUNCATE"),
        ("RENAME ", "DDL RENAME"),
        ("CALL ", "stored procedure CALL"),
        ("EXECUTE ", "EXECUTE/procedure"),
        ("COPY ", "PostgreSQL COPY"),
        ("LOAD DATA", "MySQL LOAD DATA"),
        ("LOAD XML", "MySQL LOAD XML"),
        ("HANDLER ", "MySQL HANDLER"),
        ("LOCK TABLES", "LOCK TABLES"),
        ("UNLOCK TABLES", "UNLOCK TABLES"),
        ("REPLACE INTO", "MySQL REPLACE"),
        ("ON DUPLICATE KEY", "MySQL ON DUPLICATE KEY"),
        ("RETURNING ", "PostgreSQL RETURNING (not mapped yet)"),
        ("::", "PostgreSQL cast operator ::"),
        ("ILIKE ", "PostgreSQL ILIKE"),
        ("REGEXP ", "MySQL REGEXP"),
        ("RLIKE ", "MySQL RLIKE"),
    ];

    for (needle, label) in forbidden {
        if upper_sql.contains(needle) {
            return Err(GatewayError::Unsupported(format!(
                "translation policy '{}': {} is not supported for {} -> {}",
                policy.name, label, policy.frontend_protocol, policy.backend_protocol
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HeuristicDialectParser, GatewayValue};

    fn mysql_to_pg() -> TranslationPolicyConfig {
        TranslationPolicyConfig {
            name: "mysql-to-pg".into(),
            enabled: true,
            frontend_protocol: ProtocolKind::MySql,
            backend_protocol: ProtocolKind::PostgreSql,
            allowed_statements: default_allowed_statements(),
        }
    }

    #[test]
    fn disabled_policy_rejects() {
        let mut policy = mysql_to_pg();
        policy.enabled = false;
        let dialect = HeuristicDialectParser::mysql();
        let err = check_translation_sql(&policy, "select 1", &dialect).unwrap_err();
        assert!(err.to_string().contains("disabled"));
    }

    #[test]
    fn allows_select_insert_update_delete() {
        let policy = mysql_to_pg();
        let dialect = HeuristicDialectParser::mysql();
        assert_eq!(
            check_translation_sql(&policy, "select * from t", &dialect).unwrap(),
            TranslationStatementKind::Select
        );
        assert_eq!(
            check_translation_sql(&policy, "insert into t values (1)", &dialect).unwrap(),
            TranslationStatementKind::Insert
        );
    }

    #[test]
    fn rejects_ddl_and_vendor_constructs() {
        let policy = mysql_to_pg();
        let dialect = HeuristicDialectParser::mysql();
        assert!(check_translation_sql(&policy, "drop table t", &dialect)
            .unwrap_err()
            .to_string()
            .contains("DDL DROP"));
        assert!(check_translation_sql(&policy, "load data infile 'x' into table t", &dialect)
            .unwrap_err()
            .to_string()
            .contains("LOAD DATA"));
        assert!(check_translation_sql(&policy, "select a::text from t", &dialect)
            .unwrap_err()
            .to_string()
            .contains("cast operator"));
    }

    #[test]
    fn rejects_disallowed_statement_kind() {
        let mut policy = mysql_to_pg();
        policy.allowed_statements = vec![TranslationStatementKind::Select];
        let dialect = HeuristicDialectParser::mysql();
        let err = check_translation_sql(&policy, "delete from t", &dialect).unwrap_err();
        assert!(err.to_string().contains("not allowed"));
    }

    #[test]
    fn rejects_prepared_statements() {
        let policy = mysql_to_pg();
        let dialect = HeuristicDialectParser::mysql();
        let err = prepare_cross_protocol_command(
            &policy,
            GatewayCommand::Prepare {
                sql: "select 1".into(),
            },
            &dialect,
        )
        .unwrap_err();
        assert!(err.to_string().contains("prepared statements"));
    }

    #[test]
    fn golden_rewrite_mysql_to_postgresql() {
        let cases = [
            (
                "SELECT `id`, IFNULL(name, '') FROM `users` LIMIT 10, 20",
                "SELECT \"id\", COALESCE(name, '') FROM \"users\" LIMIT 20 OFFSET 10",
            ),
            (
                "select ifnull(a, 0) from t",
                "select COALESCE(a, 0) from t",
            ),
            (
                "SELECT * FROM t LIMIT 5",
                "SELECT * FROM t LIMIT 5",
            ),
            (
                "SELECT * FROM t LIMIT 5 OFFSET 2",
                "SELECT * FROM t LIMIT 5 OFFSET 2",
            ),
            (
                "INSERT INTO `t` (`a`) VALUES ('`keep`')",
                "INSERT INTO \"t\" (\"a\") VALUES ('`keep`')",
            ),
        ];
        for (input, expected) in cases {
            let out = rewrite_sql_for_backend(
                input,
                &ProtocolKind::MySql,
                &ProtocolKind::PostgreSql,
            )
            .unwrap();
            assert_eq!(out, expected, "input={input}");
        }
    }

    #[test]
    fn maps_resultset_column_types() {
        let response = GatewayResponse::ResultSet {
            columns: vec![
                Column {
                    name: "id".into(),
                    data_type: "int4".into(),
                },
                Column {
                    name: "flag".into(),
                    data_type: "bool".into(),
                },
            ],
            rows: vec![vec![GatewayValue::Integer(1), GatewayValue::Boolean(true)]],
        };
        let mapped = map_response_types(
            response,
            &ProtocolKind::PostgreSql,
            &ProtocolKind::MySql,
        );
        match mapped {
            GatewayResponse::ResultSet { columns, .. } => {
                assert_eq!(columns[0].data_type, "long");
                assert_eq!(columns[1].data_type, "tiny");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn prepare_query_rewrites_sql() {
        let policy = mysql_to_pg();
        let dialect = HeuristicDialectParser::mysql();
        let cmd = prepare_cross_protocol_command(
            &policy,
            GatewayCommand::Query {
                sql: "SELECT `id` FROM t LIMIT 1, 2".into(),
            },
            &dialect,
        )
        .unwrap();
        assert_eq!(
            cmd,
            GatewayCommand::Query {
                sql: "SELECT \"id\" FROM t LIMIT 2 OFFSET 1".into(),
            }
        );
    }
}
