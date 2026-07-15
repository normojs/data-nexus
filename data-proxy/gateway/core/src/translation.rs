use serde::{Deserialize, Serialize};

use crate::{DialectParser, GatewayError, GatewayResult, ProtocolKind};

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
    use crate::HeuristicDialectParser;

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
}
