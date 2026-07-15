use crate::ProtocolKind;

/// Protocol-neutral SQL dialect helpers used by routing, plugins, and rewrite.
///
/// Implementations must not depend on a specific parser crate. Full AST parsing
/// can be layered later; this trait starts with classification needed by core.
pub trait DialectParser: Send + Sync {
    fn dialect(&self) -> ProtocolKind;

    /// Whether the statement is safe to route to a read-only replica.
    fn is_read_only(&self, sql: &str) -> bool;

    /// First SQL keyword (uppercased), if any.
    fn leading_keyword(&self, sql: &str) -> Option<String> {
        let sql = sql.trim_start();
        let upper = sql.to_ascii_uppercase();
        let token = upper
            .split_whitespace()
            .next()
            .map(|token| token.trim_end_matches(';').to_owned())?;
        if token.is_empty() {
            None
        } else {
            Some(token)
        }
    }
}

/// Shared heuristic for MySQL / PostgreSQL simple-query routing.
///
/// Not a full SQL parser: good enough for read/write splitting defaults.
#[derive(Debug, Clone)]
pub struct HeuristicDialectParser {
    dialect: ProtocolKind,
}

impl HeuristicDialectParser {
    pub fn new(dialect: ProtocolKind) -> Self {
        Self { dialect }
    }

    pub fn mysql() -> Self {
        Self::new(ProtocolKind::MySql)
    }

    pub fn postgresql() -> Self {
        Self::new(ProtocolKind::PostgreSql)
    }
}

impl DialectParser for HeuristicDialectParser {
    fn dialect(&self) -> ProtocolKind {
        self.dialect.clone()
    }

    fn is_read_only(&self, sql: &str) -> bool {
        let sql = sql.trim_start();
        let upper = sql.to_ascii_uppercase();
        let first_token =
            upper.split_whitespace().next().unwrap_or_default().trim_end_matches(';');

        let read_keywords = match self.dialect {
            ProtocolKind::MySql => {
                matches!(
                    first_token,
                    "SELECT" | "SHOW" | "EXPLAIN" | "DESCRIBE" | "DESC" | "WITH" | "VALUES"
                )
            }
            ProtocolKind::PostgreSql => {
                matches!(
                    first_token,
                    "SELECT" | "SHOW" | "EXPLAIN" | "WITH" | "VALUES" | "TABLE"
                )
            }
        };

        read_keywords
            && !upper.contains(" FOR UPDATE")
            && !upper.contains(" FOR SHARE")
            && !upper.contains(" FOR NO KEY UPDATE")
            && !upper.contains(" FOR KEY SHARE")
    }
}

/// Build the default dialect parser for a backend protocol.
pub fn default_dialect_parser(protocol: &ProtocolKind) -> HeuristicDialectParser {
    match protocol {
        ProtocolKind::MySql => HeuristicDialectParser::mysql(),
        ProtocolKind::PostgreSql => HeuristicDialectParser::postgresql(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mysql_classifies_select_as_read_only() {
        let parser = HeuristicDialectParser::mysql();
        assert!(parser.is_read_only("select * from t"));
        assert!(!parser.is_read_only("select * from t for update"));
        assert!(!parser.is_read_only("insert into t values (1)"));
    }

    #[test]
    fn postgresql_classifies_table_keyword_as_read_only() {
        let parser = HeuristicDialectParser::postgresql();
        assert!(parser.is_read_only("TABLE users"));
        assert!(!parser.is_read_only("update users set x = 1"));
    }

    #[test]
    fn leading_keyword_helper() {
        let parser = HeuristicDialectParser::mysql();
        assert_eq!(parser.leading_keyword("  select 1"), Some("SELECT".into()));
        assert_eq!(parser.leading_keyword(""), None);
    }
}
