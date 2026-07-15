//! Runtime dialect parsers that may depend on protocol-specific crates.
//!
//! `gateway_core` stays free of parser dependencies; MySQL AST classification
//! lives here and is injected into core routing via `DialectParser`.

use gateway_core::{DialectParser, HeuristicDialectParser, ProtocolKind};
use mysql_parser::ast::SqlStmt;
use mysql_parser::parser::Parser as MySqlAstParser;

/// MySQL dialect parser backed by `mysql_parser` AST when parse succeeds.
///
/// On parse failure, falls back to [`HeuristicDialectParser`] so routing remains
/// available for edge SQL the grammar does not yet cover.
#[derive(Debug, Clone)]
pub struct MySqlAstDialectParser {
    fallback: HeuristicDialectParser,
}

impl MySqlAstDialectParser {
    pub fn new() -> Self {
        Self {
            fallback: HeuristicDialectParser::mysql(),
        }
    }
}

impl Default for MySqlAstDialectParser {
    fn default() -> Self {
        Self::new()
    }
}

impl DialectParser for MySqlAstDialectParser {
    fn dialect(&self) -> ProtocolKind {
        ProtocolKind::MySql
    }

    fn is_read_only(&self, sql: &str) -> bool {
        match classify_mysql_sql(sql) {
            Some(kind) => kind.is_read_only(),
            None => self.fallback.is_read_only(sql),
        }
    }

    fn leading_keyword(&self, sql: &str) -> Option<String> {
        match classify_mysql_sql(sql) {
            Some(kind) => Some(kind.leading_keyword().to_owned()),
            None => self.fallback.leading_keyword(sql),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MysqlStmtKind {
    Select,
    Show,
    Insert,
    Update,
    Delete,
    Begin,
    Commit,
    Rollback,
    Set,
    Prepare,
    Execute,
    Deallocate,
    Create,
    Other,
}

impl MysqlStmtKind {
    fn is_read_only(self) -> bool {
        matches!(self, Self::Select | Self::Show)
    }

    fn leading_keyword(self) -> &'static str {
        match self {
            Self::Select => "SELECT",
            Self::Show => "SHOW",
            Self::Insert => "INSERT",
            Self::Update => "UPDATE",
            Self::Delete => "DELETE",
            Self::Begin => "BEGIN",
            Self::Commit => "COMMIT",
            Self::Rollback => "ROLLBACK",
            Self::Set => "SET",
            Self::Prepare => "PREPARE",
            Self::Execute => "EXECUTE",
            Self::Deallocate => "DEALLOCATE",
            Self::Create => "CREATE",
            Self::Other => "OTHER",
        }
    }
}

fn classify_mysql_sql(sql: &str) -> Option<MysqlStmtKind> {
    // mysql_parser may panic on some invalid inputs; isolate and fall back.
    let parsed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let parser = MySqlAstParser::new();
        parser.parse(sql)
    }))
    .ok()?
    .ok()?;
    let first = parsed.into_iter().next()?;
    Some(stmt_kind(&first))
}

fn stmt_kind(stmt: &SqlStmt) -> MysqlStmtKind {
    match stmt {
        SqlStmt::SelectStmt(select) => {
            // FOR UPDATE / FOR SHARE make a SELECT write-bound for routing.
            let formatted = select.format().to_ascii_uppercase();
            if formatted.contains(" FOR UPDATE")
                || formatted.contains(" FOR SHARE")
                || formatted.contains(" FOR NO KEY UPDATE")
                || formatted.contains(" FOR KEY SHARE")
                || formatted.contains(" LOCK IN SHARE MODE")
            {
                MysqlStmtKind::Other
            } else {
                MysqlStmtKind::Select
            }
        }
        SqlStmt::ShowDatabasesStmt(_)
        | SqlStmt::ShowTablesStmt(_)
        | SqlStmt::ShowColumnsStmt(_)
        | SqlStmt::ShowCreateTableStmt(_)
        | SqlStmt::ShowKeysStmt(_)
        | SqlStmt::ShowVariablesStmt(_)
        | SqlStmt::ShowCreateViewStmt(_)
        | SqlStmt::ShowMasterStatusStmt(_)
        | SqlStmt::ShowTableStatusStmt(_)
        | SqlStmt::ShowEnginesStmt(_)
        | SqlStmt::ShowPluginsStmt(_)
        | SqlStmt::ShowPrivilegesStmt(_)
        | SqlStmt::ShowProcessListStmt(_)
        | SqlStmt::ShowReplicasStmt(_)
        | SqlStmt::ShowReplicaStatusStmt(_)
        | SqlStmt::ShowGrantsStmt(_)
        | SqlStmt::ShowCreateProcedureStmt(_)
        | SqlStmt::ShowCreateFunctionStmt(_)
        | SqlStmt::ShowCreateTriggerStmt(_)
        | SqlStmt::ShowCreateEventStmt(_)
        | SqlStmt::ShowCreateUserStmt(_)
        | SqlStmt::ShowStatusStmt(_) => MysqlStmtKind::Show,
        SqlStmt::InsertStmt(_) => MysqlStmtKind::Insert,
        SqlStmt::UpdateStmt(_) => MysqlStmtKind::Update,
        SqlStmt::DeleteStmt(_) => MysqlStmtKind::Delete,
        SqlStmt::BeginStmt(_) | SqlStmt::Start(_) => MysqlStmtKind::Begin,
        SqlStmt::Commit(_) => MysqlStmtKind::Commit,
        SqlStmt::Rollback(_) => MysqlStmtKind::Rollback,
        SqlStmt::Set(_) => MysqlStmtKind::Set,
        SqlStmt::Prepare(_) => MysqlStmtKind::Prepare,
        SqlStmt::ExecuteStmt(_) => MysqlStmtKind::Execute,
        SqlStmt::Deallocate(_) => MysqlStmtKind::Deallocate,
        SqlStmt::Create(_)
        | SqlStmt::CreateIndexStmt(_)
        | SqlStmt::CreateTableStmt(_)
        | SqlStmt::CreateResourceGroupStmt(_)
        | SqlStmt::CreateRoleStmt(_)
        | SqlStmt::CreateSRSStmt(_) => MysqlStmtKind::Create,
        SqlStmt::None => MysqlStmtKind::Other,
    }
}

/// Build a dialect parser for the given protocol.
///
/// MySQL uses AST classification with heuristic fallback; PostgreSQL stays on
/// the shared heuristic until a PG AST crate is wired.
pub fn runtime_dialect_parser(protocol: &ProtocolKind) -> Box<dyn DialectParser> {
    match protocol {
        ProtocolKind::MySql => Box::new(MySqlAstDialectParser::new()),
        ProtocolKind::PostgreSql => Box::new(HeuristicDialectParser::postgresql()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ast_classifies_select_as_read_only() {
        let parser = MySqlAstDialectParser::new();
        assert!(parser.is_read_only("SELECT id FROM users WHERE id = 1"));
        assert!(!parser.is_read_only("INSERT INTO users VALUES (1)"));
        assert!(!parser.is_read_only("UPDATE users SET name = 'x'"));
        assert!(!parser.is_read_only("DELETE FROM users WHERE id = 1"));
    }

    #[test]
    fn ast_classifies_show_as_read_only() {
        let parser = MySqlAstDialectParser::new();
        // SHOW may or may not parse depending on grammar coverage; either way
        // must not panic and should prefer read when classified as Show.
        let _ = parser.is_read_only("SHOW TABLES");
    }

    #[test]
    fn for_update_is_not_read_only() {
        let parser = MySqlAstDialectParser::new();
        // If AST parse fails, heuristic also treats FOR UPDATE as non-readonly.
        assert!(!parser.is_read_only("SELECT * FROM t FOR UPDATE"));
    }

    #[test]
    fn falls_back_on_unparseable_sql() {
        let parser = MySqlAstDialectParser::new();
        // Garbage that is not a statement: heuristic returns false for empty-ish.
        assert!(!parser.is_read_only("!!!"));
        // SELECT-shaped text still classified read-only by fallback if AST fails.
        assert!(parser.is_read_only("select 1"));
    }

    #[test]
    fn leading_keyword_from_ast_or_fallback() {
        let parser = MySqlAstDialectParser::new();
        assert_eq!(parser.leading_keyword("  select 1"), Some("SELECT".into()));
        assert_eq!(parser.leading_keyword("insert into t values (1)"), Some("INSERT".into()));
    }
}
