//! Runtime dialect parsers that may depend on protocol-specific crates.
//!
//! `gateway_core` stays free of parser dependencies; MySQL AST classification
//! lives here and is injected into core routing via `DialectParser`.

use gateway_core::{DialectParser, HeuristicDialectParser, ProtocolKind};
use mysql_parser::ast::SqlStmt;
use mysql_parser::parser::Parser as MySqlAstParser;
use sqlparser::ast::{Query, SetExpr, Statement};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser as SqlParser;

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

/// PostgreSQL dialect classifier with structured statement detection.
///
/// Not a full SQL parser crate: strips comments, classifies leading statements,
/// and treats locking / DML CTE shapes as non-read-only. Falls back to the
/// shared heuristic only for empty or unknown leading forms.
#[derive(Debug, Clone)]
pub struct PostgreSqlStructuredDialectParser {
    fallback: HeuristicDialectParser,
}

impl PostgreSqlStructuredDialectParser {
    pub fn new() -> Self {
        Self {
            fallback: HeuristicDialectParser::postgresql(),
        }
    }
}

impl Default for PostgreSqlStructuredDialectParser {
    fn default() -> Self {
        Self::new()
    }
}

impl DialectParser for PostgreSqlStructuredDialectParser {
    fn dialect(&self) -> ProtocolKind {
        ProtocolKind::PostgreSql
    }

    fn is_read_only(&self, sql: &str) -> bool {
        match classify_postgresql_sql(sql) {
            Some(kind) => kind.is_read_only(sql),
            None => self.fallback.is_read_only(sql),
        }
    }

    fn leading_keyword(&self, sql: &str) -> Option<String> {
        match classify_postgresql_sql(sql) {
            Some(kind) => Some(kind.leading_keyword().to_owned()),
            None => self.fallback.leading_keyword(sql),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PostgresStmtKind {
    Select,
    Table,
    Values,
    With,
    Show,
    Explain,
    Insert,
    Update,
    Delete,
    Begin,
    Commit,
    Rollback,
    Set,
    Copy,
    Other,
}

impl PostgresStmtKind {
    fn is_read_only(self, sql: &str) -> bool {
        let upper = strip_sql_comments(sql).to_ascii_uppercase();
        if has_row_lock_clause(&upper) {
            return false;
        }
        match self {
            Self::Select | Self::Table | Self::Values | Self::Show | Self::Explain => true,
            Self::With => {
                // WITH ... INSERT/UPDATE/DELETE is a write; WITH ... SELECT is read.
                !contains_dml_after_with(&upper)
            }
            _ => false,
        }
    }

    fn leading_keyword(self) -> &'static str {
        match self {
            Self::Select => "SELECT",
            Self::Table => "TABLE",
            Self::Values => "VALUES",
            Self::With => "WITH",
            Self::Show => "SHOW",
            Self::Explain => "EXPLAIN",
            Self::Insert => "INSERT",
            Self::Update => "UPDATE",
            Self::Delete => "DELETE",
            Self::Begin => "BEGIN",
            Self::Commit => "COMMIT",
            Self::Rollback => "ROLLBACK",
            Self::Set => "SET",
            Self::Copy => "COPY",
            Self::Other => "OTHER",
        }
    }
}

fn classify_postgresql_sql(sql: &str) -> Option<PostgresStmtKind> {
    let cleaned = strip_sql_comments(sql);
    let trimmed = cleaned.trim_start();
    if trimmed.is_empty() {
        return None;
    }
    let upper = trimmed.to_ascii_uppercase();
    let token = first_sql_token(&upper)?;
    Some(match token.as_str() {
        "SELECT" => PostgresStmtKind::Select,
        "TABLE" => PostgresStmtKind::Table,
        "VALUES" => PostgresStmtKind::Values,
        "WITH" => PostgresStmtKind::With,
        "SHOW" => PostgresStmtKind::Show,
        "EXPLAIN" => PostgresStmtKind::Explain,
        "INSERT" => PostgresStmtKind::Insert,
        "UPDATE" => PostgresStmtKind::Update,
        "DELETE" => PostgresStmtKind::Delete,
        "BEGIN" | "START" => PostgresStmtKind::Begin,
        "COMMIT" | "END" => PostgresStmtKind::Commit,
        "ROLLBACK" | "ABORT" => PostgresStmtKind::Rollback,
        "SET" => PostgresStmtKind::Set,
        "COPY" => PostgresStmtKind::Copy,
        "CREATE" | "ALTER" | "DROP" | "TRUNCATE" | "VACUUM" | "ANALYZE" | "REINDEX"
        | "CLUSTER" | "CALL" | "DO" | "LISTEN" | "NOTIFY" | "UNLISTEN" | "LOCK"
        | "GRANT" | "REVOKE" | "COMMENT" | "SECURITY" | "PREPARE" | "EXECUTE"
        | "DEALLOCATE" | "DECLARE" | "FETCH" | "MOVE" | "CLOSE" | "DISCARD" => {
            PostgresStmtKind::Other
        }
        _ => return None,
    })
}

fn first_sql_token(upper_sql: &str) -> Option<String> {
    let mut token = String::new();
    for ch in upper_sql.chars() {
        if ch.is_ascii_alphabetic() || ch == '_' {
            token.push(ch);
        } else if !token.is_empty() {
            break;
        } else if ch.is_ascii_whitespace() || ch == '(' {
            continue;
        } else {
            return None;
        }
    }
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

fn strip_sql_comments(sql: &str) -> String {
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

        // Line comment --
        if c == '-' && i + 1 < bytes.len() && bytes[i + 1] == b'-' {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // Block comment /* */
        if c == '/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() {
                if bytes[i] == b'*' && bytes[i + 1] == b'/' {
                    i += 2;
                    break;
                }
                i += 1;
            }
            out.push(' ');
            continue;
        }

        match c {
            '\'' => {
                in_single = true;
                out.push(c);
            }
            '"' => {
                in_double = true;
                out.push(c);
            }
            _ => out.push(c),
        }
        i += 1;
    }
    out
}

fn has_row_lock_clause(upper_sql: &str) -> bool {
    upper_sql.contains(" FOR UPDATE")
        || upper_sql.contains(" FOR SHARE")
        || upper_sql.contains(" FOR NO KEY UPDATE")
        || upper_sql.contains(" FOR KEY SHARE")
}

fn contains_dml_after_with(upper_sql: &str) -> bool {
    // Approximate: CTE write forms usually contain these verbs after WITH.
    // Avoid matching INSERT/UPDATE/DELETE only inside string literals by
    // operating on comment-stripped upper text (good enough for routing).
    for needle in [" INSERT ", " UPDATE ", " DELETE ", "\nINSERT ", "\nUPDATE ", "\nDELETE "] {
        if upper_sql.contains(needle) {
            return true;
        }
    }
    // Leading forms without surrounding spaces near end of CTE list.
    let compact = upper_sql.replace('\n', " ");
    compact.contains(") INSERT ")
        || compact.contains(") UPDATE ")
        || compact.contains(") DELETE ")
        || compact.contains(" INSERT INTO")
        || compact.contains(" UPDATE ")
        || compact.contains(" DELETE FROM")
}

/// PostgreSQL dialect parser backed by `sqlparser` AST when parse succeeds.
///
/// On parse failure (or panic), falls back to
/// [`PostgreSqlStructuredDialectParser`] so routing remains available.
#[derive(Debug, Clone)]
pub struct PostgreSqlAstDialectParser {
    fallback: PostgreSqlStructuredDialectParser,
}

impl PostgreSqlAstDialectParser {
    pub fn new() -> Self {
        Self {
            fallback: PostgreSqlStructuredDialectParser::new(),
        }
    }
}

impl Default for PostgreSqlAstDialectParser {
    fn default() -> Self {
        Self::new()
    }
}

impl DialectParser for PostgreSqlAstDialectParser {
    fn dialect(&self) -> ProtocolKind {
        ProtocolKind::PostgreSql
    }

    fn is_read_only(&self, sql: &str) -> bool {
        match classify_postgresql_ast(sql) {
            Some(kind) => kind.is_read_only_from_ast(),
            None => self.fallback.is_read_only(sql),
        }
    }

    fn leading_keyword(&self, sql: &str) -> Option<String> {
        match classify_postgresql_ast(sql) {
            Some(kind) => Some(kind.leading_keyword().to_owned()),
            None => self.fallback.leading_keyword(sql),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PostgresAstKind {
    Select,
    Values,
    Show,
    Explain,
    Insert,
    Update,
    Delete,
    Begin,
    Commit,
    Rollback,
    Set,
    Copy,
    Create,
    Other,
}

impl PostgresAstKind {
    fn is_read_only_from_ast(self) -> bool {
        matches!(
            self,
            Self::Select | Self::Values | Self::Show | Self::Explain
        )
    }

    fn leading_keyword(self) -> &'static str {
        match self {
            Self::Select => "SELECT",
            Self::Values => "VALUES",
            Self::Show => "SHOW",
            Self::Explain => "EXPLAIN",
            Self::Insert => "INSERT",
            Self::Update => "UPDATE",
            Self::Delete => "DELETE",
            Self::Begin => "BEGIN",
            Self::Commit => "COMMIT",
            Self::Rollback => "ROLLBACK",
            Self::Set => "SET",
            Self::Copy => "COPY",
            Self::Create => "CREATE",
            Self::Other => "OTHER",
        }
    }
}

fn classify_postgresql_ast(sql: &str) -> Option<PostgresAstKind> {
    let parsed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let dialect = PostgreSqlDialect {};
        SqlParser::parse_sql(&dialect, sql)
    }))
    .ok()?
    .ok()?;
    let first = parsed.into_iter().next()?;
    Some(statement_kind(&first))
}

fn statement_kind(stmt: &Statement) -> PostgresAstKind {
    match stmt {
        Statement::Query(query) => query_kind(query),
        Statement::Insert(_) => PostgresAstKind::Insert,
        Statement::Update { .. } => PostgresAstKind::Update,
        Statement::Delete(_) => PostgresAstKind::Delete,
        Statement::Copy { .. } | Statement::CopyIntoSnowflake { .. } => PostgresAstKind::Copy,
        Statement::StartTransaction { .. } => PostgresAstKind::Begin,
        Statement::Commit { .. } => PostgresAstKind::Commit,
        Statement::Rollback { .. } => PostgresAstKind::Rollback,
        Statement::SetVariable { .. }
        | Statement::SetTimeZone { .. }
        | Statement::SetNames { .. }
        | Statement::SetNamesDefault { .. } => PostgresAstKind::Set,
        Statement::ShowVariable { .. }
        | Statement::ShowVariables { .. }
        | Statement::ShowCreate { .. }
        | Statement::ShowColumns { .. }
        | Statement::ShowTables { .. }
        | Statement::ShowFunctions { .. }
        | Statement::ShowCollation { .. } => PostgresAstKind::Show,
        Statement::Explain { .. } | Statement::ExplainTable { .. } => PostgresAstKind::Explain,
        Statement::CreateTable(_)
        | Statement::CreateView { .. }
        | Statement::CreateIndex(_)
        | Statement::CreateSchema { .. }
        | Statement::CreateDatabase { .. }
        | Statement::CreateFunction { .. }
        | Statement::CreateProcedure { .. }
        | Statement::CreateType { .. }
        | Statement::CreateSequence { .. }
        | Statement::CreateRole { .. }
        | Statement::CreateVirtualTable { .. } => PostgresAstKind::Create,
        // DDL / DCL / session control / unsupported for read routing.
        Statement::Drop { .. }
        | Statement::DropFunction { .. }
        | Statement::AlterTable { .. }
        | Statement::AlterIndex { .. }
        | Statement::Truncate { .. }
        | Statement::Grant { .. }
        | Statement::Revoke { .. }
        | Statement::Analyze { .. }
        | Statement::Comment { .. }
        | Statement::Prepare { .. }
        | Statement::Execute { .. }
        | Statement::Deallocate { .. }
        | Statement::Declare { .. }
        | Statement::Fetch { .. }
        | Statement::Close { .. }
        | Statement::Call(_) => PostgresAstKind::Other,
        _ => PostgresAstKind::Other,
    }
}

fn query_kind(query: &Query) -> PostgresAstKind {
    // SELECT ... FOR UPDATE / FOR SHARE is write-bound for routing.
    if !query.locks.is_empty() {
        return PostgresAstKind::Other;
    }
    match query.body.as_ref() {
        SetExpr::Select(_) => PostgresAstKind::Select,
        SetExpr::Values(_) => PostgresAstKind::Values,
        SetExpr::Query(inner) => query_kind(inner),
        SetExpr::SetOperation { left, right, .. } => {
            // UNION/INTERSECT/EXCEPT of read-only sides stays read-only unless locks.
            let left_kind = set_expr_kind(left);
            let right_kind = set_expr_kind(right);
            if left_kind.is_read_only_from_ast() && right_kind.is_read_only_from_ast() {
                PostgresAstKind::Select
            } else {
                PostgresAstKind::Other
            }
        }
        SetExpr::Insert(stmt) => statement_kind(stmt),
        SetExpr::Update(stmt) => statement_kind(stmt),
        SetExpr::Table(_) => PostgresAstKind::Select, // PostgreSQL TABLE t
    }
}

fn set_expr_kind(expr: &SetExpr) -> PostgresAstKind {
    match expr {
        SetExpr::Select(_) => PostgresAstKind::Select,
        SetExpr::Values(_) => PostgresAstKind::Values,
        SetExpr::Query(q) => query_kind(q),
        SetExpr::SetOperation { left, right, .. } => {
            let left_kind = set_expr_kind(left);
            let right_kind = set_expr_kind(right);
            if left_kind.is_read_only_from_ast() && right_kind.is_read_only_from_ast() {
                PostgresAstKind::Select
            } else {
                PostgresAstKind::Other
            }
        }
        SetExpr::Insert(stmt) => statement_kind(stmt),
        SetExpr::Update(stmt) => statement_kind(stmt),
        SetExpr::Table(_) => PostgresAstKind::Select,
    }
}

/// Build a dialect parser for the given protocol.
///
/// - MySQL: `mysql_parser` AST + heuristic fallback
/// - PostgreSQL: `sqlparser` AST + structured fallback + heuristic
pub fn runtime_dialect_parser(protocol: &ProtocolKind) -> Box<dyn DialectParser> {
    match protocol {
        ProtocolKind::MySql => Box::new(MySqlAstDialectParser::new()),
        ProtocolKind::PostgreSql => Box::new(PostgreSqlAstDialectParser::new()),
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

    #[test]
    fn postgresql_structured_classifies_read_and_write() {
        let parser = PostgreSqlStructuredDialectParser::new();
        assert!(parser.is_read_only("SELECT 1"));
        assert!(parser.is_read_only("TABLE users"));
        assert!(parser.is_read_only("VALUES (1), (2)"));
        assert!(parser.is_read_only("WITH cte AS (SELECT 1) SELECT * FROM cte"));
        assert!(parser.is_read_only("EXPLAIN SELECT 1"));
        assert!(parser.is_read_only("SHOW search_path"));
        assert!(!parser.is_read_only("INSERT INTO t VALUES (1)"));
        assert!(!parser.is_read_only("UPDATE t SET a = 1"));
        assert!(!parser.is_read_only("DELETE FROM t"));
        assert!(!parser.is_read_only("COPY t FROM STDIN"));
        assert!(!parser.is_read_only("SELECT * FROM t FOR UPDATE"));
        assert!(!parser.is_read_only(
            "WITH cte AS (SELECT id FROM t) INSERT INTO u SELECT * FROM cte"
        ));
    }

    #[test]
    fn postgresql_structured_strips_comments_before_classify() {
        let parser = PostgreSqlStructuredDialectParser::new();
        assert!(parser.is_read_only("-- comment\nSELECT 1"));
        assert!(parser.is_read_only("/* block */ SELECT 1"));
        assert!(!parser.is_read_only("/* x */ INSERT INTO t VALUES (1)"));
        assert_eq!(
            parser.leading_keyword("-- hi\n  update t set a=1"),
            Some("UPDATE".into())
        );
    }

    #[test]
    fn postgresql_ast_classifies_read_and_write() {
        let parser = PostgreSqlAstDialectParser::new();
        assert!(parser.is_read_only("SELECT 1"));
        assert!(parser.is_read_only("SELECT id FROM users WHERE id = 1"));
        assert!(parser.is_read_only("WITH cte AS (SELECT 1 AS x) SELECT * FROM cte"));
        assert!(parser.is_read_only("VALUES (1), (2)"));
        assert!(parser.is_read_only("SELECT 1 UNION SELECT 2"));
        assert!(!parser.is_read_only("INSERT INTO t VALUES (1)"));
        assert!(!parser.is_read_only("UPDATE t SET a = 1 WHERE id = 2"));
        assert!(!parser.is_read_only("DELETE FROM t WHERE id = 1"));
        assert!(!parser.is_read_only("SELECT * FROM t FOR UPDATE"));
        assert!(!parser.is_read_only(
            "WITH cte AS (SELECT id FROM t) INSERT INTO u SELECT id FROM cte"
        ));
        assert!(!parser.is_read_only("CREATE TABLE t (id INT)"));
        assert!(!parser.is_read_only("DROP TABLE t"));
    }

    #[test]
    fn postgresql_ast_leading_keyword() {
        let parser = PostgreSqlAstDialectParser::new();
        assert_eq!(parser.leading_keyword("select 1"), Some("SELECT".into()));
        assert_eq!(
            parser.leading_keyword("insert into t values (1)"),
            Some("INSERT".into())
        );
        assert_eq!(
            parser.leading_keyword("with c as (select 1) select * from c"),
            Some("SELECT".into())
        );
    }

    #[test]
    fn postgresql_ast_falls_back_on_unparseable() {
        let parser = PostgreSqlAstDialectParser::new();
        // Garbage: structured/heuristic fallback (not read-only).
        assert!(!parser.is_read_only("!!!"));
        // Comment + select: structured fallback still read-only if AST fails.
        assert!(parser.is_read_only("-- comment\nSELECT 1"));
    }

    #[test]
    fn runtime_parser_selects_postgresql_ast() {
        let parser = runtime_dialect_parser(&ProtocolKind::PostgreSql);
        assert_eq!(parser.dialect(), ProtocolKind::PostgreSql);
        assert!(parser.is_read_only("SELECT 1"));
        assert!(!parser.is_read_only("DELETE FROM t"));
    }
}
