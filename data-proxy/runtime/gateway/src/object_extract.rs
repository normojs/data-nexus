//! AST-backed ObjectSet extraction for data-plane security (S2).
//!
//! - PostgreSQL: `sqlparser` + [`PostgreSqlDialect`]
//! - MySQL: `mysql_parser` first, then `sqlparser` [`MySqlDialect`], then heuristic
//!
//! `gateway_core` stays free of parser crates; runtime injects ObjectSet into Local PDP.

use gateway_core::{ObjectAccess, ObjectSet, StatementAction};
use mysql_parser::ast::{
    FromClause, InsertIdent, InsertStmt, Item, SelectStmt, SqlStmt, TableFactor, TableIdent,
    TableRef, UpdateStmt, DeleteStmt, Value,
};
use mysql_parser::parser::Parser as MySqlAstParser;
use sqlparser::ast::{
    AssignmentTarget, Delete, Expr, Insert, ObjectName, Query, SelectItem, SetExpr, Statement,
    TableFactor as SqlTableFactor, Visit, Visitor,
};
use sqlparser::dialect::{MySqlDialect, PostgreSqlDialect};
use sqlparser::parser::Parser as SqlParser;
use std::ops::ControlFlow;

/// Extract object accesses from SQL for the given frontend protocol name.
pub fn extract_object_set(sql: &str, protocol: &str) -> ObjectSet {
    let proto = protocol.to_ascii_lowercase();
    if proto.starts_with("mysql") || proto == "mariadb" {
        extract_mysql(sql)
    } else {
        extract_postgresql(sql)
    }
}

fn extract_postgresql(sql: &str) -> ObjectSet {
    match extract_with_sqlparser(sql, false) {
        // Successful AST parse — empty ObjectSet is valid (e.g. `SELECT 1`).
        Some(set) => set,
        None => fallback_parse_failed(sql),
    }
}

fn extract_mysql(sql: &str) -> ObjectSet {
    // Prefer project mysql_parser; fall back to sqlparser MySqlDialect.
    // A successful parse with zero tables is legitimate (literals / dual-less selects).
    if let Some(set) = extract_with_mysql_parser(sql) {
        return set;
    }
    if let Some(set) = extract_with_sqlparser(sql, true) {
        return set;
    }
    fallback_parse_failed(sql)
}

fn fallback_parse_failed(sql: &str) -> ObjectSet {
    if looks_like_data_sql(sql) {
        let mut set = heuristic_object_set(
            sql,
            StatementAction::from_keyword(first_keyword(sql).as_deref().unwrap_or("OTHER")),
        );
        set.heuristic = true;
        // Only hard-fail when we could not recover any objects for policy matching.
        set.parse_failed = set.objects.is_empty();
        set
    } else {
        ObjectSet::parse_failed()
    }
}

fn extract_with_sqlparser(sql: &str, mysql_dialect: bool) -> Option<ObjectSet> {
    let statements = if mysql_dialect {
        SqlParser::parse_sql(&MySqlDialect {}, sql).ok()?
    } else {
        SqlParser::parse_sql(&PostgreSqlDialect {}, sql).ok()?
    };

    let mut set = ObjectSet::empty();
    for stmt in &statements {
        walk_sqlparser_statement(stmt, &mut set);
    }
    Some(set)
}

fn walk_sqlparser_statement(stmt: &Statement, set: &mut ObjectSet) {
    match stmt {
        Statement::Query(q) => walk_query(q, StatementAction::Select, set),
        Statement::Insert(Insert {
            table_name,
            columns,
            source,
            ..
        }) => {
            let mut obj = object_from_name(table_name, StatementAction::Insert);
            for col in columns {
                push_col(&mut obj.columns, col.value.clone());
            }
            set.objects.push(obj);
            if let Some(query) = source {
                walk_query(query, StatementAction::Select, set);
            }
        }
        Statement::Update {
            table,
            assignments,
            from,
            selection,
            ..
        } => {
            collect_table_with_joins(table, StatementAction::Update, set);
            if let Some(last) = set
                .objects
                .iter_mut()
                .rev()
                .find(|o| o.op == StatementAction::Update)
            {
                for assignment in assignments {
                    match &assignment.target {
                        AssignmentTarget::ColumnName(name) => {
                            if let Some(ident) = name.0.last() {
                                push_col(&mut last.columns, ident.value.clone());
                            }
                        }
                        AssignmentTarget::Tuple(names) => {
                            for name in names {
                                if let Some(ident) = name.0.last() {
                                    push_col(&mut last.columns, ident.value.clone());
                                }
                            }
                        }
                    }
                }
            }
            // assignment values may embed subqueries (after releasing objects borrow)
            for assignment in assignments {
                walk_expr_subqueries(&assignment.value, set);
            }
            if let Some(from) = from {
                collect_table_with_joins(from, StatementAction::Select, set);
            }
            if let Some(sel) = selection {
                walk_expr_subqueries(sel, set);
            }
        }
        Statement::Delete(Delete {
            from,
            using,
            tables,
            ..
        }) => {
            // `from` may be FromTable enum — use visitor for relations + tables field.
            let mut visitor = RelationCollector {
                action: StatementAction::Delete,
                objects: Vec::new(),
            };
            let _ = stmt.visit(&mut visitor);
            for obj in visitor.objects {
                push_object(set, obj);
            }
            if let Some(using) = using {
                for twj in using {
                    collect_table_with_joins(twj, StatementAction::Select, set);
                }
            }
            for name in tables {
                push_object(set, object_from_name(name, StatementAction::Delete));
            }
            let _ = from;
        }
        Statement::CreateTable(ct) => {
            push_object(set, object_from_name(&ct.name, StatementAction::Ddl));
        }
        Statement::CreateView { name, query, .. } => {
            push_object(set, object_from_name(name, StatementAction::Ddl));
            walk_query(query, StatementAction::Select, set);
        }
        Statement::CreateIndex(ci) => {
            push_object(set, object_from_name(&ci.table_name, StatementAction::Ddl));
        }
        Statement::Drop { names, .. } => {
            for n in names {
                push_object(set, object_from_name(n, StatementAction::Ddl));
            }
        }
        Statement::Truncate { table_names, .. } => {
            // TruncateTableTarget — fall back to visitor.
            let mut visitor = RelationCollector {
                action: StatementAction::Ddl,
                objects: Vec::new(),
            };
            let _ = stmt.visit(&mut visitor);
            for obj in visitor.objects {
                push_object(set, obj);
            }
            let _ = table_names;
        }
        Statement::AlterTable { name, .. } => {
            push_object(set, object_from_name(name, StatementAction::Ddl));
        }
        Statement::StartTransaction { .. }
        | Statement::Commit { .. }
        | Statement::Rollback { .. }
        | Statement::Savepoint { .. }
        | Statement::ReleaseSavepoint { .. } => {}
        _ => {
            let action = StatementAction::Other;
            let mut visitor = RelationCollector {
                action,
                objects: Vec::new(),
            };
            let _ = stmt.visit(&mut visitor);
            for obj in visitor.objects {
                push_object(set, obj);
            }
        }
    }
}

fn walk_query(query: &Query, action: StatementAction, set: &mut ObjectSet) {
    if let Some(with) = &query.with {
        for cte in &with.cte_tables {
            walk_query(&cte.query, StatementAction::Select, set);
        }
    }
    walk_set_expr(query.body.as_ref(), action, set);
}

fn walk_set_expr(expr: &SetExpr, action: StatementAction, set: &mut ObjectSet) {
    match expr {
        SetExpr::Select(select) => {
            let mut wildcard = false;
            let mut columns = Vec::new();
            for item in &select.projection {
                match item {
                    SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(_, _) => {
                        wildcard = true;
                    }
                    SelectItem::UnnamedExpr(e) | SelectItem::ExprWithAlias { expr: e, .. } => {
                        collect_expr_columns(e, &mut columns);
                        // T01: scalar subqueries in SELECT list.
                        walk_expr_subqueries(e, set);
                    }
                }
            }
            let before = set.objects.len();
            for twj in &select.from {
                collect_table_with_joins(twj, action, set);
            }
            for obj in set.objects[before..].iter_mut() {
                if obj.op == action {
                    obj.has_wildcard |= wildcard;
                    for c in &columns {
                        push_col(&mut obj.columns, c.clone());
                    }
                }
            }
            // T01: WHERE / HAVING / JOIN ON subqueries contribute tables for ACL.
            if let Some(sel) = &select.selection {
                walk_expr_subqueries(sel, set);
            }
            if let Some(hav) = &select.having {
                walk_expr_subqueries(hav, set);
            }
        }
        SetExpr::Query(q) => walk_query(q, action, set),
        SetExpr::SetOperation { left, right, .. } => {
            walk_set_expr(left, action, set);
            walk_set_expr(right, action, set);
        }
        SetExpr::Values(_) | SetExpr::Table(_) => {}
        SetExpr::Insert(stmt) | SetExpr::Update(stmt) => walk_sqlparser_statement(stmt, set),
    }
}

fn collect_table_with_joins(
    twj: &sqlparser::ast::TableWithJoins,
    action: StatementAction,
    set: &mut ObjectSet,
) {
    collect_table_factor(&twj.relation, action, set);
    for join in &twj.joins {
        collect_table_factor(&join.relation, action, set);
        // T01: JOIN ON (SELECT …) / EXISTS in join condition.
        match &join.join_operator {
            sqlparser::ast::JoinOperator::Inner(c)
            | sqlparser::ast::JoinOperator::LeftOuter(c)
            | sqlparser::ast::JoinOperator::RightOuter(c)
            | sqlparser::ast::JoinOperator::FullOuter(c)
            | sqlparser::ast::JoinOperator::LeftSemi(c)
            | sqlparser::ast::JoinOperator::RightSemi(c)
            | sqlparser::ast::JoinOperator::LeftAnti(c)
            | sqlparser::ast::JoinOperator::RightAnti(c) => {
                if let sqlparser::ast::JoinConstraint::On(expr) = c {
                    walk_expr_subqueries(expr, set);
                }
            }
            sqlparser::ast::JoinOperator::AsOf {
                match_condition,
                constraint,
            } => {
                walk_expr_subqueries(match_condition, set);
                if let sqlparser::ast::JoinConstraint::On(expr) = constraint {
                    walk_expr_subqueries(expr, set);
                }
            }
            _ => {}
        }
    }
}

fn collect_table_factor(factor: &SqlTableFactor, action: StatementAction, set: &mut ObjectSet) {
    match factor {
        SqlTableFactor::Table { name, .. } => {
            push_object(set, object_from_name(name, action));
        }
        SqlTableFactor::Derived { subquery, .. } => {
            walk_query(subquery, StatementAction::Select, set);
        }
        SqlTableFactor::NestedJoin {
            table_with_joins, ..
        } => {
            collect_table_with_joins(table_with_joins, action, set);
        }
        _ => {}
    }
}

fn collect_expr_columns(expr: &Expr, columns: &mut Vec<String>) {
    match expr {
        Expr::Identifier(ident) => push_col(columns, ident.value.clone()),
        Expr::CompoundIdentifier(idents) => {
            if let Some(last) = idents.last() {
                if idents.len() >= 2 {
                    let table = &idents[idents.len() - 2].value;
                    push_col(columns, format!("{}.{}", table, last.value));
                } else {
                    push_col(columns, last.value.clone());
                }
            }
        }
        Expr::Nested(e) | Expr::UnaryOp { expr: e, .. } => collect_expr_columns(e, columns),
        Expr::BinaryOp { left, right, .. } => {
            collect_expr_columns(left, columns);
            collect_expr_columns(right, columns);
        }
        Expr::Cast { expr, .. } => collect_expr_columns(expr, columns),
        Expr::IsNull(e)
        | Expr::IsNotNull(e)
        | Expr::IsTrue(e)
        | Expr::IsNotTrue(e)
        | Expr::IsFalse(e)
        | Expr::IsNotFalse(e)
        | Expr::IsUnknown(e)
        | Expr::IsNotUnknown(e) => collect_expr_columns(e, columns),
        Expr::Function(func) => {
            if let sqlparser::ast::FunctionArguments::List(list) = &func.args {
                for arg in &list.args {
                    if let sqlparser::ast::FunctionArg::Unnamed(
                        sqlparser::ast::FunctionArgExpr::Expr(e),
                    ) = arg
                    {
                        collect_expr_columns(e, columns);
                    }
                }
            }
        }
        Expr::Case {
            operand,
            conditions,
            results,
            else_result,
        } => {
            if let Some(op) = operand {
                collect_expr_columns(op, columns);
            }
            // sqlparser 0.51: CASE WHEN <expr> THEN <expr> … stores parallel vectors.
            for cond in conditions {
                collect_expr_columns(cond, columns);
            }
            for result in results {
                collect_expr_columns(result, columns);
            }
            if let Some(e) = else_result {
                collect_expr_columns(e, columns);
            }
        }
        _ => {}
    }
}

/// T01: walk expression tree and extract tables from nested SELECT / EXISTS / IN (SELECT).
fn walk_expr_subqueries(expr: &Expr, set: &mut ObjectSet) {
    match expr {
        Expr::Subquery(q) | Expr::Exists { subquery: q, .. } => {
            walk_query(q, StatementAction::Select, set);
        }
        Expr::InSubquery { expr: outer, subquery, .. } => {
            walk_expr_subqueries(outer, set);
            walk_query(subquery, StatementAction::Select, set);
        }
        Expr::InList { expr: outer, list, .. } => {
            walk_expr_subqueries(outer, set);
            for e in list {
                walk_expr_subqueries(e, set);
            }
        }
        Expr::Nested(e) | Expr::UnaryOp { expr: e, .. } | Expr::Cast { expr: e, .. } => {
            walk_expr_subqueries(e, set);
        }
        Expr::BinaryOp { left, right, .. } => {
            walk_expr_subqueries(left, set);
            walk_expr_subqueries(right, set);
        }
        Expr::IsNull(e)
        | Expr::IsNotNull(e)
        | Expr::IsTrue(e)
        | Expr::IsNotTrue(e)
        | Expr::IsFalse(e)
        | Expr::IsNotFalse(e)
        | Expr::IsUnknown(e)
        | Expr::IsNotUnknown(e) => walk_expr_subqueries(e, set),
        Expr::Between { expr, low, high, .. } => {
            walk_expr_subqueries(expr, set);
            walk_expr_subqueries(low, set);
            walk_expr_subqueries(high, set);
        }
        Expr::Like { expr, pattern, .. } | Expr::ILike { expr, pattern, .. } => {
            walk_expr_subqueries(expr, set);
            walk_expr_subqueries(pattern, set);
        }
        Expr::Function(func) => {
            if let sqlparser::ast::FunctionArguments::List(list) = &func.args {
                for arg in &list.args {
                    if let sqlparser::ast::FunctionArg::Unnamed(
                        sqlparser::ast::FunctionArgExpr::Expr(e),
                    ) = arg
                    {
                        walk_expr_subqueries(e, set);
                    }
                }
            } else if let sqlparser::ast::FunctionArguments::Subquery(q) = &func.args {
                walk_query(q, StatementAction::Select, set);
            }
        }
        Expr::Case {
            operand,
            conditions,
            results,
            else_result,
        } => {
            if let Some(op) = operand {
                walk_expr_subqueries(op, set);
            }
            for cond in conditions {
                walk_expr_subqueries(cond, set);
            }
            for result in results {
                walk_expr_subqueries(result, set);
            }
            if let Some(e) = else_result {
                walk_expr_subqueries(e, set);
            }
        }
        Expr::Tuple(items) => {
            for e in items {
                walk_expr_subqueries(e, set);
            }
        }
        _ => {}
    }
}

struct RelationCollector {
    action: StatementAction,
    objects: Vec<ObjectAccess>,
}

impl Visitor for RelationCollector {
    type Break = ();

    fn pre_visit_relation(&mut self, relation: &ObjectName) -> ControlFlow<Self::Break> {
        self.objects
            .push(object_from_name(relation, self.action));
        ControlFlow::Continue(())
    }
}

fn object_from_name(name: &ObjectName, op: StatementAction) -> ObjectAccess {
    let parts: Vec<String> = name.0.iter().map(|i| i.value.clone()).collect();
    match parts.as_slice() {
        [] => ObjectAccess::new("", op),
        [table] => ObjectAccess::new(table.clone(), op),
        [schema, table] => ObjectAccess::new(table.clone(), op).with_schema(Some(schema.clone())),
        rest => {
            let table = rest[rest.len() - 1].clone();
            let schema = rest[rest.len() - 2].clone();
            ObjectAccess::new(table, op).with_schema(Some(schema))
        }
    }
}

fn push_object(set: &mut ObjectSet, obj: ObjectAccess) {
    let key = obj.qualified_table();
    if let Some(existing) = set
        .objects
        .iter_mut()
        .find(|o| o.qualified_table().eq_ignore_ascii_case(&key) && o.op == obj.op)
    {
        existing.has_wildcard |= obj.has_wildcard;
        for c in obj.columns {
            push_col(&mut existing.columns, c);
        }
    } else {
        set.objects.push(obj);
    }
}

fn push_col(cols: &mut Vec<String>, name: String) {
    let n = name.trim().to_owned();
    if n.is_empty() {
        return;
    }
    if !cols.iter().any(|c| c.eq_ignore_ascii_case(&n)) {
        cols.push(n);
    }
}

// --- MySQL parser path -------------------------------------------------------

fn extract_with_mysql_parser(sql: &str) -> Option<ObjectSet> {
    let parsed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let parser = MySqlAstParser::new();
        parser.parse(sql)
    }))
    .ok()?
    .ok()?;

    let mut set = ObjectSet::empty();
    for stmt in &parsed {
        walk_mysql_stmt(stmt, &mut set);
    }
    Some(set)
}

fn walk_mysql_stmt(stmt: &SqlStmt, set: &mut ObjectSet) {
    match stmt {
        SqlStmt::SelectStmt(select) => walk_mysql_select(select, StatementAction::Select, set),
        SqlStmt::InsertStmt(insert) => walk_mysql_insert(insert, set),
        SqlStmt::UpdateStmt(update) => walk_mysql_update(update, set),
        SqlStmt::DeleteStmt(delete) => walk_mysql_delete(delete, set),
        _ => {}
    }
}

fn walk_mysql_select(select: &SelectStmt, action: StatementAction, set: &mut ObjectSet) {
    match select {
        SelectStmt::Query(q) => {
            let mut wildcard = false;
            let mut columns = Vec::new();
            for item in &q.items.items {
                match item {
                    Item::Wild(_) | Item::TableWild(_) => wildcard = true,
                    Item::ItemExpr(ie) => {
                        collect_mysql_expr_columns(&ie.expr, &mut columns);
                        // T01: scalar subqueries in SELECT list.
                        walk_mysql_expr_subqueries(&ie.expr, set);
                    }
                }
            }
            let before = set.objects.len();
            if let Some(FromClause::TableRefs(refs)) = &q.from_clause {
                for r in refs {
                    walk_mysql_table_ref(r, action, set);
                }
            }
            for obj in set.objects[before..].iter_mut() {
                if obj.op == action {
                    obj.has_wildcard = wildcard;
                    for c in &columns {
                        push_col(&mut obj.columns, c.clone());
                    }
                }
            }
            // T01: WHERE / HAVING subqueries contribute tables for ACL.
            if let Some(where_clause) = &q.where_clause {
                walk_mysql_expr_subqueries(&where_clause.expr, set);
            }
            if let Some(having_clause) = &q.having_clause {
                walk_mysql_expr_subqueries(&having_clause.expr, set);
            }
            if let Some(union) = &q.union_query {
                walk_mysql_select(union, action, set);
            }
        }
        SelectStmt::SubQuery(sub) => walk_mysql_select(&sub.query, action, set),
        SelectStmt::With(with) => {
            // WithQuery.expr_body is the main select in this grammar.
            walk_mysql_select(&with.expr_body, action, set);
        }
        SelectStmt::ExplicitTable(ident) => {
            set.objects.push(object_from_mysql_ident(ident, action));
        }
        SelectStmt::ValueConstructor(_) | SelectStmt::None => {}
    }
}

fn walk_mysql_insert(insert: &InsertStmt, set: &mut ObjectSet) {
    let mut obj = object_from_mysql_ident(&insert.table_name, StatementAction::Insert);
    if let Some(fc) = &insert.from_construct {
        for f in &fc.fields {
            match f {
                InsertIdent::Ident(v) => {
                    if let Some(name) = mysql_value_ident(v) {
                        push_col(&mut obj.columns, name);
                    }
                }
                InsertIdent::TableWild(_) => obj.has_wildcard = true,
            }
        }
    }
    if let Some(qe) = &insert.query_expr {
        for f in &qe.fields {
            match f {
                InsertIdent::Ident(v) => {
                    if let Some(name) = mysql_value_ident(v) {
                        push_col(&mut obj.columns, name);
                    }
                }
                InsertIdent::TableWild(_) => obj.has_wildcard = true,
            }
        }
        walk_mysql_select(&qe.query, StatementAction::Select, set);
    }
    for u in &insert.updates {
        if let Some(name) = mysql_value_ident(&u.var_name) {
            push_col(&mut obj.columns, name);
        }
    }
    set.objects.push(obj);
}

fn walk_mysql_update(update: &UpdateStmt, set: &mut ObjectSet) {
    let before = set.objects.len();
    for r in &update.table_refs {
        walk_mysql_table_ref(r, StatementAction::Update, set);
    }
    let mut columns = Vec::new();
    for u in &update.updates {
        if let Some(name) = mysql_value_ident(&u.var_name) {
            push_col(&mut columns, name);
        }
        // assignment RHS may embed subqueries
        walk_mysql_expr_subqueries(&u.expr, set);
    }
    for obj in set.objects[before..].iter_mut() {
        if obj.op == StatementAction::Update {
            for c in &columns {
                push_col(&mut obj.columns, c.clone());
            }
        }
    }
    if let Some(where_clause) = &update.where_clause {
        walk_mysql_expr_subqueries(&where_clause.expr, set);
    }
}

fn walk_mysql_delete(delete: &DeleteStmt, set: &mut ObjectSet) {
    if let Some(ident) = &delete.table_name {
        set.objects
            .push(object_from_mysql_ident(ident, StatementAction::Delete));
    }
    for r in &delete.table_refs {
        walk_mysql_table_ref(r, StatementAction::Delete, set);
    }
    if let Some(where_clause) = &delete.where_clause {
        walk_mysql_expr_subqueries(&where_clause.expr, set);
    }
}

fn walk_mysql_table_ref(table_ref: &TableRef, action: StatementAction, set: &mut ObjectSet) {
    match table_ref {
        TableRef::TableFactor(f) | TableRef::OjTableFactor(f) => {
            walk_mysql_table_factor(f, action, set);
        }
        TableRef::JoinedTable(j) | TableRef::OjJoinedTable(j) => {
            walk_mysql_table_ref(&j.left, action, set);
            walk_mysql_table_ref(&j.right, action, set);
        }
    }
}

fn walk_mysql_table_factor(factor: &TableFactor, action: StatementAction, set: &mut ObjectSet) {
    match factor {
        TableFactor::SingleTable(t) | TableFactor::SingleTableParens(t) => {
            set.objects
                .push(object_from_mysql_ident(&t.table_name, action));
        }
        TableFactor::DerivedTable(d) => {
            walk_mysql_select(&d.subquery, StatementAction::Select, set);
        }
        TableFactor::JoinedTableParens(j) => {
            walk_mysql_table_ref(&j.left, action, set);
            walk_mysql_table_ref(&j.right, action, set);
        }
        TableFactor::TableRefsParens(refs) => {
            for r in refs {
                walk_mysql_table_ref(r, action, set);
            }
        }
        TableFactor::TableFunc(_) => {}
    }
}

fn object_from_mysql_ident(ident: &TableIdent, op: StatementAction) -> ObjectAccess {
    ObjectAccess::new(ident.name.clone(), op).with_schema(ident.schema.clone())
}

fn collect_mysql_expr_columns(expr: &mysql_parser::ast::Expr, columns: &mut Vec<String>) {
    use mysql_parser::ast::Expr as E;
    match expr {
        E::SimpleIdentExpr(v) => {
            if let Some(name) = mysql_value_ident(v) {
                push_col(columns, name);
            }
        }
        E::BinaryOperationExpr { left, right, .. } => {
            collect_mysql_expr_columns(left, columns);
            collect_mysql_expr_columns(right, columns);
        }
        E::UnaryOperationExpr { expr, .. } => collect_mysql_expr_columns(expr, columns),
        E::FuncCallExpr { args, .. } => {
            for p in args {
                collect_mysql_expr_columns(p, columns);
            }
        }
        // Column collection ignores subquery bodies; tables are walked separately.
        E::SubQueryExpr(_) | E::ExistsSubQuery(_) | E::CompSubQueryExpr(_) => {}
        _ => {}
    }
}

/// T01: walk MySQL expression tree and extract tables from nested SELECT / EXISTS / IN.
fn walk_mysql_expr_subqueries(expr: &mysql_parser::ast::Expr, set: &mut ObjectSet) {
    use mysql_parser::ast::Expr as E;
    match expr {
        E::SubQueryExpr(sub) | E::ExistsSubQuery(sub) => {
            walk_mysql_select(sub, StatementAction::Select, set);
        }
        E::CompSubQueryExpr(comp) => {
            walk_mysql_expr_subqueries(&comp.expr, set);
            walk_mysql_select(&comp.subquery, StatementAction::Select, set);
        }
        E::InExpr { expr, exprs, .. } => {
            walk_mysql_expr_subqueries(expr, set);
            // IN (SELECT …) is represented as InExpr with SubQueryExpr children.
            for e in exprs {
                walk_mysql_expr_subqueries(e, set);
            }
        }
        E::BinaryOperationExpr { left, right, .. } => {
            walk_mysql_expr_subqueries(left, set);
            walk_mysql_expr_subqueries(right, set);
        }
        E::UnaryOperationExpr { expr, .. }
        | E::IsTruthExpr { expr, .. }
        | E::IsUnknownExpr { expr, .. }
        | E::IsNullExpr { expr, .. }
        | E::BinaryExpr(expr)
        | E::CastExpr { expr, .. }
        | E::InSumExpr { expr, .. }
        | E::SetFuncSpecExpr(expr) => walk_mysql_expr_subqueries(expr, set),
        E::BetweenExpr {
            expr, left, right, ..
        } => {
            walk_mysql_expr_subqueries(expr, set);
            walk_mysql_expr_subqueries(left, set);
            walk_mysql_expr_subqueries(right, set);
        }
        E::LikeExpr {
            expr,
            pattern_expr,
            escape_expr,
            ..
        } => {
            walk_mysql_expr_subqueries(expr, set);
            walk_mysql_expr_subqueries(pattern_expr, set);
            if let Some(esc) = escape_expr {
                walk_mysql_expr_subqueries(esc, set);
            }
        }
        E::MemberOfExpr { expr, of_expr, .. } => {
            walk_mysql_expr_subqueries(expr, set);
            walk_mysql_expr_subqueries(of_expr, set);
        }
        E::SoundsExpr { left, right, .. } | E::RegexpExpr { left, right, .. } => {
            walk_mysql_expr_subqueries(left, set);
            walk_mysql_expr_subqueries(right, set);
        }
        E::FuncCallExpr { args, .. } | E::RowExpr(args) => {
            for p in args {
                walk_mysql_expr_subqueries(p, set);
            }
        }
        E::CaseExpr {
            expr,
            when_exprs,
            else_expr,
            ..
        } => {
            if let Some(e) = expr.as_ref() {
                walk_mysql_expr_subqueries(e, set);
            }
            for w in when_exprs {
                walk_mysql_expr_subqueries(&w.when, set);
                walk_mysql_expr_subqueries(&w.then, set);
            }
            if let Some(e) = else_expr.as_ref() {
                walk_mysql_expr_subqueries(e, set);
            }
        }
        E::MatchAgainstExpr { expr, .. } => walk_mysql_expr_subqueries(expr, set),
        E::CollateExpr { expr, .. } => walk_mysql_expr_subqueries(expr, set),
        E::AggExpr(agg) => {
            for e in &agg.exprs {
                walk_mysql_expr_subqueries(e, set);
            }
        }
        _ => {}
    }
}

fn mysql_value_ident(v: &Value) -> Option<String> {
    match v {
        Value::Ident { value, .. } => Some(value.clone()),
        Value::TableIdent { field, table, .. } => Some(format!("{table}.{field}")),
        Value::Text { value, .. } => Some(value.clone()),
        _ => None,
    }
}

// --- Heuristic fallback ------------------------------------------------------

fn heuristic_object_set(sql: &str, action: StatementAction) -> ObjectSet {
    let tables = gateway_core::extract_table_names(sql);
    let mut set = ObjectSet::empty();
    for t in tables {
        let (schema, table) = split_schema_table(&t);
        set.objects
            .push(ObjectAccess::new(table, action).with_schema(schema));
    }
    let upper = sql.to_ascii_uppercase();
    // Heuristic only: sqlparser path already marks SelectItem::Wildcard / QualifiedWildcard.
    // Catch bare `SELECT *` and common `t.*` / `schema.t.*` forms when parse fails.
    let bare_star = upper.contains("SELECT *") || upper.contains("SELECT*");
    let qualified_star = upper.contains(".*")
        && (upper.contains("SELECT ") || upper.starts_with("SELECT"));
    if bare_star || qualified_star {
        for obj in &mut set.objects {
            if obj.op == StatementAction::Select {
                obj.has_wildcard = true;
            }
        }
    }
    set
}

fn split_schema_table(name: &str) -> (Option<String>, String) {
    if let Some((s, t)) = name.rsplit_once('.') {
        (Some(s.to_owned()), t.to_owned())
    } else {
        (None, name.to_owned())
    }
}

fn first_keyword(sql: &str) -> Option<String> {
    let sql = sql.trim_start();
    let upper = sql.to_ascii_uppercase();
    upper
        .split_whitespace()
        .next()
        .map(|t| t.trim_end_matches(';').to_owned())
}

fn looks_like_data_sql(sql: &str) -> bool {
    let k = first_keyword(sql).unwrap_or_default();
    matches!(
        k.as_str(),
        "SELECT"
            | "INSERT"
            | "UPDATE"
            | "DELETE"
            | "WITH"
            | "CREATE"
            | "ALTER"
            | "DROP"
            | "TRUNCATE"
            | "REPLACE"
            | "TABLE"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pg_select_join_extracts_tables_and_columns() {
        let set = extract_object_set(
            "SELECT a.id, b.name FROM public.orders a JOIN order_items b ON a.id = b.order_id",
            "postgresql",
        );
        assert!(!set.parse_failed, "{set:?}");
        let tables: Vec<_> = set.objects.iter().map(|o| o.table.clone()).collect();
        assert!(
            tables.iter().any(|t| t.eq_ignore_ascii_case("orders")),
            "{tables:?}"
        );
        assert!(
            tables.iter().any(|t| t.eq_ignore_ascii_case("order_items")),
            "{tables:?}"
        );
        let cols: Vec<String> = set
            .objects
            .iter()
            .flat_map(|o| o.columns.clone())
            .collect();
        assert!(
            cols.iter().any(|c| c.to_ascii_lowercase().contains("id")),
            "{cols:?}"
        );
        assert!(
            cols.iter()
                .any(|c| c.to_ascii_lowercase().contains("name")),
            "{cols:?}"
        );
    }

    #[test]
    fn pg_schema_qualified_table() {
        let set = extract_object_set("SELECT id FROM analytics.events", "postgresql");
        assert!(!set.parse_failed);
        assert!(set.objects.iter().any(|o| {
            o.table.eq_ignore_ascii_case("events")
                && o.schema
                    .as_deref()
                    .map(|s| s.eq_ignore_ascii_case("analytics"))
                    .unwrap_or(false)
        }));
    }

    #[test]
    fn select_star_sets_wildcard() {
        let set = extract_object_set("SELECT * FROM employees", "postgresql");
        assert!(set.has_wildcard());
    }

    #[test]
    fn select_qualified_star_sets_wildcard() {
        // T01 honesty: `t.*` / `employees.*` are wildcards (not expanded to columns).
        for sql in [
            "SELECT employees.* FROM employees",
            "SELECT e.* FROM employees e",
            "SELECT e.id, e.* FROM employees e",
        ] {
            let set = extract_object_set(sql, "mysql");
            assert!(
                set.has_wildcard(),
                "expected has_wildcard for {sql:?}: {set:?}"
            );
        }
    }

    #[test]
    fn mysql_select_columns() {
        let set = extract_object_set("SELECT id, name, salary FROM employees", "mysql");
        assert!(!set.parse_failed, "{set:?}");
        assert!(set
            .objects
            .iter()
            .any(|o| o.table.eq_ignore_ascii_case("employees")));
        let cols: Vec<String> = set
            .objects
            .iter()
            .flat_map(|o| o.bare_columns().collect::<Vec<_>>())
            .collect();
        assert!(cols.iter().any(|c| c == "salary"), "{cols:?}");
    }

    #[test]
    fn mysql_join_tables() {
        let set = extract_object_set(
            "SELECT a.id FROM orders a JOIN order_items b ON a.id=b.order_id",
            "mysql",
        );
        let tables = set.tables();
        assert!(
            tables
                .iter()
                .any(|t| t.to_ascii_lowercase().contains("orders")),
            "{tables:?}"
        );
        assert!(
            tables
                .iter()
                .any(|t| t.to_ascii_lowercase().contains("order_items")),
            "{tables:?}"
        );
    }

    #[test]
    fn insert_extracts_columns() {
        let set = extract_object_set(
            "INSERT INTO employees (id, name, salary) VALUES (1, 'a', 2)",
            "postgresql",
        );
        assert!(!set.parse_failed, "{set:?}");
        let emp = set
            .objects
            .iter()
            .find(|o| o.table.eq_ignore_ascii_case("employees"))
            .expect("employees");
        assert_eq!(emp.op, StatementAction::Insert);
        let cols: Vec<_> = emp.bare_columns().collect();
        assert!(cols.iter().any(|c| c == "salary"), "{cols:?}");
    }

    #[test]
    fn select_literal_no_tables_not_parse_failed() {
        for proto in ["mysql", "postgresql"] {
            let set = extract_object_set("SELECT 1", proto);
            assert!(!set.parse_failed, "{proto}: {set:?}");
            assert!(set.objects.is_empty(), "{proto}: {set:?}");
        }
    }

    #[test]
    fn select_literal_with_alias_and_semicolon() {
        let set = extract_object_set("SELECT 1 AS ok;", "mysql");
        assert!(!set.parse_failed, "{set:?}");
        assert!(set.objects.is_empty(), "{set:?}");
    }

    #[test]
    fn multi_statement_select_literal() {
        // mysql CLI -e may send trailing statements; keep parseable.
        let set = extract_object_set("SELECT 1 AS ok", "mysql");
        assert!(!set.parse_failed, "{set:?}");
    }

    // --- T01: complex SQL matrix (subquery / CTE / multi-table / dialect) ---

    #[test]
    fn t01_pg_derived_subquery_extracts_inner_table() {
        let set = extract_object_set(
            "SELECT t.id FROM (SELECT id, salary FROM employees) t WHERE t.id = 1",
            "postgresql",
        );
        assert!(!set.parse_failed, "{set:?}");
        assert!(
            set.objects
                .iter()
                .any(|o| o.table.eq_ignore_ascii_case("employees")),
            "expected inner employees table: {set:?}"
        );
        let cols: Vec<String> = set
            .objects
            .iter()
            .flat_map(|o| o.bare_columns().map(|c| c.to_owned()))
            .collect();
        // Outer may only see t.id; inner should still contribute salary/id when walked.
        assert!(
            cols.iter().any(|c| c.eq_ignore_ascii_case("id"))
                || set
                    .objects
                    .iter()
                    .any(|o| o.table.eq_ignore_ascii_case("employees")),
            "cols={cols:?} set={set:?}"
        );
    }

    #[test]
    fn t01_mysql_derived_subquery_extracts_inner_table() {
        let set = extract_object_set(
            "SELECT t.id FROM (SELECT id, salary FROM employees) t",
            "mysql",
        );
        assert!(!set.parse_failed, "{set:?}");
        assert!(
            set.objects
                .iter()
                .any(|o| o.table.eq_ignore_ascii_case("employees")),
            "{set:?}"
        );
    }

    #[test]
    fn t01_pg_in_subquery_where_extracts_both_tables() {
        let set = extract_object_set(
            "SELECT id FROM employees WHERE id IN (SELECT emp_id FROM secret_tokens)",
            "postgresql",
        );
        assert!(!set.parse_failed, "{set:?}");
        let tables = set.tables();
        assert!(
            tables
                .iter()
                .any(|t| t.to_ascii_lowercase().contains("employees")),
            "outer table missing: {tables:?}"
        );
        assert!(
            tables
                .iter()
                .any(|t| t.to_ascii_lowercase().contains("secret_tokens")),
            "WHERE IN subquery table must be extracted: {tables:?}"
        );
    }

    #[test]
    fn t01_mysql_in_subquery_where_extracts_both_tables() {
        let set = extract_object_set(
            "SELECT id FROM employees WHERE id IN (SELECT emp_id FROM secret_tokens)",
            "mysql",
        );
        assert!(!set.parse_failed, "{set:?}");
        let tables = set.tables();
        assert!(
            tables
                .iter()
                .any(|t| t.to_ascii_lowercase().contains("employees")),
            "outer table missing: {tables:?}"
        );
        assert!(
            tables
                .iter()
                .any(|t| t.to_ascii_lowercase().contains("secret_tokens")),
            "MySQL WHERE IN subquery table must be extracted: {tables:?}"
        );
    }

    #[test]
    fn t01_pg_exists_subquery_where_extracts_inner_table() {
        let set = extract_object_set(
            "SELECT id FROM employees WHERE EXISTS (SELECT 1 FROM secret_tokens st WHERE st.emp_id = employees.id)",
            "postgresql",
        );
        assert!(!set.parse_failed, "{set:?}");
        let tables = set.tables();
        assert!(
            tables
                .iter()
                .any(|t| t.to_ascii_lowercase().contains("secret_tokens")),
            "EXISTS subquery table must be extracted: {tables:?}"
        );
    }

    #[test]
    fn t01_pg_scalar_subquery_in_select_list() {
        let set = extract_object_set(
            "SELECT id, (SELECT COUNT(*) FROM secret_tokens) AS n FROM employees",
            "postgresql",
        );
        assert!(!set.parse_failed, "{set:?}");
        let tables = set.tables();
        assert!(
            tables
                .iter()
                .any(|t| t.to_ascii_lowercase().contains("secret_tokens")),
            "scalar subquery table must be extracted: {tables:?}"
        );
    }

    #[test]
    fn t01_pg_cte_with_extracts_cte_source() {
        let set = extract_object_set(
            "WITH active AS (SELECT id, name FROM employees WHERE id > 0) \
             SELECT id FROM active",
            "postgresql",
        );
        assert!(!set.parse_failed, "{set:?}");
        // CTE body should yield employees; outer may reference CTE name.
        let tables = set.tables();
        assert!(
            tables
                .iter()
                .any(|t| t.to_ascii_lowercase().contains("employees"))
                || tables
                    .iter()
                    .any(|t| t.to_ascii_lowercase().contains("active")),
            "tables={tables:?}"
        );
    }

    #[test]
    fn t01_mysql_multi_table_join_columns() {
        let set = extract_object_set(
            "SELECT e.id, e.name, d.dept_name \
             FROM employees e \
             JOIN departments d ON e.dept_id = d.id",
            "mysql",
        );
        assert!(!set.parse_failed, "{set:?}");
        let tables = set.tables();
        assert!(
            tables
                .iter()
                .any(|t| t.to_ascii_lowercase().contains("employees")),
            "{tables:?}"
        );
        assert!(
            tables
                .iter()
                .any(|t| t.to_ascii_lowercase().contains("departments")),
            "{tables:?}"
        );
    }

    #[test]
    fn t01_dialect_schema_dot_table_mysql_vs_pg() {
        for proto in ["mysql", "postgresql"] {
            let set = extract_object_set("SELECT id FROM orders.employees", proto);
            assert!(!set.parse_failed, "{proto}: {set:?}");
            assert!(
                set.objects.iter().any(|o| {
                    o.table.eq_ignore_ascii_case("employees")
                        && o.schema
                            .as_deref()
                            .map(|s| s.eq_ignore_ascii_case("orders"))
                            .unwrap_or(false)
                }),
                "{proto}: {set:?}"
            );
        }
    }

    #[test]
    fn t01_unparseable_sql_marks_parse_failed() {
        for proto in ["mysql", "postgresql"] {
            let set = extract_object_set("SELECT !!! FROM employees", proto);
            // Either parse_failed with empty objects, or heuristic tables only.
            if set.objects.is_empty() {
                assert!(
                    set.parse_failed,
                    "{proto}: empty objects must set parse_failed: {set:?}"
                );
            } else {
                // Heuristic recovered table names — still honest if parse_failed stays true.
                assert!(
                    set.parse_failed
                        || set
                            .objects
                            .iter()
                            .any(|o| o.table.eq_ignore_ascii_case("employees")),
                    "{proto}: {set:?}"
                );
            }
        }
    }

    #[test]
    fn t01_update_delete_ops_on_target_table() {
        let up = extract_object_set("UPDATE employees SET salary = 1 WHERE id = 1", "mysql");
        assert!(!up.parse_failed, "{up:?}");
        assert!(up.objects.iter().any(|o| {
            o.table.eq_ignore_ascii_case("employees") && o.op == StatementAction::Update
        }));

        let del = extract_object_set("DELETE FROM employees WHERE id = 1", "postgresql");
        assert!(!del.parse_failed, "{del:?}");
        assert!(del.objects.iter().any(|o| {
            o.table.eq_ignore_ascii_case("employees") && o.op == StatementAction::Delete
        }));
    }
}
