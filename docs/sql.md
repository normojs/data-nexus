



```sql
SHOW TABLE STATUS;
```



```sql
-- parse sql "SHOW TABLE STATUS LIKE 'demo1'" err: Error { kind: Parser(ParseError { details: "Parsing error at line 1 column 19. No repair sequences found." }) }

SHOW TABLE STATUS LIKE 'demo1'

```



```
/* comment */
show_tables_stmt -> Box<ShowTablesStmt>:
    'SHOW' opt_show_cmd_type 'TABLES' opt_db opt_wild_or_where
    {
        Box::new(ShowTablesStmt {
           span: $span,
           opt_show_cmd_type: $2,
           opt_db: $4,
           opt_wild_or_where: $5,
        })
    }
;
```





```
| show_tables_stmt    { SqlStmt::ShowTablesStmt($1) }

show_table_status_stmt


#[derive(Debug, Clone)]
pub struct ShowDetailsStmt {
    pub span: Span,
}

```



```
show_create_view_stmt -> Box<ShowCreateViewStmt>:
    'SHOW' 'CREATE' 'VIEW' table_ident
    {
        Box::new(ShowCreateViewStmt {
           span: $span,
           view_name: $4,
        })
    }
;
```



```
| bit_expr 'LIKE' simple_expr
  {
    Expr::LikeExpr {
      span: $span,
      expr: Box::new($1),
      pattern_expr: Box::new($3),
      escape_expr: None,
      is_not: false,
    }
  }
```