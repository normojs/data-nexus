use crate::{DialectParser, GatewayError, GatewayResult, ProtocolKind, RoutePlan};

/// Dialect-aware entry for sharding rewrite planning.
///
/// Full MySQL-parser-based rewrite remains in the strategy crate. This trait is
/// the protocol-neutral seam so core routing can reject unsupported dialects
/// without importing mysql_parser.
pub trait ShardingPlanner: Send + Sync {
    fn dialect(&self) -> ProtocolKind;

    /// Plan a rewrite for `sql`. Returning `RoutePlan::Reject` means the
    /// statement is unsupported for sharding under this dialect.
    fn plan_rewrite(
        &self,
        sql: &str,
        dialect: &dyn DialectParser,
    ) -> GatewayResult<RoutePlan>;
}

/// Default stub used until dialect-specific rewrite is fully decoupled.
///
/// Always rejects so callers fail fast instead of silently using a MySQL-only path.
#[derive(Debug, Clone)]
pub struct UnsupportedShardingPlanner {
    dialect: ProtocolKind,
}

impl UnsupportedShardingPlanner {
    pub fn new(dialect: ProtocolKind) -> Self {
        Self { dialect }
    }
}

impl ShardingPlanner for UnsupportedShardingPlanner {
    fn dialect(&self) -> ProtocolKind {
        self.dialect.clone()
    }

    fn plan_rewrite(
        &self,
        sql: &str,
        dialect: &dyn DialectParser,
    ) -> GatewayResult<RoutePlan> {
        if dialect.dialect() != self.dialect {
            return Err(GatewayError::Configuration(format!(
                "sharding planner dialect {:?} does not match request dialect {:?}",
                self.dialect,
                dialect.dialect()
            )));
        }
        Ok(RoutePlan::reject(format!(
            "sharding rewrite is not implemented for {:?} (sql prefix: {:?})",
            self.dialect,
            sql.chars().take(32).collect::<String>()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HeuristicDialectParser;

    #[test]
    fn stub_rejects_mysql_sharding() {
        let planner = UnsupportedShardingPlanner::new(ProtocolKind::MySql);
        let dialect = HeuristicDialectParser::mysql();
        let plan = planner.plan_rewrite("select 1 from t", &dialect).unwrap();
        assert!(plan.is_reject());
    }

    #[test]
    fn stub_errors_on_dialect_mismatch() {
        let planner = UnsupportedShardingPlanner::new(ProtocolKind::MySql);
        let dialect = HeuristicDialectParser::postgresql();
        let err = planner.plan_rewrite("select 1", &dialect).unwrap_err();
        assert!(err.to_string().contains("does not match"));
    }
}
