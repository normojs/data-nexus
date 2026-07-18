use serde::{Deserialize, Serialize};

use crate::{GatewayCommand, ProtocolKind, RoutePlan};

/// Protocol-neutral snapshot of one gateway command for plugins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "payload")]
pub enum CommandSummary {
    Query { sql: String },
    QueryParams { sql: String },
    Prepare { sql: String },
    Execute { statement_id: String },
    CloseStatement { statement_id: String },
    ClientWire,
    UseDatabase { database: String },
    Begin,
    Commit,
    Rollback,
    Ping,
    Quit,
}

impl CommandSummary {
    pub fn from_command(command: &GatewayCommand) -> Self {
        match command {
            GatewayCommand::Query { sql } => Self::Query { sql: sql.clone() },
            GatewayCommand::QueryParams { sql, .. } => Self::QueryParams { sql: sql.clone() },
            GatewayCommand::Prepare { sql } => Self::Prepare { sql: sql.clone() },
            GatewayCommand::Execute { statement_id, .. } => {
                Self::Execute { statement_id: statement_id.clone() }
            }
            GatewayCommand::CloseStatement { statement_id } => {
                Self::CloseStatement { statement_id: statement_id.clone() }
            }
            GatewayCommand::ClientWire { .. } => Self::ClientWire,
            GatewayCommand::UseDatabase { database } => {
                Self::UseDatabase { database: database.clone() }
            }
            GatewayCommand::Begin => Self::Begin,
            GatewayCommand::Commit => Self::Commit,
            GatewayCommand::Rollback => Self::Rollback,
            GatewayCommand::Ping => Self::Ping,
            GatewayCommand::Quit => Self::Quit,
        }
    }

    /// Text used by regex-based governance plugins (SQL body when available).
    pub fn match_text(&self) -> &str {
        match self {
            Self::Query { sql } | Self::QueryParams { sql } | Self::Prepare { sql } => sql.as_str(),
            Self::Execute { statement_id } | Self::CloseStatement { statement_id } => {
                statement_id.as_str()
            }
            Self::UseDatabase { database } => database.as_str(),
            Self::ClientWire => "CLIENT_WIRE",
            Self::Begin => "BEGIN",
            Self::Commit => "COMMIT",
            Self::Rollback => "ROLLBACK",
            Self::Ping => "PING",
            Self::Quit => "QUIT",
        }
    }

    pub fn rewritten_sql(&self, sql: String) -> Option<GatewayCommand> {
        match self {
            Self::Query { .. } => Some(GatewayCommand::Query { sql }),
            Self::QueryParams { .. } => Some(GatewayCommand::QueryParams {
                sql,
                parameters: vec![],
            }),
            Self::Prepare { .. } => Some(GatewayCommand::Prepare { sql }),
            _ => None,
        }
    }
}

/// Request context passed to governance plugins before command execution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PluginContext {
    pub service: String,
    pub client_protocol: ProtocolKind,
    pub user: Option<String>,
    pub database: Option<String>,
    pub command: CommandSummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_plan: Option<RoutePlan>,
}

impl PluginContext {
    pub fn match_text(&self) -> &str {
        self.command.match_text()
    }
}

/// Decision returned by a governance plugin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "payload")]
pub enum PluginDecision {
    Continue {
        /// When set, caller must release the concurrency permit after the command.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        concurrency_rule_idx: Option<usize>,
    },
    Reject {
        code: String,
        message: String,
    },
    Rewrite {
        sql: String,
    },
}

impl PluginDecision {
    pub fn continue_default() -> Self {
        Self::Continue { concurrency_rule_idx: None }
    }

    pub fn continue_with_permit(idx: usize) -> Self {
        Self::Continue { concurrency_rule_idx: Some(idx) }
    }

    pub fn reject(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Reject { code: code.into(), message: message.into() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_summary_match_text_prefers_sql() {
        let summary = CommandSummary::from_command(&GatewayCommand::Query {
            sql: "select 1".into(),
        });
        assert_eq!(summary.match_text(), "select 1");
        assert_eq!(CommandSummary::Begin.match_text(), "BEGIN");
    }

    #[test]
    fn rewrite_only_applies_to_query_like_commands() {
        let summary = CommandSummary::from_command(&GatewayCommand::Query {
            sql: "select 1".into(),
        });
        assert_eq!(
            summary.rewritten_sql("select 2".into()),
            Some(GatewayCommand::Query { sql: "select 2".into() })
        );
        assert!(CommandSummary::Ping.rewritten_sql("x".into()).is_none());
    }
}
