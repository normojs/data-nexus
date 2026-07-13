use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::EndpointConfig;

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolKind {
    #[serde(alias = "mysql")]
    MySql,
    #[serde(alias = "postgres", alias = "postgresql")]
    PostgreSql,
}

impl Default for ProtocolKind {
    fn default() -> Self {
        Self::MySql
    }
}

impl ProtocolKind {
    pub fn as_label(&self) -> &'static str {
        match self {
            Self::MySql => "my_sql",
            Self::PostgreSql => "postgre_sql",
        }
    }
}

impl fmt::Display for ProtocolKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_label())
    }
}

impl FromStr for ProtocolKind {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "mysql" | "my_sql" => Ok(Self::MySql),
            "postgres" | "postgresql" | "postgre_sql" => Ok(Self::PostgreSql),
            value => Err(format!("unsupported protocol kind '{}'", value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionState {
    Idle,
    Active,
    Failed,
}

impl Default for TransactionState {
    fn default() -> Self {
        Self::Idle
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SessionState {
    pub user: Option<String>,
    pub database: Option<String>,
    pub charset: Option<String>,
    pub autocommit: Option<bool>,
    #[serde(default)]
    pub transaction_state: TransactionState,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "value")]
pub enum GatewayValue {
    Null,
    Boolean(bool),
    Integer(i64),
    UnsignedInteger(u64),
    Float(f64),
    Decimal(String),
    String(String),
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Column {
    pub name: String,
    pub data_type: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "payload")]
pub enum GatewayCommand {
    Query { sql: String },
    Prepare { sql: String },
    Execute { statement_id: String, parameters: Vec<GatewayValue> },
    CloseStatement { statement_id: String },
    UseDatabase { database: String },
    Begin,
    Commit,
    Rollback,
    Ping,
    Quit,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "payload")]
pub enum GatewayResponse {
    Ok { affected_rows: u64, last_insert_id: Option<u64> },
    Error { code: String, message: String },
    ResultSet { columns: Vec<Column>, rows: Vec<Vec<GatewayValue>> },
    Prepared { statement_id: String, parameter_count: u16 },
    Pong,
    Bye,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "payload")]
pub enum RoutePlan {
    Single { target: RouteTarget },
    Broadcast { targets: Vec<RouteTarget> },
    Sharded { targets: Vec<RouteTarget> },
    Reject { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteTarget {
    pub endpoint: EndpointConfig,
}

impl RoutePlan {
    pub fn from_endpoints(endpoints: Vec<EndpointConfig>) -> Self {
        match endpoints.len() {
            0 => Self::Reject { reason: "route plan has no endpoints".into() },
            1 => Self::Single { target: RouteTarget { endpoint: endpoints[0].clone() } },
            _ => Self::Broadcast {
                targets: endpoints.into_iter().map(|endpoint| RouteTarget { endpoint }).collect(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_protocol_kind_aliases() {
        assert_eq!("mysql".parse::<ProtocolKind>(), Ok(ProtocolKind::MySql));
        assert_eq!("my_sql".parse::<ProtocolKind>(), Ok(ProtocolKind::MySql));
        assert_eq!("postgres".parse::<ProtocolKind>(), Ok(ProtocolKind::PostgreSql));
        assert_eq!("postgresql".parse::<ProtocolKind>(), Ok(ProtocolKind::PostgreSql));
        assert_eq!("postgre_sql".parse::<ProtocolKind>(), Ok(ProtocolKind::PostgreSql));
        assert_eq!(
            "oracle".parse::<ProtocolKind>(),
            Err("unsupported protocol kind 'oracle'".into())
        );
    }

    #[test]
    fn builds_route_plan_from_endpoint_count() {
        let endpoint = EndpointConfig {
            name: "orders-primary".into(),
            protocol: ProtocolKind::MySql,
            address: "127.0.0.1:3306".into(),
            database: Some("orders".into()),
            username: "root".into(),
            password: "secret".into(),
            role: crate::EndpointRole::ReadWrite,
            weight: 1,
        };

        assert_eq!(
            RoutePlan::from_endpoints(vec![]),
            RoutePlan::Reject { reason: "route plan has no endpoints".into() }
        );
        assert_eq!(
            RoutePlan::from_endpoints(vec![endpoint.clone()]),
            RoutePlan::Single { target: RouteTarget { endpoint: endpoint.clone() } }
        );
        assert_eq!(
            RoutePlan::from_endpoints(vec![endpoint.clone(), endpoint.clone()]),
            RoutePlan::Broadcast {
                targets: vec![RouteTarget { endpoint: endpoint.clone() }, RouteTarget { endpoint },]
            }
        );
    }
}
