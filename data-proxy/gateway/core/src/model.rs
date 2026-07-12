use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

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

impl fmt::Display for ProtocolKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MySql => f.write_str("my_sql"),
            Self::PostgreSql => f.write_str("postgre_sql"),
        }
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
}
