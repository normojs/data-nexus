use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolKind {
    MySql,
    PostgreSql,
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
