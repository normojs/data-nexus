use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Wire-protocol family used by listeners and backends.
///
/// Canonical config strings are `mysql` and `postgresql`.
/// Deserialization also accepts common aliases (`my_sql`, `postgres`, `postgre_sql`, `pg`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolKind {
    MySql,
    PostgreSql,
}

impl ProtocolKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MySql => "mysql",
            Self::PostgreSql => "postgresql",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        let normalized: String = value
            .chars()
            .filter(|c| *c != '_' && *c != '-' && *c != ' ')
            .flat_map(|c| c.to_lowercase())
            .collect();

        match normalized.as_str() {
            "mysql" | "mariadb" => Ok(Self::MySql),
            "postgresql" | "postgres" | "pgsql" | "pg" => Ok(Self::PostgreSql),
            other => Err(format!(
                "unknown protocol '{}'; expected mysql or postgresql (aliases: my_sql, postgres, postgre_sql, pg)",
                other
            )),
        }
    }
}

impl fmt::Display for ProtocolKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ProtocolKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ProtocolKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        ProtocolKind::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_and_alias_protocol_names() {
        assert_eq!(ProtocolKind::parse("mysql").unwrap(), ProtocolKind::MySql);
        assert_eq!(ProtocolKind::parse("my_sql").unwrap(), ProtocolKind::MySql);
        assert_eq!(ProtocolKind::parse("MySQL").unwrap(), ProtocolKind::MySql);
        assert_eq!(ProtocolKind::parse("postgresql").unwrap(), ProtocolKind::PostgreSql);
        assert_eq!(ProtocolKind::parse("postgre_sql").unwrap(), ProtocolKind::PostgreSql);
        assert_eq!(ProtocolKind::parse("postgres").unwrap(), ProtocolKind::PostgreSql);
        assert_eq!(ProtocolKind::parse("pg").unwrap(), ProtocolKind::PostgreSql);
        assert!(ProtocolKind::parse("oracle").is_err());
    }

    #[test]
    fn serializes_canonical_protocol_names() {
        assert_eq!(serde_json::to_string(&ProtocolKind::MySql).unwrap(), "\"mysql\"");
        assert_eq!(
            serde_json::to_string(&ProtocolKind::PostgreSql).unwrap(),
            "\"postgresql\""
        );
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_endpoint: Option<String>,
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
