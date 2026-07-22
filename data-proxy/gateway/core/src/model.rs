use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Wire-protocol family used by listeners and backends.
///
/// Canonical config strings are `mysql` and `postgresql`.
/// Deserialization also accepts common aliases (`my_sql`, `postgres`, `postgre_sql`, `pg`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// A10: next ResultSet should use binary protocol rows.
    /// MySQL: COM_STMT_EXECUTE → ProtocolBinary.
    /// PostgreSQL: Bind result_format=1 → binary DataRow / RowDescription format=1.
    /// Frontend clears this after encoding one resultset (or non-result response).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub prefer_binary_result: bool,
    /// A10: PostgreSQL extended-query unit is open (after Parse/Bind/Execute,
    /// before Sync). Result footers must not emit ReadyForQuery — only Sync does.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pg_extended_query: bool,
    /// A10: client Execute max_rows for current portal page (0 / None = unlimited).
    /// When set and the stream is truncated at this limit, PG frontend may emit
    /// PortalSuspended instead of CommandComplete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pg_execute_max_rows: Option<u32>,
    /// A10: last streaming encode hit a row cap with more backend rows remaining
    /// (set by transport; consumed by PG footer for PortalSuspended).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub result_truncated: bool,
    /// A10: portal name for logical multi-Execute paging (skip already-sent rows).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pg_portal_name: Option<String>,
    /// A10: rows already returned for `pg_portal_name` (re-Execute skips these).
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub pg_portal_skip_rows: u64,
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
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
    /// A10: parameterized simple/extended query — SQL keeps `$n` placeholders;
    /// backend binds via prepared protocol (no string rewrite).
    QueryParams {
        sql: String,
        parameters: Vec<GatewayValue>,
    },
    Prepare { sql: String },
    Execute { statement_id: String, parameters: Vec<GatewayValue> },
    CloseStatement { statement_id: String },
    /// A10: describe result columns for SQL via backend prepare/catalog (no rows).
    /// Used when frontend cannot infer SELECT-list columns (e.g. `SELECT *`).
    DescribeSql { sql: String },
    /// Frontend-only wire packets (A10 extended protocol acks: ParseComplete, BindComplete, Sync…).
    /// Backend must return these unchanged as [`GatewayResponse::Wire`].
    ClientWire { packets: Vec<Vec<u8>> },
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
    /// Same-protocol wire payloads ready for the frontend writer (A3).
    ///
    /// MySQL: packet payloads **without** the 4-byte frame header (as
    /// `PacketSend::Encode` expects). PostgreSQL: full backend messages.
    Wire { packets: Vec<Vec<u8>> },
    /// A10: gateway-owned prepared id. Optional `columns` from backend catalog
    /// prepare (MySQL COM_STMT_PREPARE result column defs; PG may leave empty).
    Prepared {
        statement_id: String,
        parameter_count: u16,
        #[serde(default)]
        columns: Vec<Column>,
    },
    /// A10: column metadata only (extended-protocol Describe / catalog prepare).
    /// Frontend encodes as RowDescription (or NoData if empty); no CommandComplete.
    RowDescription { columns: Vec<Column> },
    Pong,
    Bye,
}

/// How backend connectors should return large query results (A1/A3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMode {
    /// Full result materialization (default, pre-A1 behavior).
    Materialized,
    /// Decode rows in windows of `window_rows`, optionally stop at `max_rows`.
    Streaming { window_rows: usize, max_rows: Option<u64> },
    /// Same-protocol raw packet relay without logical decode (A3).
    Passthrough,
}

impl Default for ExecuteMode {
    fn default() -> Self {
        Self::Materialized
    }
}

impl ExecuteMode {
    pub fn from_streaming_config(window_rows: u32, max_rows: Option<u64>) -> Self {
        let window = window_rows.max(1) as usize;
        Self::Streaming {
            window_rows: window,
            max_rows,
        }
    }

    pub fn effective_max_rows(self) -> Option<u64> {
        match self {
            Self::Materialized | Self::Passthrough => None,
            Self::Streaming { max_rows, .. } => max_rows,
        }
    }

    pub fn window_rows(self) -> Option<usize> {
        match self {
            Self::Materialized | Self::Passthrough => None,
            Self::Streaming { window_rows, .. } => Some(window_rows),
        }
    }

    pub fn is_passthrough(self) -> bool {
        matches!(self, Self::Passthrough)
    }

    /// A06: promote Materialized → Streaming for row-returning commands.
    ///
    /// Control statements (BEGIN/COMMIT/Ping) keep Materialized. SELECT / QueryParams /
    /// prepared Execute should not assemble a full `Vec<Vec<_>>` when a windowed path
    /// exists — peak retained rows stay ≈ one backend window + one encode window.
    pub fn promote_row_stream(self) -> Self {
        match self {
            Self::Materialized => Self::from_streaming_config(256, None),
            other => other,
        }
    }

    pub fn is_streaming(self) -> bool {
        matches!(self, Self::Streaming { .. })
    }
}

#[cfg(test)]
mod execute_mode_tests {
    use super::*;

    #[test]
    fn execute_mode_from_streaming() {
        let m = ExecuteMode::from_streaming_config(0, Some(10));
        assert_eq!(m.window_rows(), Some(1));
        assert_eq!(m.effective_max_rows(), Some(10));
    }

    #[test]
    fn a06_promote_materialized_row_stream() {
        let m = ExecuteMode::Materialized.promote_row_stream();
        assert!(m.is_streaming());
        assert_eq!(m.window_rows(), Some(256));
        assert_eq!(m.effective_max_rows(), None);
        // Streaming / Passthrough unchanged.
        let s = ExecuteMode::from_streaming_config(64, Some(10));
        assert_eq!(s.promote_row_stream(), s);
        assert_eq!(
            ExecuteMode::Passthrough.promote_row_stream(),
            ExecuteMode::Passthrough
        );
    }
}
