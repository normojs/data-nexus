use std::collections::HashMap;

use gateway_core::{
    Column as GatewayColumn, FrontendProtocolAdapter, GatewayCommand, GatewayError,
    GatewayResponse, GatewayResult, GatewayValue, ProtocolKind, SessionState, TransactionState,
};
use postgresql_protocol::{
    decode_frontend_message, decode_startup_packet, encode_authentication_ok,
    encode_backend_key_data, encode_bind_complete, encode_close_complete, encode_command_complete,
    encode_data_row, encode_error_response, encode_no_data, encode_parameter_description,
    encode_parameter_status, encode_parse_complete, encode_ready_for_query, encode_row_description,
    FieldDescription, FrontendMessage, StartupMessage, StartupPacket, TransactionStatus,
    MAX_STARTUP_PACKET_LEN,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const DEFAULT_CLIENT_ENCODING: &str = "UTF8";

#[derive(Clone, Debug)]
pub struct PostgreSqlFrontendProtocol {
    server_version: String,
    process_id: i32,
    secret_key: i32,
    /// A10: named prepared statements (Parse) → SQL text.
    prepared: HashMap<String, String>,
    /// A10: statement name → parameter count (from `$n` in query).
    prepared_params: HashMap<String, u16>,
    /// A10: portals (Bind) → bound SQL ready for Query rewrite.
    portals: HashMap<String, String>,
    /// A10: portal → parameter count for Describe('P').
    portal_params: HashMap<String, u16>,
    /// A10: portal → result format codes from Bind (0=text, 1=binary).
    /// Empty / all-zero → text; single `[1]` or any `1` → prefer binary results.
    portal_result_formats: HashMap<String, Vec<i16>>,
}

impl PostgreSqlFrontendProtocol {
    pub fn new(server_version: String) -> Self {
        Self {
            server_version,
            process_id: 0,
            secret_key: 0,
            prepared: HashMap::new(),
            prepared_params: HashMap::new(),
            portals: HashMap::new(),
            portal_params: HashMap::new(),
            portal_result_formats: HashMap::new(),
        }
    }

    pub fn with_backend_key(server_version: String, process_id: i32, secret_key: i32) -> Self {
        Self {
            server_version,
            process_id,
            secret_key,
            prepared: HashMap::new(),
            prepared_params: HashMap::new(),
            portals: HashMap::new(),
            portal_params: HashMap::new(),
            portal_result_formats: HashMap::new(),
        }
    }

    pub fn protocol(&self) -> ProtocolKind {
        ProtocolKind::PostgreSql
    }

    pub async fn handshake<S>(&self, mut stream: S) -> GatewayResult<PostgreSqlHandshake<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        loop {
            let frame = read_startup_frame(&mut stream).await?;
            match decode_startup_packet(&frame).map_err(postgresql_protocol_error)? {
                StartupPacket::SslRequest => {
                    stream
                        .write_all(b"N")
                        .await
                        .map_err(|error| postgresql_io_error("write ssl response", error))?;
                    stream
                        .flush()
                        .await
                        .map_err(|error| postgresql_io_error("flush ssl response", error))?;
                }
                StartupPacket::CancelRequest { .. } => {
                    return Err(GatewayError::Unsupported(
                        "postgresql cancel request during startup is not supported".into(),
                    ))
                }
                StartupPacket::Startup(startup) => {
                    let session = session_from_startup(&startup);
                    write_handshake_response(
                        &mut stream,
                        &self.server_version,
                        self.process_id,
                        self.secret_key,
                        session.charset.as_deref().unwrap_or(DEFAULT_CLIENT_ENCODING),
                    )
                    .await?;

                    return Ok(PostgreSqlHandshake { stream, startup, session });
                }
            }
        }
    }
}

impl FrontendProtocolAdapter for PostgreSqlFrontendProtocol {
    fn protocol(&self) -> ProtocolKind {
        ProtocolKind::PostgreSql
    }

    fn decode(
        &mut self,
        frame: &[u8],
        session: &mut SessionState,
    ) -> GatewayResult<Vec<GatewayCommand>> {
        match decode_frontend_message(frame).map_err(postgresql_protocol_error)? {
            FrontendMessage::Query(sql) => Ok(vec![decode_query_command(sql, session)]),
            FrontendMessage::Terminate => Ok(vec![GatewayCommand::Quit]),
            FrontendMessage::Sync => Ok(vec![GatewayCommand::ClientWire {
                packets: vec![encode_ready_for_query(transaction_status(session))],
            }]),
            FrontendMessage::Flush => Ok(vec![]),
            FrontendMessage::Parse {
                statement,
                query,
                param_types: _,
            } => {
                let nparams = count_pg_placeholders_frontend(&query);
                self.prepared_params.insert(statement.clone(), nparams);
                self.prepared.insert(statement, query);
                Ok(vec![GatewayCommand::ClientWire {
                    packets: vec![encode_parse_complete()],
                }])
            }
            FrontendMessage::Bind {
                portal,
                statement,
                parameters,
                result_formats,
            } => {
                let sql = self.prepared.get(&statement).cloned().ok_or_else(|| {
                    GatewayError::Protocol(format!(
                        "postgresql Bind: unknown statement '{statement}'"
                    ))
                })?;
                let nparams = self
                    .prepared_params
                    .get(&statement)
                    .copied()
                    .unwrap_or_else(|| count_pg_placeholders_frontend(&sql));
                let params: Vec<GatewayValue> = parameters
                    .into_iter()
                    .map(|p| match p {
                        None => GatewayValue::Null,
                        Some(s) => GatewayValue::String(s),
                    })
                    .collect();
                let bound = bind_pg_text_params(&sql, &params)?;
                self.portals.insert(portal.clone(), bound);
                self.portal_params.insert(portal.clone(), nparams);
                self.portal_result_formats
                    .insert(portal, result_formats);
                Ok(vec![GatewayCommand::ClientWire {
                    packets: vec![encode_bind_complete()],
                }])
            }
            FrontendMessage::Describe { target, name } => {
                // Describe statement ('S') or portal ('P'):
                // ParameterDescription + NoData (row metadata still unavailable without
                // backend describe — honest A10 boundary).
                let nparams = if target == b'S' {
                    self.prepared_params.get(&name).copied().or_else(|| {
                        self.prepared
                            .get(&name)
                            .map(|sql| count_pg_placeholders_frontend(sql))
                    })
                } else {
                    self.portal_params.get(&name).copied()
                };
                let n = nparams.unwrap_or(0) as usize;
                // unknown OIDs (0) — clients treat as unspecified / text.
                let oids = vec![0i32; n];
                Ok(vec![GatewayCommand::ClientWire {
                    packets: vec![encode_parameter_description(&oids), encode_no_data()],
                }])
            }
            FrontendMessage::Execute { portal, max_rows: _ } => {
                let sql = self.portals.get(&portal).cloned().ok_or_else(|| {
                    GatewayError::Protocol(format!(
                        "postgresql Execute: unknown portal '{portal}'"
                    ))
                })?;
                // A10: honor Bind result_formats — any binary (1) requests binary rows.
                let want_binary = self
                    .portal_result_formats
                    .get(&portal)
                    .map(|fmts| fmts.iter().any(|f| *f == 1))
                    .unwrap_or(false);
                session.prefer_binary_result = want_binary;
                Ok(vec![GatewayCommand::Query { sql }])
            }
            FrontendMessage::Close { target, name } => {
                if target == b'S' {
                    self.prepared.remove(&name);
                    self.prepared_params.remove(&name);
                } else {
                    self.portals.remove(&name);
                    self.portal_params.remove(&name);
                    self.portal_result_formats.remove(&name);
                }
                Ok(vec![GatewayCommand::ClientWire {
                    packets: vec![encode_close_complete()],
                }])
            }
        }
    }

    fn encode(
        &mut self,
        response: GatewayResponse,
        session: &SessionState,
    ) -> GatewayResult<Vec<Vec<u8>>> {
        let ready = encode_ready_for_query(transaction_status(session));
        match response {
            GatewayResponse::Ok { affected_rows, .. } => {
                Ok(vec![encode_command_complete(&format!("OK {}", affected_rows)), ready])
            }
            GatewayResponse::Pong => Ok(vec![encode_command_complete("SELECT 1"), ready]),
            GatewayResponse::Bye => Ok(vec![]),
            GatewayResponse::Error { code, message } => Ok(vec![
                encode_error_response("ERROR", postgresql_sqlstate(&code), &message),
                ready,
            ]),
            GatewayResponse::ResultSet { columns, rows } => {
                if session.prefer_binary_result {
                    encode_resultset_binary(columns, rows, ready)
                } else {
                    encode_resultset(columns, rows, ready)
                }
            }
            GatewayResponse::Wire { packets } => Ok(packets),
            // A10: gateway-owned prepared registry is not the PG extended protocol.
            // Clients using Parse/Bind still need extended-query decode (not in this
            // slice). When a Prepared response is produced (e.g. via IR), answer with
            // CommandComplete + Ready so the session does not hang on Unsupported.
            GatewayResponse::Prepared {
                statement_id,
                parameter_count,
            } => Ok(vec![
                encode_command_complete(&format!(
                    "PREPARE {statement_id} params={parameter_count}"
                )),
                ready,
            ]),
        }
    }

    fn encode_resultset_header(
        &mut self,
        columns: &[GatewayColumn],
        session: &SessionState,
    ) -> GatewayResult<Vec<Vec<u8>>> {
        if session.prefer_binary_result {
            encode_pg_resultset_header_formats(columns, 1)
        } else {
            encode_pg_resultset_header(columns)
        }
    }

    fn encode_resultset_rows(
        &mut self,
        columns: &[GatewayColumn],
        rows: &[Vec<GatewayValue>],
        session: &SessionState,
    ) -> GatewayResult<Vec<Vec<u8>>> {
        if session.prefer_binary_result {
            encode_pg_resultset_rows_binary(columns, rows)
        } else {
            encode_pg_resultset_rows(columns, rows)
        }
    }

    fn encode_resultset_footer(
        &mut self,
        _columns: &[GatewayColumn],
        total_rows: usize,
        session: &SessionState,
    ) -> GatewayResult<Vec<Vec<u8>>> {
        let ready = encode_ready_for_query(transaction_status(session));
        Ok(vec![
            encode_command_complete(&format!("SELECT {total_rows}")),
            ready,
        ])
    }
}

pub struct PostgreSqlHandshake<S> {
    pub stream: S,
    pub startup: StartupMessage,
    pub session: SessionState,
}

async fn read_startup_frame<S>(stream: &mut S) -> GatewayResult<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut len_bytes = [0; 4];
    stream
        .read_exact(&mut len_bytes)
        .await
        .map_err(|error| postgresql_io_error("read startup length", error))?;

    let len = i32::from_be_bytes(len_bytes);
    if len < 8 || len as usize > MAX_STARTUP_PACKET_LEN {
        return Err(GatewayError::Protocol(format!(
            "invalid postgresql startup packet length {}",
            len
        )));
    }

    let len = len as usize;
    let mut frame = vec![0; len];
    frame[0..4].copy_from_slice(&len_bytes);
    stream
        .read_exact(&mut frame[4..])
        .await
        .map_err(|error| postgresql_io_error("read startup body", error))?;
    Ok(frame)
}

async fn write_handshake_response<S>(
    stream: &mut S,
    server_version: &str,
    process_id: i32,
    secret_key: i32,
    client_encoding: &str,
) -> GatewayResult<()>
where
    S: AsyncWrite + Unpin,
{
    let mut response = Vec::new();
    response.extend_from_slice(&encode_authentication_ok());
    response.extend_from_slice(&encode_parameter_status("server_version", server_version));
    response.extend_from_slice(&encode_parameter_status("server_encoding", "UTF8"));
    response.extend_from_slice(&encode_parameter_status("client_encoding", client_encoding));
    response.extend_from_slice(&encode_parameter_status("DateStyle", "ISO, MDY"));
    response.extend_from_slice(&encode_parameter_status("integer_datetimes", "on"));
    response.extend_from_slice(&encode_backend_key_data(process_id, secret_key));
    response.extend_from_slice(&encode_ready_for_query(TransactionStatus::Idle));

    stream
        .write_all(&response)
        .await
        .map_err(|error| postgresql_io_error("write handshake response", error))?;
    stream.flush().await.map_err(|error| postgresql_io_error("flush handshake response", error))?;
    Ok(())
}

fn session_from_startup(startup: &StartupMessage) -> SessionState {
    SessionState {
        user: startup.get("user").map(ToOwned::to_owned),
        database: startup.get("database").map(ToOwned::to_owned),
        charset: startup
            .get("client_encoding")
            .map(ToOwned::to_owned)
            .or_else(|| Some(DEFAULT_CLIENT_ENCODING.to_owned())),
        ..SessionState::default()
    }
}

fn decode_query_command(sql: String, session: &mut SessionState) -> GatewayCommand {
    if let Some(client_encoding) = client_encoding_from_set_query(&sql) {
        session.charset = Some(client_encoding);
    }

    match sql.trim().to_ascii_lowercase().as_str() {
        "begin" | "start transaction" => {
            session.transaction_state = TransactionState::Active;
            GatewayCommand::Begin
        }
        "commit" => {
            session.transaction_state = TransactionState::Idle;
            GatewayCommand::Commit
        }
        "rollback" => {
            session.transaction_state = TransactionState::Idle;
            GatewayCommand::Rollback
        }
        _ => GatewayCommand::Query { sql },
    }
}

/// Count distinct `$n` placeholders for Describe ParameterDescription.
fn count_pg_placeholders_frontend(sql: &str) -> u16 {
    let mut max = 0u16;
    let bytes = sql.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
            let mut j = i + 1;
            let mut n: u16 = 0;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                n = n
                    .saturating_mul(10)
                    .saturating_add((bytes[j] - b'0') as u16);
                j += 1;
            }
            if n > max {
                max = n;
            }
            i = j;
            continue;
        }
        i += 1;
    }
    max
}

/// Substitute `$n` placeholders with SQL literals (text-format Bind params).
fn bind_pg_text_params(sql: &str, parameters: &[GatewayValue]) -> GatewayResult<String> {
    let mut max = 0usize;
    let bytes = sql.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
            let mut j = i + 1;
            let mut n = 0usize;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                n = n.saturating_mul(10).saturating_add((bytes[j] - b'0') as usize);
                j += 1;
            }
            if n > max {
                max = n;
            }
            i = j;
            continue;
        }
        i += 1;
    }
    if max != parameters.len() {
        return Err(GatewayError::Protocol(format!(
            "postgresql Bind expects {max} parameters, got {}",
            parameters.len()
        )));
    }
    if max == 0 {
        return Ok(sql.to_owned());
    }
    let mut out = sql.to_owned();
    for n in (1..=max).rev() {
        let lit = match &parameters[n - 1] {
            GatewayValue::Null => "NULL".to_string(),
            GatewayValue::Boolean(b) => if *b { "TRUE" } else { "FALSE" }.to_string(),
            GatewayValue::Integer(i) => i.to_string(),
            GatewayValue::UnsignedInteger(u) => u.to_string(),
            GatewayValue::Float(f) => {
                if f.is_finite() {
                    f.to_string()
                } else {
                    "NULL".into()
                }
            }
            GatewayValue::Decimal(s) | GatewayValue::String(s) => {
                format!("'{}'", s.replace('\'', "''"))
            }
            GatewayValue::Bytes(b) => {
                let mut hex = String::from("E'\\\\x");
                for byte in b {
                    hex.push_str(&format!("{byte:02x}"));
                }
                hex.push('\'');
                hex
            }
        };
        out = out.replace(&format!("${n}"), &lit);
    }
    Ok(out)
}

fn client_encoding_from_set_query(sql: &str) -> Option<String> {
    let sql = sql.trim().trim_end_matches(';').trim();
    let value = strip_ascii_prefix(sql, "set client_encoding")
        .or_else(|| strip_ascii_prefix(sql, "set names"))?;

    parse_set_value(value)
}

fn parse_set_value(value: &str) -> Option<String> {
    let mut value = value.trim();
    if let Some(rest) = strip_keyword(value, "to") {
        value = rest.trim();
    } else if let Some(rest) = value.strip_prefix('=') {
        value = rest.trim();
    }

    let value = value.trim_end_matches(';').trim();
    if value.is_empty() {
        return None;
    }

    if value.starts_with('\'') {
        return unquote(value, '\'').map(|value| value.replace("''", "'"));
    }
    if value.starts_with('"') {
        return unquote(value, '"').map(|value| value.replace("\"\"", "\""));
    }

    value.split_whitespace().next().map(|value| value.trim_matches(';').to_owned())
}

fn strip_ascii_prefix<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    let head = value.get(..prefix.len())?;
    if !head.eq_ignore_ascii_case(prefix) {
        return None;
    }

    let rest = &value[prefix.len()..];
    if rest.chars().next().map_or(true, char::is_whitespace) {
        Some(rest)
    } else {
        None
    }
}

fn strip_keyword<'a>(value: &'a str, keyword: &str) -> Option<&'a str> {
    let rest = strip_ascii_prefix(value, keyword)?;
    Some(rest)
}

fn unquote(value: &str, quote: char) -> Option<&str> {
    let value = value.strip_prefix(quote)?;
    let end = value.find(quote)?;
    Some(&value[..end])
}


fn encode_pg_resultset_header(columns: &[GatewayColumn]) -> GatewayResult<Vec<Vec<u8>>> {
    encode_pg_resultset_header_formats(columns, 0)
}

fn encode_pg_resultset_header_formats(
    columns: &[GatewayColumn],
    format_code: i16,
) -> GatewayResult<Vec<Vec<u8>>> {
    let fields = columns
        .iter()
        .map(|c| {
            let mut f = gateway_column_to_postgresql_field(c);
            f.format_code = format_code;
            f
        })
        .collect::<Vec<_>>();
    Ok(vec![
        encode_row_description(&fields).map_err(postgresql_protocol_error)?,
    ])
}

fn encode_pg_resultset_rows(
    columns: &[GatewayColumn],
    rows: &[Vec<GatewayValue>],
) -> GatewayResult<Vec<Vec<u8>>> {
    let mut messages = Vec::with_capacity(rows.len());
    for row in rows {
        if row.len() != columns.len() {
            return Err(GatewayError::Protocol(format!(
                "postgresql resultset row has {} values for {} columns",
                row.len(),
                columns.len()
            )));
        }
        let values = row.iter().map(gateway_value_to_text).collect::<Vec<_>>();
        messages.push(encode_data_row(&values).map_err(postgresql_protocol_error)?);
    }
    Ok(messages)
}

/// A10: binary-format DataRow values (int2/4/8, float4/8, bool, text/bytea as raw bytes).
fn encode_pg_resultset_rows_binary(
    columns: &[GatewayColumn],
    rows: &[Vec<GatewayValue>],
) -> GatewayResult<Vec<Vec<u8>>> {
    let mut messages = Vec::with_capacity(rows.len());
    for row in rows {
        if row.len() != columns.len() {
            return Err(GatewayError::Protocol(format!(
                "postgresql binary resultset row has {} values for {} columns",
                row.len(),
                columns.len()
            )));
        }
        let mut values = Vec::with_capacity(row.len());
        for (i, v) in row.iter().enumerate() {
            values.push(gateway_value_to_pg_binary(v, &columns[i].data_type)?);
        }
        messages.push(encode_data_row(&values).map_err(postgresql_protocol_error)?);
    }
    Ok(messages)
}

fn encode_resultset(
    columns: Vec<GatewayColumn>,
    rows: Vec<Vec<GatewayValue>>,
    ready: Vec<u8>,
) -> GatewayResult<Vec<Vec<u8>>> {
    let mut messages = encode_pg_resultset_header(&columns)?;
    messages.extend(encode_pg_resultset_rows(&columns, &rows)?);
    messages.push(encode_command_complete(&format!("SELECT {}", rows.len())));
    messages.push(ready);
    Ok(messages)
}

fn encode_resultset_binary(
    columns: Vec<GatewayColumn>,
    rows: Vec<Vec<GatewayValue>>,
    ready: Vec<u8>,
) -> GatewayResult<Vec<Vec<u8>>> {
    let mut messages = encode_pg_resultset_header_formats(&columns, 1)?;
    messages.extend(encode_pg_resultset_rows_binary(&columns, &rows)?);
    messages.push(encode_command_complete(&format!("SELECT {}", rows.len())));
    messages.push(ready);
    Ok(messages)
}

fn gateway_column_to_postgresql_field(column: &GatewayColumn) -> FieldDescription {
    let (type_oid, type_size) = postgresql_type_info(&column.data_type);
    FieldDescription {
        name: column.name.clone(),
        type_oid,
        type_size,
        type_modifier: -1,
        format_code: 0,
    }
}

fn postgresql_type_info(data_type: &str) -> (i32, i16) {
    match data_type.to_ascii_lowercase().as_str() {
        "bool" | "boolean" => (16, 1),
        "int2" | "smallint" => (21, 2),
        "int" | "int4" | "integer" => (23, 4),
        "int8" | "bigint" => (20, 8),
        "float4" | "real" => (700, 4),
        "float8" | "double" | "double precision" => (701, 8),
        "numeric" | "decimal" => (1700, -1),
        "date" => (1082, 4),
        "time" => (1083, 8),
        "timestamp" => (1114, 8),
        "timestamptz" => (1184, 8),
        "bytea" | "bytes" | "binary" | "varbinary" => (17, -1),
        "varchar" | "char" | "bpchar" => (1043, -1),
        _ => (25, -1),
    }
}

fn gateway_value_to_text(value: &GatewayValue) -> Option<Vec<u8>> {
    match value {
        GatewayValue::Null => None,
        GatewayValue::Boolean(value) => Some(if *value { b"t".to_vec() } else { b"f".to_vec() }),
        GatewayValue::Integer(value) => Some(value.to_string().into_bytes()),
        GatewayValue::UnsignedInteger(value) => Some(value.to_string().into_bytes()),
        GatewayValue::Float(value) => Some(value.to_string().into_bytes()),
        GatewayValue::Decimal(value) | GatewayValue::String(value) => {
            Some(value.as_bytes().to_vec())
        }
        GatewayValue::Bytes(value) => Some(value.clone()),
    }
}

/// A10: encode one cell in PostgreSQL binary format.
///
/// Native layouts: bool, int2/4/8, float4/8, date, timestamp/timestamptz
/// (integer_datetimes=on), text/varchar, bytea. Numeric still UTF-8 fallback.
fn gateway_value_to_pg_binary(
    value: &GatewayValue,
    data_type: &str,
) -> GatewayResult<Option<Vec<u8>>> {
    if matches!(value, GatewayValue::Null) {
        return Ok(None);
    }
    let dt = data_type.to_ascii_lowercase();
    match value {
        GatewayValue::Null => Ok(None),
        GatewayValue::Boolean(b) => Ok(Some(vec![if *b { 1 } else { 0 }])),
        GatewayValue::Integer(i) => match dt.as_str() {
            "date" => Ok(Some((*i as i32).to_be_bytes().to_vec())),
            "timestamp" | "timestamptz" => Ok(Some(i.to_be_bytes().to_vec())),
            _ => Ok(Some(encode_pg_int_binary(*i, &dt))),
        },
        GatewayValue::UnsignedInteger(u) => {
            if *u > i64::MAX as u64 {
                return Err(GatewayError::Protocol(format!(
                    "postgresql binary: unsigned value {u} exceeds i64"
                )));
            }
            Ok(Some(encode_pg_int_binary(*u as i64, &dt)))
        }
        GatewayValue::Float(f) => {
            if matches!(dt.as_str(), "float4" | "real") {
                let bits = (*f as f32).to_bits();
                Ok(Some(bits.to_be_bytes().to_vec()))
            } else {
                Ok(Some(f.to_bits().to_be_bytes().to_vec()))
            }
        }
        GatewayValue::Decimal(s) | GatewayValue::String(s) => match dt.as_str() {
            "date" => {
                let days = parse_pg_date_days(s).ok_or_else(|| {
                    GatewayError::Protocol(format!("invalid postgresql DATE value '{s}'"))
                })?;
                Ok(Some(days.to_be_bytes().to_vec()))
            }
            "timestamp" => {
                let us = parse_pg_timestamp_us(s, false).ok_or_else(|| {
                    GatewayError::Protocol(format!("invalid postgresql TIMESTAMP value '{s}'"))
                })?;
                Ok(Some(us.to_be_bytes().to_vec()))
            }
            "timestamptz" => {
                let us = parse_pg_timestamp_us(s, true).ok_or_else(|| {
                    GatewayError::Protocol(format!(
                        "invalid postgresql TIMESTAMPTZ value '{s}'"
                    ))
                })?;
                Ok(Some(us.to_be_bytes().to_vec()))
            }
            "time" | "timetz" => {
                // TIME binary is microseconds since midnight (i64); ignore zone for A10.
                let us = parse_pg_time_us(s).ok_or_else(|| {
                    GatewayError::Protocol(format!("invalid postgresql TIME value '{s}'"))
                })?;
                Ok(Some(us.to_be_bytes().to_vec()))
            }
            // Numeric binary is complex; UTF-8 bytes (text-like clients ok).
            _ => Ok(Some(s.as_bytes().to_vec())),
        },
        GatewayValue::Bytes(b) => Ok(Some(b.clone())),
    }
}

fn encode_pg_int_binary(i: i64, data_type: &str) -> Vec<u8> {
    match data_type {
        "int2" | "smallint" => (i as i16).to_be_bytes().to_vec(),
        "int8" | "bigint" => i.to_be_bytes().to_vec(),
        // int4 default
        _ => (i as i32).to_be_bytes().to_vec(),
    }
}

/// PostgreSQL DATE binary: days since 2000-01-01 as i32 BE.
fn parse_pg_date_days(s: &str) -> Option<i32> {
    let (y, m, d) = parse_ymd(s.trim())?;
    Some(days_from_pg_epoch(y, m, d))
}

/// TIMESTAMP/TIMESTAMPTZ: microseconds since 2000-01-01 00:00:00 UTC (integer_datetimes).
/// `allow_tz`: if true, optional `+HH`, `+HH:MM`, `Z` offsets are applied; if false, offset rejected.
fn parse_pg_timestamp_us(s: &str, allow_tz: bool) -> Option<i64> {
    let s = s.trim().replace('T', " ");
    let (body, offset_secs) = split_tz_offset(&s, allow_tz)?;
    let (date, time) = match body.split_once(' ') {
        Some((d, t)) => (d, t),
        None => (body.as_str(), "00:00:00"),
    };
    let (y, mo, d) = parse_ymd(date)?;
    let (h, mi, sec, micro) = parse_hms_micro_pg(time)?;
    let days = days_from_pg_epoch(y, mo, d) as i64;
    let us = days
        .checked_mul(86_400_000_000)?
        .checked_add(h as i64 * 3_600_000_000)?
        .checked_add(mi as i64 * 60_000_000)?
        .checked_add(sec as i64 * 1_000_000)?
        .checked_add(micro as i64)?;
    // Offset: local = UTC + offset → store UTC = local - offset.
    us.checked_sub(offset_secs.checked_mul(1_000_000)?)
}

/// TIME: microseconds since midnight as i64 (optional fractional).
fn parse_pg_time_us(s: &str) -> Option<i64> {
    let s = s.trim();
    // Drop trailing zone if present (timetz text).
    let body = s
        .split_once(['+', '-'])
        .map(|(b, _)| b.trim())
        .unwrap_or(s);
    // Avoid stripping leading minus as zone: TIME is non-negative in PG.
    let (h, mi, sec, micro) = parse_hms_micro_pg(body)?;
    Some(
        h as i64 * 3_600_000_000
            + mi as i64 * 60_000_000
            + sec as i64 * 1_000_000
            + micro as i64,
    )
}

fn parse_ymd(s: &str) -> Option<(i32, u32, u32)> {
    let mut parts = s.split('-');
    let y: i32 = parts.next()?.parse().ok()?;
    let m: u32 = parts.next()?.parse().ok()?;
    let d: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some((y, m, d))
}

fn parse_hms_micro_pg(s: &str) -> Option<(u32, u32, u32, u32)> {
    let s = s.trim();
    let (hms, frac) = match s.split_once('.') {
        Some((a, b)) => (a, Some(b)),
        None => (s, None),
    };
    let mut p = hms.split(':');
    let h: u32 = p.next()?.parse().ok()?;
    let mi: u32 = p.next()?.parse().ok()?;
    let sec: u32 = p.next()?.parse().ok()?;
    if p.next().is_some() || h > 24 || mi > 59 || sec > 60 {
        return None;
    }
    let micro = match frac {
        None => 0u32,
        Some(f) => {
            let f = f.trim();
            if f.is_empty() || f.len() > 6 || !f.chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
            let mut v = f.parse::<u32>().ok()?;
            for _ in f.len()..6 {
                v *= 10;
            }
            v
        }
    };
    Some((h, mi, sec, micro))
}

/// Returns (body_without_tz, offset_seconds_east_of_utc).
///
/// Timezone is only scanned in the **time** portion (after the last space) so
/// date separators in `YYYY-MM-DD` are never mistaken for offsets.
fn split_tz_offset(s: &str, allow_tz: bool) -> Option<(String, i64)> {
    let s = s.trim();
    if let Some(body) = s.strip_suffix('Z').or_else(|| s.strip_suffix('z')) {
        if !allow_tz {
            return None;
        }
        return Some((body.trim().to_string(), 0));
    }

    // Restrict TZ search to the time token so `2000-01-01 00:00:01` is safe.
    let (prefix, time_part) = match s.rfind(' ') {
        Some(sp) => (&s[..sp], &s[sp + 1..]),
        None => {
            // No space: either DATE-only (`YYYY-MM-DD`) or TIME-only (`HH:MM:SS±zz`).
            // DATE-only has no colon → no TZ. TIME-only may have ± offset.
            if !s.contains(':') {
                return Some((s.to_string(), 0));
            }
            ("", s)
        }
    };

    let bytes = time_part.as_bytes();
    let mut idx = None;
    for i in (1..bytes.len()).rev() {
        if (bytes[i] == b'+' || bytes[i] == b'-') && bytes[i - 1].is_ascii_digit() {
            idx = Some(i);
            break;
        }
    }
    let Some(i) = idx else {
        return Some((s.to_string(), 0));
    };
    if !allow_tz {
        return None;
    }
    let (time_body, off) = time_part.split_at(i);
    let sign: i64 = if off.starts_with('+') { 1 } else { -1 };
    let rest = &off[1..];
    let (hh, mm) = if let Some((h, m)) = rest.split_once(':') {
        (h.parse::<i64>().ok()?, m.parse::<i64>().ok()?)
    } else if rest.len() == 4 && rest.chars().all(|c| c.is_ascii_digit()) {
        (
            rest[..2].parse::<i64>().ok()?,
            rest[2..].parse::<i64>().ok()?,
        )
    } else if rest.len() <= 2 {
        (rest.parse::<i64>().ok()?, 0)
    } else {
        return None;
    };
    if !(0..=14).contains(&hh) || !(0..=59).contains(&mm) {
        return None;
    }
    let body = if prefix.is_empty() {
        time_body.trim().to_string()
    } else {
        format!("{} {}", prefix.trim(), time_body.trim())
    };
    Some((body, sign * (hh * 3600 + mm * 60)))
}

/// Days since 2000-01-01 (PostgreSQL date epoch), civil calendar.
fn days_from_pg_epoch(year: i32, month: u32, day: u32) -> i32 {
    // Proleptic Gregorian → Rata Die, then offset so 2000-01-01 = 0.
    // Algorithm: Howard Hinnant civil_from_days inverse.
    let y = year as i64 - if month <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp as u64 + 2) / 5 + day as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let z = (era * 146_097 + doe as i64) as i32 - 719_468;
    // Unix epoch days for 2000-01-01 is 10957 (1970-01-01 → 2000-01-01).
    // Rata Die for 1970-01-01 is 719163; for 2000-01-01 is 730120.
    // Our z is days since 0000-03-01 style; convert via known epoch.
    // Simpler: compute days since Unix epoch then subtract 10957.
    let unix_days = days_since_unix_epoch(year, month, day);
    unix_days - 10_957
}

fn days_since_unix_epoch(year: i32, month: u32, day: u32) -> i32 {
    // Days from civil date to 1970-01-01 using Hinnant algorithm.
    let y = year as i64 - if month <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let m = month as u64;
    let d = day as u64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let z = era * 146_097 + doe as i64 - 719_468;
    z as i32
}

fn transaction_status(session: &SessionState) -> TransactionStatus {
    match session.transaction_state {
        TransactionState::Idle => TransactionStatus::Idle,
        TransactionState::Active => TransactionStatus::InTransaction,
        TransactionState::Failed => TransactionStatus::Failed,
    }
}

fn postgresql_sqlstate(code: &str) -> &str {
    if code.len() == 5 && code.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        code
    } else {
        "XX000"
    }
}

fn postgresql_protocol_error(error: postgresql_protocol::ProtocolError) -> GatewayError {
    GatewayError::Protocol(error.to_string())
}

fn postgresql_io_error(context: &str, error: std::io::Error) -> GatewayError {
    GatewayError::Protocol(format!("postgresql handshake {} failed: {}", context, error))
}

#[cfg(test)]
mod tests {
    use gateway_core::FrontendProtocolAdapter;
    use postgresql_protocol::{
        encode_query_message, encode_ssl_request, encode_startup_message, encode_sync_message,
        encode_terminate_message,
    };
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn handshake_accepts_startup_and_updates_session() {
        let (server, mut client) = duplex(4096);
        let protocol = PostgreSqlFrontendProtocol::with_backend_key("14.0".into(), 17, 23);

        let server_task = tokio::spawn(async move { protocol.handshake(server).await });

        client
            .write_all(&encode_startup_message(&[
                ("user", "app"),
                ("database", "orders"),
                ("client_encoding", "LATIN1"),
            ]))
            .await
            .unwrap();

        let mut response = Vec::new();
        read_until_ready_for_query(&mut client, &mut response).await;

        let handshake = server_task.await.unwrap().unwrap();
        assert_eq!(handshake.session.user, Some("app".into()));
        assert_eq!(handshake.session.database, Some("orders".into()));
        assert_eq!(handshake.session.charset, Some("LATIN1".into()));
        assert!(response.starts_with(&encode_authentication_ok()));
        assert!(response
            .windows(encode_parameter_status("client_encoding", "LATIN1").len())
            .any(|window| window == encode_parameter_status("client_encoding", "LATIN1")));
        assert!(response
            .windows(encode_backend_key_data(17, 23).len())
            .any(|window| window == encode_backend_key_data(17, 23)));
        assert!(response.ends_with(&encode_ready_for_query(TransactionStatus::Idle)));
    }

    #[tokio::test]
    async fn handshake_declines_ssl_then_accepts_startup() {
        let (server, mut client) = duplex(4096);
        let protocol = PostgreSqlFrontendProtocol::new("14.0".into());

        let server_task = tokio::spawn(async move { protocol.handshake(server).await });

        client.write_all(&encode_ssl_request()).await.unwrap();
        let mut ssl_response = [0; 1];
        client.read_exact(&mut ssl_response).await.unwrap();
        assert_eq!(ssl_response, [b'N']);

        client.write_all(&encode_startup_message(&[("user", "app")])).await.unwrap();
        let mut response = Vec::new();
        read_until_ready_for_query(&mut client, &mut response).await;

        let handshake = server_task.await.unwrap().unwrap();
        assert_eq!(handshake.session.user, Some("app".into()));
        assert_eq!(handshake.session.database, None);
        assert_eq!(handshake.session.charset, Some("UTF8".into()));
        assert!(response.ends_with(&encode_ready_for_query(TransactionStatus::Idle)));
    }

    #[test]
    fn decodes_simple_query_and_transaction_shortcuts() {
        let mut protocol = PostgreSqlFrontendProtocol::new("14.0".into());
        let mut session = SessionState::default();

        assert_eq!(
            protocol.decode(&encode_query_message("select 1"), &mut session),
            Ok(vec![GatewayCommand::Query { sql: "select 1".into() }])
        );

        assert_eq!(
            protocol.decode(&encode_query_message("begin"), &mut session),
            Ok(vec![GatewayCommand::Begin])
        );
        assert_eq!(session.transaction_state, TransactionState::Active);

        assert_eq!(
            protocol.decode(&encode_query_message("commit"), &mut session),
            Ok(vec![GatewayCommand::Commit])
        );
        assert_eq!(session.transaction_state, TransactionState::Idle);
    }

    #[test]
    fn decodes_client_encoding_session_updates() {
        let mut protocol = PostgreSqlFrontendProtocol::new("14.0".into());
        let mut session = SessionState::default();

        assert_eq!(
            protocol
                .decode(&encode_query_message("SET client_encoding TO 'LATIN1';"), &mut session),
            Ok(vec![GatewayCommand::Query { sql: "SET client_encoding TO 'LATIN1';".into() }])
        );
        assert_eq!(session.charset, Some("LATIN1".into()));

        assert_eq!(
            protocol.decode(&encode_query_message("set names utf8"), &mut session),
            Ok(vec![GatewayCommand::Query { sql: "set names utf8".into() }])
        );
        assert_eq!(session.charset, Some("utf8".into()));
        assert_eq!(client_encoding_from_set_query("SET client_encoding TO 'UTF8"), None);
    }

    #[test]
    fn decodes_terminate_and_sync() {
        let mut protocol = PostgreSqlFrontendProtocol::new("14.0".into());
        let mut session = SessionState::default();

        assert_eq!(
            protocol.decode(&encode_terminate_message(), &mut session),
            Ok(vec![GatewayCommand::Quit])
        );
        assert_eq!(protocol.decode(&encode_sync_message(), &mut session), Ok(vec![]));
    }

    #[test]
    fn a10_encodes_prepared_as_command_complete() {
        let mut protocol = PostgreSqlFrontendProtocol::new("14.0".into());
        let session = SessionState::default();
        let packets = protocol
            .encode(
                GatewayResponse::Prepared {
                    statement_id: "1".into(),
                    parameter_count: 0,
                },
                &session,
            )
            .unwrap();
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0][0], b'C');
        assert_eq!(packets[1], encode_ready_for_query(TransactionStatus::Idle));
        assert!(
            String::from_utf8_lossy(&packets[0]).contains("PREPARE 1"),
            "{:?}",
            packets[0]
        );
    }

    #[test]
    fn a10_describe_statement_sends_parameter_description() {
        let mut protocol = PostgreSqlFrontendProtocol::new("14.0".into());
        let mut session = SessionState::default();

        // Build Parse frame: statement "s1", query "SELECT $1, $2", 0 type oids.
        let mut body = Vec::new();
        body.extend_from_slice(b"s1\0");
        body.extend_from_slice(b"SELECT $1, $2\0");
        body.extend_from_slice(&0i16.to_be_bytes());
        let mut parse = vec![b'P'];
        let len = (body.len() + 4) as i32;
        parse.extend_from_slice(&len.to_be_bytes());
        parse.extend_from_slice(&body);
        let cmds = protocol.decode(&parse, &mut session).unwrap();
        assert_eq!(cmds.len(), 1);
        assert!(matches!(cmds[0], GatewayCommand::ClientWire { .. }));

        // Describe statement s1
        let mut dbody = vec![b'S'];
        dbody.extend_from_slice(b"s1\0");
        let mut describe = vec![b'D'];
        let dlen = (dbody.len() + 4) as i32;
        describe.extend_from_slice(&dlen.to_be_bytes());
        describe.extend_from_slice(&dbody);
        let cmds = protocol.decode(&describe, &mut session).unwrap();
        match &cmds[0] {
            GatewayCommand::ClientWire { packets } => {
                assert_eq!(packets.len(), 2);
                assert_eq!(packets[0][0], b't'); // ParameterDescription
                assert_eq!(packets[1][0], b'n'); // NoData
                // nparams = 2 (after 1-byte tag + 4-byte length)
                assert_eq!(i16::from_be_bytes([packets[0][5], packets[0][6]]), 2);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a10_bind_binary_result_format_sets_prefer_binary() {
        let mut protocol = PostgreSqlFrontendProtocol::new("14.0".into());
        let mut session = SessionState::default();

        // Parse s1 / SELECT 1
        let mut body = Vec::new();
        body.extend_from_slice(b"s1\0");
        body.extend_from_slice(b"SELECT 1\0");
        body.extend_from_slice(&0i16.to_be_bytes());
        let mut parse = vec![b'P'];
        let len = (body.len() + 4) as i32;
        parse.extend_from_slice(&len.to_be_bytes());
        parse.extend_from_slice(&body);
        protocol.decode(&parse, &mut session).unwrap();

        // Bind portal p1, statement s1, result_format=1 (binary)
        let mut bbody = Vec::new();
        bbody.extend_from_slice(b"p1\0");
        bbody.extend_from_slice(b"s1\0");
        bbody.extend_from_slice(&0i16.to_be_bytes()); // param formats
        bbody.extend_from_slice(&0i16.to_be_bytes()); // nparams
        bbody.extend_from_slice(&1i16.to_be_bytes()); // nresult_formats
        bbody.extend_from_slice(&1i16.to_be_bytes()); // binary
        let mut bind = vec![b'B'];
        let blen = (bbody.len() + 4) as i32;
        bind.extend_from_slice(&blen.to_be_bytes());
        bind.extend_from_slice(&bbody);
        protocol.decode(&bind, &mut session).unwrap();
        assert!(!session.prefer_binary_result);

        // Execute p1
        let mut ebody = Vec::new();
        ebody.extend_from_slice(b"p1\0");
        ebody.extend_from_slice(&0i32.to_be_bytes());
        let mut exec = vec![b'E'];
        let elen = (ebody.len() + 4) as i32;
        exec.extend_from_slice(&elen.to_be_bytes());
        exec.extend_from_slice(&ebody);
        let cmds = protocol.decode(&exec, &mut session).unwrap();
        assert!(matches!(cmds[0], GatewayCommand::Query { .. }));
        assert!(session.prefer_binary_result);
    }

    #[test]
    fn a10_encodes_binary_resultset_when_prefer_binary() {
        let mut protocol = PostgreSqlFrontendProtocol::new("14.0".into());
        let session = SessionState {
            prefer_binary_result: true,
            ..Default::default()
        };
        let packets = protocol
            .encode(
                GatewayResponse::ResultSet {
                    columns: vec![
                        GatewayColumn {
                            name: "id".into(),
                            data_type: "int4".into(),
                        },
                        GatewayColumn {
                            name: "flag".into(),
                            data_type: "bool".into(),
                        },
                    ],
                    rows: vec![vec![
                        GatewayValue::Integer(42),
                        GatewayValue::Boolean(true),
                    ]],
                },
                &session,
            )
            .unwrap();
        // RowDescription + DataRow + CommandComplete + Ready
        assert_eq!(packets.len(), 4);
        assert_eq!(packets[0][0], b'T');
        // format_code is last 2 bytes of each field; field ends with format 1.
        // At least one format_code=1 appears in RowDescription.
        assert!(
            packets[0].windows(2).any(|w| w == [0, 1]),
            "expected binary format_code in RowDescription: {:?}",
            packets[0]
        );
        assert_eq!(packets[1][0], b'D');
        // DataRow: ncols=2, int4 42 as 4 BE bytes, bool true as 1 byte
        // D + len(4) + ncols(2) + len1(4) + val1(4) + len2(4) + val2(1)
        let row = &packets[1];
        assert_eq!(i16::from_be_bytes([row[5], row[6]]), 2);
        assert_eq!(i32::from_be_bytes([row[7], row[8], row[9], row[10]]), 4);
        assert_eq!(i32::from_be_bytes([row[11], row[12], row[13], row[14]]), 42);
        assert_eq!(i32::from_be_bytes([row[15], row[16], row[17], row[18]]), 1);
        assert_eq!(row[19], 1); // true
        assert_eq!(packets[2][0], b'C');
        assert_eq!(packets[3][0], b'Z');
    }

    #[test]
    fn a10_binary_int8_and_null() {
        let mut protocol = PostgreSqlFrontendProtocol::new("14.0".into());
        let session = SessionState {
            prefer_binary_result: true,
            ..Default::default()
        };
        let packets = protocol
            .encode(
                GatewayResponse::ResultSet {
                    columns: vec![
                        GatewayColumn {
                            name: "big".into(),
                            data_type: "int8".into(),
                        },
                        GatewayColumn {
                            name: "n".into(),
                            data_type: "int4".into(),
                        },
                    ],
                    rows: vec![vec![GatewayValue::Integer(0x100000002), GatewayValue::Null]],
                },
                &session,
            )
            .unwrap();
        let row = &packets[1];
        assert_eq!(i16::from_be_bytes([row[5], row[6]]), 2);
        assert_eq!(i32::from_be_bytes([row[7], row[8], row[9], row[10]]), 8);
        let v = i64::from_be_bytes([
            row[11], row[12], row[13], row[14], row[15], row[16], row[17], row[18],
        ]);
        assert_eq!(v, 0x100000002);
        // NULL is -1 length
        assert_eq!(
            i32::from_be_bytes([row[19], row[20], row[21], row[22]]),
            -1
        );
    }

    #[test]
    fn a10_pg_date_epoch_helpers() {
        // 2000-01-01 → 0 days from PG epoch
        assert_eq!(days_from_pg_epoch(2000, 1, 1), 0);
        // 2000-01-02 → 1
        assert_eq!(days_from_pg_epoch(2000, 1, 2), 1);
        // 1970-01-01 → -10957
        assert_eq!(days_from_pg_epoch(1970, 1, 1), -10_957);
        // 2024-01-01: known PG date 8766 days after 2000-01-01
        // 24*365 + 6 leap days (2000,2004,2008,2012,2016,2020) = 8766
        assert_eq!(days_from_pg_epoch(2024, 1, 1), 8766);
        assert_eq!(parse_pg_date_days("2024-01-01"), Some(8766));
    }

    #[test]
    fn a10_binary_date_timestamp_time() {
        let mut protocol = PostgreSqlFrontendProtocol::new("14.0".into());
        let session = SessionState {
            prefer_binary_result: true,
            ..Default::default()
        };
        let packets = protocol
            .encode(
                GatewayResponse::ResultSet {
                    columns: vec![
                        GatewayColumn {
                            name: "d".into(),
                            data_type: "date".into(),
                        },
                        GatewayColumn {
                            name: "ts".into(),
                            data_type: "timestamp".into(),
                        },
                        GatewayColumn {
                            name: "t".into(),
                            data_type: "time".into(),
                        },
                    ],
                    rows: vec![vec![
                        GatewayValue::String("2000-01-01".into()),
                        GatewayValue::String("2000-01-01 00:00:01".into()),
                        GatewayValue::String("01:00:00".into()),
                    ]],
                },
                &session,
            )
            .unwrap();
        let row = &packets[1];
        assert_eq!(row[0], b'D');
        assert_eq!(i16::from_be_bytes([row[5], row[6]]), 3);
        // date: 4 bytes, value 0
        assert_eq!(i32::from_be_bytes([row[7], row[8], row[9], row[10]]), 4);
        assert_eq!(i32::from_be_bytes([row[11], row[12], row[13], row[14]]), 0);
        // timestamp: 8 bytes, 1_000_000 us
        assert_eq!(i32::from_be_bytes([row[15], row[16], row[17], row[18]]), 8);
        let ts = i64::from_be_bytes([
            row[19], row[20], row[21], row[22], row[23], row[24], row[25], row[26],
        ]);
        assert_eq!(ts, 1_000_000);
        // time: 8 bytes, 3600e6 us
        assert_eq!(i32::from_be_bytes([row[27], row[28], row[29], row[30]]), 8);
        let tm = i64::from_be_bytes([
            row[31], row[32], row[33], row[34], row[35], row[36], row[37], row[38],
        ]);
        assert_eq!(tm, 3_600_000_000);
    }

    #[test]
    fn a10_binary_timestamptz_offset() {
        // 2000-01-01 00:00:00+00 → 0; 2000-01-01 01:00:00+01 → 0 UTC
        assert_eq!(
            parse_pg_timestamp_us("2000-01-01 00:00:00+00", true),
            Some(0)
        );
        assert_eq!(
            parse_pg_timestamp_us("2000-01-01 01:00:00+01", true),
            Some(0)
        );
        assert_eq!(
            parse_pg_timestamp_us("2000-01-01 00:00:00Z", true),
            Some(0)
        );
        // Without allow_tz, offset rejected
        assert!(parse_pg_timestamp_us("2000-01-01 00:00:00+00", false).is_none());
        // Fractional
        assert_eq!(
            parse_pg_timestamp_us("2000-01-01 00:00:00.5", false),
            Some(500_000)
        );
    }

    #[test]
    fn a10_binary_date_invalid_fail_closed() {
        let err = gateway_value_to_pg_binary(
            &GatewayValue::String("not-a-date".into()),
            "date",
        )
        .unwrap_err();
        assert!(matches!(err, GatewayError::Protocol(_)));
    }

    #[test]
    fn encodes_ok_error_and_bye_responses() {
        let mut protocol = PostgreSqlFrontendProtocol::new("14.0".into());
        let session = SessionState::default();

        assert_eq!(
            protocol
                .encode(GatewayResponse::Ok { affected_rows: 3, last_insert_id: None }, &session),
            Ok(vec![
                encode_command_complete("OK 3"),
                encode_ready_for_query(TransactionStatus::Idle)
            ])
        );

        let error = protocol
            .encode(
                GatewayResponse::Error { code: "23505".into(), message: "duplicate".into() },
                &session,
            )
            .unwrap();
        assert_eq!(error.len(), 2);
        assert_eq!(error[0][0], b'E');
        assert!(error[0].windows(b"C23505\0".len()).any(|window| window == b"C23505\0"));
        assert_eq!(error[1], encode_ready_for_query(TransactionStatus::Idle));

        assert_eq!(protocol.encode(GatewayResponse::Bye, &session), Ok(vec![]));
    }

    #[test]
    fn encodes_resultset_response() {
        let mut protocol = PostgreSqlFrontendProtocol::new("14.0".into());
        let session = SessionState::default();

        let packets = protocol
            .encode(
                GatewayResponse::ResultSet {
                    columns: vec![
                        GatewayColumn { name: "id".into(), data_type: "int".into() },
                        GatewayColumn { name: "name".into(), data_type: "text".into() },
                    ],
                    rows: vec![
                        vec![GatewayValue::Integer(42), GatewayValue::String("Ada".into())],
                        vec![GatewayValue::Integer(43), GatewayValue::Null],
                    ],
                },
                &session,
            )
            .unwrap();

        assert_eq!(packets.len(), 5);
        assert_eq!(packets[0][0], b'T');
        assert_eq!(
            packets[1],
            encode_data_row(&[Some(b"42".to_vec()), Some(b"Ada".to_vec())]).unwrap()
        );
        assert_eq!(packets[2], encode_data_row(&[Some(b"43".to_vec()), None]).unwrap());
        assert_eq!(packets[3], encode_command_complete("SELECT 2"));
        assert_eq!(packets[4], encode_ready_for_query(TransactionStatus::Idle));
    }

    #[test]
    fn rejects_resultset_rows_with_wrong_width() {
        let mut protocol = PostgreSqlFrontendProtocol::new("14.0".into());
        let session = SessionState::default();

        let result = protocol.encode(
            GatewayResponse::ResultSet {
                columns: vec![GatewayColumn { name: "id".into(), data_type: "int".into() }],
                rows: vec![vec![]],
            },
            &session,
        );

        assert!(
            matches!(result, Err(GatewayError::Protocol(message)) if message.contains("row has 0 values"))
        );
    }

    async fn read_until_ready_for_query(
        client: &mut tokio::io::DuplexStream,
        response: &mut Vec<u8>,
    ) {
        loop {
            let mut header = [0; 5];
            client.read_exact(&mut header).await.unwrap();
            response.extend_from_slice(&header);

            let len = i32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
            let mut body = vec![0; len - 4];
            client.read_exact(&mut body).await.unwrap();
            response.extend_from_slice(&body);

            if header[0] == b'Z' {
                break;
            }
        }
    }
}
