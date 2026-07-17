use std::collections::HashMap;

use gateway_core::{
    Column as GatewayColumn, FrontendProtocolAdapter, GatewayCommand, GatewayError,
    GatewayResponse, GatewayResult, GatewayValue, ProtocolKind, SessionState, TransactionState,
};
use postgresql_protocol::{
    decode_frontend_message, decode_startup_packet, encode_authentication_ok,
    encode_backend_key_data, encode_bind_complete, encode_close_complete, encode_command_complete,
    encode_data_row, encode_error_response, encode_no_data, encode_parameter_status,
    encode_parse_complete, encode_ready_for_query, encode_row_description,
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
    /// A10: named prepared statements (Parse).
    prepared: HashMap<String, String>,
    /// A10: portals (Bind) → bound SQL ready for Query rewrite.
    portals: HashMap<String, String>,
}

impl PostgreSqlFrontendProtocol {
    pub fn new(server_version: String) -> Self {
        Self {
            server_version,
            process_id: 0,
            secret_key: 0,
            prepared: HashMap::new(),
            portals: HashMap::new(),
        }
    }

    pub fn with_backend_key(server_version: String, process_id: i32, secret_key: i32) -> Self {
        Self {
            server_version,
            process_id,
            secret_key,
            prepared: HashMap::new(),
            portals: HashMap::new(),
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
                self.prepared.insert(statement, query);
                Ok(vec![GatewayCommand::ClientWire {
                    packets: vec![encode_parse_complete()],
                }])
            }
            FrontendMessage::Bind {
                portal,
                statement,
                parameters,
            } => {
                let sql = self.prepared.get(&statement).cloned().ok_or_else(|| {
                    GatewayError::Protocol(format!(
                        "postgresql Bind: unknown statement '{statement}'"
                    ))
                })?;
                let params: Vec<GatewayValue> = parameters
                    .into_iter()
                    .map(|p| match p {
                        None => GatewayValue::Null,
                        Some(s) => GatewayValue::String(s),
                    })
                    .collect();
                let bound = bind_pg_text_params(&sql, &params)?;
                self.portals.insert(portal, bound);
                Ok(vec![GatewayCommand::ClientWire {
                    packets: vec![encode_bind_complete()],
                }])
            }
            FrontendMessage::Describe { target, name } => {
                let _ = (target, name);
                Ok(vec![GatewayCommand::ClientWire {
                    packets: vec![encode_no_data()],
                }])
            }
            FrontendMessage::Execute { portal, max_rows: _ } => {
                let sql = self.portals.get(&portal).cloned().ok_or_else(|| {
                    GatewayError::Protocol(format!(
                        "postgresql Execute: unknown portal '{portal}'"
                    ))
                })?;
                Ok(vec![GatewayCommand::Query { sql }])
            }
            FrontendMessage::Close { target, name } => {
                if target == b'S' {
                    self.prepared.remove(&name);
                } else {
                    self.portals.remove(&name);
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
            GatewayResponse::ResultSet { columns, rows } => encode_resultset(columns, rows, ready),
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
        _session: &SessionState,
    ) -> GatewayResult<Vec<Vec<u8>>> {
        encode_pg_resultset_header(columns)
    }

    fn encode_resultset_rows(
        &mut self,
        columns: &[GatewayColumn],
        rows: &[Vec<GatewayValue>],
        _session: &SessionState,
    ) -> GatewayResult<Vec<Vec<u8>>> {
        encode_pg_resultset_rows(columns, rows)
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
    let fields = columns.iter().map(gateway_column_to_postgresql_field).collect::<Vec<_>>();
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
