// Copyright 2022 SphereEx Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use byteorder::{BigEndian, ByteOrder};
use gateway_core::{
    Column, DialectParser, FrontendProtocolAdapter, GatewayCommand, GatewayError, GatewayResponse,
    GatewayResult, GatewayValue, ProtocolKind, SessionState, TransactionState,
};

const PROTOCOL_VERSION_3_0: u32 = 196_608;
const SSL_REQUEST_CODE: u32 = 80_877_103;
const CANCEL_REQUEST_CODE: u32 = 80_877_102;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostgreSqlStartupMessage {
    pub parameters: Vec<(String, String)>,
}

impl PostgreSqlStartupMessage {
    pub fn parameter(&self, key: &str) -> Option<&str> {
        self.parameters.iter().find_map(|(name, value)| (name == key).then_some(value.as_str()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PostgreSqlStartupAction {
    Startup(PostgreSqlStartupMessage),
    SslRequest,
    CancelRequest { process_id: u32, secret_key: u32 },
}

#[derive(Clone, Debug, Default)]
pub struct PostgreSqlFrontendProtocol {
    dialect_parser: PostgreSqlDialectParser,
}

impl PostgreSqlFrontendProtocol {
    pub fn new() -> Self {
        Self { dialect_parser: PostgreSqlDialectParser }
    }

    pub fn decode_startup(
        &mut self,
        frame: &[u8],
        session: &mut SessionState,
    ) -> GatewayResult<PostgreSqlStartupAction> {
        let payload = decode_startup_payload(frame)?;
        let code = BigEndian::read_u32(&payload[..4]);

        match code {
            PROTOCOL_VERSION_3_0 => {
                let startup = decode_startup_parameters(&payload[4..])?;
                if let Some(user) = startup.parameter("user") {
                    session.user = Some(user.to_string());
                }
                if let Some(database) = startup.parameter("database") {
                    session.database = Some(database.to_string());
                }
                Ok(PostgreSqlStartupAction::Startup(startup))
            }
            SSL_REQUEST_CODE => Ok(PostgreSqlStartupAction::SslRequest),
            CANCEL_REQUEST_CODE => {
                if payload.len() != 12 {
                    return Err(GatewayError::Protocol(format!(
                        "postgresql cancel request payload length must be 12, got {}",
                        payload.len()
                    )));
                }
                Ok(PostgreSqlStartupAction::CancelRequest {
                    process_id: BigEndian::read_u32(&payload[4..8]),
                    secret_key: BigEndian::read_u32(&payload[8..12]),
                })
            }
            other => Err(GatewayError::Protocol(format!(
                "unsupported postgresql startup protocol code {}",
                other
            ))),
        }
    }

    pub fn encode_startup_complete(&self, session: &SessionState) -> Vec<u8> {
        let mut out = encode_authentication_ok();
        out.extend_from_slice(&encode_parameter_status("server_version", "15.0"));
        out.extend_from_slice(&encode_parameter_status("client_encoding", "UTF8"));
        out.extend_from_slice(&encode_parameter_status("DateStyle", "ISO, MDY"));
        out.extend_from_slice(&encode_parameter_status("integer_datetimes", "on"));
        out.extend_from_slice(&encode_backend_key_data(0, 0));
        out.extend_from_slice(&encode_ready_for_query(session));
        out
    }

    pub fn encode_ssl_denied(&self) -> Vec<u8> {
        vec![b'N']
    }
}

#[derive(Clone, Debug, Default)]
pub struct PostgreSqlDialectParser;

impl DialectParser for PostgreSqlDialectParser {
    fn dialect(&self) -> ProtocolKind {
        ProtocolKind::PostgreSql
    }

    fn parse_query(
        &self,
        sql: String,
        session: &mut SessionState,
    ) -> GatewayResult<GatewayCommand> {
        match sql.trim().trim_end_matches(';').to_ascii_lowercase().as_str() {
            "begin" | "start transaction" => {
                session.transaction_state = TransactionState::Active;
                Ok(GatewayCommand::Begin)
            }
            "commit" => {
                session.transaction_state = TransactionState::Idle;
                Ok(GatewayCommand::Commit)
            }
            "rollback" => {
                session.transaction_state = TransactionState::Idle;
                Ok(GatewayCommand::Rollback)
            }
            _ => Ok(GatewayCommand::Query { sql }),
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
        let (message_type, payload) = decode_frontend_message(frame)?;
        match message_type {
            b'Q' => Ok(vec![self.dialect_parser.parse_query(decode_cstring(payload)?, session)?]),
            b'X' => Ok(vec![GatewayCommand::Quit]),
            other => Err(GatewayError::Unsupported(format!(
                "unsupported postgresql frontend message '{}'",
                char::from(other)
            ))),
        }
    }

    fn encode(
        &mut self,
        response: GatewayResponse,
        session: &SessionState,
    ) -> GatewayResult<Vec<Vec<u8>>> {
        let frame = match response {
            GatewayResponse::Ok { affected_rows, .. } => {
                let mut out = encode_command_complete(&format!("OK {}", affected_rows));
                out.extend_from_slice(&encode_ready_for_query(session));
                Ok(out)
            }
            GatewayResponse::Error { code, message } => {
                let mut out = encode_error_response(&code, &message);
                out.extend_from_slice(&encode_ready_for_query(session));
                Ok(out)
            }
            GatewayResponse::Pong => {
                let mut out = encode_command_complete("PONG");
                out.extend_from_slice(&encode_ready_for_query(session));
                Ok(out)
            }
            GatewayResponse::Bye => Ok(Vec::new()),
            GatewayResponse::ResultSet { columns, rows } => {
                let row_count = rows.len();
                let mut out = encode_row_description(&columns)?;
                for row in rows {
                    out.extend_from_slice(&encode_data_row(&row)?);
                }
                out.extend_from_slice(&encode_command_complete(&format!("SELECT {}", row_count)));
                out.extend_from_slice(&encode_ready_for_query(session));
                Ok(out)
            }
            GatewayResponse::Prepared { .. } => Err(GatewayError::Unsupported(
                "postgresql prepared response encoding is not implemented yet".into(),
            )),
        }?;

        Ok(if frame.is_empty() { Vec::new() } else { vec![frame] })
    }
}

fn encode_backend_message(message_type: u8, payload: &[u8]) -> Vec<u8> {
    let len = 4 + payload.len();
    let mut frame = vec![message_type, 0, 0, 0, 0];
    BigEndian::write_u32(&mut frame[1..5], len as u32);
    frame.extend_from_slice(payload);
    frame
}

fn encode_authentication_ok() -> Vec<u8> {
    let mut payload = vec![0; 4];
    BigEndian::write_u32(&mut payload, 0);
    encode_backend_message(b'R', &payload)
}

fn encode_parameter_status(name: &str, value: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(name.len() + value.len() + 2);
    payload.extend_from_slice(name.as_bytes());
    payload.push(0);
    payload.extend_from_slice(value.as_bytes());
    payload.push(0);
    encode_backend_message(b'S', &payload)
}

fn encode_backend_key_data(process_id: u32, secret_key: u32) -> Vec<u8> {
    let mut payload = vec![0; 8];
    BigEndian::write_u32(&mut payload[..4], process_id);
    BigEndian::write_u32(&mut payload[4..], secret_key);
    encode_backend_message(b'K', &payload)
}

fn encode_row_description(columns: &[Column]) -> GatewayResult<Vec<u8>> {
    let mut payload = Vec::new();
    push_i16(&mut payload, columns.len())?;

    for column in columns {
        payload.extend_from_slice(column.name.as_bytes());
        payload.push(0);
        push_i32(&mut payload, 0);
        push_i16(&mut payload, 0)?;
        push_i32(&mut payload, postgresql_type_oid(&column.data_type));
        push_i16_value(&mut payload, postgresql_type_size(&column.data_type));
        push_i32(&mut payload, -1);
        push_i16(&mut payload, 0)?;
    }

    Ok(encode_backend_message(b'T', &payload))
}

fn encode_data_row(row: &[GatewayValue]) -> GatewayResult<Vec<u8>> {
    let mut payload = Vec::new();
    push_i16(&mut payload, row.len())?;

    for value in row {
        match gateway_value_to_text(value) {
            None => push_i32(&mut payload, -1),
            Some(text) => {
                push_i32(&mut payload, checked_i32_len(text.len())?);
                payload.extend_from_slice(text.as_bytes());
            }
        }
    }

    Ok(encode_backend_message(b'D', &payload))
}

fn push_i16(payload: &mut Vec<u8>, value: usize) -> GatewayResult<()> {
    if value > i16::MAX as usize {
        return Err(GatewayError::Protocol(format!(
            "postgresql message field count {} exceeds i16 max",
            value
        )));
    }
    push_i16_value(payload, value as i16);
    Ok(())
}

fn push_i16_value(payload: &mut Vec<u8>, value: i16) {
    let mut out = [0; 2];
    BigEndian::write_i16(&mut out, value);
    payload.extend_from_slice(&out);
}

fn push_i32(payload: &mut Vec<u8>, value: i32) {
    let mut out = [0; 4];
    BigEndian::write_i32(&mut out, value);
    payload.extend_from_slice(&out);
}

fn checked_i32_len(len: usize) -> GatewayResult<i32> {
    if len > i32::MAX as usize {
        return Err(GatewayError::Protocol(format!(
            "postgresql value length {} exceeds i32 max",
            len
        )));
    }
    Ok(len as i32)
}

fn postgresql_type_oid(data_type: &str) -> i32 {
    match data_type.trim().to_ascii_lowercase().as_str() {
        "bool" | "boolean" => 16,
        "bytea" | "bytes" => 17,
        "char" => 18,
        "int2" | "smallint" => 21,
        "int4" | "integer" | "int" => 23,
        "int8" | "bigint" => 20,
        "float4" | "real" => 700,
        "float8" | "double precision" | "double" | "float" => 701,
        "numeric" | "decimal" => 1700,
        "varchar" | "character varying" => 1043,
        "date" => 1082,
        "time" | "time without time zone" => 1083,
        "timestamp" | "timestamp without time zone" => 1114,
        "timestamptz" | "timestamp with time zone" => 1184,
        "text" | "string" | _ => 25,
    }
}

fn postgresql_type_size(data_type: &str) -> i16 {
    match data_type.trim().to_ascii_lowercase().as_str() {
        "bool" | "boolean" | "char" => 1,
        "int2" | "smallint" => 2,
        "int4" | "integer" | "int" | "float4" | "real" => 4,
        "int8" | "bigint" | "float8" | "double precision" | "double" | "float" => 8,
        _ => -1,
    }
}

fn gateway_value_to_text(value: &GatewayValue) -> Option<String> {
    match value {
        GatewayValue::Null => None,
        GatewayValue::Boolean(value) => Some(if *value { "t" } else { "f" }.into()),
        GatewayValue::Integer(value) => Some(value.to_string()),
        GatewayValue::UnsignedInteger(value) => Some(value.to_string()),
        GatewayValue::Float(value) => Some(value.to_string()),
        GatewayValue::Decimal(value) | GatewayValue::String(value) => Some(value.clone()),
        GatewayValue::Bytes(value) => Some(format_postgresql_bytea_hex(value)),
    }
}

fn format_postgresql_bytea_hex(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(2 + value.len() * 2);
    out.push_str("\\x");
    for byte in value {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn encode_command_complete(tag: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(tag.len() + 1);
    payload.extend_from_slice(tag.as_bytes());
    payload.push(0);
    encode_backend_message(b'C', &payload)
}

fn encode_error_response(code: &str, message: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    push_error_field(&mut payload, b'S', "ERROR");
    push_error_field(&mut payload, b'C', code);
    push_error_field(&mut payload, b'M', message);
    payload.push(0);
    encode_backend_message(b'E', &payload)
}

fn push_error_field(payload: &mut Vec<u8>, field_type: u8, value: &str) {
    payload.push(field_type);
    payload.extend_from_slice(value.as_bytes());
    payload.push(0);
}

fn encode_ready_for_query(session: &SessionState) -> Vec<u8> {
    encode_backend_message(b'Z', &[transaction_status(session)])
}

fn transaction_status(session: &SessionState) -> u8 {
    match session.transaction_state {
        TransactionState::Idle => b'I',
        TransactionState::Active => b'T',
        TransactionState::Failed => b'E',
    }
}

fn decode_startup_payload(frame: &[u8]) -> GatewayResult<&[u8]> {
    if frame.len() < 8 {
        return Err(GatewayError::Protocol(
            "postgresql startup message is shorter than length + protocol".into(),
        ));
    }

    let len = BigEndian::read_u32(&frame[..4]) as usize;
    if len < 8 {
        return Err(GatewayError::Protocol(format!(
            "postgresql startup message has invalid length {}",
            len
        )));
    }
    if frame.len() < len {
        return Err(GatewayError::Protocol(format!(
            "postgresql startup message length {} exceeds frame length {}",
            len,
            frame.len()
        )));
    }

    Ok(&frame[4..len])
}

fn decode_startup_parameters(payload: &[u8]) -> GatewayResult<PostgreSqlStartupMessage> {
    if payload.last() != Some(&0) {
        return Err(GatewayError::Protocol(
            "postgresql startup parameters are missing final null terminator".into(),
        ));
    }

    let mut fields = Vec::new();
    let mut offset = 0;
    while offset < payload.len() {
        let Some(key_end) = payload[offset..].iter().position(|byte| *byte == 0) else {
            return Err(GatewayError::Protocol(
                "postgresql startup parameter key is missing null terminator".into(),
            ));
        };
        if key_end == 0 {
            break;
        }
        let key =
            decode_utf8("postgresql startup parameter key", &payload[offset..offset + key_end])?;
        offset += key_end + 1;

        let Some(value_end) = payload[offset..].iter().position(|byte| *byte == 0) else {
            return Err(GatewayError::Protocol(format!(
                "postgresql startup parameter '{}' is missing value terminator",
                key
            )));
        };
        let value = decode_utf8(
            "postgresql startup parameter value",
            &payload[offset..offset + value_end],
        )?;
        offset += value_end + 1;
        fields.push((key, value));
        if offset == payload.len() {
            return Err(GatewayError::Protocol(
                "postgresql startup parameters are missing final null terminator".into(),
            ));
        }
    }

    Ok(PostgreSqlStartupMessage { parameters: fields })
}

fn decode_utf8(context: &str, value: &[u8]) -> GatewayResult<String> {
    std::str::from_utf8(value).map(|value| value.to_string()).map_err(|error| {
        GatewayError::Protocol(format!("invalid {} utf8 payload: {}", context, error))
    })
}

fn decode_frontend_message(frame: &[u8]) -> GatewayResult<(u8, &[u8])> {
    if frame.len() < 5 {
        return Err(GatewayError::Protocol(
            "postgresql frontend message is shorter than type + length".into(),
        ));
    }

    let message_type = frame[0];
    let len = BigEndian::read_u32(&frame[1..5]) as usize;
    if len < 4 {
        return Err(GatewayError::Protocol(format!(
            "postgresql frontend message has invalid length {}",
            len
        )));
    }

    let expected = len + 1;
    if frame.len() < expected {
        return Err(GatewayError::Protocol(format!(
            "postgresql frontend message length {} exceeds frame length {}",
            len,
            frame.len()
        )));
    }

    Ok((message_type, &frame[5..expected]))
}

fn decode_cstring(payload: &[u8]) -> GatewayResult<String> {
    let Some(end) = payload.iter().position(|byte| *byte == 0) else {
        return Err(GatewayError::Protocol(
            "postgresql query payload is missing null terminator".into(),
        ));
    };

    decode_utf8("postgresql", &payload[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query_frame(sql: &str) -> Vec<u8> {
        let len = 4 + sql.len() + 1;
        let mut frame = vec![b'Q', 0, 0, 0, 0];
        BigEndian::write_u32(&mut frame[1..5], len as u32);
        frame.extend_from_slice(sql.as_bytes());
        frame.push(0);
        frame
    }

    fn terminate_frame() -> Vec<u8> {
        vec![b'X', 0, 0, 0, 4]
    }

    fn startup_frame(parameters: &[(&str, &str)]) -> Vec<u8> {
        let mut frame = vec![0, 0, 0, 0, 0, 3, 0, 0];
        for (key, value) in parameters {
            frame.extend_from_slice(key.as_bytes());
            frame.push(0);
            frame.extend_from_slice(value.as_bytes());
            frame.push(0);
        }
        frame.push(0);
        let len = frame.len();
        BigEndian::write_u32(&mut frame[..4], len as u32);
        frame
    }

    fn startup_code_frame(code: u32) -> Vec<u8> {
        let mut frame = vec![0, 0, 0, 8, 0, 0, 0, 0];
        BigEndian::write_u32(&mut frame[4..8], code);
        frame
    }

    fn cancel_request_frame(process_id: u32, secret_key: u32) -> Vec<u8> {
        let mut frame = vec![0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        BigEndian::write_u32(&mut frame[4..8], CANCEL_REQUEST_CODE);
        BigEndian::write_u32(&mut frame[8..12], process_id);
        BigEndian::write_u32(&mut frame[12..16], secret_key);
        frame
    }

    fn message(message_type: u8, payload: &[u8]) -> Vec<u8> {
        let len = 4 + payload.len();
        let mut frame = vec![message_type, 0, 0, 0, 0];
        BigEndian::write_u32(&mut frame[1..5], len as u32);
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn decodes_simple_query() {
        let mut adapter = PostgreSqlFrontendProtocol::new();
        let mut session = SessionState::default();

        let commands = adapter.decode(&query_frame("select 1"), &mut session);

        assert_eq!(adapter.protocol(), ProtocolKind::PostgreSql);
        assert_eq!(commands, Ok(vec![GatewayCommand::Query { sql: "select 1".into() }]));
    }

    #[test]
    fn decodes_transaction_query_and_updates_session() {
        let mut adapter = PostgreSqlFrontendProtocol::new();
        let mut session = SessionState::default();

        assert_eq!(
            adapter.decode(&query_frame("BEGIN;"), &mut session),
            Ok(vec![GatewayCommand::Begin])
        );
        assert_eq!(session.transaction_state, TransactionState::Active);
        assert_eq!(
            adapter.decode(&query_frame("COMMIT"), &mut session),
            Ok(vec![GatewayCommand::Commit])
        );
        assert_eq!(session.transaction_state, TransactionState::Idle);
    }

    #[test]
    fn decodes_terminate() {
        let mut adapter = PostgreSqlFrontendProtocol::new();
        let mut session = SessionState::default();

        assert_eq!(
            adapter.decode(&terminate_frame(), &mut session),
            Ok(vec![GatewayCommand::Quit])
        );
    }

    #[test]
    fn rejects_short_query_frame() {
        let mut adapter = PostgreSqlFrontendProtocol::new();
        let mut session = SessionState::default();

        let error = adapter.decode(&[b'Q', 0, 0], &mut session).unwrap_err();

        assert!(matches!(error, GatewayError::Protocol(message) if message.contains("shorter")));
    }

    #[test]
    fn decodes_startup_message_and_updates_session() {
        let mut adapter = PostgreSqlFrontendProtocol::new();
        let mut session = SessionState::default();

        let action = adapter.decode_startup(
            &startup_frame(&[
                ("user", "app"),
                ("database", "orders"),
                ("application_name", "psql"),
            ]),
            &mut session,
        );

        assert_eq!(session.user, Some("app".into()));
        assert_eq!(session.database, Some("orders".into()));
        assert_eq!(
            action,
            Ok(PostgreSqlStartupAction::Startup(PostgreSqlStartupMessage {
                parameters: vec![
                    ("user".into(), "app".into()),
                    ("database".into(), "orders".into()),
                    ("application_name".into(), "psql".into()),
                ],
            }))
        );
    }

    #[test]
    fn decodes_ssl_and_cancel_startup_requests() {
        let mut adapter = PostgreSqlFrontendProtocol::new();
        let mut session = SessionState::default();

        assert_eq!(
            adapter.decode_startup(&startup_code_frame(SSL_REQUEST_CODE), &mut session),
            Ok(PostgreSqlStartupAction::SslRequest)
        );
        assert_eq!(adapter.encode_ssl_denied(), vec![b'N']);

        assert_eq!(
            adapter.decode_startup(&cancel_request_frame(42, 7), &mut session),
            Ok(PostgreSqlStartupAction::CancelRequest { process_id: 42, secret_key: 7 })
        );
    }

    #[test]
    fn rejects_malformed_startup_messages() {
        let mut adapter = PostgreSqlFrontendProtocol::new();
        let mut session = SessionState::default();

        let error = adapter.decode_startup(&[0, 0, 0, 7, 0, 3, 0], &mut session).unwrap_err();

        assert!(matches!(error, GatewayError::Protocol(message) if message.contains("shorter")));

        let mut missing_final_null = startup_frame(&[("user", "app")]);
        missing_final_null.pop();
        let len = missing_final_null.len() as u32;
        BigEndian::write_u32(&mut missing_final_null[..4], len);

        let error = adapter.decode_startup(&missing_final_null, &mut session).unwrap_err();

        assert!(matches!(error, GatewayError::Protocol(message) if message.contains("final null")));
    }

    #[test]
    fn encodes_ok_as_command_complete_and_ready_for_query() {
        let mut adapter = PostgreSqlFrontendProtocol::new();
        let session = SessionState::default();

        let encoded = adapter
            .encode(GatewayResponse::Ok { affected_rows: 3, last_insert_id: None }, &session);

        let mut expected = message(b'C', b"OK 3\0");
        expected.extend_from_slice(&message(b'Z', b"I"));
        assert_eq!(encoded, Ok(vec![expected]));
    }

    #[test]
    fn encodes_error_response_and_ready_for_query() {
        let mut adapter = PostgreSqlFrontendProtocol::new();
        let session = SessionState::default();

        let encoded = adapter.encode(
            GatewayResponse::Error { code: "XX000".into(), message: "boom".into() },
            &session,
        );

        let mut expected = message(b'E', b"SERROR\0CXX000\0Mboom\0\0");
        expected.extend_from_slice(&message(b'Z', b"I"));
        assert_eq!(encoded, Ok(vec![expected]));
    }

    #[test]
    fn encodes_ready_for_query_transaction_status() {
        let mut adapter = PostgreSqlFrontendProtocol::new();
        let mut session = SessionState::default();
        session.transaction_state = TransactionState::Active;

        let encoded = adapter.encode(GatewayResponse::Pong, &session);

        let mut expected = message(b'C', b"PONG\0");
        expected.extend_from_slice(&message(b'Z', b"T"));
        assert_eq!(encoded, Ok(vec![expected]));
    }

    #[test]
    fn encodes_bye_as_empty_response() {
        let mut adapter = PostgreSqlFrontendProtocol::new();
        let session = SessionState::default();

        assert_eq!(adapter.encode(GatewayResponse::Bye, &session), Ok(Vec::new()));
    }

    #[test]
    fn encodes_resultset_as_row_description_data_rows_and_ready_for_query() {
        let mut adapter = PostgreSqlFrontendProtocol::new();
        let session = SessionState::default();

        let encoded = adapter.encode(
            GatewayResponse::ResultSet {
                columns: vec![
                    Column { name: "id".into(), data_type: "int4".into() },
                    Column { name: "name".into(), data_type: "text".into() },
                    Column { name: "active".into(), data_type: "bool".into() },
                    Column { name: "payload".into(), data_type: "bytea".into() },
                ],
                rows: vec![
                    vec![
                        GatewayValue::Integer(1),
                        GatewayValue::String("alice".into()),
                        GatewayValue::Boolean(true),
                        GatewayValue::Bytes(vec![0xde, 0xad]),
                    ],
                    vec![
                        GatewayValue::Integer(2),
                        GatewayValue::Null,
                        GatewayValue::Boolean(false),
                        GatewayValue::Bytes(Vec::new()),
                    ],
                ],
            },
            &session,
        );

        let mut row_description = Vec::new();
        push_test_i16(&mut row_description, 4);
        push_test_column(&mut row_description, "id", 23, 4);
        push_test_column(&mut row_description, "name", 25, -1);
        push_test_column(&mut row_description, "active", 16, 1);
        push_test_column(&mut row_description, "payload", 17, -1);

        let mut first_row = Vec::new();
        push_test_i16(&mut first_row, 4);
        push_test_value(&mut first_row, Some("1"));
        push_test_value(&mut first_row, Some("alice"));
        push_test_value(&mut first_row, Some("t"));
        push_test_value(&mut first_row, Some("\\xdead"));

        let mut second_row = Vec::new();
        push_test_i16(&mut second_row, 4);
        push_test_value(&mut second_row, Some("2"));
        push_test_value(&mut second_row, None);
        push_test_value(&mut second_row, Some("f"));
        push_test_value(&mut second_row, Some("\\x"));

        let mut expected = message(b'T', &row_description);
        expected.extend_from_slice(&message(b'D', &first_row));
        expected.extend_from_slice(&message(b'D', &second_row));
        expected.extend_from_slice(&message(b'C', b"SELECT 2\0"));
        expected.extend_from_slice(&message(b'Z', b"I"));
        assert_eq!(encoded, Ok(vec![expected]));
    }

    fn push_test_column(payload: &mut Vec<u8>, name: &str, type_oid: i32, type_size: i16) {
        payload.extend_from_slice(name.as_bytes());
        payload.push(0);
        push_test_i32(payload, 0);
        push_test_i16(payload, 0);
        push_test_i32(payload, type_oid);
        push_test_i16(payload, type_size);
        push_test_i32(payload, -1);
        push_test_i16(payload, 0);
    }

    fn push_test_value(payload: &mut Vec<u8>, value: Option<&str>) {
        match value {
            Some(value) => {
                push_test_i32(payload, value.len() as i32);
                payload.extend_from_slice(value.as_bytes());
            }
            None => push_test_i32(payload, -1),
        }
    }

    fn push_test_i16(payload: &mut Vec<u8>, value: i16) {
        let mut out = [0; 2];
        BigEndian::write_i16(&mut out, value);
        payload.extend_from_slice(&out);
    }

    fn push_test_i32(payload: &mut Vec<u8>, value: i32) {
        let mut out = [0; 4];
        BigEndian::write_i32(&mut out, value);
        payload.extend_from_slice(&out);
    }

    #[test]
    fn encodes_startup_complete_response() {
        let adapter = PostgreSqlFrontendProtocol::new();
        let session = SessionState::default();

        let encoded = adapter.encode_startup_complete(&session);

        let mut expected = message(b'R', &[0, 0, 0, 0]);
        expected.extend_from_slice(&message(b'S', b"server_version\015.0\0"));
        expected.extend_from_slice(&message(b'S', b"client_encoding\0UTF8\0"));
        expected.extend_from_slice(&message(b'S', b"DateStyle\0ISO, MDY\0"));
        expected.extend_from_slice(&message(b'S', b"integer_datetimes\0on\0"));
        expected.extend_from_slice(&message(b'K', &[0, 0, 0, 0, 0, 0, 0, 0]));
        expected.extend_from_slice(&message(b'Z', b"I"));
        assert_eq!(encoded, expected);
    }
}
