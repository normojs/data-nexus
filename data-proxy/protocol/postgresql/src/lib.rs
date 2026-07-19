use std::{collections::BTreeMap, error::Error, fmt};

use byteorder::{BigEndian, ByteOrder};

pub const PROTOCOL_VERSION_3: i32 = 196_608;
pub const SSL_REQUEST_CODE: i32 = 80_877_103;
pub const CANCEL_REQUEST_CODE: i32 = 80_877_102;
pub const MAX_STARTUP_PACKET_LEN: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    InvalidLength { expected: Option<usize>, actual: usize },
    InvalidProtocolVersion(i32),
    UnsupportedFrontendMessage(u8),
    InvalidUtf8(String),
    MissingTerminator,
    MalformedStartupParameters,
    MalformedCString,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected: Some(expected), actual } => {
                write!(f, "invalid postgresql packet length: expected {}, got {}", expected, actual)
            }
            Self::InvalidLength { expected: None, actual } => {
                write!(f, "invalid postgresql packet length: {}", actual)
            }
            Self::InvalidProtocolVersion(version) => {
                write!(f, "unsupported postgresql protocol version {}", version)
            }
            Self::UnsupportedFrontendMessage(tag) => {
                write!(f, "unsupported postgresql frontend message '{}'", *tag as char)
            }
            Self::InvalidUtf8(error) => write!(f, "invalid postgresql utf8: {}", error),
            Self::MissingTerminator => {
                write!(f, "postgresql startup parameters are missing a null terminator")
            }
            Self::MalformedStartupParameters => {
                write!(f, "malformed postgresql startup parameters")
            }
            Self::MalformedCString => write!(f, "malformed postgresql cstring"),
        }
    }
}

impl Error for ProtocolError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupPacket {
    Startup(StartupMessage),
    SslRequest,
    CancelRequest { process_id: i32, secret_key: i32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupMessage {
    pub protocol_version: i32,
    pub parameters: BTreeMap<String, String>,
}

impl StartupMessage {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.parameters.get(name).map(String::as_str)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrontendMessage {
    Query(String),
    Terminate,
    Sync,
    /// Extended query: Parse (statement name, query, param type oids).
    Parse {
        statement: String,
        query: String,
        param_types: Vec<i32>,
    },
    /// Extended query: Bind (portal, statement, params).
    ///
    /// A10: text params always; `result_formats` records client-requested column
    /// formats (0=text, 1=binary). Empty/`[0]` → all text; `[1]` → all binary;
    /// per-column list of length N applies to N columns.
    Bind {
        portal: String,
        statement: String,
        parameters: Vec<Option<String>>,
        result_formats: Vec<i16>,
    },
    /// Extended query: Describe statement ('S') or portal ('P').
    Describe { target: u8, name: String },
    /// Extended query: Execute portal.
    Execute { portal: String, max_rows: i32 },
    /// Extended query: Close statement ('S') or portal ('P').
    Close { target: u8, name: String },
    /// Extended query: Flush (no-op for gateway; treated like empty).
    Flush,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDescription {
    pub name: String,
    pub type_oid: i32,
    pub type_size: i16,
    pub type_modifier: i32,
    pub format_code: i16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionStatus {
    Idle,
    InTransaction,
    Failed,
}

impl TransactionStatus {
    pub fn as_byte(self) -> u8 {
        match self {
            Self::Idle => b'I',
            Self::InTransaction => b'T',
            Self::Failed => b'E',
        }
    }
}

pub fn decode_frontend_message(frame: &[u8]) -> Result<FrontendMessage, ProtocolError> {
    if frame.len() < 5 {
        return Err(ProtocolError::InvalidLength { expected: None, actual: frame.len() });
    }

    let declared_len = BigEndian::read_i32(&frame[1..5]);
    if declared_len < 4 {
        return Err(ProtocolError::InvalidLength {
            expected: None,
            actual: declared_len.max(0) as usize,
        });
    }

    let expected_len = declared_len as usize + 1;
    if expected_len != frame.len() {
        return Err(ProtocolError::InvalidLength {
            expected: Some(expected_len),
            actual: frame.len(),
        });
    }

    let body = &frame[5..];
    match frame[0] {
        b'Q' => Ok(FrontendMessage::Query(decode_single_cstring(body)?)),
        b'X' => {
            require_empty_body(body)?;
            Ok(FrontendMessage::Terminate)
        }
        b'S' => {
            require_empty_body(body)?;
            Ok(FrontendMessage::Sync)
        }
        b'H' => {
            require_empty_body(body)?;
            Ok(FrontendMessage::Flush)
        }
        b'P' => decode_parse_body(body),
        b'B' => decode_bind_body(body),
        b'D' => decode_describe_or_close_body(body, true),
        b'E' => decode_execute_body(body),
        b'C' => decode_describe_or_close_body(body, false),
        tag => Err(ProtocolError::UnsupportedFrontendMessage(tag)),
    }
}

fn decode_parse_body(body: &[u8]) -> Result<FrontendMessage, ProtocolError> {
    let (statement, rest) = split_cstring(body)?;
    let (query, rest) = split_cstring(rest)?;
    if rest.len() < 2 {
        return Err(ProtocolError::InvalidLength {
            expected: Some(2),
            actual: rest.len(),
        });
    }
    let nparams = BigEndian::read_i16(&rest[0..2]) as usize;
    let mut offset = 2;
    let mut param_types = Vec::with_capacity(nparams);
    for _ in 0..nparams {
        if rest.len() < offset + 4 {
            return Err(ProtocolError::InvalidLength {
                expected: Some(offset + 4),
                actual: rest.len(),
            });
        }
        param_types.push(BigEndian::read_i32(&rest[offset..offset + 4]));
        offset += 4;
    }
    if offset != rest.len() {
        return Err(ProtocolError::InvalidLength {
            expected: Some(offset),
            actual: rest.len(),
        });
    }
    Ok(FrontendMessage::Parse {
        statement,
        query,
        param_types,
    })
}

fn decode_bind_body(body: &[u8]) -> Result<FrontendMessage, ProtocolError> {
    let (portal, rest) = split_cstring(body)?;
    let (statement, rest) = split_cstring(rest)?;
    if rest.len() < 2 {
        return Err(ProtocolError::InvalidLength {
            expected: Some(2),
            actual: rest.len(),
        });
    }
    let nformats = BigEndian::read_i16(&rest[0..2]) as usize;
    let mut offset = 2;
    let mut param_formats = Vec::with_capacity(nformats);
    for _ in 0..nformats {
        if rest.len() < offset + 2 {
            return Err(ProtocolError::InvalidLength {
                expected: Some(offset + 2),
                actual: rest.len(),
            });
        }
        let fmt = BigEndian::read_i16(&rest[offset..offset + 2]);
        // 0 = text, 1 = binary (A10: accept both; binary decoded heuristically below).
        if fmt != 0 && fmt != 1 {
            return Err(ProtocolError::UnsupportedFrontendMessage(b'B'));
        }
        param_formats.push(fmt);
        offset += 2;
    }
    if rest.len() < offset + 2 {
        return Err(ProtocolError::InvalidLength {
            expected: Some(offset + 2),
            actual: rest.len(),
        });
    }
    let nparams = BigEndian::read_i16(&rest[offset..offset + 2]) as usize;
    offset += 2;
    let mut parameters = Vec::with_capacity(nparams);
    for i in 0..nparams {
        if rest.len() < offset + 4 {
            return Err(ProtocolError::InvalidLength {
                expected: Some(offset + 4),
                actual: rest.len(),
            });
        }
        let len = BigEndian::read_i32(&rest[offset..offset + 4]);
        offset += 4;
        if len < 0 {
            parameters.push(None);
            continue;
        }
        let len = len as usize;
        if rest.len() < offset + len {
            return Err(ProtocolError::InvalidLength {
                expected: Some(offset + len),
                actual: rest.len(),
            });
        }
        let raw = &rest[offset..offset + len];
        // PG: if nformats==0 all text; if nformats==1 apply that format to all;
        // if nformats==nparams use per-param format.
        let fmt = if param_formats.is_empty() {
            0
        } else if param_formats.len() == 1 {
            param_formats[0]
        } else {
            *param_formats.get(i).unwrap_or(&0)
        };
        let value = if fmt == 0 {
            // Text format. Some clients still send raw binary for small integers when
            // ParameterDescription advertised unspecified/text OIDs — detect NULs.
            if raw.iter().any(|&b| b == 0) && matches!(raw.len(), 2 | 4 | 8) {
                Some(decode_pg_binary_param_to_text(raw)?)
            } else {
                Some(
                    std::str::from_utf8(raw)
                        .map_err(|e| ProtocolError::InvalidUtf8(e.to_string()))?
                        .to_string(),
                )
            }
        } else {
            // Binary → text representation for gateway IR (QueryParams binds as text/typed).
            Some(decode_pg_binary_param_to_text(raw)?)
        };
        parameters.push(value);
        offset += len;
    }
    if rest.len() < offset + 2 {
        return Err(ProtocolError::InvalidLength {
            expected: Some(offset + 2),
            actual: rest.len(),
        });
    }
    let nresult_formats = BigEndian::read_i16(&rest[offset..offset + 2]) as usize;
    offset += 2;
    let mut result_formats = Vec::with_capacity(nresult_formats);
    for _ in 0..nresult_formats {
        if rest.len() < offset + 2 {
            return Err(ProtocolError::InvalidLength {
                expected: Some(offset + 2),
                actual: rest.len(),
            });
        }
        let fmt = BigEndian::read_i16(&rest[offset..offset + 2]);
        if fmt != 0 && fmt != 1 {
            return Err(ProtocolError::UnsupportedFrontendMessage(b'B'));
        }
        result_formats.push(fmt);
        offset += 2;
    }
    if offset != rest.len() {
        return Err(ProtocolError::InvalidLength {
            expected: Some(offset),
            actual: rest.len(),
        });
    }
    Ok(FrontendMessage::Bind {
        portal,
        statement,
        parameters,
        result_formats,
    })
}

/// A10: turn common binary Bind values into text for QueryParams IR.
/// Length-based heuristic: 2→i16, 4→i32, 8→i64, 1→bool, else UTF-8 or error.
fn decode_pg_binary_param_to_text(raw: &[u8]) -> Result<String, ProtocolError> {
    match raw.len() {
        0 => Ok(String::new()),
        1 => Ok((raw[0] != 0).to_string()),
        // psycopg often binds small ints as INT2 binary (2 bytes).
        2 => Ok(BigEndian::read_i16(raw).to_string()),
        4 => Ok(BigEndian::read_i32(raw).to_string()),
        8 => Ok(BigEndian::read_i64(raw).to_string()),
        _ => {
            if let Ok(s) = std::str::from_utf8(raw) {
                Ok(s.to_string())
            } else {
                // Fail closed on opaque binary we cannot represent as text bind.
                Err(ProtocolError::UnsupportedFrontendMessage(b'B'))
            }
        }
    }
}

fn decode_describe_or_close_body(
    body: &[u8],
    is_describe: bool,
) -> Result<FrontendMessage, ProtocolError> {
    if body.is_empty() {
        return Err(ProtocolError::InvalidLength {
            expected: Some(1),
            actual: 0,
        });
    }
    let target = body[0];
    let (name, rest) = split_cstring(&body[1..])?;
    if !rest.is_empty() {
        return Err(ProtocolError::InvalidLength {
            expected: Some(0),
            actual: rest.len(),
        });
    }
    if is_describe {
        Ok(FrontendMessage::Describe { target, name })
    } else {
        Ok(FrontendMessage::Close { target, name })
    }
}

fn decode_execute_body(body: &[u8]) -> Result<FrontendMessage, ProtocolError> {
    let (portal, rest) = split_cstring(body)?;
    if rest.len() != 4 {
        return Err(ProtocolError::InvalidLength {
            expected: Some(4),
            actual: rest.len(),
        });
    }
    let max_rows = BigEndian::read_i32(rest);
    Ok(FrontendMessage::Execute { portal, max_rows })
}

fn split_cstring(input: &[u8]) -> Result<(String, &[u8]), ProtocolError> {
    let nul = input
        .iter()
        .position(|&b| b == 0)
        .ok_or(ProtocolError::MalformedCString)?;
    let s = std::str::from_utf8(&input[..nul])
        .map_err(|e| ProtocolError::InvalidUtf8(e.to_string()))?
        .to_string();
    Ok((s, &input[nul + 1..]))
}

pub fn encode_parse_complete() -> Vec<u8> {
    encode_message(b'1', &[])
}

pub fn encode_bind_complete() -> Vec<u8> {
    encode_message(b'2', &[])
}

pub fn encode_close_complete() -> Vec<u8> {
    encode_message(b'3', &[])
}

pub fn encode_no_data() -> Vec<u8> {
    encode_message(b'n', &[])
}

pub fn encode_parameter_description(type_oids: &[i32]) -> Vec<u8> {
    let mut body = Vec::with_capacity(2 + type_oids.len() * 4);
    body.extend_from_slice(&(type_oids.len() as i16).to_be_bytes());
    for oid in type_oids {
        body.extend_from_slice(&oid.to_be_bytes());
    }
    encode_message(b't', &body)
}

pub fn decode_startup_packet(frame: &[u8]) -> Result<StartupPacket, ProtocolError> {
    if frame.len() < 8 || frame.len() > MAX_STARTUP_PACKET_LEN {
        return Err(ProtocolError::InvalidLength { expected: None, actual: frame.len() });
    }

    let declared_len = BigEndian::read_i32(&frame[0..4]);
    if declared_len < 8 {
        return Err(ProtocolError::InvalidLength {
            expected: None,
            actual: declared_len.max(0) as usize,
        });
    }

    let declared_len = declared_len as usize;
    if declared_len != frame.len() {
        return Err(ProtocolError::InvalidLength {
            expected: Some(declared_len),
            actual: frame.len(),
        });
    }

    let code = BigEndian::read_i32(&frame[4..8]);
    match code {
        SSL_REQUEST_CODE => {
            if declared_len != 8 {
                return Err(ProtocolError::InvalidLength {
                    expected: Some(8),
                    actual: declared_len,
                });
            }
            Ok(StartupPacket::SslRequest)
        }
        CANCEL_REQUEST_CODE => {
            if declared_len != 16 {
                return Err(ProtocolError::InvalidLength {
                    expected: Some(16),
                    actual: declared_len,
                });
            }
            Ok(StartupPacket::CancelRequest {
                process_id: BigEndian::read_i32(&frame[8..12]),
                secret_key: BigEndian::read_i32(&frame[12..16]),
            })
        }
        PROTOCOL_VERSION_3 => Ok(StartupPacket::Startup(StartupMessage {
            protocol_version: PROTOCOL_VERSION_3,
            parameters: decode_startup_parameters(&frame[8..])?,
        })),
        version => Err(ProtocolError::InvalidProtocolVersion(version)),
    }
}

pub fn encode_startup_message(parameters: &[(&str, &str)]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&PROTOCOL_VERSION_3.to_be_bytes());
    for (name, value) in parameters {
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        body.extend_from_slice(value.as_bytes());
        body.push(0);
    }
    body.push(0);
    encode_untagged_packet(&body)
}

pub fn encode_ssl_request() -> Vec<u8> {
    encode_untagged_packet(&SSL_REQUEST_CODE.to_be_bytes())
}

pub fn encode_query_message(sql: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(sql.len() + 1);
    body.extend_from_slice(sql.as_bytes());
    body.push(0);
    encode_message(b'Q', &body)
}

pub fn encode_terminate_message() -> Vec<u8> {
    encode_message(b'X', &[])
}

pub fn encode_sync_message() -> Vec<u8> {
    encode_message(b'S', &[])
}

pub fn encode_cancel_request(process_id: i32, secret_key: i32) -> Vec<u8> {
    let mut body = Vec::with_capacity(12);
    body.extend_from_slice(&CANCEL_REQUEST_CODE.to_be_bytes());
    body.extend_from_slice(&process_id.to_be_bytes());
    body.extend_from_slice(&secret_key.to_be_bytes());
    encode_untagged_packet(&body)
}

pub fn encode_authentication_ok() -> Vec<u8> {
    encode_message(b'R', &0i32.to_be_bytes())
}

pub fn encode_parameter_status(name: &str, value: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(name.len() + value.len() + 2);
    body.extend_from_slice(name.as_bytes());
    body.push(0);
    body.extend_from_slice(value.as_bytes());
    body.push(0);
    encode_message(b'S', &body)
}

pub fn encode_backend_key_data(process_id: i32, secret_key: i32) -> Vec<u8> {
    let mut body = Vec::with_capacity(8);
    body.extend_from_slice(&process_id.to_be_bytes());
    body.extend_from_slice(&secret_key.to_be_bytes());
    encode_message(b'K', &body)
}

pub fn encode_command_complete(tag: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(tag.len() + 1);
    body.extend_from_slice(tag.as_bytes());
    body.push(0);
    encode_message(b'C', &body)
}

pub fn encode_row_description(fields: &[FieldDescription]) -> Result<Vec<u8>, ProtocolError> {
    let mut body = Vec::new();
    push_i16(&mut body, checked_i16(fields.len())?);
    for field in fields {
        body.extend_from_slice(field.name.as_bytes());
        body.push(0);
        body.extend_from_slice(&0i32.to_be_bytes());
        body.extend_from_slice(&0i16.to_be_bytes());
        body.extend_from_slice(&field.type_oid.to_be_bytes());
        body.extend_from_slice(&field.type_size.to_be_bytes());
        body.extend_from_slice(&field.type_modifier.to_be_bytes());
        body.extend_from_slice(&field.format_code.to_be_bytes());
    }
    Ok(encode_message(b'T', &body))
}

pub fn encode_data_row(values: &[Option<Vec<u8>>]) -> Result<Vec<u8>, ProtocolError> {
    let mut body = Vec::new();
    push_i16(&mut body, checked_i16(values.len())?);
    for value in values {
        match value {
            Some(value) => {
                body.extend_from_slice(&checked_i32(value.len())?.to_be_bytes());
                body.extend_from_slice(value);
            }
            None => body.extend_from_slice(&(-1i32).to_be_bytes()),
        }
    }
    Ok(encode_message(b'D', &body))
}

pub fn encode_ready_for_query(status: TransactionStatus) -> Vec<u8> {
    encode_message(b'Z', &[status.as_byte()])
}

pub fn encode_error_response(severity: &str, code: &str, message: &str) -> Vec<u8> {
    let mut body = Vec::new();
    push_error_field(&mut body, b'S', severity);
    push_error_field(&mut body, b'C', code);
    push_error_field(&mut body, b'M', message);
    body.push(0);
    encode_message(b'E', &body)
}

fn decode_startup_parameters(payload: &[u8]) -> Result<BTreeMap<String, String>, ProtocolError> {
    if payload.last() != Some(&0) {
        return Err(ProtocolError::MissingTerminator);
    }

    let mut parameters = BTreeMap::new();
    let mut offset = 0;
    while offset < payload.len() {
        let key_end = find_null(payload, offset).ok_or(ProtocolError::MissingTerminator)?;
        if key_end == offset {
            if key_end + 1 != payload.len() {
                return Err(ProtocolError::MalformedStartupParameters);
            }
            return Ok(parameters);
        }

        let value_start = key_end + 1;
        let value_end = find_null(payload, value_start).ok_or(ProtocolError::MissingTerminator)?;
        let key = decode_utf8(&payload[offset..key_end])?;
        let value = decode_utf8(&payload[value_start..value_end])?;
        parameters.insert(key, value);
        offset = value_end + 1;
    }

    Err(ProtocolError::MissingTerminator)
}

fn decode_single_cstring(payload: &[u8]) -> Result<String, ProtocolError> {
    let end = find_null(payload, 0).ok_or(ProtocolError::MissingTerminator)?;
    if end + 1 != payload.len() {
        return Err(ProtocolError::MalformedCString);
    }
    decode_utf8(&payload[..end])
}

fn decode_utf8(bytes: &[u8]) -> Result<String, ProtocolError> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|error| ProtocolError::InvalidUtf8(error.to_string()))
}

fn find_null(payload: &[u8], offset: usize) -> Option<usize> {
    payload[offset..].iter().position(|byte| *byte == 0).map(|relative| offset + relative)
}

fn require_empty_body(body: &[u8]) -> Result<(), ProtocolError> {
    if body.is_empty() {
        Ok(())
    } else {
        Err(ProtocolError::InvalidLength { expected: Some(5), actual: body.len() + 5 })
    }
}

fn checked_i16(value: usize) -> Result<i16, ProtocolError> {
    i16::try_from(value).map_err(|_| ProtocolError::InvalidLength { expected: None, actual: value })
}

fn checked_i32(value: usize) -> Result<i32, ProtocolError> {
    i32::try_from(value).map_err(|_| ProtocolError::InvalidLength { expected: None, actual: value })
}

fn push_i16(body: &mut Vec<u8>, value: i16) {
    body.extend_from_slice(&value.to_be_bytes());
}

fn encode_untagged_packet(body: &[u8]) -> Vec<u8> {
    let len = (body.len() + 4) as i32;
    let mut packet = Vec::with_capacity(len as usize);
    packet.extend_from_slice(&len.to_be_bytes());
    packet.extend_from_slice(body);
    packet
}

fn encode_message(tag: u8, body: &[u8]) -> Vec<u8> {
    let len = (body.len() + 4) as i32;
    let mut packet = Vec::with_capacity(body.len() + 5);
    packet.push(tag);
    packet.extend_from_slice(&len.to_be_bytes());
    packet.extend_from_slice(body);
    packet
}

fn push_error_field(body: &mut Vec<u8>, tag: u8, value: &str) {
    body.push(tag);
    body.extend_from_slice(value.as_bytes());
    body.push(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_startup_message_parameters() {
        let frame = encode_startup_message(&[
            ("user", "app"),
            ("database", "orders"),
            ("application_name", "psql"),
        ]);

        let decoded = decode_startup_packet(&frame);

        assert_eq!(
            decoded,
            Ok(StartupPacket::Startup(StartupMessage {
                protocol_version: PROTOCOL_VERSION_3,
                parameters: BTreeMap::from([
                    ("application_name".into(), "psql".into()),
                    ("database".into(), "orders".into()),
                    ("user".into(), "app".into()),
                ]),
            }))
        );
    }

    #[test]
    fn decodes_ssl_and_cancel_requests() {
        assert_eq!(decode_startup_packet(&encode_ssl_request()), Ok(StartupPacket::SslRequest));
        assert_eq!(
            decode_startup_packet(&encode_cancel_request(7, 11)),
            Ok(StartupPacket::CancelRequest { process_id: 7, secret_key: 11 })
        );
    }

    #[test]
    fn rejects_malformed_startup_parameters() {
        let mut body = Vec::new();
        body.extend_from_slice(&PROTOCOL_VERSION_3.to_be_bytes());
        body.extend_from_slice(b"user\0app\0");
        let mut frame = Vec::new();
        frame.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
        frame.extend_from_slice(&body);

        assert_eq!(decode_startup_packet(&frame), Err(ProtocolError::MissingTerminator));
    }

    #[test]
    fn encodes_handshake_messages() {
        assert_eq!(encode_authentication_ok(), vec![b'R', 0, 0, 0, 8, 0, 0, 0, 0]);
        assert_eq!(
            encode_parameter_status("server_version", "14.0"),
            b"S\0\0\0\x18server_version\014.0\0".to_vec()
        );
        assert_eq!(
            encode_backend_key_data(7, 11),
            vec![b'K', 0, 0, 0, 12, 0, 0, 0, 7, 0, 0, 0, 11]
        );
        assert_eq!(encode_ready_for_query(TransactionStatus::Idle), vec![b'Z', 0, 0, 0, 5, b'I']);
    }

    #[test]
    fn decodes_frontend_query_terminate_and_sync() {
        assert_eq!(
            decode_frontend_message(&encode_query_message("select 1")),
            Ok(FrontendMessage::Query("select 1".into()))
        );
        assert_eq!(
            decode_frontend_message(&encode_terminate_message()),
            Ok(FrontendMessage::Terminate)
        );
        assert_eq!(decode_frontend_message(&encode_sync_message()), Ok(FrontendMessage::Sync));
    }

    #[test]
    fn rejects_unsupported_frontend_message() {
        assert_eq!(
            decode_frontend_message(&[b'Z', 0, 0, 0, 4]),
            Err(ProtocolError::UnsupportedFrontendMessage(b'Z'))
        );
    }

    #[test]
    fn decodes_empty_parse_message() {
        let mut body = vec![0, 0]; // statement="", query=""
        body.extend_from_slice(&0i16.to_be_bytes());
        let mut frame = vec![b'P'];
        let len = (body.len() + 4) as i32;
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(&body);
        assert_eq!(
            decode_frontend_message(&frame),
            Ok(FrontendMessage::Parse {
                statement: String::new(),
                query: String::new(),
                param_types: vec![],
            })
        );
    }

    #[test]
    fn encodes_command_complete() {
        assert_eq!(encode_command_complete("SELECT 2"), b"C\0\0\0\rSELECT 2\0".to_vec());
    }

    #[test]
    fn encodes_row_description() {
        let encoded = encode_row_description(&[FieldDescription {
            name: "id".into(),
            type_oid: 23,
            type_size: 4,
            type_modifier: -1,
            format_code: 0,
        }])
        .unwrap();

        assert_eq!(encoded[0], b'T');
        assert_eq!(&encoded[1..5], &27i32.to_be_bytes());
        assert_eq!(&encoded[5..7], &1i16.to_be_bytes());
        assert_eq!(&encoded[7..10], b"id\0");
        assert_eq!(&encoded[16..20], &23i32.to_be_bytes());
    }

    #[test]
    fn encodes_data_row() {
        assert_eq!(
            encode_data_row(&[Some(b"42".to_vec()), None]).unwrap(),
            vec![b'D', 0, 0, 0, 16, 0, 2, 0, 0, 0, 2, b'4', b'2', 255, 255, 255, 255]
        );
    }

    #[test]
    fn a10_decodes_bind_result_formats_binary() {
        // portal="", statement="s", 0 param formats, 0 params, 1 result format = binary
        let mut body = Vec::new();
        body.push(0); // portal
        body.extend_from_slice(b"s\0");
        body.extend_from_slice(&0i16.to_be_bytes()); // nformats
        body.extend_from_slice(&0i16.to_be_bytes()); // nparams
        body.extend_from_slice(&1i16.to_be_bytes()); // nresult_formats
        body.extend_from_slice(&1i16.to_be_bytes()); // binary
        let mut frame = vec![b'B'];
        let len = (body.len() + 4) as i32;
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(&body);
        assert_eq!(
            decode_frontend_message(&frame),
            Ok(FrontendMessage::Bind {
                portal: String::new(),
                statement: "s".into(),
                parameters: vec![],
                result_formats: vec![1],
            })
        );
    }

    #[test]
    fn a10_decodes_bind_result_formats_text_default() {
        let mut body = Vec::new();
        body.push(0);
        body.extend_from_slice(b"s\0");
        body.extend_from_slice(&0i16.to_be_bytes());
        body.extend_from_slice(&0i16.to_be_bytes());
        body.extend_from_slice(&0i16.to_be_bytes()); // no result formats
        let mut frame = vec![b'B'];
        let len = (body.len() + 4) as i32;
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(&body);
        match decode_frontend_message(&frame).unwrap() {
            FrontendMessage::Bind { result_formats, .. } => assert!(result_formats.is_empty()),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a10_decodes_bind_binary_i32_param_to_text() {
        // psycopg often binds integers as binary (fmt=1, len=4).
        let mut body = Vec::new();
        body.push(0); // portal ""
        body.extend_from_slice(b"s1\0");
        body.extend_from_slice(&1i16.to_be_bytes()); // nformats=1
        body.extend_from_slice(&1i16.to_be_bytes()); // binary
        body.extend_from_slice(&1i16.to_be_bytes()); // nparams=1
        body.extend_from_slice(&4i32.to_be_bytes()); // value len
        body.extend_from_slice(&0i32.to_be_bytes()); // i32 0
        body.extend_from_slice(&0i16.to_be_bytes()); // nresult_formats
        let mut frame = vec![b'B'];
        let len = (body.len() + 4) as i32;
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(&body);
        assert_eq!(
            decode_frontend_message(&frame),
            Ok(FrontendMessage::Bind {
                portal: String::new(),
                statement: "s1".into(),
                parameters: vec![Some("0".into())],
                result_formats: vec![],
            })
        );
    }

    #[test]
    fn a10_decodes_bind_binary_i16_param_to_text() {
        // psycopg often binds small ints as INT2 binary (fmt=1, len=2).
        let mut body = Vec::new();
        body.push(0);
        body.extend_from_slice(b"s1\0");
        body.extend_from_slice(&1i16.to_be_bytes());
        body.extend_from_slice(&1i16.to_be_bytes());
        body.extend_from_slice(&1i16.to_be_bytes());
        body.extend_from_slice(&2i32.to_be_bytes());
        body.extend_from_slice(&0i16.to_be_bytes());
        body.extend_from_slice(&0i16.to_be_bytes());
        let mut frame = vec![b'B'];
        let len = (body.len() + 4) as i32;
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(&body);
        assert_eq!(
            decode_frontend_message(&frame),
            Ok(FrontendMessage::Bind {
                portal: String::new(),
                statement: "s1".into(),
                parameters: vec![Some("0".into())],
                result_formats: vec![],
            })
        );
    }

    #[test]
    fn a10_decodes_text_format_nul_i16_as_binary() {
        // Some clients advertise text format codes but still send binary INT2 bytes
        // (contains NUL) when ParameterDescription used unspecified/text OIDs.
        let mut body = Vec::new();
        body.push(0);
        body.extend_from_slice(b"s1\0");
        body.extend_from_slice(&0i16.to_be_bytes()); // nformats=0 → text
        body.extend_from_slice(&1i16.to_be_bytes());
        body.extend_from_slice(&2i32.to_be_bytes());
        body.extend_from_slice(&0i16.to_be_bytes()); // binary 0 as i16
        body.extend_from_slice(&0i16.to_be_bytes());
        let mut frame = vec![b'B'];
        let len = (body.len() + 4) as i32;
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(&body);
        assert_eq!(
            decode_frontend_message(&frame),
            Ok(FrontendMessage::Bind {
                portal: String::new(),
                statement: "s1".into(),
                parameters: vec![Some("0".into())],
                result_formats: vec![],
            })
        );
    }
}
