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
        tag => Err(ProtocolError::UnsupportedFrontendMessage(tag)),
    }
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
            decode_frontend_message(&[b'P', 0, 0, 0, 4]),
            Err(ProtocolError::UnsupportedFrontendMessage(b'P'))
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
}
