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

pub const PROTOCOL_VERSION_3_0: u32 = 196_608;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    InvalidFrame(String),
    InvalidUtf8(String),
    UnsupportedMessage(u8),
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFrame(message) => {
                write!(formatter, "invalid postgresql frame: {}", message)
            }
            Self::InvalidUtf8(message) => write!(formatter, "invalid postgresql utf8: {}", message),
            Self::UnsupportedMessage(message_type) => write!(
                formatter,
                "unsupported postgresql backend message '{}'",
                char::from(*message_type)
            ),
        }
    }
}

impl std::error::Error for ProtocolError {}

pub type ProtocolResult<T> = Result<T, ProtocolError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupParameter {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDescription {
    pub name: String,
    pub table_oid: i32,
    pub column_attribute_number: i16,
    pub type_oid: i32,
    pub type_size: i16,
    pub type_modifier: i32,
    pub format_code: i16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendMessage {
    AuthenticationOk,
    AuthenticationCleartextPassword,
    AuthenticationMd5Password { salt: [u8; 4] },
    ParameterStatus { name: String, value: String },
    BackendKeyData { process_id: i32, secret_key: i32 },
    RowDescription { fields: Vec<FieldDescription> },
    DataRow { values: Vec<Option<Vec<u8>>> },
    CommandComplete { tag: String },
    ErrorResponse { fields: Vec<(u8, String)> },
    ReadyForQuery { transaction_status: u8 },
}

pub fn encode_startup_message(parameters: &[StartupParameter]) -> Vec<u8> {
    let mut frame = vec![0, 0, 0, 0, 0, 0, 0, 0];
    BigEndian::write_u32(&mut frame[4..8], PROTOCOL_VERSION_3_0);
    for parameter in parameters {
        frame.extend_from_slice(parameter.name.as_bytes());
        frame.push(0);
        frame.extend_from_slice(parameter.value.as_bytes());
        frame.push(0);
    }
    frame.push(0);
    let len = frame.len() as u32;
    BigEndian::write_u32(&mut frame[..4], len);
    frame
}

pub fn encode_query(sql: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(sql.len() + 1);
    payload.extend_from_slice(sql.as_bytes());
    payload.push(0);
    encode_frontend_message(b'Q', &payload)
}

pub fn encode_password_message(password: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(password.len() + 1);
    payload.extend_from_slice(password.as_bytes());
    payload.push(0);
    encode_frontend_message(b'p', &payload)
}

pub fn decode_backend_message(frame: &[u8]) -> ProtocolResult<BackendMessage> {
    let (message_type, payload) = decode_typed_message(frame)?;
    match message_type {
        b'R' => decode_authentication(payload),
        b'S' => decode_parameter_status(payload),
        b'K' => decode_backend_key_data(payload),
        b'T' => decode_row_description(payload),
        b'D' => decode_data_row(payload),
        b'C' => Ok(BackendMessage::CommandComplete { tag: decode_cstring(payload)? }),
        b'E' => decode_error_response(payload),
        b'Z' => {
            if payload.len() != 1 {
                return Err(ProtocolError::InvalidFrame(format!(
                    "ReadyForQuery payload length must be 1, got {}",
                    payload.len()
                )));
            }
            Ok(BackendMessage::ReadyForQuery { transaction_status: payload[0] })
        }
        other => Err(ProtocolError::UnsupportedMessage(other)),
    }
}

fn encode_frontend_message(message_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![message_type, 0, 0, 0, 0];
    BigEndian::write_u32(&mut frame[1..5], (payload.len() + 4) as u32);
    frame.extend_from_slice(payload);
    frame
}

fn decode_typed_message(frame: &[u8]) -> ProtocolResult<(u8, &[u8])> {
    if frame.len() < 5 {
        return Err(ProtocolError::InvalidFrame("message is shorter than type + length".into()));
    }
    let len = BigEndian::read_u32(&frame[1..5]) as usize;
    if len < 4 {
        return Err(ProtocolError::InvalidFrame(format!("invalid length {}", len)));
    }
    if frame.len() < len + 1 {
        return Err(ProtocolError::InvalidFrame(format!(
            "declared length {} exceeds frame length {}",
            len,
            frame.len()
        )));
    }
    Ok((frame[0], &frame[5..len + 1]))
}

fn decode_authentication(payload: &[u8]) -> ProtocolResult<BackendMessage> {
    if payload.len() < 4 {
        return Err(ProtocolError::InvalidFrame(
            "authentication payload is shorter than auth code".into(),
        ));
    }
    match BigEndian::read_u32(&payload[..4]) {
        0 => Ok(BackendMessage::AuthenticationOk),
        3 => Ok(BackendMessage::AuthenticationCleartextPassword),
        5 => {
            if payload.len() != 8 {
                return Err(ProtocolError::InvalidFrame(format!(
                    "md5 authentication payload length must be 8, got {}",
                    payload.len()
                )));
            }
            let mut salt = [0; 4];
            salt.copy_from_slice(&payload[4..8]);
            Ok(BackendMessage::AuthenticationMd5Password { salt })
        }
        code => Err(ProtocolError::InvalidFrame(format!(
            "unsupported authentication request code {}",
            code
        ))),
    }
}

fn decode_parameter_status(payload: &[u8]) -> ProtocolResult<BackendMessage> {
    let (name, offset) = decode_cstring_at(payload, 0)?;
    let (value, offset) = decode_cstring_at(payload, offset)?;
    ensure_exhausted(payload, offset, "ParameterStatus")?;
    Ok(BackendMessage::ParameterStatus { name, value })
}

fn decode_backend_key_data(payload: &[u8]) -> ProtocolResult<BackendMessage> {
    if payload.len() != 8 {
        return Err(ProtocolError::InvalidFrame(format!(
            "BackendKeyData payload length must be 8, got {}",
            payload.len()
        )));
    }
    Ok(BackendMessage::BackendKeyData {
        process_id: BigEndian::read_i32(&payload[..4]),
        secret_key: BigEndian::read_i32(&payload[4..8]),
    })
}

fn decode_row_description(payload: &[u8]) -> ProtocolResult<BackendMessage> {
    let (field_count, mut offset) = read_i16(payload, 0)?;
    if field_count < 0 {
        return Err(ProtocolError::InvalidFrame(format!(
            "negative row description field count {}",
            field_count
        )));
    }

    let mut fields = Vec::with_capacity(field_count as usize);
    for _ in 0..field_count {
        let (name, next) = decode_cstring_at(payload, offset)?;
        offset = next;
        let (table_oid, next) = read_i32(payload, offset)?;
        offset = next;
        let (column_attribute_number, next) = read_i16(payload, offset)?;
        offset = next;
        let (type_oid, next) = read_i32(payload, offset)?;
        offset = next;
        let (type_size, next) = read_i16(payload, offset)?;
        offset = next;
        let (type_modifier, next) = read_i32(payload, offset)?;
        offset = next;
        let (format_code, next) = read_i16(payload, offset)?;
        offset = next;

        fields.push(FieldDescription {
            name,
            table_oid,
            column_attribute_number,
            type_oid,
            type_size,
            type_modifier,
            format_code,
        });
    }
    ensure_exhausted(payload, offset, "RowDescription")?;
    Ok(BackendMessage::RowDescription { fields })
}

fn decode_data_row(payload: &[u8]) -> ProtocolResult<BackendMessage> {
    let (column_count, mut offset) = read_i16(payload, 0)?;
    if column_count < 0 {
        return Err(ProtocolError::InvalidFrame(format!(
            "negative data row column count {}",
            column_count
        )));
    }

    let mut values = Vec::with_capacity(column_count as usize);
    for _ in 0..column_count {
        let (len, next) = read_i32(payload, offset)?;
        offset = next;
        if len == -1 {
            values.push(None);
            continue;
        }
        if len < -1 {
            return Err(ProtocolError::InvalidFrame(format!(
                "invalid data row value length {}",
                len
            )));
        }
        let end = offset + len as usize;
        if payload.len() < end {
            return Err(ProtocolError::InvalidFrame(format!(
                "data row value length {} exceeds remaining payload {}",
                len,
                payload.len().saturating_sub(offset)
            )));
        }
        values.push(Some(payload[offset..end].to_vec()));
        offset = end;
    }
    ensure_exhausted(payload, offset, "DataRow")?;
    Ok(BackendMessage::DataRow { values })
}

fn decode_error_response(payload: &[u8]) -> ProtocolResult<BackendMessage> {
    let mut fields = Vec::new();
    let mut offset = 0;
    while offset < payload.len() {
        let field_type = payload[offset];
        offset += 1;
        if field_type == 0 {
            ensure_exhausted(payload, offset, "ErrorResponse")?;
            return Ok(BackendMessage::ErrorResponse { fields });
        }
        let (value, next) = decode_cstring_at(payload, offset)?;
        fields.push((field_type, value));
        offset = next;
    }

    Err(ProtocolError::InvalidFrame("ErrorResponse is missing final terminator".into()))
}

fn decode_cstring(payload: &[u8]) -> ProtocolResult<String> {
    let (value, offset) = decode_cstring_at(payload, 0)?;
    ensure_exhausted(payload, offset, "cstring")?;
    Ok(value)
}

fn decode_cstring_at(payload: &[u8], offset: usize) -> ProtocolResult<(String, usize)> {
    if offset > payload.len() {
        return Err(ProtocolError::InvalidFrame(format!(
            "cstring offset {} exceeds payload length {}",
            offset,
            payload.len()
        )));
    }
    let Some(end) = payload[offset..].iter().position(|byte| *byte == 0) else {
        return Err(ProtocolError::InvalidFrame("cstring is missing null terminator".into()));
    };
    let end = offset + end;
    let value = std::str::from_utf8(&payload[offset..end])
        .map(|value| value.to_string())
        .map_err(|error| ProtocolError::InvalidUtf8(error.to_string()))?;
    Ok((value, end + 1))
}

fn read_i16(payload: &[u8], offset: usize) -> ProtocolResult<(i16, usize)> {
    let end = offset + 2;
    if payload.len() < end {
        return Err(ProtocolError::InvalidFrame(format!(
            "cannot read i16 at offset {} from payload length {}",
            offset,
            payload.len()
        )));
    }
    Ok((BigEndian::read_i16(&payload[offset..end]), end))
}

fn read_i32(payload: &[u8], offset: usize) -> ProtocolResult<(i32, usize)> {
    let end = offset + 4;
    if payload.len() < end {
        return Err(ProtocolError::InvalidFrame(format!(
            "cannot read i32 at offset {} from payload length {}",
            offset,
            payload.len()
        )));
    }
    Ok((BigEndian::read_i32(&payload[offset..end]), end))
}

fn ensure_exhausted(payload: &[u8], offset: usize, context: &str) -> ProtocolResult<()> {
    if offset != payload.len() {
        return Err(ProtocolError::InvalidFrame(format!(
            "{} has {} trailing bytes",
            context,
            payload.len() - offset
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend_message(message_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![message_type, 0, 0, 0, 0];
        BigEndian::write_u32(&mut frame[1..5], (payload.len() + 4) as u32);
        frame.extend_from_slice(payload);
        frame
    }

    fn push_i16(payload: &mut Vec<u8>, value: i16) {
        let mut out = [0; 2];
        BigEndian::write_i16(&mut out, value);
        payload.extend_from_slice(&out);
    }

    fn push_i32(payload: &mut Vec<u8>, value: i32) {
        let mut out = [0; 4];
        BigEndian::write_i32(&mut out, value);
        payload.extend_from_slice(&out);
    }

    #[test]
    fn encodes_startup_and_query_messages() {
        let startup = encode_startup_message(&[
            StartupParameter { name: "user".into(), value: "app".into() },
            StartupParameter { name: "database".into(), value: "orders".into() },
        ]);

        assert_eq!(startup, b"\0\0\0\"\0\x03\0\0user\0app\0database\0orders\0\0".to_vec());
        assert_eq!(encode_query("select 1"), b"Q\0\0\0\rselect 1\0".to_vec());
        assert_eq!(encode_password_message("secret"), b"p\0\0\0\x0bsecret\0".to_vec());
    }

    #[test]
    fn decodes_authentication_messages() {
        assert_eq!(
            decode_backend_message(&backend_message(b'R', &[0, 0, 0, 0])),
            Ok(BackendMessage::AuthenticationOk)
        );
        assert_eq!(
            decode_backend_message(&backend_message(b'R', &[0, 0, 0, 3])),
            Ok(BackendMessage::AuthenticationCleartextPassword)
        );
        assert_eq!(
            decode_backend_message(&backend_message(b'R', &[0, 0, 0, 5, 1, 2, 3, 4])),
            Ok(BackendMessage::AuthenticationMd5Password { salt: [1, 2, 3, 4] })
        );
    }

    #[test]
    fn decodes_status_and_ready_messages() {
        assert_eq!(
            decode_backend_message(&backend_message(b'S', b"server_version\015.0\0")),
            Ok(BackendMessage::ParameterStatus {
                name: "server_version".into(),
                value: "15.0".into(),
            })
        );
        assert_eq!(
            decode_backend_message(&backend_message(b'K', &[0, 0, 0, 42, 0, 0, 0, 7])),
            Ok(BackendMessage::BackendKeyData { process_id: 42, secret_key: 7 })
        );
        assert_eq!(
            decode_backend_message(&backend_message(b'Z', b"I")),
            Ok(BackendMessage::ReadyForQuery { transaction_status: b'I' })
        );
    }

    #[test]
    fn decodes_row_description_and_data_row() {
        let mut row_description = Vec::new();
        push_i16(&mut row_description, 2);
        row_description.extend_from_slice(b"id\0");
        push_i32(&mut row_description, 0);
        push_i16(&mut row_description, 0);
        push_i32(&mut row_description, 23);
        push_i16(&mut row_description, 4);
        push_i32(&mut row_description, -1);
        push_i16(&mut row_description, 0);
        row_description.extend_from_slice(b"name\0");
        push_i32(&mut row_description, 0);
        push_i16(&mut row_description, 0);
        push_i32(&mut row_description, 25);
        push_i16(&mut row_description, -1);
        push_i32(&mut row_description, -1);
        push_i16(&mut row_description, 0);

        assert_eq!(
            decode_backend_message(&backend_message(b'T', &row_description)),
            Ok(BackendMessage::RowDescription {
                fields: vec![
                    FieldDescription {
                        name: "id".into(),
                        table_oid: 0,
                        column_attribute_number: 0,
                        type_oid: 23,
                        type_size: 4,
                        type_modifier: -1,
                        format_code: 0,
                    },
                    FieldDescription {
                        name: "name".into(),
                        table_oid: 0,
                        column_attribute_number: 0,
                        type_oid: 25,
                        type_size: -1,
                        type_modifier: -1,
                        format_code: 0,
                    },
                ],
            })
        );

        let mut data_row = Vec::new();
        push_i16(&mut data_row, 2);
        push_i32(&mut data_row, 1);
        data_row.extend_from_slice(b"1");
        push_i32(&mut data_row, -1);

        assert_eq!(
            decode_backend_message(&backend_message(b'D', &data_row)),
            Ok(BackendMessage::DataRow { values: vec![Some(b"1".to_vec()), None] })
        );
    }

    #[test]
    fn decodes_command_complete_and_error_response() {
        assert_eq!(
            decode_backend_message(&backend_message(b'C', b"SELECT 1\0")),
            Ok(BackendMessage::CommandComplete { tag: "SELECT 1".into() })
        );
        assert_eq!(
            decode_backend_message(&backend_message(b'E', b"SERROR\0C42601\0Msyntax\0\0")),
            Ok(BackendMessage::ErrorResponse {
                fields: vec![
                    (b'S', "ERROR".into()),
                    (b'C', "42601".into()),
                    (b'M', "syntax".into())
                ],
            })
        );
    }

    #[test]
    fn rejects_malformed_backend_messages() {
        assert!(matches!(
            decode_backend_message(&[b'Z', 0, 0, 0, 3]),
            Err(ProtocolError::InvalidFrame(message)) if message.contains("invalid length")
        ));
        assert!(matches!(
            decode_backend_message(&backend_message(b'D', &[0, 1, 0, 0, 0, 8, b'a'])),
            Err(ProtocolError::InvalidFrame(message)) if message.contains("exceeds")
        ));
    }
}
