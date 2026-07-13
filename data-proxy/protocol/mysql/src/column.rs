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

use bytes::{Buf, BufMut, BytesMut};

use crate::{
    err::ProtocolError,
    mysql_const::ColumnType,
    util::{try_get_length, BufExt, BufMutExt},
};

#[derive(Debug, Clone)]
pub struct ColumnInfo {
    pub schema: Option<String>,
    pub table_name: Option<String>,
    pub column_name: String,
    pub charset: u8,
    pub column_length: u32,
    pub column_type: ColumnType,
    pub column_flag: u16,
    pub decimals: u8,
}

pub fn try_decode_columns<T: AsRef<[u8]>>(buf: T) -> Result<Vec<ColumnInfo>, ProtocolError> {
    let mut buf = buf.as_ref();
    let mut columns = vec![];
    while buf.has_remaining() {
        if buf.len() < 4 {
            return Err(invalid_column_packet("decode_columns.header", buf));
        }

        let payload_length = try_get_length(buf)?;
        if buf.len() < 4 + payload_length {
            return Err(invalid_column_packet("decode_columns.payload", buf));
        }

        columns.push(try_decode_column(&buf[4..4 + payload_length])?);
        buf = &buf[4 + payload_length..];
    }

    Ok(columns)
}

pub fn decode_columns<T: AsRef<[u8]>>(buf: T) -> Vec<ColumnInfo> {
    try_decode_columns(buf).expect("column definitions should be valid")
}

pub fn try_decode_column<T: AsRef<[u8]>>(buf: T) -> Result<ColumnInfo, ProtocolError> {
    let mut buf = buf.as_ref();
    buf.try_decode_column()
}

pub fn decode_column<T: AsRef<[u8]>>(buf: T) -> ColumnInfo {
    try_decode_column(buf).expect("column definition should be valid")
}

//Remove the column of consecutive indexes in the chunk
pub fn remove_column_by_idx(columns: &mut BytesMut, chunk: &[usize]) {
    try_remove_column_by_idx(columns, chunk).expect("column packets should be valid")
}

pub fn try_remove_column_by_idx(
    columns: &mut BytesMut,
    chunk: &[usize],
) -> Result<(), ProtocolError> {
    let mut pos = 0;
    let start_idx = chunk.first().unwrap_or_else(|| &0);

    for _ in 0..*start_idx {
        pos = next_column_packet_offset(columns, pos)?;
    }

    let start = pos;
    // Get the end offset before mutating the buffer, so errors leave it intact.
    for _ in chunk.iter() {
        if pos == columns.len() {
            break;
        }
        pos = next_column_packet_offset(columns, pos)?;
    }

    let mut remain_part = columns.split_off(start);
    remain_part.advance(pos - start);
    columns.unsplit(remain_part);
    Ok(())
}

pub fn add_column_by_idx<T: AsRef<[u8]>>(columns: &mut BytesMut, idx: usize, add: T) {
    try_add_column_by_idx(columns, idx, add).expect("column packets should be valid")
}

pub fn try_add_column_by_idx<T: AsRef<[u8]>>(
    columns: &mut BytesMut,
    idx: usize,
    add: T,
) -> Result<(), ProtocolError> {
    let mut pos = 0;
    for _ in 0..idx {
        pos = next_column_packet_offset(columns, pos)?;
    }

    let remain_part = columns.split_off(pos);
    columns.put_slice(add.as_ref());
    columns.put_slice(&remain_part);
    Ok(())
}

/// ColumnBuf trait， Inherit BufExt
/// For example:
/// let mut buf = BytesMut::new(&[0x01,0x02]);
/// buf.decode_column();
pub trait Column: BufExt {
    fn try_decode_columns(&mut self) -> Result<Vec<ColumnInfo>, ProtocolError> {
        let mut columns = vec![];
        while self.has_remaining() {
            if self.remaining() < 4 {
                return Err(invalid_column_packet("decode_columns.header", &[]));
            }

            let mut header = [0; 4];
            self.copy_to_slice(&mut header);
            let payload_length = try_get_length(&header)?;
            if self.remaining() < payload_length {
                return Err(invalid_column_packet("decode_columns.payload", &[]));
            }

            let payload = self.copy_to_bytes(payload_length);
            columns.push(try_decode_column(payload.as_ref())?);
        }
        Ok(columns)
    }

    fn decode_columns(&mut self) -> Vec<ColumnInfo> {
        self.try_decode_columns().expect("column definitions should be valid")
    }

    // Decode column , see https://dev.mysql.com/doc/internals/en/com-query-response.html#packet-Protocol::ColumnDefinition41
    fn try_decode_column(&mut self) -> Result<ColumnInfo, ProtocolError> {
        //Catalog
        self.try_skip_lenc_length()?;

        //Schema
        let mut schema: Option<String> = None;
        let (str_bytes, is_null) = self.try_get_lenc_str_bytes()?;
        if !is_null {
            schema = Some(decode_column_string("schema", str_bytes)?);
        }

        //Table -- virtual table-name
        let mut table_name: Option<String> = None;
        let (str_bytes, is_null) = self.try_get_lenc_str_bytes()?;

        if !is_null {
            table_name = Some(decode_column_string("table_name", str_bytes)?);
        }

        //Org table -- physical table-name
        self.try_skip_lenc_length()?;

        //Name -- virtual column name
        let (str_bytes, _) = self.try_get_lenc_str_bytes()?;
        let column_name = decode_column_string("column_name", str_bytes)?;

        //Org name -- physical column name
        self.try_skip_lenc_length()?;

        if self.remaining() < 13 {
            return Err(ProtocolError::InvalidPacket {
                method: "decode_column.fixed_fields".to_string(),
                data: vec![],
            });
        }

        //Next length  -- length of the following fields (always 0x0c)
        self.get_u8();

        //Character set -- is the column character set and is defined in Protocol::CharacterSet.
        let charset = self.get_u8();
        self.get_u8();

        //Column length -- maximum length of the field
        let column_length = self.get_u32_le();

        //Column type
        let column_type = ColumnType::from(self.get_u8());

        //Flags -- flags
        let column_flag = self.get_u16_le();

        //decimals -- max shown decimal digits
        let decimals = self.get_u8();

        //filter - [00] [00]
        self.get_u16_le();

        Ok(ColumnInfo {
            schema,
            table_name,
            column_name,
            charset,
            column_length,
            column_type,
            column_flag,
            decimals,
        })
    }

    fn decode_column(&mut self) -> ColumnInfo {
        self.try_decode_column().expect("column definition should be valid")
    }
}

fn decode_column_string(method: &str, data: Vec<u8>) -> Result<String, ProtocolError> {
    String::from_utf8(data.clone()).map_err(|_| ProtocolError::InvalidPacket {
        method: format!("decode_column.{method}"),
        data,
    })
}

fn next_column_packet_offset(columns: &[u8], offset: usize) -> Result<usize, ProtocolError> {
    let header = columns
        .get(offset..offset + 4)
        .ok_or_else(|| invalid_column_packet("column_packet.header", columns))?;
    let payload_length = try_get_length(header)?;
    let end = offset
        .checked_add(4)
        .and_then(|start| start.checked_add(payload_length))
        .ok_or_else(|| invalid_column_packet("column_packet.length", header))?;

    if end > columns.len() {
        return Err(invalid_column_packet("column_packet.payload", &columns[offset..]));
    }

    Ok(end)
}

fn invalid_column_packet(method: &str, data: &[u8]) -> ProtocolError {
    ProtocolError::InvalidPacket { method: method.to_string(), data: data.to_vec() }
}

impl ColumnInfo {
    pub fn encode<T: BufMutExt>(&self, buf: &mut T) {
        // Catalog
        buf.put_lenc_int(3, false);
        buf.put_slice(b"def");

        // Schema
        if let Some(schema) = &self.schema {
            buf.put_lenc_int(schema.len() as u64, false);
            buf.put_slice(schema.as_bytes());
        } else {
            buf.put_lenc_int(0, true);
        }

        // Table name
        if let Some(name) = &self.table_name {
            buf.put_lenc_int(name.len() as u64, false);
            buf.put_slice(name.as_bytes());
        } else {
            buf.put_lenc_int(0, true);
        }

        //Org table -- physical table-name
        buf.put_lenc_int(0, true);

        //Name -- virtual column name
        buf.put_lenc_int(self.column_name.len() as u64, false);
        buf.put_slice(self.column_name.as_bytes());

        //Org name -- physical column name
        buf.put_lenc_int(0, true);

        //Next length  -- length of the following fields (always 0x0c)
        buf.put_u8(0x0c);

        //Character set -- is the column character set and is defined in Protocol::CharacterSet.
        buf.put_u8(self.charset);
        buf.put_u8(0);

        //Column length -- maximum length of the field
        buf.put_u32_le(self.column_length);

        //Column type
        buf.put_u8(self.column_type as u8);

        //Flags -- flags
        buf.put_u16_le(self.column_flag);

        //decimals -- max shown decimal digits
        buf.put_u8(self.decimals);

        //filter - [00] [00]
        buf.put_u16_le(0);
    }
}

/// Implements Column for T.
impl Column for &[u8] {}
impl Column for BytesMut {}

#[cfg(test)]
mod test {
    use bytes::BytesMut;

    use super::*;
    use crate::{column::Column, mysql_const::ColumnType};

    #[test]
    fn test_decode_encode_column_info() {
        let data = [
            0x03, 0x64, 0x65, 0x66, 0x00, 0x00, 0x00, 0x01, 0x3f, 0x00, 0x0c, 0x3f, 0x00, 0x00,
            0x00, 0x00, 0x00, 0xfd, 0x80, 0x00, 0x00, 0x00, 0x00,
        ];

        let mut buf = BytesMut::from(&data[..]);
        let info = buf.decode_column();
        assert_eq!(info.charset, 0x3f);
        assert_eq!(info.column_type, ColumnType::MYSQL_TYPE_VAR_STRING);
        assert_eq!(info.column_flag, 0x80);
        assert_eq!(info.column_length, 0);

        let mut encode_buf = vec![];
        info.encode(&mut encode_buf);
        assert_eq!(&data[..], encode_buf)
    }

    #[test]
    fn test_remove_column_by_idx() {
        let data = [1, 0, 0, 0, 1, 2, 0, 0, 0, 2, 3, 1, 0, 0, 0, 3];

        let expect_data = [1, 0, 0, 0, 1, 2, 0, 0, 0, 2, 3];
        let mut buf = BytesMut::from(&data[..]);
        remove_column_by_idx(&mut buf, &[2]);
        assert_eq!(&buf[..], expect_data);
    }

    #[test]
    fn test_add_column_by_idx() {
        let data = [1, 0, 0, 0, 1, 2, 0, 0, 0, 2, 3];

        let expect_data = [1, 0, 0, 0, 1, 2, 0, 0, 0, 2, 3, 1, 0, 0, 0, 3];
        let mut buf = BytesMut::from(&data[..]);
        add_column_by_idx(&mut buf, 2, vec![1, 0, 0, 0, 3]);
        assert_eq!(&buf[..], expect_data);
    }

    #[test]
    fn test_try_decode_columns_rejects_truncated_packet_header() {
        assert!(try_decode_columns([0x01, 0x00, 0x00]).is_err());
    }

    #[test]
    fn test_try_decode_columns_rejects_truncated_packet_payload() {
        assert!(try_decode_columns([0x18, 0x00, 0x00, 0x00, 0x03, 0x64]).is_err());
    }

    #[test]
    fn test_try_column_mutation_rejects_truncated_packet() {
        let mut buf = BytesMut::from(&[0x01, 0x00, 0x00, 0x00][..]);
        assert!(try_remove_column_by_idx(&mut buf, &[0]).is_err());

        let mut buf = BytesMut::from(&[0x01, 0x00, 0x00][..]);
        assert!(try_add_column_by_idx(&mut buf, 1, []).is_err());
    }
}
