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
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

use crate::{
    err::ProtocolError,
    mysql_const::{
        CLIENT_PROTOCOL_41, CLIENT_SESSION_TRACK, CLIENT_TRANSACTIONS, SERVER_SESSION_STATE_CHANGED,
    },
    util::{try_length_encoded_string, BufExt, BufMutExt},
};

#[derive(Debug, FromPrimitive)]
#[repr(u8)]
pub enum SessionStateType {
    SystemVariables,            // Session system variables
    Schema,                     // Current schema
    StateChange,                // Session state changes
    Gtids,                      // GTIDs
    TransactionCharacteristics, // Transaction characteristics
    TransactionState,           // Transaction state
}

#[derive(Debug)]
pub enum SessionState {
    SystemVariables(Vec<(Vec<u8>, Vec<u8>)>),
    Schema(Vec<u8>),
    StateChange(bool),
    Gtids(Vec<u8>),
    TransactionCharacteristics(Vec<u8>),
    TransactionState(Vec<u8>),
    Unknown(Vec<u8>),
}

impl SessionState {
    pub fn decode(data: &mut BytesMut) -> SessionState {
        Self::try_decode(data).expect("session state packet should be valid")
    }

    pub fn try_decode_all(data: &mut BytesMut) -> Result<Vec<SessionState>, ProtocolError> {
        let (num, ..) = data.try_get_lenc_int()?;
        ensure_packet_len("session_state_changes.payload", data, num as usize)?;

        let mut payload = data.split_to(num as usize);
        let mut states = Vec::new();
        while !payload.is_empty() {
            states.push(SessionState::try_decode(&mut payload)?);
        }

        Ok(states)
    }

    pub fn try_decode(data: &mut BytesMut) -> Result<SessionState, ProtocolError> {
        if data.is_empty() {
            return Err(invalid_packet("session_state.decode", data));
        }

        let original = data.clone();
        let state_type = data.get_u8();
        let (num, ..) = data.try_get_lenc_int()?;
        ensure_packet_len("session_state.payload", data, num as usize)?;

        let mut payload = data.split_to(num as usize);

        match FromPrimitive::from_u8(state_type) {
            Some(SessionStateType::SystemVariables) => {
                let mut pairs = Vec::new();
                while !payload.is_empty() {
                    let (name, _) = try_length_encoded_string(&mut payload)?;
                    let (value, _) = try_length_encoded_string(&mut payload)?;
                    pairs.push((name, value))
                }

                Ok(SessionState::SystemVariables(pairs))
            }
            Some(SessionStateType::Schema) => {
                let (schema, _) = try_length_encoded_string(&mut payload)?;
                Ok(SessionState::Schema(schema))
            }
            Some(SessionStateType::StateChange) => {
                let (is_tracked, _) = try_length_encoded_string(&mut payload)?;
                Ok(SessionState::StateChange(is_tracked == b"1"))
            }
            Some(SessionStateType::Gtids) => {
                let (gtids, _) = try_length_encoded_string(&mut payload)?;
                Ok(SessionState::Gtids(gtids))
            }
            Some(SessionStateType::TransactionCharacteristics) => {
                let (char, _) = try_length_encoded_string(&mut payload)?;
                Ok(SessionState::TransactionCharacteristics(char))
            }
            Some(SessionStateType::TransactionState) => {
                let (state, _) = try_length_encoded_string(&mut payload)?;
                Ok(SessionState::TransactionState(state))
            }
            None => {
                let consumed_len = original.len() - data.len();
                Ok(SessionState::Unknown(original[..consumed_len].to_vec()))
            }
        }
    }
}

#[derive(Debug)]
pub struct ResultOkInfo {
    affected_rows: u64,
    last_insert_id: u64,
    status: Option<u16>,
    warnings: Option<u16>,
    info: Option<Vec<u8>>,
    state_changes: Option<Vec<SessionState>>,
}

impl ResultOkInfo {
    fn new() -> ResultOkInfo {
        ResultOkInfo {
            affected_rows: 0,
            last_insert_id: 0,
            status: None,
            warnings: None,
            info: None,
            state_changes: None,
        }
    }

    pub fn decode(capability: u32, data: &mut BytesMut) -> ResultOkInfo {
        Self::try_decode(capability, data).expect("ok packet should be valid")
    }

    pub fn try_decode(capability: u32, data: &mut BytesMut) -> Result<ResultOkInfo, ProtocolError> {
        let mut ok_info = ResultOkInfo::new();

        let (affect_rows, ..) = data.try_get_lenc_int()?;
        ok_info.affected_rows = affect_rows;

        let (last_inert_id, ..) = data.try_get_lenc_int()?;
        ok_info.last_insert_id = last_inert_id;

        if capability & CLIENT_PROTOCOL_41 > 0 {
            ensure_packet_len("ok_packet.status_warnings", data, 4)?;
            ok_info.status = Some(data.get_u16_le());
            ok_info.warnings = Some(data.get_u16_le());
        } else if capability & CLIENT_TRANSACTIONS > 0 {
            ensure_packet_len("ok_packet.status", data, 2)?;
            ok_info.status = Some(data.get_u16_le());
        }

        if data.is_empty() {
            return Ok(ok_info);
        }

        if capability & CLIENT_SESSION_TRACK > 0 {
            let (info, _) = try_length_encoded_string(data)?;
            ok_info.info = Some(info);

            if let Some(status) = ok_info.status {
                if status & SERVER_SESSION_STATE_CHANGED > 0 {
                    ok_info.state_changes = Some(SessionState::try_decode_all(data)?)
                }
            }
        } else {
            let payload = data.split();
            ok_info.info = Some(payload.to_vec())
        }

        Ok(ok_info)
    }

    pub fn encode(&self, capability: u32) -> Box<[u8]> {
        let mut data = BytesMut::with_capacity(64);
        data.put_u8(0x00);

        data.put_lenc_int(self.affected_rows, true);
        data.put_lenc_int(self.last_insert_id, true);

        if capability & CLIENT_PROTOCOL_41 > 0 {
            if let Some(status) = &self.status {
                data.put_u16_le(*status);
            }

            if let Some(warnings) = &self.warnings {
                data.put_u16_le(*warnings);
            }
        } else if capability & CLIENT_TRANSACTIONS > 0 {
            if let Some(status) = &self.status {
                data.put_u16_le(*status);
            }
        }

        if let Some(info) = &self.info {
            data.put_lenc_int(info.len() as u64, false);
            data.put_slice(&info);
        }
        data[..].into()
    }
}

fn ensure_packet_len(method: &str, data: &BytesMut, needed: usize) -> Result<(), ProtocolError> {
    if data.len() < needed {
        return Err(invalid_packet(method, data));
    }
    Ok(())
}

fn invalid_packet(method: &str, data: &BytesMut) -> ProtocolError {
    ProtocolError::InvalidPacket { method: method.to_string(), data: data.to_vec() }
}

#[cfg(test)]
mod test {
    use bytes::BytesMut;

    use super::{ResultOkInfo, SessionState};
    use crate::client::conn::ClientConn;

    #[tokio::test]
    async fn test_decode_ok_packet_schema() {
        let mut packet = BytesMut::from(
            &[
                0x13, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x40, 0x00, 0x00, 0x00, 0x0a, 0x01,
                0x05, 0x04, 0x74, 0x65, 0x73, 0x74, 0x02, 0x01, 0x31,
            ][..],
        );

        let _ = packet.split_to(4 + 1);

        let driver = ClientConn::test_conn(
            "root".to_string(),
            "123456".to_string(),
            "127.0.0.1:13306".to_string(),
        )
        .await
        .unwrap();

        let auth_info = driver.framed.as_ref().unwrap().auth_info().unwrap();
        let info = ResultOkInfo::decode(auth_info.capability, &mut packet);

        let state_changes = info.state_changes.unwrap();
        assert_eq!(state_changes.len(), 2);

        if let SessionState::Schema(schema) = &state_changes[0] {
            assert_eq!(b"test"[..], schema[..])
        } else {
            panic!("expected schema state change")
        }

        if let SessionState::StateChange(is_tracked) = state_changes[1] {
            assert!(is_tracked)
        } else {
            panic!("expected state-change tracker flag")
        }
    }

    #[tokio::test]
    async fn test_decode_ok_packet_vars() {
        let mut packet = BytesMut::from(
            &[
                0x1d, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x14, 0x00,
                0x0f, 0x0a, 0x61, 0x75, 0x74, 0x6f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x03, 0x4f,
                0x46, 0x46, 0x02, 0x01, 0x31,
            ][..],
        );

        let _ = packet.split_to(4 + 1);

        let driver = ClientConn::test_conn(
            "root".to_string(),
            "123456".to_string(),
            "127.0.0.1:13306".to_string(),
        )
        .await
        .unwrap();

        let auth_info = driver.framed.as_ref().unwrap().auth_info().unwrap();
        let info = ResultOkInfo::decode(auth_info.capability, &mut packet);

        let state_changes = info.state_changes.unwrap();
        assert_eq!(state_changes.len(), 2);

        if let SessionState::SystemVariables(vars) = &state_changes[0] {
            assert_eq!(b"autocommit"[..], vars[0].0);
            assert_eq!(b"OFF"[..], vars[0].1);
        } else {
            panic!("expected system variables state change")
        }

        if let SessionState::StateChange(is_tracked) = state_changes[1] {
            assert!(is_tracked)
        } else {
            panic!("expected state-change tracker flag")
        }
    }

    #[tokio::test]
    async fn test_decode_ok_packet_common() {
        let mut packet =
            BytesMut::from(&[0x07, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00][..]);

        let _ = packet.split_to(4 + 1);
        let driver = ClientConn::test_conn(
            "root".to_string(),
            "123456".to_string(),
            "127.0.0.1:13306".to_string(),
        )
        .await
        .unwrap();

        let auth_info = driver.framed.as_ref().unwrap().auth_info().unwrap();
        let info = ResultOkInfo::decode(auth_info.capability, &mut packet);
        assert_eq!(info.state_changes.is_none(), true);
    }

    #[tokio::test]
    async fn test_ok_packet_encode() {
        let driver = ClientConn::test_conn(
            "root".to_string(),
            "123456".to_string(),
            "127.0.0.1:13306".to_string(),
        )
        .await
        .unwrap();
        let auth_info = driver.framed.as_ref().unwrap().auth_info().unwrap();
        let ok_info = ResultOkInfo {
            affected_rows: 256,
            last_insert_id: 0,
            status: Some(0x0022),
            warnings: Some(0),
            info: Some(b"Records: 256  Duplicates: 0  Warnings: 0".to_vec()),
            state_changes: None,
        };

        let expected = [
            0x00, 0xfc, 0x00, 0x01, 0x00, 0x22, 0x00, 0x00, 0x00, 0x28, 0x52, 0x65, 0x63, 0x6f,
            0x72, 0x64, 0x73, 0x3a, 0x20, 0x32, 0x35, 0x36, 0x20, 0x20, 0x44, 0x75, 0x70, 0x6c,
            0x69, 0x63, 0x61, 0x74, 0x65, 0x73, 0x3a, 0x20, 0x30, 0x20, 0x20, 0x57, 0x61, 0x72,
            0x6e, 0x69, 0x6e, 0x67, 0x73, 0x3a, 0x20, 0x30,
        ];

        let res = ok_info.encode(auth_info.capability);

        assert_eq!(&expected[..], &res[..])
    }
}
