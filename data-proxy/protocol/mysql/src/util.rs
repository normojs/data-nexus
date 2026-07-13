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

use std::cmp::Ordering;

use byteorder::{ByteOrder, LittleEndian};
use bytes::{Buf, BufMut, BytesMut};
use chrono::prelude::*;
use crypto::{self, digest::Digest};
use rand::{rngs::StdRng, Rng, SeedableRng};

use crate::{
    err::ProtocolError,
    mysql_const::{EOF_HEADER, OK_HEADER},
};

// random_buf: generate random byte vector
#[inline]
pub fn random_buf(size: i64) -> Vec<u8> {
    let mut buf = vec![];
    let mut r = StdRng::seed_from_u64(Utc::now().timestamp_subsec_nanos().into());
    let mut i: usize = 0;

    while i < size as usize {
        buf.push(r.gen_range(0..127));
        if buf[i] == 0 || buf[i] as char == '$' {
            buf[i] += 1;
        }
        i += 1;
    }
    buf
}

// calc_password: Hash password use sha1
pub fn calc_password(scramble: &[u8], password: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return vec![];
    }
    let mut crypt = crypto::sha1::Sha1::new();
    crypt.input(password);
    let mut stage1 = vec![0; 20];
    crypt.result(&mut stage1);

    crypt.reset();
    crypt.input(&stage1);
    let mut hash = vec![0; 20];
    crypt.result(&mut hash);

    crypt.reset();
    crypt.input(scramble);
    crypt.input(&hash);
    let mut scramble = vec![0; 20];
    crypt.result(&mut scramble);

    for i in 0..20 {
        scramble[i as usize] ^= stage1[i]
    }
    scramble
}

// calc_caching_sha2password: Hash password using MySQL 8+ method (SHA256)
pub fn calc_caching_sha2password(scramble: &[u8], password: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return vec![0];
    }

    let mut crypt = crypto::sha2::Sha256::new();
    crypt.input(password);
    let mut message1 = vec![0; 32];
    crypt.result(&mut message1);

    crypt.reset();
    crypt.input(&message1);
    let mut message1_hash = vec![0; 32];
    crypt.result(&mut message1_hash);

    crypt.reset();
    crypt.input(&message1_hash);
    crypt.input(scramble);
    let mut message2 = vec![0; 32];
    crypt.result(&mut message2);

    for i in 0..32 {
        message1[i as usize] ^= message2[i];
    }

    message1
}

pub fn compare(a: &[u8], b: &[u8]) -> bool {
    for (ai, bi) in a.iter().zip(b.iter()) {
        match ai.cmp(bi) {
            Ordering::Equal => continue,
            _ => return false,
        }
    }

    /* if every single element was equal, compare length */
    a.len().cmp(&b.len()) == Ordering::Equal
}

#[inline]
pub fn length_encode_int(data: &[u8]) -> (u64, bool, u64) {
    try_length_encode_int(data).expect("length encoded integer should be valid")
}

#[inline]
pub fn try_length_encode_int(data: &[u8]) -> Result<(u64, bool, u64), ProtocolError> {
    let first = *data.first().ok_or_else(|| invalid_packet("length_encode_int", data))?;
    let value = match first {
        0xfb => (0, true, 1),
        0xfc => {
            ensure_len("length_encode_int", data, 3)?;
            (LittleEndian::read_uint(&data[1..], 2), false, 3)
        }
        0xfd => {
            ensure_len("length_encode_int", data, 4)?;
            (LittleEndian::read_uint(&data[1..], 3), false, 4)
        }
        0xfe => {
            ensure_len("length_encode_int", data, 9)?;
            (LittleEndian::read_uint(&data[1..], 8), false, 9)
        }
        x => (x as u64, false, 1),
    };

    Ok(value)
}

pub trait BufExt: Buf {
    fn get_lenc_int(&mut self) -> (u64, bool, u8) {
        self.try_get_lenc_int().expect("length encoded integer should be valid")
    }

    fn try_get_lenc_int(&mut self) -> Result<(u64, bool, u8), ProtocolError> {
        if !self.has_remaining() {
            return Err(ProtocolError::InvalidPacket {
                method: "get_lenc_int".to_string(),
                data: vec![],
            });
        }
        let first = self.get_u8();
        let res = match first {
            0xfb => (0, true, 1),
            0xfc => {
                ensure_remaining("get_lenc_int", self, 2)?;
                (self.get_uint_le(2), false, 3)
            }
            0xfd => {
                ensure_remaining("get_lenc_int", self, 3)?;
                (self.get_uint_le(3), false, 4)
            }
            0xfe => {
                ensure_remaining("get_lenc_int", self, 8)?;
                (self.get_uint_le(8), false, 9)
            }
            _ => (first as u64, false, 1),
        };
        Ok(res)
    }

    fn get_lenc_str_bytes(&mut self) -> (Vec<u8>, bool) {
        self.try_get_lenc_str_bytes().expect("length encoded string should be valid")
    }

    fn try_get_lenc_str_bytes(&mut self) -> Result<(Vec<u8>, bool), ProtocolError> {
        let (length, is_null, _) = self.try_get_lenc_int()?;

        // When length < 1 means that the origin bytes is 0x00 or 0xfb,
        // In the str context, means the str is null, so return true here.
        if length < 1 || is_null || !self.has_remaining() {
            return Ok((vec![0], true));
        }

        ensure_remaining("get_lenc_str_bytes", self, length as usize)?;
        let mut data = vec![0; length as usize];
        self.copy_to_slice(&mut data);

        Ok((data, is_null))
    }

    fn skip_lenc_length(&mut self) {
        self.try_skip_lenc_length().expect("length encoded string should be valid")
    }

    fn try_skip_lenc_length(&mut self) -> Result<(), ProtocolError> {
        let (length, ..) = self.try_get_lenc_int()?;
        ensure_remaining("skip_lenc_length", self, length as usize)?;
        self.advance(length as usize);
        Ok(())
    }
}

//impl<T: AsRef<[u8]> + Buf> BufExt for T {}
impl BufExt for &[u8] {}

impl BufExt for BytesMut {}

pub trait BufMutExt: BufMut {
    fn put_lenc_int(&mut self, n: u64, is_num: bool) {
        // See https://dev.mysql.com/doc/internals/en/integer.html#length-encoded-integer
        if n == 0 {
            if is_num {
                self.put_u8(0);
            } else {
                self.put_u8(0xfb);
            }
            return;
        }

        if n <= 250 {
            self.put_u8(n as u8);
        } else if n <= 0xffff {
            self.put_u8(0xfc);
            self.put_uint_le(n, 2);
        } else if n <= 0xffffff {
            self.put_u8(0xfd);
            self.put_uint_le(n, 3);
        } else {
            self.put_u8(0xfe);
            self.put_uint_le(n, 8);
        }
    }
}

impl BufMutExt for Vec<u8> {}
impl BufMutExt for BytesMut {}

pub fn length_encoded_string(data: &mut BytesMut) -> (Vec<u8>, bool) {
    try_length_encoded_string(data).expect("length encoded string should be valid")
}

pub fn try_length_encoded_string(data: &mut BytesMut) -> Result<(Vec<u8>, bool), ProtocolError> {
    let (num, is_null, _) = data.try_get_lenc_int()?;

    if num < 1 {
        return Ok((vec![0xfb], is_null));
    }

    if data.is_empty() {
        return Ok((vec![], false));
    }

    ensure_len("length_encoded_string", data, num as usize)?;
    Ok((data.split_to(num as usize).to_vec(), false))
}

// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_eof_packet.html
#[inline]
pub fn is_eof(data: &[u8]) -> bool {
    data.len() >= 5 && data.len() <= 9 && data[4] == EOF_HEADER
}

// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_ok_packet.html
#[inline]
pub fn is_ok(data: &[u8]) -> bool {
    data.len() > 7 && data[4] == OK_HEADER
}

fn ensure_len(method: &str, data: &[u8], needed: usize) -> Result<(), ProtocolError> {
    if data.len() < needed {
        return Err(invalid_packet(method, data));
    }
    Ok(())
}

fn ensure_remaining<B: Buf + ?Sized>(
    method: &str,
    data: &B,
    needed: usize,
) -> Result<(), ProtocolError> {
    if data.remaining() < needed {
        return Err(ProtocolError::InvalidPacket { method: method.to_string(), data: vec![] });
    }
    Ok(())
}

fn invalid_packet(method: &str, data: &[u8]) -> ProtocolError {
    ProtocolError::InvalidPacket { method: method.to_string(), data: data.to_vec() }
}

#[inline]
pub fn is_ok_header(data: u8) -> bool {
    if data == OK_HEADER {
        return true;
    }
    false
}

#[inline]
pub fn get_length(buf: &[u8]) -> usize {
    try_get_length(buf).expect("packet header should contain a three-byte payload length")
}

/// Decode the three-byte little-endian payload length in a MySQL packet header.
#[inline]
pub fn try_get_length(buf: &[u8]) -> Result<usize, ProtocolError> {
    ensure_len("get_length", buf, 3)?;
    Ok(buf[0] as usize | ((buf[1] as usize) << 8) | ((buf[2] as usize) << 16))
}

#[cfg(test)]
mod test {
    use bytes::BytesMut;

    use super::{length_encoded_string, BufExt};
    use crate::util::{
        calc_caching_sha2password, calc_password, compare, get_length, is_eof, is_ok, random_buf,
        try_get_length,
    };

    #[test]
    fn test_random_buf() {
        let result = random_buf(6);
        assert_eq!(result.len(), 6);
    }

    #[test]
    fn test_calc_password() {
        let scramble = [0x70, 0x69, 0x73, 0x61, 0x6e, 0x69, 0x78];
        let password = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36];
        let calc_password = calc_password(&scramble[..], &password[..]);
        let result = [
            139, 87, 122, 170, 122, 110, 60, 78, 2, 63, 208, 152, 19, 86, 207, 190, 178, 51, 61,
            127,
        ];
        assert_eq!(calc_password, &result[..])
    }

    #[test]
    fn test_calc_caching_sha2password() {
        let scramble = [0x70, 0x69, 0x73, 0x61, 0x6e, 0x69, 0x78];
        let password = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36];
        let calc_password = calc_caching_sha2password(&scramble[..], &password[..]);
        let result = [
            97, 231, 153, 111, 85, 161, 188, 166, 190, 240, 239, 147, 138, 193, 141, 190, 194, 120,
            170, 210, 235, 241, 79, 175, 198, 189, 36, 193, 105, 166, 179, 173,
        ];
        assert_eq!(calc_password, &result[..])
    }

    #[test]
    fn test_compare_success() {
        let scramble = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36];
        let password = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36];
        let result = compare(&scramble[..], &password[..]);
        assert_eq!(result, true)
    }

    #[test]
    fn test_compare_fail() {
        let scramble = [0x30, 0x32, 0x33, 0x34, 0x35, 0x36];
        let password = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36];
        let result = compare(&scramble[..], &password[..]);
        assert_eq!(result, false)
    }

    #[test]
    fn test_length_encode_int() {
        let mut data = &[0xfb, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37][..];
        let (a, b, c) = data.get_lenc_int();
        assert_eq!(a, 0);
        assert_eq!(b, true);
        assert_eq!(c, 1);

        let mut data = &[0xfc, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37][..];
        let (a, b, c) = data.get_lenc_int();
        assert_eq!(a, 12849);
        assert_eq!(b, false);
        assert_eq!(c, 3);

        let mut data = &[0xfd, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37][..];
        let (a, b, c) = data.get_lenc_int();
        assert_eq!(a, 3355185);
        assert_eq!(b, false);
        assert_eq!(c, 4);

        let mut data = &[0xfe, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38][..];
        let (a, b, c) = data.get_lenc_int();
        assert_eq!(a, 4050765991979987505);
        assert_eq!(b, false);
        assert_eq!(c, 9);

        let mut data = &[0x00, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37][..];
        let (a, b, c) = data.get_lenc_int();
        assert_eq!(a, 0);
        assert_eq!(b, false);
        assert_eq!(c, 1);
    }

    #[test]
    fn test_length_enc_string() {
        let data = [0x04, 0x55, 0x73, 0x65, 0x72];
        let mut buf = BytesMut::from(&data[..]);

        let (info, _is_null) = length_encoded_string(&mut buf);
        let name = std::str::from_utf8(&info).unwrap();
        assert_eq!(name, "User");
    }

    #[test]
    fn test_buf_length_enc_string() {
        let data = [0x04, 0x55, 0x73, 0x65, 0x72];
        let mut buf = BytesMut::from(&data[..]);

        let (info, _is_null) = buf.get_lenc_str_bytes();
        let name = std::str::from_utf8(&info).unwrap();
        assert_eq!(name, "User");
    }

    #[test]
    fn test_is_eof_success() {
        let data = [0x05, 0x00, 0x00, 0x05, 0xfe, 0x00, 0x00];
        let result = is_eof(&data[..]);
        assert_eq!(result, true);
    }

    #[test]
    fn test_is_eof_data_error() {
        let data = [0x05, 0x00, 0x00, 0x05, 0xff, 0x00, 0x00, 0x02, 0x00];
        let result = is_eof(&data[..]);
        assert_eq!(result, false);
    }

    #[test]
    fn test_is_eof_length_error() {
        let data = [0x05, 0x00, 0x00, 0x05, 0xfe, 0x00, 0x00, 0x02, 0x00, 0x00];
        let result = is_eof(&data[..]);
        assert_eq!(result, false);
    }

    #[test]
    fn test_is_ok_success() {
        let data = [0x07, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00];
        let result = is_ok(&data[..]);
        assert_eq!(result, true);
    }

    #[test]
    fn test_is_ok_data_error() {
        let data = [0x05, 0x00, 0x00, 0x05, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00];
        let result = is_ok(&data[..]);
        assert_eq!(result, false);
    }

    #[test]
    fn test_is_ok_length_error() {
        let data = [0x05, 0x00, 0x00, 0x05, 0x00, 0x00];
        let result = is_eof(&data[..]);
        assert_eq!(result, false);
    }

    #[test]
    fn test_get_length() {
        let data = [0x05, 0x00, 0x00, 0x05, 0x00, 0x00];
        let result = get_length(&data[..]);
        assert_eq!(result, 5);
    }

    #[test]
    fn test_try_get_length_rejects_truncated_header() {
        assert!(try_get_length(&[]).is_err());
        assert!(try_get_length(&[0x01, 0x00]).is_err());
    }
}
