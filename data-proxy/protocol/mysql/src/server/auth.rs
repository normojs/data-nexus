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

use std::{
    str,
    sync::atomic::{AtomicU32, Ordering},
};

use bytes::{Buf, BufMut, BytesMut};
use futures::{SinkExt, StreamExt};
use tokio_util::codec::{Decoder, Encoder, Framed};
use tracing::{debug, error, field::debug};

use super::{err::MySQLError, stream::LocalStream};
use crate::{
    charset::{COLLATION_NAME_ID_MYSQL5, DEFAULT_CHARSET_NAME},
    err::ProtocolError,
    mysql_const::*,
    server::codec::{make_err_packet, ok_packet},
    session::{Session, SessionMut},
    util::*,
};

/// @see mysql_const.rs:169#CLIENT_LONG_PASSWORD
const DEFAULT_CAPABILITY: u32 = CLIENT_LONG_PASSWORD
    | CLIENT_LONG_FLAG
    | CLIENT_CONNECT_WITH_DB
    | CLIENT_PROTOCOL_41
    | CLIENT_TRANSACTIONS
    | CLIENT_SECURE_CONNECTION
    | CLIENT_SSL
    | CLIENT_FOUND_ROWS
    | CLIENT_MULTI_STATEMENTS
    | CLIENT_PS_MULTI_RESULTS
    | CLIENT_LOCAL_FILES
    | CLIENT_CONNECT_ATTRS
    | CLIENT_PLUGIN_AUTH
    | CLIENT_INTERACTIVE
    | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA;

lazy_static! {
    static ref CONNECTION_ID: AtomicU32 = AtomicU32::new(0);
}

/**
表示服务器在进行握手过程中可能的状态。
这个枚举类型可以用于表示服务器在握手过程中所处的状态，并根据状态进行相应的处理。
 */
#[derive(Debug, PartialEq)]
pub enum ServerHandshakeStatus {
    /// 写入初始握手消息
    WriteInitial,
    /// 读取客户端的初始握手消息
    ReadResponseFirst,
    /// 读取客户端的后续握手消息
    ReadResponse,
    /// 切换到TLS协议
    SwitchToTLS,
    /// 写入自动切换协议的消息
    WriteAutoSwitch,
    /// 读取自动切换协议的响应消息
    ReadAutoSwitchResponse,
    /// 比较认证数据
    CompareAuthData,
    /// 握手完成
    Complete,
}

/// ServerHandshakeCodec是Rust中定义的一个结构体，用于存储服务器握手阶段的各项信息，以支持数据库连接的建立与认证过程。
pub struct ServerHandshakeCodec {
    /// 序列号
    seq: u8,
    /// 服务器版本
    server_version: String,
    /// 连接ID
    connection_id: u32,
    /// 连接能力
    capability: u32,
    /// 字符集
    charset: String,
    /// 盐值
    salt: Vec<u8>,
    /// 状态
    status: u16,
    /// 用户名，
    user: String,
    /// 数据库名，
    db: String,
    /// 密码，
    password: String,
    /// 认证数据
    auth_data: BytesMut,
    /// 认证插件名
    auth_plugin_name: String,
    /// 自动提交
    autocommit: Option<String>,
    /// 下一个握手状态
    next_handshake_status: ServerHandshakeStatus,
}

impl ServerHandshakeCodec {
    /// 新建
    ///
    /// # 参数
    /// - `user`：用户名
    /// - `password`：密码
    pub fn new(user: String, password: String, db: String, server_version: String) -> Self {
        CONNECTION_ID.fetch_add(1, Ordering::Relaxed);

        Self {
            seq: 0,
            server_version,
            connection_id: CONNECTION_ID.load(Ordering::Relaxed),
            capability: 0,
            charset: DEFAULT_CHARSET_NAME.to_string(),
            salt: random_buf(20),
            status: SERVER_STATUS_AUTOCOMMIT,
            user,
            db,
            password,
            auth_data: BytesMut::with_capacity(20),
            auth_plugin_name: "".to_string(),
            autocommit: None,
            next_handshake_status: ServerHandshakeStatus::ReadResponseFirst,
        }
    }

    /// 这个函数是一个编码握手消息的函数。它将一些信息编码成字节流，并返回一个BytesMut类型的字节切片
    fn encode_initial_handshake(&self) -> BytesMut {
        let mut data = BytesMut::with_capacity(128);

        // 初始化头部：将4个字节放入字节流中
        data.put_bytes(0, 4);

        // 设置最小版本号为10
        data.put_u8(10);

        // 将服务器版本号放入字节流中
        data.extend_from_slice(self.server_version.as_bytes());
        data.put_u8(0);

        // 将连接ID放入字节流中
        data.extend_from_slice(&self.connection_id.to_le_bytes());

        // auth-plugin-data-part-1
        // data.extend_from_slice(&mut self.salt[0..8]);
        // 将盐值的前8个字节放入字节流中
        data.extend_from_slice(&self.salt[0..8]);

        // filter[00]
        // 将过滤器设置为0
        data.put_u8(0);

        // capability flag lower 2 bytes, using default capability here
        // 将默认能力标志的低2个字节放入字节流中
        data.put_u8(DEFAULT_CAPABILITY as u8);
        data.put_u8((DEFAULT_CAPABILITY >> 8) as u8);

        //charset, utf-8 default
        // 将字符集编码放入字节流中
        data.put_u8(COLLATION_NAME_ID_MYSQL5[&*self.charset]);

        //status
        // 将状态放入字节流中
        data.put_u8(self.status as u8);
        data.put_u8((self.status >> 8) as u8);

        //below 13 byte may not be used
        //capability flag upper 2 bytes, using default capability here
        // 将默认能力标志的高2个字节放入字节流
        data.put_u8((DEFAULT_CAPABILITY >> 16) as u8);
        data.put_u8((DEFAULT_CAPABILITY >> 24) as u8);

        // fiter [0x15], for wireshark dump, value is 0x15
        // data.push(0x15);
        // 将过滤器设置为0x15
        data.put_u8(20 + 1);

        //reserved 10 [00]
        // 将保留的10个字节设置为
        data.put_bytes(0, 10);

        //auth-plugin-data-part-2
        // data.extend_from_slice(&mut self.salt[8..]);
        // 将盐值的后8个字节放入字节流中
        data.extend_from_slice(&self.salt[8..]);

        //filter [00]
        // 将过滤器设置为0
        data.put_u8(0);

        // 将AUTH_NATIVE_PASSWORD常量放入字节流中
        data.extend_from_slice(AUTH_NATIVE_PASSWORD.as_bytes());
        data.put_u8(0);

        data
        //self.pkt.make_packet_header(data.len() - 4, &mut data);
        //self.pkt.write_buf(&data).await
    }

    fn decode_handshake_response(&mut self, data: &mut BytesMut) -> Result<(), ProtocolError> {
        // 这个函数的功能是找到一个字节切片data中第一个值为0的元素的索引，并返回该索引。如果字节切片中没有值为0的元素，则会抛出一个unwrap错误。
        let idx = data.iter().position(|&x| x == 0).unwrap();
        // 将字节切片data中从索引idx开始到末尾的部分转换为一个字符串user
        let user = str::from_utf8(&data.split_to(idx)).unwrap().to_string();

        // 如果user与self.user不相等，则会使用数据库里的数据进行处理，并抛出一个ProtocolError::AuthFailed错误。
        if user != self.user {
            // TODO: 使用数据库里的数据
            error!("user is not found，current user is: {}", user);
            self.user = user;
            return Err(ProtocolError::AuthFailed(self.make_auth_err_info()));
        }

        let _ = data.get_u8();

        // length encoded data
        // CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA：这个标志位通常用于指示客户端支持使用长度编码的插件认证数据
        // @see mysql_const.rs:196#CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
        if self.capability & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA > 0 {
            // 长编码数据
            let (auth_data, is_null) = length_encoded_string(data);
            if is_null {
                return Err(ProtocolError::AuthFailed(self.make_auth_lenc_err_info()));
            }
            self.auth_data = BytesMut::from(&auth_data[..]);
            debug!("capability support `CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA`");
        } else if self.capability & CLIENT_SECURE_CONNECTION > 0 {
            let n = data.get_u8() as usize;
            self.auth_data = data.split_to(n);
            debug!("capability support `CLIENT_SECURE_CONNECTION`");
        } else {
            let idx = data.iter().position(|&x| x == 0).unwrap();
            self.auth_data = data.split_to(idx);
            let _ = data.get_u8();
            debug!("capability support `CLIENT_SECURE_CONNECTION`");
        }

        // 携带了数据库信息
        if self.capability & CLIENT_CONNECT_WITH_DB > 0 && !data.is_empty() {
            let idx = data.iter().position(|&x| x == 0).unwrap();
            let db = str::from_utf8(&data.split_to(idx)).unwrap().to_string();
            // TODO：使用数据库配置，判断是否有改权限
            if self.db != db {
                self.db = db;
                // TODO: 错误改成权限错误
                return Err(ProtocolError::AuthFailed(self.make_schema_err_info()));
            }

            // Eat db \0
            let _ = data.get_u8();
        }

        if self.capability & CLIENT_PLUGIN_AUTH > 0 {
            let idx = data.iter().position(|&x| x == 0).unwrap();
            self.auth_plugin_name = str::from_utf8(&data.split_to(idx)).unwrap().to_string();
            let _ = data.get_u8();
        } else {
            self.auth_plugin_name = AUTH_NATIVE_PASSWORD.to_string()
        }

        // Currently, we don't use CLIENT_CONNECT_ATTRS
        // 目前，我们不使用客户端连接属性
        data.clear();

        // TODO：暂时支持吃AUTH_NATIVE_PASSWORD插件
        if &self.auth_plugin_name != AUTH_NATIVE_PASSWORD {
            debug!("auth_plugin_name: {}", self.auth_plugin_name);
            self.auth_plugin_name = AUTH_NATIVE_PASSWORD.to_string();
            self.next_handshake_status = ServerHandshakeStatus::WriteAutoSwitch;
            return Ok(());
        }

        self.next_handshake_status = ServerHandshakeStatus::CompareAuthData;
        Ok(())
        //self.compare_auth_data()
    }

    /// 一个BytesMut类型的变量data进行解码
    fn decode_first(&mut self, data: &mut BytesMut) -> bool {
        // 一个32位无符号整数
        self.capability = data.get_u32_le();

        // skip max packet size
        // 获取data中的一个32位无符号整数，并跳过该数据
        data.get_u32_le();

        //charset, skip, if you want to use another charset, use set names
        //c.collation = CollationId(data[pos])
        // 获取data中的一个8位无符号整数，并跳过该数据
        data.get_u8();

        //skip reserved 23[00]
        // 将data中前23个字节的数据提取出来，并跳过该数据
        let _ = data.split_to(23);
        // 判断data是否为空，并返回结果
        data.is_empty()
    }

    /// 该函数是一个方法，返回一个BytesMut类型的值。该函数的功能是生成一个认证开关请求。
    /// 函数内部首先创建一个容量为128的BytesMut对象dst，然后将一个长度为4的字节切片[0; 4]添加到dst中。
    /// 接下来，将EOF_HEADER（一个无符号8位整数）添加到dst中。
    /// 然后，将self.auth_plugin_name（一个字符串）转换为字节切片，并将其添加到dst中。
    /// 然后，将一个无符号8位整数0添加到dst中。
    /// 接下来，将self.salt（一个字符串）转换为字节切片，并将其添加到dst中。
    /// 最后，将一个无符号8位整数0添加到dst中。最终，返回dst。
    fn generate_auth_switch_request(&self) -> BytesMut {
        let mut dst = BytesMut::with_capacity(128);
        dst.extend_from_slice(&[0; 4]);
        dst.put_u8(EOF_HEADER);
        dst.extend_from_slice(self.auth_plugin_name.as_bytes());
        dst.put_u8(0);
        dst.extend_from_slice(&self.salt);
        dst.put_u8(0);

        dst
    }

    /// 该函数用于比较用户提供的认证数据（如密码）与服务器计算出的预期数据，以验证用户身份。
    /// 它首先更新握手状态，然后根据认证插件类型执行不同操作。
    /// 对于AUTH_NATIVE_PASSWORD插件，函数会使用给定盐值和密码计算哈希并与输入数据对比；
    /// 若不匹配则返回认证失败错误。对于其他插件类型，则直接返回认证失败错误。
    fn compare_auth_data(&mut self) -> Result<(), ProtocolError> {
        self.next_handshake_status = ServerHandshakeStatus::Complete;

        match self.auth_plugin_name.as_str() {
            AUTH_NATIVE_PASSWORD => {
                if !compare(&self.auth_data, &calc_password(&self.salt, self.password.as_bytes())) {
                    // TODO: 使用数据库里的数据比较
                    error!("password incorrect");
                    return Err(ProtocolError::AuthFailed(self.make_auth_err_info()));
                }
                Ok(())
            }
            // 不支持的插件类型，返回认证失败错误。
            _ => Err(ProtocolError::AuthFailed(self.make_auth_plugin_err_info())),
        }
    }

    /// 该函数用于处理服务器的认证切换响应。首先更新认证状态为已完成。然后根据认证插件类型进行判断：
    /// 对于AUTH_NATIVE_PASSWORD类型，计算并验证密码哈希；
    /// 否则，返回认证失败错误。最终返回结果，验证成功则为Ok(())，否则为认证失败错误。
    fn handle_auth_switch_response(&mut self, data: &mut BytesMut) -> Result<(), ProtocolError> {
        self.next_handshake_status = ServerHandshakeStatus::Complete;

        match self.auth_plugin_name.as_str() {
            AUTH_NATIVE_PASSWORD => {
                let passwd_salt = calc_password(&self.salt, self.password.as_bytes());
                debug!("passwd_salt: {:?}, data: {:?}", passwd_salt, data);
                if !compare(&passwd_salt, &data[..]) {
                    return Err(ProtocolError::AuthFailed(self.make_auth_err_info()));
                }
                Ok(())
            }
            // 不支持的插件类型，返回认证失败错误。
            _ => Err(ProtocolError::AuthFailed(self.make_auth_plugin_err_info())),
        }
    }

    /// 创建认证错误信息
    fn make_auth_err_info(&mut self) -> Vec<u8> {
        make_err_packet(MySQLError::new(
            1045,
            "28000".as_bytes().to_vec(),
            format!("Access denied for user {:?}, (using password: Yes)", self.user),
        ))
    }

    /// 创建数据库不存在错误信息
    fn make_schema_err_info(&mut self) -> Vec<u8> {
        make_err_packet(MySQLError::new(
            1049,
            "42000".as_bytes().to_vec(),
            format!("Unknown database {:?}", self.db),
        ))
    }

    /// 创建认证插件错误信息
    fn make_auth_plugin_err_info(&mut self) -> Vec<u8> {
        make_err_packet(MySQLError::new(
            1045,
            "28000".as_bytes().to_vec(),
            format!("unsupport authentication plugin name {:?}", self.auth_plugin_name,),
        ))
    }

    /// 创建认证长度错误信息
    fn make_auth_lenc_err_info(&mut self) -> Vec<u8> {
        make_err_packet(MySQLError::new(
            1045,
            "28000".as_bytes().to_vec(),
            "auth data is null".to_string(),
        ))
    }
}

/// 解码器
impl Decoder for ServerHandshakeCodec {
    type Item = ();
    type Error = ProtocolError;

    /**
        该函数是一个解码器，用于处理不同状态下的数据包。首先检查输入字节缓冲区的大小是否满足解码条件，
        然后根据内部状态变量next_handshake_status执行相应的解码逻辑（如解码首次响应、常规响应或自动切换响应）。
        在解码过程中可能进行切片操作、序列号增加以及验证认证数据等操作，并在成功解码一个完整消息后返回Some(())，否则返回None。
        整个函数的结果类型为Result<Option<()>, Self::Error>，表示解码过程可能出现错误且可能无法解出有效消息。
    */
    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() || src.len() < 3 {
            return Ok(None);
        }

        let length = get_length(&*src) as usize;

        if 4 + length > src.len() {
            return Ok(None);
        }

        let _ = src.split_to(4);
        self.seq += 1;

        match self.next_handshake_status {
            ServerHandshakeStatus::ReadResponseFirst => {
                let is_empty = self.decode_first(src);

                if is_empty {
                    self.next_handshake_status = ServerHandshakeStatus::SwitchToTLS;
                } else {
                    self.decode_handshake_response(src)?;
                    if self.next_handshake_status == ServerHandshakeStatus::CompareAuthData {
                        self.compare_auth_data()?;
                    }
                }

                Ok(Some(()))
            }

            ServerHandshakeStatus::ReadResponse => {
                self.decode_first(src);
                self.decode_handshake_response(src)?;

                if self.next_handshake_status == ServerHandshakeStatus::CompareAuthData {
                    self.compare_auth_data()?;
                }
                Ok(Some(()))
            }

            ServerHandshakeStatus::ReadAutoSwitchResponse => {
                self.handle_auth_switch_response(src)?;
                Ok(Some(()))
            }

            _ => Ok(Some(())),
        }
    }
}

impl Encoder<BytesMut> for ServerHandshakeCodec {
    type Error = ProtocolError;

    fn encode(&mut self, item: BytesMut, dst: &mut BytesMut) -> Result<(), Self::Error> {
        if self.next_handshake_status == ServerHandshakeStatus::WriteAutoSwitch {
            self.next_handshake_status = ServerHandshakeStatus::ReadAutoSwitchResponse;
        }

        dst.extend_from_slice(&item[..]);

        let length = item.len() - 4;
        // we have ensured length is 3bytes, so we can use unsafe block
        unsafe {
            let bytes = *(&(length as u64).to_le() as *const u64 as *const [u8; 8]);
            let data_ptr = dst.as_mut_ptr();
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), data_ptr, 3);
            *data_ptr.add(3) = self.seq;
        }

        self.seq += 1;

        Ok(())
    }
}

impl Session for ServerHandshakeCodec {
    fn get_db(&self) -> Option<String> {
        if self.db.is_empty() {
            None
        } else {
            Some(self.db.clone())
        }
    }

    fn get_charset(&self) -> Option<String> {
        Some(self.charset.clone())
    }

    fn get_autocommit(&self) -> Option<String> {
        self.autocommit.clone()
    }
}

impl SessionMut for ServerHandshakeCodec {
    fn set_db(&mut self, db: String) {
        self.db = db
    }

    fn set_charset(&mut self, charset: String) {
        self.charset = charset
    }

    fn set_autocommit(&mut self, autocommit: String) {
        self.autocommit = Some(autocommit)
    }
}

pub async fn handshake(
    mut framed: Framed<LocalStream, ServerHandshakeCodec>,
) -> Result<(Framed<LocalStream, ServerHandshakeCodec>, bool), ProtocolError> {
    // Send initial handshake
    let initial_handshake = framed.codec().encode_initial_handshake();
    framed.send(initial_handshake).await?;

    loop {
        if let Err(ProtocolError::AuthFailed(data)) = framed.next().await.unwrap() {
            framed.send(BytesMut::from(&data[..])).await?;
            return Ok((framed, false));
        }

        let next_state = &framed.codec().next_handshake_status;
        debug!("[#handshake] database connecting...");
        match next_state {
            ServerHandshakeStatus::SwitchToTLS => {
                debug!("[#handshake] SwitchToTLS...");
                let mut parts = framed.into_parts();
                parts.io.make_tls().await?;

                framed = Framed::from_parts(parts);
                framed.codec_mut().next_handshake_status = ServerHandshakeStatus::ReadResponse;
            }

            ServerHandshakeStatus::WriteAutoSwitch => {
                debug!("[#handshake] WriteAutoSwitch...");
                framed.send(framed.codec().generate_auth_switch_request()).await?;
            }

            ServerHandshakeStatus::Complete => {
                debug!("[#handshake] Complete...");
                break;
            }
            _ => {}
        }
    }

    framed.send(BytesMut::from(&ok_packet()[..])).await?;

    Ok((framed, true))
}

#[cfg(test)]
mod test {
    use bytes::BytesMut;
    use futures::{SinkExt, StreamExt};
    use tokio_util::codec::Framed;

    use crate::{
        err::ProtocolError,
        server::auth::{ServerHandshakeCodec, ServerHandshakeStatus},
    };

    #[tokio::test]
    async fn test_handshake() {
        //let packet_codec = PacketCodec::new(8192);
        let user = "root".to_string();
        let password = "123456".to_string();
        let db = "sbtest_pisa".to_string();
        let server_version = "5.7.36".to_string();
        let hs = ServerHandshakeCodec::new(user, password, db, server_version);

        let (client, server) = tokio::io::duplex(512);
        let mut framed = Framed::new(client, hs);

        let client_reponse_data = [
            0xaf, 0x00, 0x00, 0x01, 0x8d, 0xa2, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x40, 0x08, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x72, 0x6f, 0x6f, 0x74, 0x00, 0x14,
            0x38, 0x80, 0xb3, 0xc9, 0xc7, 0x29, 0x71, 0x1d, 0xeb, 0xf2, 0xe9, 0x43, 0x36, 0x24,
            0x4c, 0x71, 0xef, 0x32, 0x1a, 0x5d, 0x73, 0x62, 0x74, 0x65, 0x73, 0x74, 0x5f, 0x70,
            0x69, 0x73, 0x61, 0x00, 0x6d, 0x79, 0x73, 0x71, 0x6c, 0x5f, 0x6e, 0x61, 0x74, 0x69,
            0x76, 0x65, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00, 0x52, 0x03,
            0x5f, 0x6f, 0x73, 0x05, 0x4c, 0x69, 0x6e, 0x75, 0x78, 0x0c, 0x5f, 0x63, 0x6c, 0x69,
            0x65, 0x6e, 0x74, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x08, 0x6c, 0x69, 0x62, 0x6d, 0x79,
            0x73, 0x71, 0x6c, 0x04, 0x5f, 0x70, 0x69, 0x64, 0x04, 0x35, 0x32, 0x38, 0x31, 0x0f,
            0x5f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f,
            0x6e, 0x06, 0x35, 0x2e, 0x36, 0x2e, 0x35, 0x31, 0x09, 0x5f, 0x70, 0x6c, 0x61, 0x74,
            0x66, 0x6f, 0x72, 0x6d, 0x06, 0x78, 0x38, 0x36, 0x5f, 0x36, 0x34,
        ];

        let _ = framed.send(BytesMut::from(&client_reponse_data[..])).await;

        let mut parts = framed.into_parts();
        parts.io = server;

        framed = Framed::from_parts(parts);
        let res = framed.next().await.unwrap();
        assert!(framed.codec().next_handshake_status == ServerHandshakeStatus::Complete);

        if let Err(ProtocolError::AuthFailed(_data)) = res {
            assert!(true);
        }
    }

    #[tokio::test]
    async fn test_handshake_auto_switch() {
        let user = "root".to_string();
        let password = "123456".to_string();
        let db = "sbtest_pisa".to_string();
        let server_version = "5.7.36".to_string();
        let hs = ServerHandshakeCodec::new(user, password, db, server_version);

        let (mut client, mut server) = tokio::io::duplex(512);
        let mut framed = Framed::new(client, hs);

        let client_reponse_data = [
            0xae, 0x00, 0x00, 0x01, 0x8d, 0xa2, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x40, 0x08, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x72, 0x6f, 0x6f, 0x74, 0x00, 0x14,
            0x38, 0x80, 0xb3, 0xc9, 0xc7, 0x29, 0x71, 0x1d, 0xeb, 0xf2, 0xe9, 0x43, 0x36, 0x24,
            0x4c, 0x71, 0xef, 0x32, 0x1a, 0x5d, 0x73, 0x62, 0x74, 0x65, 0x73, 0x74, 0x5f, 0x70,
            0x69, 0x73, 0x61, 0x00, 116, 101, 115, 116, 95, 112, 97, 115, 115, 119, 111, 114, 100,
            95, 112, 108, 117, 103, 105, 110, 0x00, 0x52, 0x03, 0x5f, 0x6f, 0x73, 0x05, 0x4c, 0x69,
            0x6e, 0x75, 0x78, 0x0c, 0x5f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x6e, 0x61,
            0x6d, 0x65, 0x08, 0x6c, 0x69, 0x62, 0x6d, 0x79, 0x73, 0x71, 0x6c, 0x04, 0x5f, 0x70,
            0x69, 0x64, 0x04, 0x35, 0x32, 0x38, 0x31, 0x0f, 0x5f, 0x63, 0x6c, 0x69, 0x65, 0x6e,
            0x74, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x06, 0x35, 0x2e, 0x36, 0x2e,
            0x35, 0x31, 0x09, 0x5f, 0x70, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x06, 0x78,
            0x38, 0x36, 0x5f, 0x36, 0x34,
        ];

        let _ = framed.send(BytesMut::from(&client_reponse_data[..])).await;

        let mut parts = framed.into_parts();
        client = parts.io;
        parts.io = server;
        framed = Framed::from_parts(parts);

        let _res = framed.next().await.unwrap();

        assert_eq!(framed.codec().next_handshake_status, ServerHandshakeStatus::WriteAutoSwitch);

        framed.codec_mut().next_handshake_status = ServerHandshakeStatus::ReadAutoSwitchResponse;

        let mut parts = framed.into_parts();
        server = parts.io;
        parts.io = client;
        framed = Framed::from_parts(parts);

        let auto_switch_response_data = [
            0x14, 0x00, 0x00, 0x03, 0x38, 0x80, 0xb3, 0xc9, 0xc7, 0x29, 0x71, 0x1d, 0xeb, 0xf2,
            0xe9, 0x43, 0x36, 0x24, 0x4c, 0x71, 0xef, 0x32, 0x1a, 0x5d,
        ];

        let _ = framed.send(BytesMut::from(&auto_switch_response_data[..])).await;

        let mut parts = framed.into_parts();
        parts.io = server;
        framed = Framed::from_parts(parts);

        let res = framed.next().await.unwrap();
        assert_eq!(framed.codec().next_handshake_status, ServerHandshakeStatus::Complete);

        if let Err(ProtocolError::AuthFailed(_data)) = res {
            assert!(true);
        }
    }
}
