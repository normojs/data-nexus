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
    marker::PhantomData,
    sync::{atomic::AtomicU32, Arc},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bytes::{Buf, BytesMut};
use common::ast_cache::ParserAstCache;
use conn_pool::Pool;
use futures::{SinkExt, StreamExt};
use gateway_core::{
    Column, DialectParser, FrontendProtocolAdapter, GatewayCommand, GatewayError, GatewayResponse,
    GatewayResult, GatewayValue, ProtocolKind, SessionState, TransactionState,
};
use mysql_parser::parser::Parser;
use mysql_protocol::{
    client::conn::ClientConn,
    column::ColumnInfo,
    err::ProtocolError,
    mysql_const::{
        ColumnType, ComType, COM_INIT_DB, COM_PING, COM_QUERY, COM_QUIT, COM_STMT_CLOSE,
        COM_STMT_EXECUTE, COM_STMT_PREPARE,
    },
    server::{
        auth::{handshake, ServerHandshakeCodec},
        codec::{
            make_eof_packet, make_err_packet, ok_packet, CommonPacket, PacketCodec, PacketSend,
        },
        err::MySQLError,
        stream::LocalStream,
    },
    session::Session,
    util::BufMutExt,
};
use parking_lot::Mutex;
use pisa_error::error::{Error, ErrorKind};
use plugin::{build_phase::PluginPhase, err::BoxError, PluginContext, PluginDecision};
use strategy::{route::RouteStrategy, sharding_rewrite::ShardingRewrite};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_util::codec::{Decoder, Encoder, Framed};
use tracing::error;

use crate::{
    server::{
        metrics::{GatewayMetricsContext, MySQLServerMetricsCollector},
        stmt_cache::StmtCache,
    },
    transaction_fsm::TransFsm,
};

#[derive(Clone, Debug)]
pub struct MySqlFrontendProtocol {
    user: String,
    password: String,
    database: String,
    server_version: String,
    dialect_parser: MySqlDialectParser,
}

impl MySqlFrontendProtocol {
    pub fn new(user: String, password: String, database: String, server_version: String) -> Self {
        Self { user, password, database, server_version, dialect_parser: MySqlDialectParser }
    }

    pub async fn handshake(
        &self,
        socket: TcpStream,
    ) -> Result<Framed<LocalStream, PacketCodec>, Error> {
        let handshake_codec = ServerHandshakeCodec::new(
            self.user.clone(),
            self.password.clone(),
            self.database.clone(),
            self.server_version.clone(),
        );
        let handshake_framed =
            Framed::with_capacity(LocalStream::from(socket), handshake_codec, 8196);

        let (handshake_framed, authenticated) =
            handshake(handshake_framed).await.map_err(ErrorKind::from)?;
        if !authenticated {
            return Err(Error::new(ErrorKind::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "mysql authentication failed",
            ))));
        }

        let parts = handshake_framed.into_parts();
        let packet_codec = PacketCodec::new(parts.codec, 8196);
        Ok(Framed::with_capacity(parts.io, packet_codec, 16384))
    }
}

#[derive(Clone, Debug)]
pub struct MySqlDialectParser;

impl DialectParser for MySqlDialectParser {
    fn dialect(&self) -> ProtocolKind {
        ProtocolKind::MySql
    }

    fn parse_query(
        &self,
        sql: String,
        session: &mut SessionState,
    ) -> GatewayResult<GatewayCommand> {
        match sql.trim().to_ascii_lowercase().as_str() {
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

pub fn session_state_from_mysql_session<S>(mysql_session: &S) -> GatewayResult<SessionState>
where
    S: Session,
{
    let charset = mysql_session
        .get_charset()
        .ok_or_else(|| GatewayError::Protocol("mysql session charset is missing".into()))?;

    let autocommit =
        mysql_session.get_autocommit().map(|value| parse_mysql_autocommit(&value)).transpose()?;

    Ok(SessionState {
        database: mysql_session.get_db(),
        charset: Some(charset),
        autocommit,
        ..SessionState::default()
    })
}

fn parse_mysql_autocommit(value: &str) -> GatewayResult<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "on" | "true" => Ok(true),
        "0" | "off" | "false" => Ok(false),
        other => Err(GatewayError::Protocol(format!(
            "invalid mysql autocommit session value '{}'",
            other
        ))),
    }
}

impl FrontendProtocolAdapter for MySqlFrontendProtocol {
    fn protocol(&self) -> ProtocolKind {
        ProtocolKind::MySql
    }

    fn decode(
        &mut self,
        frame: &[u8],
        session: &mut SessionState,
    ) -> GatewayResult<Vec<GatewayCommand>> {
        let (command, payload) = frame
            .split_first()
            .ok_or_else(|| GatewayError::Protocol("empty mysql command frame".into()))?;

        let command = match *command {
            COM_QUIT => GatewayCommand::Quit,
            COM_INIT_DB => {
                let database = decode_text_payload(payload)?;
                session.database = Some(database.clone());
                GatewayCommand::UseDatabase { database }
            }
            COM_QUERY => self.dialect_parser.parse_query(decode_text_payload(payload)?, session)?,
            COM_PING => GatewayCommand::Ping,
            COM_STMT_PREPARE => GatewayCommand::Prepare { sql: decode_text_payload(payload)? },
            COM_STMT_EXECUTE => GatewayCommand::Execute {
                statement_id: decode_statement_id(payload)?,
                parameters: vec![],
            },
            COM_STMT_CLOSE => {
                GatewayCommand::CloseStatement { statement_id: decode_statement_id(payload)? }
            }
            other => {
                return Err(GatewayError::Unsupported(format!(
                    "unsupported mysql command byte {}",
                    other
                )))
            }
        };

        Ok(vec![command])
    }

    fn encode(
        &mut self,
        response: GatewayResponse,
        _session: &SessionState,
    ) -> GatewayResult<Vec<Vec<u8>>> {
        match response {
            GatewayResponse::Ok { .. } | GatewayResponse::Pong | GatewayResponse::Bye => {
                Ok(vec![ok_packet()[4..].to_vec()])
            }
            GatewayResponse::Error { code, message } => {
                let code = code.parse::<u16>().unwrap_or(1105);
                Ok(vec![make_err_packet(MySQLError::new(code, b"HY000".to_vec(), message))[4..]
                    .to_vec()])
            }
            GatewayResponse::ResultSet { columns, rows } => encode_text_resultset(columns, rows),
            GatewayResponse::Prepared { .. } => Err(GatewayError::Unsupported(
                "mysql prepared response encoding is still handled by the legacy packet stream"
                    .into(),
            )),
        }
    }
}

fn encode_text_resultset(
    columns: Vec<Column>,
    rows: Vec<Vec<GatewayValue>>,
) -> GatewayResult<Vec<Vec<u8>>> {
    if columns.len() > u64::MAX as usize {
        return Err(GatewayError::Protocol("mysql result set has too many columns".into()));
    }

    let mut frames = Vec::with_capacity(columns.len() + rows.len() + 3);
    let mut column_count = Vec::new();
    column_count.put_lenc_int(columns.len() as u64, true);
    frames.push(column_count);

    for column in &columns {
        let mut frame = Vec::new();
        mysql_column_info(column).encode(&mut frame);
        frames.push(frame);
    }

    frames.push(make_eof_packet()[4..].to_vec());
    for row in rows {
        if row.len() != columns.len() {
            return Err(GatewayError::Protocol(format!(
                "mysql result row has {} values for {} columns",
                row.len(),
                columns.len()
            )));
        }
        frames.push(encode_text_row(&row));
    }
    frames.push(make_eof_packet()[4..].to_vec());

    Ok(frames)
}

fn mysql_column_info(column: &Column) -> ColumnInfo {
    ColumnInfo {
        schema: None,
        table_name: None,
        column_name: column.name.clone(),
        charset: 0x21,
        column_length: 1024,
        column_type: mysql_column_type(&column.data_type),
        column_flag: 0,
        decimals: 0,
    }
}

fn mysql_column_type(data_type: &str) -> ColumnType {
    match data_type.to_ascii_lowercase().as_str() {
        "bool" | "boolean" => ColumnType::MYSQL_TYPE_TINY,
        "int2" | "smallint" => ColumnType::MYSQL_TYPE_SHORT,
        "int4" | "int" | "integer" => ColumnType::MYSQL_TYPE_LONG,
        "int8" | "bigint" => ColumnType::MYSQL_TYPE_LONGLONG,
        "float4" | "float" | "real" => ColumnType::MYSQL_TYPE_FLOAT,
        "float8" | "double" | "double precision" => ColumnType::MYSQL_TYPE_DOUBLE,
        "numeric" | "decimal" => ColumnType::MYSQL_TYPE_NEWDECIMAL,
        "bytea" | "blob" | "binary" => ColumnType::MYSQL_TYPE_BLOB,
        _ => ColumnType::MYSQL_TYPE_VAR_STRING,
    }
}

fn encode_text_row(row: &[GatewayValue]) -> Vec<u8> {
    let mut frame = Vec::new();
    for value in row {
        match value {
            GatewayValue::Null => frame.push(0xfb),
            value => {
                let text = mysql_text_value(value);
                frame.put_lenc_int(text.len() as u64, true);
                frame.extend_from_slice(&text);
            }
        }
    }
    frame
}

fn mysql_text_value(value: &GatewayValue) -> Vec<u8> {
    match value {
        GatewayValue::Boolean(value) => {
            if *value {
                b"1".to_vec()
            } else {
                b"0".to_vec()
            }
        }
        GatewayValue::Integer(value) => value.to_string().into_bytes(),
        GatewayValue::UnsignedInteger(value) => value.to_string().into_bytes(),
        GatewayValue::Float(value) => value.to_string().into_bytes(),
        GatewayValue::Decimal(value) | GatewayValue::String(value) => value.as_bytes().to_vec(),
        GatewayValue::Bytes(value) => value.clone(),
        GatewayValue::Null => Vec::new(),
    }
}

fn decode_text_payload(payload: &[u8]) -> GatewayResult<String> {
    let text = std::str::from_utf8(payload)
        .map_err(|error| GatewayError::Protocol(format!("invalid mysql utf8 payload: {}", error)))?
        .trim_matches(char::from(0))
        .to_string();
    Ok(text)
}

fn decode_statement_id(payload: &[u8]) -> GatewayResult<String> {
    if payload.len() < 4 {
        return Err(GatewayError::Protocol(
            "mysql statement command payload is missing statement id".into(),
        ));
    }

    Ok(u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]).to_string())
}

/// The Context arg required to handle the command.
pub struct ReqContext<T, C> {
    pub name: String,
    pub fsm: TransFsm,
    pub route_strategy: Arc<Mutex<RouteStrategy>>,
    pub pool: Pool<ClientConn>,
    pub parser: Arc<Parser>,
    pub ast_cache: Arc<Mutex<ParserAstCache>>,
    pub plugin: Option<PluginPhase>,
    pub metrics_collector: MySQLServerMetricsCollector,
    pub metrics_context: GatewayMetricsContext,
    // `concurrency_control_rule_idx` is index of concurrency_control rules
    // required to add permits when the concurrency_control layer service is enabled.
    pub concurrency_control_rule_idx: Option<usize>,
    pub framed: Framed<T, C>,
    pub rewriter: Option<ShardingRewrite>,
    pub rewrite_outputs: strategy::sharding_rewrite::ShardingRewriteOutput,
    pub has_readwritesplitting: bool,
    pub stmt_cache: StmtCache,
    pub stmt_id: AtomicU32,
}

/// Handle the return value of the command.
pub struct RespContext {
    // The endpoint of the backend database.
    pub ep: Option<String>,
    // The duration of handling the command.
    pub duration: Duration,
}

/// Handles decoded MySQL commands after the frontend protocol loop has parsed
/// the command byte and payload.
#[async_trait]
pub trait MySqlCommandService<T, C> {
    async fn init_db(cx: &mut ReqContext<T, C>, payload: &[u8]) -> Result<RespContext, Error>;
    async fn query(cx: &mut ReqContext<T, C>, payload: &[u8]) -> Result<RespContext, Error>;
    async fn prepare(cx: &mut ReqContext<T, C>, payload: &[u8]) -> Result<RespContext, Error>;
    async fn execute(cx: &mut ReqContext<T, C>, payload: &[u8]) -> Result<RespContext, Error>;
    async fn stmt_close(cx: &mut ReqContext<T, C>, payload: &[u8]) -> Result<RespContext, Error>;
    async fn quit(cx: &mut ReqContext<T, C>) -> Result<RespContext, Error>;
    async fn field_list(cx: &mut ReqContext<T, C>, payload: &[u8]) -> Result<RespContext, Error>;
}

/// Runs one MySQL frontend connection and delegates command execution to a
/// `MySqlCommandService`.
pub struct MySqlFrontendConnection<S, T, C> {
    _inner: S,
    is_quit: bool,
    _phat: PhantomData<(T, C)>,
}

impl<S, T, C> MySqlFrontendConnection<S, T, C>
where
    S: MySqlCommandService<T, C>,
    T: AsyncRead + AsyncWrite + Unpin,
    C: Decoder<Item = BytesMut, Error = ProtocolError>
        + Encoder<PacketSend<Box<[u8]>>, Error = ProtocolError>
        + CommonPacket,
{
    pub fn new(inner: S) -> Self {
        Self { _inner: inner, is_quit: false, _phat: PhantomData }
    }

    pub async fn run(&mut self, mut cx: ReqContext<T, C>) -> Result<(), Error>
    where
        C: Decoder<Item = BytesMut, Error = ProtocolError>
            + Encoder<PacketSend<Box<[u8]>>>
            + CommonPacket,
    {
        while let Some(data) = cx.framed.next().await {
            match data {
                Ok(data) => {
                    if let Err(err) = self.handle_command(&mut cx, data).await {
                        let err_info = make_err_packet(MySQLError::new(
                            2002,
                            "HY000".as_bytes().to_vec(),
                            String::from("There is no healthy backend to connect."),
                        ));
                        cx.framed
                            .send(PacketSend::Encode(err_info[4..].into()))
                            .await
                            .map_err(ErrorKind::from)?;
                        error!("exec command err: {:?}", err);
                    };

                    cx.framed.codec_mut().reset_seq();

                    if let Some(idx) = cx.concurrency_control_rule_idx {
                        let plugin = cx.plugin.as_mut().ok_or_else(|| {
                            Error::new(ErrorKind::Runtime(Box::new(std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "concurrency control permit exists without plugin state",
                            ))))
                        })?;
                        plugin.concurrency_control.add_permits(idx);
                        cx.concurrency_control_rule_idx = None;
                    }

                    if self.is_quit {
                        return Ok(());
                    }
                }

                Err(e) => return Err(Error::from(ErrorKind::from(e))),
            }
        }

        Ok(())
    }

    async fn handle_command(
        &mut self,
        cx: &mut ReqContext<T, C>,
        mut data: BytesMut,
    ) -> Result<RespContext, Error> {
        let now = Instant::now();
        let com = data.get_u8();
        let payload = data.split();

        if let Err(err) = self.plugin_run(cx, com, &payload) {
            let err_info = make_err_packet(MySQLError::new(
                1047,
                "08S01".as_bytes().to_vec(),
                err.to_string(),
            ));
            cx.framed
                .send(PacketSend::Encode(err_info[4..].into()))
                .await
                .map_err(ErrorKind::from)?;
            return Ok(RespContext { ep: None, duration: now.elapsed() });
        }

        match ComType::from(com) {
            ComType::QUIT => {
                self.is_quit = true;
                S::quit(cx).await
            }
            ComType::INIT_DB => S::init_db(cx, &payload).await,
            ComType::QUERY => S::query(cx, &payload).await,
            ComType::FIELD_LIST => S::field_list(cx, &payload).await,
            ComType::PING => {
                cx.framed
                    .send(PacketSend::Encode(ok_packet()[4..].into()))
                    .await
                    .map_err(ErrorKind::from)?;
                Ok(RespContext { ep: None, duration: now.elapsed() })
            }
            ComType::STMT_PREPARE => S::prepare(cx, &payload).await,
            ComType::STMT_EXECUTE => S::execute(cx, &payload).await,
            ComType::STMT_CLOSE => S::stmt_close(cx, &payload).await,
            ComType::STMT_RESET => {
                cx.framed
                    .send(PacketSend::Encode(ok_packet()[4..].into()))
                    .await
                    .map_err(ErrorKind::from)?;
                Ok(RespContext { ep: None, duration: now.elapsed() })
            }
            x => {
                let err_info = make_err_packet(MySQLError::new(
                    1047,
                    "08S01".as_bytes().to_vec(),
                    format!("command {} not support", x.as_ref()),
                ));
                cx.framed
                    .send(PacketSend::Encode(err_info[4..].into()))
                    .await
                    .map_err(ErrorKind::from)?;
                Ok(RespContext { ep: None, duration: now.elapsed() })
            }
        }
    }

    fn plugin_run(
        &mut self,
        cx: &mut ReqContext<T, C>,
        command: u8,
        payload: &[u8],
    ) -> Result<(), BoxError> {
        if let Some(plugin) = cx.plugin.as_mut() {
            let context = PluginContext::new(
                ProtocolKind::MySql,
                ComType::from(command).as_ref().to_string(),
                String::from_utf8_lossy(payload).to_string(),
            );

            let (permit_idx, decision) = plugin.handle(context)?;
            match decision {
                PluginDecision::Continue => {
                    cx.concurrency_control_rule_idx = permit_idx;
                    Ok(())
                }
                PluginDecision::Reject { reason } => {
                    Err(Box::new(std::io::Error::new(std::io::ErrorKind::PermissionDenied, reason)))
                }
                PluginDecision::Rewrite { .. } => Ok(()),
            }
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use mysql_protocol::{column::try_decode_column, session::SessionMut};

    use super::*;

    fn adapter() -> MySqlFrontendProtocol {
        MySqlFrontendProtocol::new("app".into(), "secret".into(), "test".into(), "8.0".into())
    }

    #[test]
    fn decodes_query_command() {
        let mut adapter = adapter();
        let mut session = SessionState::default();

        let commands =
            adapter.decode(&[COM_QUERY, b's', b'e', b'l', b'e', b'c', b't'], &mut session);

        assert_eq!(commands, Ok(vec![GatewayCommand::Query { sql: "select".into() }]));
    }

    #[test]
    fn decodes_use_database_and_updates_session() {
        let mut adapter = adapter();
        let mut session = SessionState::default();

        let commands =
            adapter.decode(&[COM_INIT_DB, b'o', b'r', b'd', b'e', b'r', b's'], &mut session);

        assert_eq!(commands, Ok(vec![GatewayCommand::UseDatabase { database: "orders".into() }]));
        assert_eq!(session.database, Some("orders".into()));
    }

    #[test]
    fn decodes_transaction_shortcuts() {
        let mut adapter = adapter();
        let mut session = SessionState::default();

        let commands = adapter.decode(&[COM_QUERY, b'b', b'e', b'g', b'i', b'n'], &mut session);

        assert_eq!(commands, Ok(vec![GatewayCommand::Begin]));
        assert_eq!(session.transaction_state, TransactionState::Active);
    }

    #[test]
    fn decodes_statement_close() {
        let mut adapter = adapter();
        let mut session = SessionState::default();
        let mut frame = vec![COM_STMT_CLOSE];
        frame.extend_from_slice(&42u32.to_le_bytes());

        let commands = adapter.decode(&frame, &mut session);

        assert_eq!(
            commands,
            Ok(vec![GatewayCommand::CloseStatement { statement_id: "42".into() }])
        );
    }

    #[test]
    fn encodes_ok_and_error_packets_without_mysql_header() {
        let mut adapter = adapter();
        let session = SessionState::default();

        assert_eq!(
            adapter.encode(GatewayResponse::Pong, &session),
            Ok(vec![ok_packet()[4..].to_vec()])
        );

        let error = adapter.encode(
            GatewayResponse::Error { code: "1047".into(), message: "nope".into() },
            &session,
        );

        assert!(
            matches!(error, Ok(packets) if packets.first().and_then(|packet| packet.first()) == Some(&0xff))
        );
    }

    #[test]
    fn encodes_resultset_as_mysql_text_protocol_frames() {
        let mut adapter = adapter();
        let session = SessionState::default();

        let packets = adapter
            .encode(
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
                            GatewayValue::UnsignedInteger(2),
                            GatewayValue::Null,
                            GatewayValue::Boolean(false),
                            GatewayValue::Bytes(Vec::new()),
                        ],
                    ],
                },
                &session,
            )
            .unwrap();

        assert_eq!(packets.len(), 9);
        assert_eq!(packets[0], vec![4]);
        assert_eq!(packets[5], make_eof_packet()[4..].to_vec());
        assert_eq!(packets[8], make_eof_packet()[4..].to_vec());

        let id_column = try_decode_column(&packets[1]).unwrap();
        assert_eq!(id_column.column_name, "id");
        assert_eq!(id_column.column_type, ColumnType::MYSQL_TYPE_LONG);

        let active_column = try_decode_column(&packets[3]).unwrap();
        assert_eq!(active_column.column_name, "active");
        assert_eq!(active_column.column_type, ColumnType::MYSQL_TYPE_TINY);

        assert_eq!(
            packets[6],
            vec![1, b'1', 5, b'a', b'l', b'i', b'c', b'e', 1, b'1', 2, 0xde, 0xad]
        );
        assert_eq!(packets[7], vec![1, b'2', 0xfb, 1, b'0', 0]);
    }

    #[test]
    fn rejects_resultset_rows_with_wrong_width() {
        let mut adapter = adapter();
        let session = SessionState::default();

        let error = adapter
            .encode(
                GatewayResponse::ResultSet {
                    columns: vec![Column { name: "id".into(), data_type: "int4".into() }],
                    rows: vec![vec![
                        GatewayValue::Integer(1),
                        GatewayValue::String("extra".into()),
                    ]],
                },
                &session,
            )
            .unwrap_err();

        assert!(matches!(
            error,
            GatewayError::Protocol(message) if message.contains("2 values for 1 columns")
        ));
    }

    #[test]
    fn converts_mysql_protocol_session_to_core_session_state() {
        let mut mysql_session =
            ServerHandshakeCodec::new("app".into(), "secret".into(), "orders".into(), "8.0".into());
        mysql_session.set_charset("utf8mb4".into());
        mysql_session.set_autocommit("OFF".into());

        let session = session_state_from_mysql_session(&mysql_session).unwrap();

        assert_eq!(session.database, Some("orders".into()));
        assert_eq!(session.charset, Some("utf8mb4".into()));
        assert_eq!(session.autocommit, Some(false));
        assert_eq!(session.transaction_state, TransactionState::Idle);
    }

    #[test]
    fn mysql_dialect_parser_classifies_transactions() {
        let parser = MySqlDialectParser;
        let mut session = SessionState::default();

        assert_eq!(parser.dialect(), ProtocolKind::MySql);
        assert_eq!(
            parser.parse_query("start transaction".into(), &mut session),
            Ok(GatewayCommand::Begin)
        );
        assert_eq!(session.transaction_state, TransactionState::Active);
        assert_eq!(
            parser.parse_query("rollback".into(), &mut session),
            Ok(GatewayCommand::Rollback)
        );
        assert_eq!(session.transaction_state, TransactionState::Idle);
        assert_eq!(
            parser.parse_query("select 1".into(), &mut session),
            Ok(GatewayCommand::Query { sql: "select 1".into() })
        );
    }
}
