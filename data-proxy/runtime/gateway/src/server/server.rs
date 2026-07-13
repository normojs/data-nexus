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

use std::{marker::PhantomData, sync::atomic::Ordering, time::Instant};

use async_trait::async_trait;
use byteorder::{ByteOrder, LittleEndian};
use bytes::BytesMut;
use conn_pool::PoolConn;
use futures::{SinkExt, StreamExt};
use gateway_core::{
    BackendConnector, Column as GatewayColumn, EndpointConfig, GatewayCommand, GatewayError,
    GatewayResponse, GatewayResult, GatewayValue, ProtocolKind, SessionState, TransactionState,
};
use mysql_parser::ast::*;
use mysql_protocol::{
    client::{
        codec::ResultsetStream,
        conn::{ClientConn, SessionAttr},
        stmt::Stmt,
    },
    column::{decode_column, Column, ColumnInfo},
    err::ProtocolError,
    mysql_const::*,
    server::{
        codec::{make_eof_packet, make_err_packet, ok_packet, CommonPacket, PacketSend},
        err::MySQLError,
    },
    session::{Session, SessionMut},
    util::{is_eof, length_encode_int},
};
use pisa_error::error::{Error, ErrorKind};
use strategy::{route::RouteInputTyp, sharding_rewrite::ShardingRewriteOutput};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Decoder, Encoder};
use tracing::{debug, error};

use super::{
    executor::Executor,
    util::{filter_avg_column, get_avg_change},
};
use crate::{
    frontend::mysql::{MySqlCommandService, ReqContext, RespContext},
    transaction_fsm::{
        build_conn_attrs, check_get_conn, query_rewrite, route, route_sharding, TransEventName,
    },
};

pub struct MySqlBackendConnector<T, C> {
    endpoints: Vec<EndpointConfig>,
    _phat: PhantomData<(T, C)>,
}

impl<T, C> MySqlBackendConnector<T, C> {
    pub fn new() -> Self {
        Self { endpoints: Vec::new(), _phat: PhantomData }
    }

    pub fn with_endpoints(endpoints: Vec<EndpointConfig>) -> Self {
        Self { endpoints, _phat: PhantomData }
    }

    fn endpoint(&self) -> GatewayResult<&EndpointConfig> {
        self.endpoints.first().ok_or_else(|| {
            GatewayError::Configuration(
                "mysql backend connector has no configured endpoints".into(),
            )
        })
    }

    async fn execute_simple_query(
        &self,
        sql: &str,
        session: &mut SessionState,
    ) -> GatewayResult<GatewayResponse> {
        let endpoint = self.endpoint()?;
        let mut conn = ClientConn::with_opts(
            endpoint.username.clone(),
            endpoint.password.clone(),
            endpoint.address.clone(),
        )
        .connect()
        .await
        .map_err(|error| GatewayError::Backend(format!("connect mysql backend: {}", error)))?;

        if let Some(database) = session.database.clone().or_else(|| endpoint.database.clone()) {
            if !database.is_empty() {
                let (_, ok) = conn.send_use_db(&database).await.map_err(|error| {
                    GatewayError::Backend(format!("select mysql database: {}", error))
                })?;
                if ok {
                    session.database = Some(database);
                } else {
                    return Err(GatewayError::Backend(format!(
                        "mysql backend rejected database '{}'",
                        database
                    )));
                }
            }
        }

        let mut stream = conn
            .send_query(sql.as_bytes())
            .await
            .map_err(|error| GatewayError::Backend(format!("write mysql query: {}", error)))?;

        read_mysql_query_response(&mut stream).await
    }
}

impl<T, C> Default for MySqlBackendConnector<T, C> {
    fn default() -> Self {
        Self::new()
    }
}

async fn read_mysql_query_response(
    stream: &mut ResultsetStream<'_>,
) -> GatewayResult<GatewayResponse> {
    let header = read_mysql_result_packet(stream, "mysql query header").await?;
    mysql_response_from_header_and_stream(header, stream).await
}

async fn mysql_response_from_header_and_stream(
    header: BytesMut,
    stream: &mut ResultsetStream<'_>,
) -> GatewayResult<GatewayResponse> {
    let payload = packet_payload("mysql query header", &header)?;
    match payload.first().copied() {
        Some(OK_HEADER) => ok_packet_to_gateway_response(payload),
        Some(ERR_HEADER) => Ok(err_packet_to_gateway_response(payload)),
        Some(_) => {
            let (column_count, is_null, _) = decode_lenc_int(payload, "mysql column count")?;
            if is_null {
                return Err(GatewayError::Protocol(
                    "mysql result set column count cannot be NULL".into(),
                ));
            }

            let mut column_infos = Vec::with_capacity(column_count as usize);
            for _ in 0..column_count {
                let column_packet =
                    read_mysql_result_packet(stream, "mysql column definition").await?;
                let column_payload = packet_payload("mysql column definition", &column_packet)?;
                column_infos.push(decode_column(column_payload));
            }

            let _ = read_mysql_result_packet(stream, "mysql column eof").await?;

            let mut rows = Vec::new();
            while let Some(row_packet) = read_optional_mysql_result_packet(stream).await? {
                let row_payload = packet_payload("mysql row", &row_packet)?;
                rows.push(text_row_to_gateway_values(row_payload, &column_infos)?);
            }

            Ok(GatewayResponse::ResultSet {
                columns: column_infos.iter().map(mysql_column_to_gateway_column).collect(),
                rows,
            })
        }
        None => Err(GatewayError::Protocol("mysql query header packet has empty payload".into())),
    }
}

async fn read_mysql_result_packet(
    stream: &mut ResultsetStream<'_>,
    context: &str,
) -> GatewayResult<BytesMut> {
    read_optional_mysql_result_packet(stream).await?.ok_or_else(|| {
        GatewayError::Backend(format!("mysql backend closed while reading {}", context))
    })
}

async fn read_optional_mysql_result_packet(
    stream: &mut ResultsetStream<'_>,
) -> GatewayResult<Option<BytesMut>> {
    match stream.next().await {
        Some(Ok(packet)) => Ok(Some(packet)),
        Some(Err(error)) => {
            Err(GatewayError::Backend(format!("read mysql result packet: {}", error)))
        }
        None => Ok(None),
    }
}

fn packet_payload<'a>(context: &str, packet: &'a [u8]) -> GatewayResult<&'a [u8]> {
    if packet.len() < 4 {
        return Err(GatewayError::Protocol(format!(
            "{} mysql packet is shorter than the 4-byte header",
            context
        )));
    }
    Ok(&packet[4..])
}

fn ok_packet_to_gateway_response(payload: &[u8]) -> GatewayResult<GatewayResponse> {
    let (affected_rows, _, affected_pos) =
        decode_lenc_int(payload.get(1..).unwrap_or_default(), "mysql OK affected rows")?;
    let last_insert_id = payload
        .get(1 + affected_pos..)
        .and_then(|data| decode_lenc_int(data, "mysql OK last insert id").ok())
        .map(|(id, ..)| id)
        .filter(|id| *id > 0);

    Ok(GatewayResponse::Ok { affected_rows, last_insert_id })
}

fn err_packet_to_gateway_response(payload: &[u8]) -> GatewayResponse {
    let code = payload
        .get(1..3)
        .map(|code| LittleEndian::read_u16(code).to_string())
        .unwrap_or_else(|| "HY000".into());

    let message_offset = if payload.get(3) == Some(&b'#') && payload.len() >= 9 { 9 } else { 3 };
    let message = payload
        .get(message_offset..)
        .map(|message| String::from_utf8_lossy(message).trim_start().to_string())
        .filter(|message| !message.is_empty())
        .unwrap_or_else(|| "mysql backend error".into());

    GatewayResponse::Error { code, message }
}

fn mysql_column_to_gateway_column(column: &ColumnInfo) -> GatewayColumn {
    GatewayColumn {
        name: column.column_name.clone(),
        data_type: column.column_type.as_ref().to_string(),
    }
}

fn text_row_to_gateway_values(
    row: &[u8],
    columns: &[ColumnInfo],
) -> GatewayResult<Vec<GatewayValue>> {
    let mut values = Vec::with_capacity(columns.len());
    let mut cursor = 0;

    for column in columns {
        if cursor >= row.len() {
            return Err(GatewayError::Protocol(format!(
                "mysql row has fewer values than the {} result columns",
                columns.len()
            )));
        }

        let (length, is_null, pos) =
            decode_lenc_int(&row[cursor..], "mysql text row value length")?;
        cursor += pos;

        if is_null {
            values.push(GatewayValue::Null);
            continue;
        }

        let end = cursor + length as usize;
        if end > row.len() {
            return Err(GatewayError::Protocol(
                "mysql text row value length exceeds packet payload".into(),
            ));
        }

        values.push(mysql_text_value_to_gateway_value(column, &row[cursor..end]));
        cursor = end;
    }

    if cursor != row.len() {
        return Err(GatewayError::Protocol(
            "mysql row has more values than the result column metadata".into(),
        ));
    }

    Ok(values)
}

fn mysql_text_value_to_gateway_value(column: &ColumnInfo, value: &[u8]) -> GatewayValue {
    match &column.column_type {
        ColumnType::MYSQL_TYPE_TINY
        | ColumnType::MYSQL_TYPE_SHORT
        | ColumnType::MYSQL_TYPE_LONG
        | ColumnType::MYSQL_TYPE_LONGLONG
        | ColumnType::MYSQL_TYPE_INT24
        | ColumnType::MYSQL_TYPE_YEAR => {
            let value_text = String::from_utf8_lossy(value);
            if column.column_flag & (ColumnFlag::UNSIGNED_FLAG as u16) > 0 {
                value_text
                    .parse::<u64>()
                    .map(GatewayValue::UnsignedInteger)
                    .unwrap_or_else(|_| GatewayValue::String(value_text.into_owned()))
            } else {
                value_text
                    .parse::<i64>()
                    .map(GatewayValue::Integer)
                    .unwrap_or_else(|_| GatewayValue::String(value_text.into_owned()))
            }
        }
        ColumnType::MYSQL_TYPE_FLOAT | ColumnType::MYSQL_TYPE_DOUBLE => {
            String::from_utf8_lossy(value).parse::<f64>().map(GatewayValue::Float).unwrap_or_else(
                |_| GatewayValue::String(String::from_utf8_lossy(value).into_owned()),
            )
        }
        ColumnType::MYSQL_TYPE_DECIMAL | ColumnType::MYSQL_TYPE_NEWDECIMAL => {
            GatewayValue::Decimal(String::from_utf8_lossy(value).into_owned())
        }
        ColumnType::MYSQL_TYPE_BLOB
        | ColumnType::MYSQL_TYPE_TINY_BLOB
        | ColumnType::MYSQL_TYPE_MEDIUM_BLOB
        | ColumnType::MYSQL_TYPE_LONG_BLOB => GatewayValue::Bytes(value.to_vec()),
        _ => GatewayValue::String(String::from_utf8_lossy(value).into_owned()),
    }
}

fn decode_lenc_int(data: &[u8], context: &str) -> GatewayResult<(u64, bool, usize)> {
    let Some(first) = data.first().copied() else {
        return Err(GatewayError::Protocol(format!("{} is missing", context)));
    };

    match first {
        0xfb => Ok((0, true, 1)),
        0xfc => decode_fixed_lenc_int(data, context, 2, 3),
        0xfd => decode_fixed_lenc_int(data, context, 3, 4),
        0xfe => decode_fixed_lenc_int(data, context, 8, 9),
        value => Ok((value as u64, false, 1)),
    }
}

fn decode_fixed_lenc_int(
    data: &[u8],
    context: &str,
    value_len: usize,
    total_len: usize,
) -> GatewayResult<(u64, bool, usize)> {
    if data.len() < total_len {
        return Err(GatewayError::Protocol(format!(
            "{} length-encoded integer is shorter than {} bytes",
            context, total_len
        )));
    }
    Ok((LittleEndian::read_uint(&data[1..], value_len), false, total_len))
}

impl<T, C> MySqlBackendConnector<T, C>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
    C: Decoder<Item = BytesMut>
        + Encoder<PacketSend<Box<[u8]>>, Error = ProtocolError>
        + Send
        + CommonPacket,
{
    async fn fsm_trigger(
        req: &mut ReqContext<T, C>,
        state_name: TransEventName,
        input_typ: RouteInputTyp,
        raw_sql: &str,
    ) -> Result<PoolConn<ClientConn>, Error> {
        let sess = req.framed.codec_mut().get_session();
        let attrs = build_conn_attrs(sess);
        let is_get_conn = req.fsm.trigger(state_name);
        if is_get_conn {
            return Self::fsm_get_new_conn(req, raw_sql, input_typ, &attrs).await;
        }

        let endpoint = route(input_typ, raw_sql, req.route_strategy.clone());
        req.fsm.get_conn_with_endpoint(endpoint, &attrs).await
    }

    async fn fsm_get_new_conn(
        req: &mut ReqContext<T, C>,
        raw_sql: &str,
        input_typ: RouteInputTyp,
        attrs: &[SessionAttr],
    ) -> Result<PoolConn<ClientConn>, Error> {
        let endpoint = route(input_typ, raw_sql, req.route_strategy.clone());
        let factory =
            ClientConn::with_opts(endpoint.user, endpoint.password, endpoint.addr.clone());
        req.pool.set_factory(&endpoint.addr, factory);
        check_get_conn(req.pool.clone(), &endpoint.addr, attrs).await
    }

    async fn init_db_inner<'b>(
        req: &mut ReqContext<T, C>,
        client_conn: &mut PoolConn<ClientConn>,
        payload: &[u8],
    ) -> Result<(), Error> {
        let db = std::str::from_utf8(payload).unwrap().trim_matches(char::from(0));

        req.fsm.set_db(Some(db.to_string()));

        let res = client_conn.send_use_db(db).await.map_err(ErrorKind::from)?;

        if res.1 {
            req.framed
                .send(PacketSend::Encode(ok_packet()[4..].into()))
                .await
                .map_err(ErrorKind::from)?;
        } else {
            // supports CLIENT_PROTOCOL_41 default
            // skip sql_state_marker and sql_state packet
            let err_info = make_err_packet(MySQLError::new(
                1049,
                "42000".as_bytes().to_vec(),
                String::from_utf8_lossy(&res.0[13..]).to_string(),
            ));
            req.framed
                .send(PacketSend::Encode(err_info[4..].into()))
                .await
                .map_err(ErrorKind::from)?;
        }

        Ok(())
    }

    async fn prepare_shard_inner(req: &mut ReqContext<T, C>, payload: &[u8]) -> Result<(), Error> {
        req.stmt_id.fetch_add(1, Ordering::Relaxed);
        let stmt_id = req.stmt_id.load(Ordering::Relaxed);
        let sess = req.framed.codec_mut().get_session();
        let attrs = build_conn_attrs(sess);
        let raw_sql = std::str::from_utf8(payload).unwrap().trim_matches(char::from(0));
        let (_, input_typ, rewrite_outputs) = Self::query_rewrite(req, raw_sql)?;
        req.rewrite_outputs = rewrite_outputs;

        // PrepareEvent trigger
        let is_get_conn = req.fsm.trigger(TransEventName::PrepareEvent);

        if req.rewrite_outputs.results.is_empty() {
            let mut client_conn = Self::fsm_trigger(
                req,
                TransEventName::PrepareEvent,
                RouteInputTyp::Statement,
                raw_sql,
            )
            .await?;
            let res = Self::prepare_normal_inner(req, &mut client_conn, payload).await;

            req.fsm.put_conn(client_conn);
            return res;
        }

        route_sharding(input_typ, raw_sql, req.route_strategy.clone(), &mut req.rewrite_outputs);
        let sharding_column = req.rewrite_outputs.results[0].ds_idx.column.clone();
        debug!(
            "prepare rewrite outputs {:?} {:?} {:?}",
            req.rewrite_outputs,
            req.rewrite_outputs.results.len(),
            is_get_conn
        );

        let (mut stmts, shard_conns) =
            Executor::shard_prepare_executor(req, attrs, is_get_conn).await?;
        for i in stmts.iter().zip(shard_conns.into_iter()) {
            req.stmt_cache.put(stmt_id, i.0.stmt_id, i.1)
        }

        let mut stmt = stmts.remove(0);
        stmt.stmt_id = stmt_id;

        req.stmt_cache.put_sharding_column(stmt_id, sharding_column);
        Self::prepare_stmt(req, stmt).await?;

        Ok(())
    }

    async fn prepare_normal_inner(
        req: &mut ReqContext<T, C>,
        client_conn: &mut PoolConn<ClientConn>,
        payload: &[u8],
    ) -> Result<(), Error> {
        let stmt = client_conn.send_prepare(payload).await.map_err(ErrorKind::from)?;
        Self::prepare_stmt(req, stmt).await?;

        Ok(())
    }

    async fn prepare_stmt(req: &mut ReqContext<T, C>, stmt: Stmt) -> Result<(), Error> {
        let mut buf = BytesMut::with_capacity(128);
        let mut data = vec![0];
        data.extend_from_slice(&u32::to_le_bytes(stmt.stmt_id));

        let avg_change = get_avg_change(&req.rewrite_outputs.results[0].changes);

        if avg_change.is_some() {
            data.extend_from_slice(&u16::to_le_bytes(stmt.cols_count - 1));
        } else {
            data.extend_from_slice(&u16::to_le_bytes(stmt.cols_count));
        }

        data.extend_from_slice(&u16::to_le_bytes(stmt.params_count));

        data.extend_from_slice(&[0, 0, 0]);

        let _ = req.framed.codec_mut().encode(PacketSend::EncodeOffset(data.into(), 0), &mut buf);

        if !stmt.params_data.is_empty() {
            for param_data in stmt.params_data {
                let _ = req
                    .framed
                    .codec_mut()
                    .encode(PacketSend::EncodeOffset(param_data[4..].into(), buf.len()), &mut buf);
            }

            let eof_packet = make_eof_packet();
            let _ = req
                .framed
                .codec_mut()
                .encode(PacketSend::EncodeOffset(eof_packet[4..].into(), buf.len()), &mut buf);
        }

        if !stmt.cols_data.is_empty() {
            let mut is_added_avg_column = false;
            for col_data in stmt.cols_data {
                let column_info = (&col_data[4..]).decode_column();
                if let Some(change) = avg_change {
                    let filter_res = filter_avg_column(change, &column_info, is_added_avg_column);
                    if filter_res.1.is_some() {
                        if !filter_res.0.is_empty() {
                            let _ = req.framed.codec_mut().encode(
                                PacketSend::EncodeOffset(filter_res.0.into(), buf.len()),
                                &mut buf,
                            );
                        }

                        is_added_avg_column = true;
                        continue;
                    }
                }

                let _ = req
                    .framed
                    .codec_mut()
                    .encode(PacketSend::EncodeOffset(col_data[4..].into(), buf.len()), &mut buf);
            }

            let eof_packet = make_eof_packet();
            let _ = req
                .framed
                .codec_mut()
                .encode(PacketSend::EncodeOffset(eof_packet[4..].into(), buf.len()), &mut buf);
        }

        req.framed.send(PacketSend::Origin(buf[..].into())).await.map_err(ErrorKind::from)?;

        Ok(())
    }

    async fn execute_shard_inner(req: &mut ReqContext<T, C>, payload: &[u8]) -> Result<(), Error> {
        Executor::shard_execute_executor(req, payload).await
    }

    async fn execute_inner(
        req: &mut ReqContext<T, C>,
        client_conn: &mut PoolConn<ClientConn>,
        payload: &[u8],
    ) -> Result<RespContext, Error> {
        let stream = client_conn.send_execute(payload).await.map_err(ErrorKind::from)?;

        Self::handle_query_resultset(req, stream).await.map_err(ErrorKind::from)?;

        Ok(RespContext { ep: None, duration: Instant::now().elapsed() })
    }

    async fn shard_query_inner(req: &mut ReqContext<T, C>, payload: &[u8]) -> Result<(), Error> {
        let sess = req.framed.codec_mut().get_session();
        let attrs = build_conn_attrs(sess);
        let raw_sql = std::str::from_utf8(payload).unwrap().trim_matches(char::from(0));
        let (is_get_conn, input_typ, rewrite_outputs) = Self::query_rewrite(req, raw_sql)?;
        req.rewrite_outputs = rewrite_outputs;

        if req.rewrite_outputs.results.is_empty() {
            let mut client_conn = Self::query_inner_get_conn(req, payload).await?;
            let res = Self::query_inner(req, &mut client_conn, payload).await;

            req.fsm.put_conn(client_conn);
            return res;
        }

        route_sharding(input_typ, raw_sql, req.route_strategy.clone(), &mut req.rewrite_outputs);
        Executor::shard_query_executor(req, attrs, is_get_conn).await?;
        Ok(())
    }

    async fn query_inner(
        req: &mut ReqContext<T, C>,
        client_conn: &mut PoolConn<ClientConn>,
        payload: &[u8],
    ) -> Result<(), Error> {
        let stream = match client_conn.send_query(payload).await {
            Ok(stream) => stream,
            Err(err) => return Err(Error::new(ErrorKind::Protocol(err))),
        };

        Self::handle_query_resultset(req, stream).await.map_err(ErrorKind::from)?;

        Ok(())
    }

    /// 在查询过程中获取数据库连接的内部函数
    ///
    /// 此函数负责处理查询请求并根据需要获取数据库连接它首先检查查询是否需要获取新连接，
    /// 如果需要，则根据路由策略确定目标数据库地址，并尝试获取或创建连接。
    /// 如果不需要新连接，则直接使用现有连接执行查询
    ///
    /// # 参数
    ///
    /// * `req` - 一个可变的请求上下文，包含框架、会话信息等
    /// * `payload` - 查询数据的字节切片
    ///
    /// # 返回
    ///
    /// 返回一个结果，包含池中的客户端连接或错误信息
    async fn query_inner_get_conn(
        req: &mut ReqContext<T, C>,
        payload: &[u8],
    ) -> Result<PoolConn<ClientConn>, Error> {
        // 获取会话信息
        let sess = req.framed.codec_mut().get_session();
        // 构建连接属性
        let attrs = build_conn_attrs(sess);
        // 将payload转换为字符串并清理
        let sql = std::str::from_utf8(payload).unwrap().trim_matches(char::from(0));
        // 进行查询重写和分析
        let (is_get_conn, input_typ, _rewrite_outputs) = Self::query_rewrite(req, sql)?;

        // 判断是否需要获取新连接
        if is_get_conn {
            // 根据输入类型和SQL进行路由，确定目标数据库地址
            let endpoint = route(input_typ, sql, req.route_strategy.clone());
            // 创建新的客户端连接工厂
            let factory =
                ClientConn::with_opts(endpoint.user, endpoint.password, endpoint.addr.clone());
            // 设置连接工厂到连接池
            req.pool.set_factory(&endpoint.addr, factory);
            // 检查并获取连接
            return check_get_conn(req.pool.clone(), &endpoint.addr, &attrs).await;
        }

        // 使用现有连接
        req.fsm.get_conn(&attrs).await
    }

    /// 重写查询SQL的方法
    ///
    /// 此函数尝试解析给定的SQL语句，并根据其类型和当前请求上下文决定是否进行重写。
    /// 它处理各种SQL语句类型，如SET、BEGIN、START、COMMIT、ROLLBACK等，并根据情况触发相应的事务状态机事件。
    /// 如果需要重写且rewriter存在，则执行重写操作。
    ///
    /// # 参数
    /// - `req`: 请求上下文的可变引用，包含rewriter和fsm等重要信息
    /// - `sql`: 需要重写的SQL语句
    ///
    /// # 返回
    /// - `Result`: 包含一个元组，元组内包含：
    ///     - `bool`: 是否获取连接
    ///     - `RouteInputTyp`: SQL语句类型
    ///     - `ShardingRewriteOutput`: 重写输出结果
    ///   如果操作成功，则返回Ok，否则返回Error
    fn query_rewrite<'a>(
        req: &'a mut ReqContext<T, C>,
        sql: &'a str,
    ) -> Result<(bool, RouteInputTyp, ShardingRewriteOutput), Error> {
        // 获取SQL的AST（抽象语法树）
        let ast = Self::get_ast(req, sql);
        let ast = match ast {
            Err(err) => {
                // 如果解析SQL出错，记录错误日志
                error!("parse sql {:?} err: {:?}", sql, err);
                // 如果rewriter存在，则返回错误
                if req.rewriter.is_some() {
                    return Err(err);
                }
                // 否则，触发查询事件并返回默认值
                let is_get_conn = req.fsm.trigger(TransEventName::QueryEvent);
                return Ok((
                    is_get_conn,
                    RouteInputTyp::Statement,
                    ShardingRewriteOutput::default(),
                ));
            }
            Ok(ast) => {
                // debug!("parse sql {:?}", sql);
                ast[0].clone()
            }
        };

        // 根据AST的类型决定是否获取连接、输入类型和是否可以重写
        let (is_get_conn, input, can_rewrite) = match &ast {
            SqlStmt::Set(stmt) => {
                // 处理SET语句
                let (is_get_conn, input) = Self::handle_set_stmt(req, &stmt);
                (is_get_conn, input, false)
            }
            // TODO: split sql stmt for sql audit
            // TODO: 将 SQL 语句拆分成用于 SQL 审计的形式
            SqlStmt::BeginStmt(_stmt) => {
                // 处理BEGIN语句，触发事务开始事件
                (req.fsm.trigger(TransEventName::StartEvent), RouteInputTyp::Transaction, false)
            }
            SqlStmt::Start(_stmt) => {
                // 处理START语句，同样触发事务开始事件
                (req.fsm.trigger(TransEventName::StartEvent), RouteInputTyp::Transaction, false)
            }
            SqlStmt::Commit(_stmt) => (
                // 处理COMMIT语句，触发事务提交事件
                req.fsm.trigger(TransEventName::CommitRollBackEvent),
                RouteInputTyp::Transaction,
                false,
            ),
            SqlStmt::Rollback(_stmt) => (
                // 处理ROLLBACK语句，触发事务回滚事件
                req.fsm.trigger(TransEventName::CommitRollBackEvent),
                RouteInputTyp::Transaction,
                false,
            ),
            _ => (
                // 对于其他类型的语句，触发查询事件并标记为可重写
                req.fsm.trigger(TransEventName::QueryEvent),
                RouteInputTyp::Statement,
                true,
            ),
        };

        // 如果rewriter存在且可以重写，则执行重写操作
        if req.rewriter.is_some() {
            let default_db = req.framed.codec_mut().get_session().get_db();
            let outputs = query_rewrite(
                req.rewriter.as_mut().unwrap(),
                sql.to_string(),
                ast,
                default_db,
                can_rewrite,
            )
            .map_err(|e| ErrorKind::Runtime(e.into()))?;
            debug!("rewrite outputs {:?}", outputs);
            return Ok((is_get_conn, input, outputs));
        }
        debug!("rewrite none");
        // 如果不需要重写，返回默认的重写输出结果
        return Ok((is_get_conn, input, ShardingRewriteOutput::default()));
    }

    // Set charset name
    fn handle_set_stmt<'b: 'a, 'a>(
        req: &'b mut ReqContext<T, C>,
        stmt: &'a SetOptValues,
    ) -> (bool, RouteInputTyp) {
        match stmt {
            SetOptValues::OptValues(vals) => match &vals.opt {
                SetOpts::SetNames(name) => {
                    if let Some(name) = &name.charset_name {
                        req.framed.codec_mut().get_session().set_charset(name.clone());
                        req.fsm.set_charset(name.clone());
                        let _ = req.fsm.reset_fsm_state();
                        return (true, RouteInputTyp::Statement);
                    }
                }
                SetOpts::SetVariable(val) => {
                    if val.var.to_uppercase() == "AUTOCOMMIT" {
                        match &val.value {
                            ExprOrDefault::Expr(expr) => match expr {
                                Expr::LiteralExpr(Value::Num { value, .. })
                                | Expr::SimpleIdentExpr(Value::Ident { value, .. }) => {
                                    if value == "0" || value.to_uppercase() == "OFF" {
                                        //req.fsm
                                        //    .trigger(
                                        //        TransEventName::SetSessionEvent,
                                        //        RouteInput::Transaction(input),
                                        //    )
                                        //    .await
                                        //    .unwrap();

                                        let is_get_conn =
                                            req.fsm.trigger(TransEventName::SetSessionEvent);
                                        return (is_get_conn, RouteInputTyp::Transaction);
                                    }

                                    if value == "1" {
                                        //let _ = req
                                        //    .fsm
                                        //    .reset_fsm_state(RouteInput::Statement(input))
                                        //    .await;
                                        req.fsm.reset_fsm_state();
                                    }

                                    req.framed
                                        .codec_mut()
                                        .get_session()
                                        .set_autocommit(value.clone());
                                    req.fsm.set_autocommit(value.clone());
                                    return (true, RouteInputTyp::Statement);
                                }
                                _ => {}
                            },
                            ExprOrDefault::On => {
                                req.framed
                                    .codec_mut()
                                    .get_session()
                                    .set_autocommit(String::from("ON"));
                                req.fsm.set_autocommit(String::from("ON"));
                                //let _ = req.fsm.reset_fsm_state(RouteInput::Statement(input)).await;
                                req.fsm.reset_fsm_state();

                                return (true, RouteInputTyp::Statement);
                            }

                            _ => {}
                        }
                    }
                }
                _ => {}
            },

            _ => {}
        }

        //req.fsm
        //    .trigger(TransEventName::SetSessionEvent, RouteInput::Statement(input))
        //    .await
        //    .unwrap();
        let is_get_conn = req.fsm.trigger(TransEventName::SetSessionEvent);
        (is_get_conn, RouteInputTyp::Statement)
    }

    fn get_ast(req: &mut ReqContext<T, C>, sql: &str) -> Result<Vec<SqlStmt>, Error> {
        let mut ast_cache = req.ast_cache.lock();
        let try_ast = ast_cache.get(sql.to_string());

        match try_ast {
            Some(stmt) => Ok(stmt.to_vec()),
            None => match req.parser.parse(sql) {
                Err(err) => Err(Error::from(ErrorKind::from(err[0].clone()))),
                Ok(stmt) => {
                    debug!("cache sql code: {}", sql.to_string());
                    debug!("cache sql ast: {:?}", stmt);
                    ast_cache.set(sql.to_string(), stmt.clone());
                    Ok(stmt)
                }
            },
        }
    }

    pub async fn handle_query_resultset<'b>(
        req: &mut ReqContext<T, C>,
        mut stream: ResultsetStream<'b>,
    ) -> Result<(), ProtocolError> {
        let data = stream.next().await;

        let header = match data {
            Some(Ok(data)) => data,
            Some(Err(e)) => return Err(e),
            None => return Ok(()),
        };

        let ok_or_err = header[4];

        if ok_or_err == OK_HEADER || ok_or_err == ERR_HEADER {
            req.framed.send(PacketSend::Encode(header[4..].into())).await?;
            return Ok(());
        }

        let (cols, ..) = length_encode_int(&header[4..]);

        let mut buf = BytesMut::with_capacity(1 << 16);

        let _ = req
            .framed
            .codec_mut()
            .encode(PacketSend::EncodeOffset(header[4..].into(), 0), &mut buf);

        for _ in 0..cols {
            let data = stream.next().await;
            let data = match data {
                Some(Ok(data)) => data,
                Some(Err(e)) => return Err(e),
                None => break,
            };

            let _ = req
                .framed
                .codec_mut()
                .encode(PacketSend::EncodeOffset(data[4..].into(), buf.len()), &mut buf);
        }

        // read eof
        let _ = stream.next().await;

        let _ = req
            .framed
            .codec_mut()
            .encode(PacketSend::EncodeOffset(make_eof_packet()[4..].into(), buf.len()), &mut buf);

        while let Some(data) = stream.next().await {
            let row = match data {
                Ok(data) => data,
                Err(e) => return Err(e),
            };

            let _ = req
                .framed
                .codec_mut()
                .encode(PacketSend::EncodeOffset(row[4..].into(), buf.len()), &mut buf);
        }

        let _ = req
            .framed
            .codec_mut()
            .encode(PacketSend::EncodeOffset(make_eof_packet()[4..].into(), buf.len()), &mut buf);

        req.framed.send(PacketSend::Origin(buf[..].into())).await?;

        Ok(())
    }

    pub async fn field_list_inner(
        req: &mut ReqContext<T, C>,
        client_conn: &mut PoolConn<ClientConn>,
        payload: &[u8],
    ) -> Result<(), Error> {
        let mut stream = match client_conn.send_common_command(COM_FIELD_LIST, payload).await {
            Ok(stream) => stream,
            Err(err) => return Err(Error::new(ErrorKind::Protocol(err))),
        };

        let mut buf = BytesMut::with_capacity(128);

        loop {
            let data = match stream.next().await {
                Some(Ok(data)) => data,
                Some(Err(e)) => return Err(Error::new(ErrorKind::Protocol(e))),
                None => break,
            };

            let _ = req
                .framed
                .codec_mut()
                .encode(PacketSend::EncodeOffset(data[4..].into(), buf.len()), &mut buf);

            if is_eof(&data) {
                break;
            }
        }

        req.framed.send(PacketSend::Origin(buf[..].into())).await.map_err(ErrorKind::from)?;

        Ok(())
    }

    async fn _sharding_command_not_support(
        cx: &mut ReqContext<T, C>,
        command: &str,
    ) -> Result<(), Error> {
        let err_info = make_err_packet(MySQLError::new(
            1047,
            "08S01".as_bytes().to_vec(),
            format!("command {:?} not support in sharding", command),
        ));
        cx.framed.send(PacketSend::Encode(err_info[4..].into())).await.map_err(ErrorKind::from)?;
        Ok(())
    }
}

#[async_trait]
impl<T, C> BackendConnector for MySqlBackendConnector<T, C>
where
    T: Send + Sync,
    C: Send + Sync,
{
    fn protocol(&self) -> ProtocolKind {
        ProtocolKind::MySql
    }

    async fn execute(
        &self,
        command: GatewayCommand,
        session: &mut SessionState,
    ) -> GatewayResult<GatewayResponse> {
        match command {
            GatewayCommand::Ping => Ok(GatewayResponse::Pong),
            GatewayCommand::Quit => Ok(GatewayResponse::Bye),
            GatewayCommand::UseDatabase { database } => {
                session.database = Some(database);
                Ok(GatewayResponse::Ok { affected_rows: 0, last_insert_id: None })
            }
            GatewayCommand::Begin => {
                session.transaction_state = TransactionState::Active;
                Ok(GatewayResponse::Ok { affected_rows: 0, last_insert_id: None })
            }
            GatewayCommand::Commit | GatewayCommand::Rollback => {
                session.transaction_state = TransactionState::Idle;
                Ok(GatewayResponse::Ok { affected_rows: 0, last_insert_id: None })
            }
            GatewayCommand::Query { sql } => self.execute_simple_query(&sql, session).await,
            command => Err(GatewayError::Unsupported(format!(
                "mysql backend connector is not wired to execute {:?} through GatewayCommand yet",
                command
            ))),
        }
    }
}

#[async_trait]
impl<'a, T, C> MySqlCommandService<T, C> for MySqlBackendConnector<T, C>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
    C: Decoder<Item = BytesMut>
        + Encoder<PacketSend<Box<[u8]>>, Error = ProtocolError>
        + Send
        + CommonPacket,
{
    async fn init_db(cx: &mut ReqContext<T, C>, payload: &[u8]) -> Result<RespContext, Error> {
        let now = Instant::now();
        let db = std::str::from_utf8(payload).unwrap().trim_matches(char::from(0));
        cx.framed.codec_mut().get_session().set_db(db.to_string());

        if cx.rewriter.is_some() {
            cx.framed
                .send(PacketSend::Encode(ok_packet()[4..].into()))
                .await
                .map_err(ErrorKind::from)?;
            return Ok(RespContext { ep: None, duration: now.elapsed() });
        }

        let mut client_conn =
            Self::fsm_trigger(cx, TransEventName::UseEvent, RouteInputTyp::Statement, db).await?;
        let ep = client_conn.get_endpoint();

        collect_sql_processed_total!(cx, "COM_INIT_DB", ep.as_ref().unwrap());
        collect_sql_under_processing_inc!(cx, "COM_INIT_DB", ep.as_ref().unwrap());

        Self::init_db_inner(cx, &mut client_conn, payload).await?;

        cx.fsm.put_conn(client_conn);

        collect_sql_under_processing_dec!(cx, "COM_INIT_DB", ep.as_ref().unwrap());
        collect_sql_processed_duration!(cx, "COM_INIT_DB", ep.as_ref().unwrap(), now.elapsed());

        Ok(RespContext { ep, duration: now.elapsed() })
    }

    async fn query(cx: &mut ReqContext<T, C>, payload: &[u8]) -> Result<RespContext, Error> {
        let now = Instant::now();

        if cx.rewriter.is_some() {
            Self::shard_query_inner(cx, payload).await?;
            return Ok(RespContext { ep: None, duration: now.elapsed() });
        }

        let mut client_conn = Self::query_inner_get_conn(cx, payload).await?;

        let ep = client_conn.get_endpoint();
        collect_sql_processed_total!(cx, "COM_QUERY", ep.as_ref().unwrap());
        collect_sql_under_processing_inc!(cx, "COM_QUERY", ep.as_ref().unwrap());

        let _ = Self::query_inner(cx, &mut client_conn, payload).await?;

        cx.fsm.put_conn(client_conn);

        collect_sql_under_processing_dec!(cx, "COM_QUERY", ep.as_ref().unwrap());
        collect_sql_processed_duration!(cx, "COM_QUERY", ep.as_ref().unwrap(), now.elapsed());

        Ok(RespContext { ep, duration: now.elapsed() })
    }

    async fn prepare(cx: &mut ReqContext<T, C>, payload: &[u8]) -> Result<RespContext, Error> {
        let now = Instant::now();

        if cx.rewriter.is_some() {
            cx.fsm.trigger(TransEventName::PrepareEvent);
            let res = Self::prepare_shard_inner(cx, payload).await;

            if let Err(ref err) = res {
                if let ErrorKind::Protocol(ProtocolError::PrepareError(data)) = err.kind() {
                    cx.framed
                        .send(PacketSend::Encode(data[4..].into()))
                        .await
                        .map_err(ErrorKind::from)?;
                }
            }

            return Ok(RespContext { ep: None, duration: now.elapsed() });
        }

        let sql = std::str::from_utf8(payload).unwrap().trim_matches(char::from(0));

        let mut client_conn =
            Self::fsm_trigger(cx, TransEventName::PrepareEvent, RouteInputTyp::Statement, sql)
                .await?;
        let ep = client_conn.get_endpoint();

        collect_sql_processed_total!(cx, "COM_PREPARE", ep.as_ref().unwrap());
        collect_sql_under_processing_inc!(cx, "COM_PREPARE", ep.as_ref().unwrap());

        let res = Self::prepare_normal_inner(cx, &mut client_conn, payload).await;
        cx.fsm.put_conn(client_conn);

        collect_sql_under_processing_dec!(cx, "COM_PREPARE", ep.as_ref().unwrap());
        collect_sql_processed_duration!(cx, "COM_PREPARE", ep.as_ref().unwrap(), now.elapsed());

        if let Err(ref err) = res {
            if let ErrorKind::Protocol(ProtocolError::PrepareError(data)) = err.kind() {
                cx.framed
                    .send(PacketSend::Encode(data[4..].into()))
                    .await
                    .map_err(ErrorKind::from)?;
            }
        }

        Ok(RespContext { ep, duration: now.elapsed() })
    }

    async fn execute(cx: &mut ReqContext<T, C>, payload: &[u8]) -> Result<RespContext, Error> {
        let now = Instant::now();

        if cx.rewriter.is_some() {
            Self::execute_shard_inner(cx, payload).await?;
            return Ok(RespContext { ep: None, duration: now.elapsed() });
        }

        let sess = cx.framed.codec_mut().get_session();
        let mut client_conn = cx.fsm.get_conn(&build_conn_attrs(sess)).await?;
        let ep = client_conn.get_endpoint();

        collect_sql_processed_total!(cx, "COM_EXECUTE", ep.as_ref().unwrap());
        collect_sql_under_processing_inc!(cx, "COM_EXECUTE", ep.as_ref().unwrap());

        let _ = Self::execute_inner(cx, &mut client_conn, payload).await;
        cx.fsm.put_conn(client_conn);

        collect_sql_under_processing_dec!(cx, "COM_EXECUTE", ep.as_ref().unwrap());
        collect_sql_processed_duration!(cx, "COM_EXECUTE", ep.as_ref().unwrap(), now.elapsed());

        Ok(RespContext { ep, duration: now.elapsed() })
    }

    async fn stmt_close(cx: &mut ReqContext<T, C>, payload: &[u8]) -> Result<RespContext, Error> {
        let now = Instant::now();
        let stmt_id = LittleEndian::read_u32(payload);
        cx.stmt_cache.remove(stmt_id);
        debug!("stmt close {:?}", stmt_id);

        Ok(RespContext { ep: None, duration: now.elapsed() })
    }

    async fn quit(_cx: &mut ReqContext<T, C>) -> Result<RespContext, Error> {
        let now = Instant::now();
        Ok(RespContext { ep: None, duration: now.elapsed() })
    }

    async fn field_list(cx: &mut ReqContext<T, C>, payload: &[u8]) -> Result<RespContext, Error> {
        let now = Instant::now();

        if cx.rewriter.is_some() {
            cx.framed
                .send(PacketSend::Encode(ok_packet()[4..].into()))
                .await
                .map_err(ErrorKind::from)?;
            return Ok(RespContext { ep: None, duration: now.elapsed() });
        }

        let mut client_conn =
            Self::fsm_trigger(cx, TransEventName::QueryEvent, RouteInputTyp::None, "").await?;

        let ep = client_conn.get_endpoint();

        collect_sql_processed_total!(cx, "COM_FIELD_LIST", ep.as_ref().unwrap());
        collect_sql_under_processing_inc!(cx, "COM_FIELD_LIST", ep.as_ref().unwrap());

        Self::field_list_inner(cx, &mut client_conn, payload).await?;

        cx.fsm.put_conn(client_conn);

        collect_sql_under_processing_dec!(cx, "COM_FIELD_LIST", ep.as_ref().unwrap());
        collect_sql_processed_duration!(cx, "COM_FIELD_LIST", ep.as_ref().unwrap(), now.elapsed());

        Ok(RespContext { ep, duration: now.elapsed() })
    }
}

#[cfg(test)]
mod tests {
    use mysql_protocol::server::codec::PacketCodec;
    use tokio::io::DuplexStream;

    use super::*;

    fn column_info(name: &str, column_type: ColumnType) -> ColumnInfo {
        ColumnInfo {
            schema: None,
            table_name: None,
            column_name: name.to_string(),
            charset: 0,
            column_length: 0,
            column_type,
            column_flag: 0,
            decimals: 0,
        }
    }

    #[tokio::test]
    async fn rejects_core_query_without_configured_endpoint() {
        let connector = MySqlBackendConnector::<DuplexStream, PacketCodec>::new();
        let mut session = SessionState::default();

        let result =
            connector.execute(GatewayCommand::Query { sql: "select 1".into() }, &mut session).await;

        assert_eq!(
            result,
            Err(GatewayError::Configuration(
                "mysql backend connector has no configured endpoints".into()
            ))
        );
    }

    #[test]
    fn decodes_mysql_text_row_values() {
        let columns = vec![
            column_info("id", ColumnType::MYSQL_TYPE_LONG),
            column_info("name", ColumnType::MYSQL_TYPE_VAR_STRING),
            column_info("empty", ColumnType::MYSQL_TYPE_VAR_STRING),
            column_info("deleted_at", ColumnType::MYSQL_TYPE_DATETIME),
        ];
        let row = b"\x0242\x05Alice\x00\xfb";

        let values = text_row_to_gateway_values(row, &columns).unwrap();

        assert_eq!(
            values,
            vec![
                GatewayValue::Integer(42),
                GatewayValue::String("Alice".into()),
                GatewayValue::String(String::new()),
                GatewayValue::Null,
            ]
        );
    }

    #[test]
    fn decodes_mysql_ok_and_err_packets() {
        assert_eq!(
            ok_packet_to_gateway_response(&[OK_HEADER, 2, 5]).unwrap(),
            GatewayResponse::Ok { affected_rows: 2, last_insert_id: Some(5) }
        );

        assert_eq!(
            err_packet_to_gateway_response(b"\xff\x28\x04#HY000syntax error"),
            GatewayResponse::Error { code: "1064".into(), message: "syntax error".into() }
        );
    }
}
