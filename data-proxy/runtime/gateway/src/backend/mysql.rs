use std::{fmt, sync::Arc};

use async_trait::async_trait;
use byteorder::{ByteOrder, LittleEndian};
use bytes::BytesMut;
use conn_pool::{ConnAttr, ConnAttrMut, ConnLike, Pool, PoolConn};
use futures::StreamExt;
use gateway_core::{
    BackendConnector, Column as GatewayColumn, EndpointConfig, EndpointRole, ExecuteMode,
    GatewayCommand, GatewayError, GatewayResponse, GatewayResult, GatewayValue, ProtocolKind,
    SessionState, TransactionState,
};
use mysql_protocol::{
    client::{
        codec::ResultsetStream,
        conn::{ClientConn, SessionAttr},
    },
    column::{decode_column, ColumnInfo},
    mysql_const::*,
};
use parking_lot::Mutex;

const DEFAULT_MYSQL_POOL_SIZE: usize = 16;

#[derive(Clone, Debug)]
pub struct MySqlBackendConnector {
    endpoints: Arc<Mutex<Vec<EndpointConfig>>>,
    pool: Pool<MySqlBackendConnection>,
    // Held across BEGIN..COMMIT/ROLLBACK so all statements share one backend conn.
    txn_lease: Arc<Mutex<Option<PoolConn<MySqlBackendConnection>>>>,
}

impl Default for MySqlBackendConnector {
    fn default() -> Self {
        Self::with_pool_size(Vec::new(), DEFAULT_MYSQL_POOL_SIZE)
    }
}

impl MySqlBackendConnector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_endpoints(endpoints: Vec<EndpointConfig>) -> Self {
        Self::with_pool_size(endpoints, DEFAULT_MYSQL_POOL_SIZE)
    }

    pub fn with_pool_size(endpoints: Vec<EndpointConfig>, pool_size: usize) -> Self {
        let pool: Pool<MySqlBackendConnection> = Pool::new(pool_size);
        for endpoint in &endpoints {
            let database = endpoint.database.clone().unwrap_or_default();
            register_endpoint_factory(&pool, endpoint, database);
        }

        Self {
            endpoints: Arc::new(Mutex::new(endpoints)),
            pool,
            txn_lease: Arc::new(Mutex::new(None)),
        }
    }

    pub fn endpoints(&self) -> Vec<EndpointConfig> {
        self.endpoints.lock().clone()
    }

    pub fn has_transaction_lease(&self) -> bool {
        self.txn_lease.lock().is_some()
    }

    fn select_endpoint(&self, session: &SessionState) -> GatewayResult<EndpointConfig> {
        if let Some(endpoint_name) = session.backend_endpoint.as_deref() {
            return self
                .endpoints
                .lock()
                .iter()
                .find(|endpoint| endpoint.name == endpoint_name)
                .cloned()
                .ok_or_else(|| {
                    GatewayError::Configuration(format!(
                        "mysql backend connector has no configured endpoint '{}'",
                        endpoint_name
                    ))
                });
        }

        self.endpoints.lock().first().cloned().ok_or_else(|| {
            GatewayError::Configuration(
                "mysql backend connector has no configured endpoints".into(),
            )
        })
    }

    async fn acquire_conn(
        &self,
        endpoint: &EndpointConfig,
        session: &SessionState,
    ) -> GatewayResult<PoolConn<MySqlBackendConnection>> {
        let pool_key = self.ensure_pool_factory_for_session(endpoint, session)?;
        let session_attrs = mysql_session_attrs(session);
        self.pool.get_conn_with_endpoint_session(&pool_key, &session_attrs).await
    }

    async fn execute_on_conn(
        conn: &mut PoolConn<MySqlBackendConnection>,
        sql: &str,
        mode: ExecuteMode,
    ) -> GatewayResult<GatewayResponse> {
        conn.simple_query(sql, mode).await
    }

    async fn take_or_acquire_lease(
        &self,
        endpoint: &EndpointConfig,
        session: &SessionState,
    ) -> GatewayResult<PoolConn<MySqlBackendConnection>> {
        if let Some(conn) = self.txn_lease.lock().take() {
            return Ok(conn);
        }
        self.acquire_conn(endpoint, session).await
    }

    fn store_lease(&self, conn: PoolConn<MySqlBackendConnection>) {
        *self.txn_lease.lock() = Some(conn);
    }

    async fn execute_simple_query(
        &self,
        endpoint: EndpointConfig,
        sql: &str,
        session: &SessionState,
        mode: ExecuteMode,
    ) -> GatewayResult<GatewayResponse> {
        if session.transaction_state == TransactionState::Active {
            let need_begin = self.txn_lease.lock().is_none();
            let mut conn = self.take_or_acquire_lease(&endpoint, session).await?;
            if need_begin {
                let begin =
                    Self::execute_on_conn(&mut conn, "BEGIN", ExecuteMode::Materialized).await?;
                if !matches!(begin, GatewayResponse::Ok { .. }) {
                    self.store_lease(conn);
                    return Ok(begin);
                }
            }
            let response = Self::execute_on_conn(&mut conn, sql, mode).await;
            self.store_lease(conn);
            return response;
        }

        let mut conn = self.acquire_conn(&endpoint, session).await?;
        Self::execute_on_conn(&mut conn, sql, mode).await
    }

    async fn finish_transaction(
        &self,
        session: &SessionState,
        sql: &str,
    ) -> GatewayResult<GatewayResponse> {
        let Some(mut conn) = self.txn_lease.lock().take() else {
            // No backend work was done inside the transaction.
            return Ok(GatewayResponse::Ok { affected_rows: 0, last_insert_id: None });
        };
        let _ = session;
        let response = Self::execute_on_conn(&mut conn, sql, ExecuteMode::Materialized).await;
        drop(conn);
        match response {
            Ok(response @ GatewayResponse::Ok { .. }) => Ok(response),
            Ok(GatewayResponse::Error { code, message }) => {
                Err(GatewayError::Backend(format!("mysql {}: {}", code, message)))
            }
            Ok(other) => Err(GatewayError::Backend(format!(
                "mysql control statement expected OK response, got {:?}",
                other
            ))),
            Err(error) => Err(error),
        }
    }

    async fn execute_control_sql(
        &self,
        endpoint: EndpointConfig,
        sql: &str,
        session: &SessionState,
        keep_lease: bool,
        release_lease: bool,
    ) -> GatewayResult<GatewayResponse> {
        let use_lease = keep_lease || self.txn_lease.lock().is_some();
        let response = if use_lease {
            let mut conn = self.take_or_acquire_lease(&endpoint, session).await?;
            let response = Self::execute_on_conn(&mut conn, sql, ExecuteMode::Materialized).await;
            if release_lease {
                drop(conn);
            } else {
                self.store_lease(conn);
            }
            response?
        } else {
            self.execute_simple_query(endpoint, sql, session, ExecuteMode::Materialized).await?
        };

        if release_lease {
            *self.txn_lease.lock() = None;
        }

        match response {
            response @ GatewayResponse::Ok { .. } => Ok(response),
            GatewayResponse::Error { code, message } => {
                Err(GatewayError::Backend(format!("mysql {}: {}", code, message)))
            }
            other => Err(GatewayError::Backend(format!(
                "mysql control statement expected OK response, got {:?}",
                other
            ))),
        }
    }

    fn ensure_pool_factory_for_session(
        &self,
        endpoint: &EndpointConfig,
        session: &SessionState,
    ) -> GatewayResult<String> {
        let _ = parse_endpoint_address(&endpoint.address)?;
        let database = effective_database(endpoint, session);
        let pool_key = mysql_pool_key(endpoint, &database);

        if !self.pool.has_factory(&pool_key) {
            register_endpoint_factory(&self.pool, endpoint, database);
        }

        Ok(pool_key)
    }
}

#[async_trait]
impl BackendConnector for MySqlBackendConnector {
    fn protocol(&self) -> ProtocolKind {
        ProtocolKind::MySql
    }

    async fn execute_with_mode(
        &self,
        command: GatewayCommand,
        session: &mut SessionState,
        mode: ExecuteMode,
    ) -> GatewayResult<GatewayResponse> {
        match command {
            GatewayCommand::Ping => Ok(GatewayResponse::Pong),
            GatewayCommand::Quit => {
                *self.txn_lease.lock() = None;
                Ok(GatewayResponse::Bye)
            }
            GatewayCommand::UseDatabase { database } => {
                // Prefer deferred USE via session attrs when leasing a connection.
                // If a txn lease is already held, apply immediately on that conn.
                if self.txn_lease.lock().is_some() {
                    if let Ok(endpoint) = self.select_endpoint(session) {
                        let _ = self
                            .execute_control_sql(
                                endpoint,
                                &format!("USE `{}`", database.replace('`', "``")),
                                session,
                                true,
                                false,
                            )
                            .await?;
                    }
                }
                session.database = Some(database);
                Ok(GatewayResponse::Ok { affected_rows: 0, last_insert_id: None })
            }
            GatewayCommand::Begin => {
                // Defer backend BEGIN until the first statement leases a connection.
                session.transaction_state = TransactionState::Active;
                Ok(GatewayResponse::Ok { affected_rows: 0, last_insert_id: None })
            }
            GatewayCommand::Commit => {
                let response = self.finish_transaction(session, "COMMIT").await?;
                session.transaction_state = TransactionState::Idle;
                Ok(response)
            }
            GatewayCommand::Rollback => {
                let response = self.finish_transaction(session, "ROLLBACK").await?;
                session.transaction_state = TransactionState::Idle;
                Ok(response)
            }
            GatewayCommand::Query { sql } => {
                let endpoint = self.select_endpoint(session)?;
                self.execute_simple_query(endpoint, &sql, session, mode).await
            }
            command => Err(GatewayError::Unsupported(format!(
                "mysql backend connector cannot execute {:?} yet",
                command
            ))),
        }
    }
}

struct MySqlBackendConnection {
    endpoint: EndpointConfig,
    pool_key: String,
    database: String,
    client: Option<ClientConn>,
}

impl Clone for MySqlBackendConnection {
    fn clone(&self) -> Self {
        Self {
            endpoint: self.endpoint.clone(),
            pool_key: self.pool_key.clone(),
            database: self.database.clone(),
            client: None,
        }
    }
}

impl Default for MySqlBackendConnection {
    fn default() -> Self {
        Self {
            endpoint: EndpointConfig {
                name: String::new(),
                protocol: ProtocolKind::MySql,
                address: String::new(),
                database: None,
                role: EndpointRole::ReadWrite,
                username: String::new(),
                password: String::new(),
                weight: 0,
            },
            pool_key: String::new(),
            database: String::new(),
            client: None,
        }
    }
}

impl MySqlBackendConnection {
    fn factory(endpoint: EndpointConfig, database: String) -> Self {
        let pool_key = mysql_pool_key(&endpoint, &database);
        Self { endpoint, pool_key, database, client: None }
    }

    async fn simple_query(
        &mut self,
        sql: &str,
        mode: ExecuteMode,
    ) -> GatewayResult<GatewayResponse> {
        let client = self.client.as_mut().ok_or_else(|| {
            GatewayError::Backend("mysql backend connection is not open".into())
        })?;
        let mut stream = client
            .send_query(sql.as_bytes())
            .await
            .map_err(|error| GatewayError::Backend(format!("write mysql query: {}", error)))?;
        if matches!(mode, ExecuteMode::Passthrough) {
            read_mysql_query_passthrough(&mut stream).await
        } else {
            read_mysql_query_response(&mut stream, mode).await
        }
    }

    fn client_ref(&self) -> GatewayResult<&ClientConn> {
        self.client.as_ref().ok_or_else(|| {
            GatewayError::Backend("mysql backend connection is not open".into())
        })
    }
}

impl fmt::Debug for MySqlBackendConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MySqlBackendConnection")
            .field("endpoint", &self.endpoint)
            .field("pool_key", &self.pool_key)
            .field("database", &self.database)
            .field("connected", &self.client.is_some())
            .finish()
    }
}

#[async_trait]
impl ConnLike for MySqlBackendConnection {
    type Error = GatewayError;

    async fn build_conn(&self) -> Result<Self, Self::Error> {
        let mut client = ClientConn::with_opts(
            self.endpoint.username.clone(),
            self.endpoint.password.clone(),
            self.endpoint.address.clone(),
        )
        .connect()
        .await
        .map_err(|error| GatewayError::Backend(format!("connect mysql backend: {}", error)))?;

        if !self.database.is_empty() {
            let (_, ok) = client.send_use_db(&self.database).await.map_err(|error| {
                GatewayError::Backend(format!("select mysql database: {}", error))
            })?;
            if !ok {
                return Err(GatewayError::Backend(format!(
                    "mysql backend rejected database '{}'",
                    self.database
                )));
            }
        }

        Ok(Self {
            endpoint: self.endpoint.clone(),
            pool_key: self.pool_key.clone(),
            database: self.database.clone(),
            client: Some(client),
        })
    }

    async fn ping(&mut self) -> Result<(), Self::Error> {
        let client = self.client.as_mut().ok_or_else(|| {
            GatewayError::Backend("mysql backend connection is not open".into())
        })?;
        client
            .send_ping()
            .await
            .map_err(|error| GatewayError::Backend(format!("mysql ping failed: {}", error)))?;
        Ok(())
    }
}

impl ConnAttr for MySqlBackendConnection {
    fn get_host(&self) -> String {
        parse_endpoint_address(&self.endpoint.address)
            .map(|(host, _)| host)
            .unwrap_or_default()
    }

    fn get_port(&self) -> u16 {
        parse_endpoint_address(&self.endpoint.address)
            .map(|(_, port)| port)
            .unwrap_or_default()
    }

    fn get_user(&self) -> String {
        self.endpoint.username.clone()
    }

    fn get_endpoint(&self) -> String {
        self.pool_key.clone()
    }

    fn get_db(&self) -> Option<String> {
        self.client_ref().ok().and_then(|client| client.get_db()).or_else(|| {
            if self.database.is_empty() {
                None
            } else {
                Some(self.database.clone())
            }
        })
    }

    fn get_charset(&self) -> Option<String> {
        self.client_ref().ok().and_then(|client| client.get_charset())
    }

    fn get_autocommit(&self) -> Option<String> {
        self.client_ref().ok().and_then(|client| client.get_autocommit())
    }
}

#[async_trait]
impl ConnAttrMut for MySqlBackendConnection {
    type Item = SessionAttr;

    async fn init(&mut self, session: &[Self::Item]) {
        let Some(client) = self.client.as_mut() else {
            return;
        };
        client.init(session).await;
        if let Some(SessionAttr::DB(Some(database))) =
            session.iter().find(|attr| matches!(attr, SessionAttr::DB(_)))
        {
            self.database = database.clone();
            self.pool_key = mysql_pool_key(&self.endpoint, database);
        }
    }
}

fn register_endpoint_factory(
    pool: &Pool<MySqlBackendConnection>,
    endpoint: &EndpointConfig,
    database: String,
) {
    let pool_key = mysql_pool_key(endpoint, &database);
    pool.set_factory(&pool_key, MySqlBackendConnection::factory(endpoint.clone(), database));
}

fn effective_database(endpoint: &EndpointConfig, session: &SessionState) -> String {
    session
        .database
        .clone()
        .or_else(|| endpoint.database.clone())
        .unwrap_or_default()
}

fn mysql_pool_key(endpoint: &EndpointConfig, database: &str) -> String {
    if database.is_empty() {
        endpoint.address.clone()
    } else {
        format!("{}|{}", endpoint.address, database)
    }
}

fn mysql_session_attrs(session: &SessionState) -> Vec<SessionAttr> {
    let mut attrs = Vec::new();
    if let Some(database) = session.database.clone() {
        attrs.push(SessionAttr::DB(Some(database)));
    }
    if let Some(charset) = session.charset.clone() {
        attrs.push(SessionAttr::Charset(charset));
    }
    if let Some(autocommit) = session.autocommit {
        attrs.push(SessionAttr::Autocommit(Some(if autocommit {
            "1".into()
        } else {
            "0".into()
        })));
    }
    attrs
}

fn parse_endpoint_address(address: &str) -> GatewayResult<(String, u16)> {
    let (host, port) = address.rsplit_once(':').ok_or_else(|| {
        GatewayError::Configuration(format!(
            "mysql endpoint address '{}' must be host:port",
            address
        ))
    })?;
    let port = port.parse::<u16>().map_err(|error| {
        GatewayError::Configuration(format!(
            "mysql endpoint address '{}' has invalid port: {}",
            address, error
        ))
    })?;

    if host.is_empty() {
        return Err(GatewayError::Configuration("mysql endpoint host must not be empty".into()));
    }

    Ok((host.to_string(), port))
}


/// Collect backend packets as frontend-ready payloads (no logical decode).
///
/// `ResultsetStream` yields full MySQL packets (4-byte header + body). Frontend
/// `PacketSend::Encode` re-wraps **body only**, so we strip the header here.
async fn read_mysql_query_passthrough(
    stream: &mut ResultsetStream<'_>,
) -> GatewayResult<GatewayResponse> {
    let mut packets = Vec::new();
    // Header packet
    let header = read_mysql_result_packet(stream, "mysql query header").await?;
    packets.push(packet_payload("mysql query header", &header)?.to_vec());
    let payload = packet_payload("mysql query header", &header)?;
    match payload.first().copied() {
        Some(OK_HEADER) | Some(ERR_HEADER) => {
            return Ok(GatewayResponse::Wire { packets });
        }
        Some(_) => {
            let (column_count, is_null, _) = decode_lenc_int(payload, "mysql column count")?;
            if is_null {
                return Err(GatewayError::Protocol(
                    "mysql result set column count cannot be NULL".into(),
                ));
            }
            for _ in 0..column_count {
                let column_packet =
                    read_mysql_result_packet(stream, "mysql column definition").await?;
                packets.push(packet_payload("mysql column definition", &column_packet)?.to_vec());
            }
            // EOF after columns
            let eof1 = read_mysql_result_packet(stream, "mysql column eof").await?;
            packets.push(packet_payload("mysql column eof", &eof1)?.to_vec());
            // Rows + final EOF (stream ends after EOF)
            while let Some(row_packet) = read_optional_mysql_result_packet(stream).await? {
                packets.push(packet_payload("mysql row/eof", &row_packet)?.to_vec());
            }
            // ResultsetStream swallows the final EOF (returns None). Frontend clients
            // still need that EOF packet to finish the text resultset.
            // ResultsetStream does not yield the terminal EOF payload; always append.
            // Payload-only EOF packet body (header re-applied by frontend Encode).
            let last_is_eof = packets
                .last()
                .map(|p| p.first() == Some(&EOF_HEADER))
                .unwrap_or(false);
            if !last_is_eof {
                packets.push(vec![EOF_HEADER, 0, 0, 0, 0]);
            }
            Ok(GatewayResponse::Wire { packets })
        }
        None => Err(GatewayError::Protocol(
            "mysql query header packet has empty payload".into(),
        )),
    }
}

pub(crate) async fn read_mysql_query_response(
    stream: &mut ResultsetStream<'_>,
    mode: ExecuteMode,
) -> GatewayResult<GatewayResponse> {
    let header = read_mysql_result_packet(stream, "mysql query header").await?;
    mysql_response_from_header_and_stream(header, stream, mode).await
}

async fn mysql_response_from_header_and_stream(
    header: BytesMut,
    stream: &mut ResultsetStream<'_>,
    mode: ExecuteMode,
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

            let max_rows = mode.effective_max_rows();
            // Window size is used for progressive decode; we still assemble the
            // final ResultSet for the current wire encode path, but never keep
            // more than max_rows and free each window after append.
            let window = mode.window_rows().unwrap_or(usize::MAX).max(1);
            let mut rows = Vec::new();
            let mut window_buf: Vec<Vec<GatewayValue>> = Vec::with_capacity(window.min(256));
            let mut total: u64 = 0;
            let mut truncated = false;

            while let Some(row_packet) = read_optional_mysql_result_packet(stream).await? {
                if truncated {
                    // Drain remaining packets so the connection stays usable.
                    continue;
                }
                let row_payload = packet_payload("mysql row", &row_packet)?;
                if let Some(max) = max_rows {
                    if total >= max {
                        truncated = true;
                        continue;
                    }
                }
                window_buf.push(text_row_to_gateway_values(row_payload, &column_infos)?);
                total += 1;
                if window_buf.len() >= window {
                    rows.extend(window_buf.drain(..));
                }
            }
            if !window_buf.is_empty() {
                rows.extend(window_buf.drain(..));
            }
            if let Some(max) = max_rows {
                if rows.len() as u64 > max {
                    rows.truncate(max as usize);
                }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint() -> EndpointConfig {
        EndpointConfig {
            name: "orders-primary".into(),
            protocol: ProtocolKind::MySql,
            address: "127.0.0.1:3306".into(),
            database: Some("orders".into()),
            role: EndpointRole::ReadWrite,
            username: "root".into(),
            password: "secret".into(),
            weight: 1,
        }
    }

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

    #[test]
    fn registers_endpoint_database_factory_in_pool() {
        let endpoint = endpoint();
        let connector = MySqlBackendConnector::with_pool_size(vec![endpoint.clone()], 4);
        let pool_key = mysql_pool_key(&endpoint, "orders");

        assert_eq!(connector.pool.capacity(), 4);
        assert!(connector.pool.has_factory(&pool_key));
        assert_eq!(connector.pool.factory_endpoints(), vec![pool_key]);
    }

    #[test]
    fn registers_session_database_factory_on_demand() {
        let endpoint = endpoint();
        let connector = MySqlBackendConnector::with_endpoints(vec![endpoint.clone()]);
        let session = SessionState { database: Some("reporting".into()), ..Default::default() };

        let pool_key = connector.ensure_pool_factory_for_session(&endpoint, &session).unwrap();

        assert_eq!(pool_key, mysql_pool_key(&endpoint, "reporting"));
        assert!(connector.pool.has_factory(&mysql_pool_key(&endpoint, "orders")));
        assert!(connector.pool.has_factory(&pool_key));
    }

    #[test]
    fn builds_session_attrs_from_session_state() {
        let session = SessionState {
            database: Some("orders".into()),
            charset: Some("utf8mb4".into()),
            autocommit: Some(false),
            ..Default::default()
        };

        let attrs = mysql_session_attrs(&session);
        assert_eq!(attrs.len(), 3);
        assert!(matches!(&attrs[0], SessionAttr::DB(Some(db)) if db == "orders"));
        assert!(matches!(&attrs[1], SessionAttr::Charset(cs) if cs == "utf8mb4"));
        assert!(matches!(&attrs[2], SessionAttr::Autocommit(Some(v)) if v == "0"));
    }

    #[tokio::test]
    async fn updates_session_for_control_commands_without_backend_when_no_query() {
        let connector = MySqlBackendConnector::with_endpoints(vec![endpoint()]);
        let mut session = SessionState::default();

        assert_eq!(
            connector.execute(GatewayCommand::Ping, &mut session).await,
            Ok(GatewayResponse::Pong)
        );
        assert_eq!(
            connector.execute(GatewayCommand::Quit, &mut session).await,
            Ok(GatewayResponse::Bye)
        );
    }

    #[tokio::test]
    async fn begin_without_reachable_backend_still_marks_transaction_active() {
        // No live MySQL: control path without endpoint still updates session.
        let connector = MySqlBackendConnector::new();
        let mut session = SessionState::default();

        assert_eq!(
            connector.execute(GatewayCommand::Begin, &mut session).await,
            Ok(GatewayResponse::Ok { affected_rows: 0, last_insert_id: None })
        );
        assert_eq!(session.transaction_state, TransactionState::Active);
        assert!(!connector.has_transaction_lease());
    }

    #[tokio::test]
    async fn rejects_query_with_invalid_endpoint_address() {
        let mut endpoint = endpoint();
        endpoint.address = "invalid-address".into();
        let connector = MySqlBackendConnector::with_endpoints(vec![endpoint]);
        let mut session = SessionState::default();

        let result =
            connector.execute(GatewayCommand::Query { sql: "select 1".into() }, &mut session).await;

        assert_eq!(
            result,
            Err(GatewayError::Configuration(
                "mysql endpoint address 'invalid-address' must be host:port".into()
            ))
        );
    }

    #[tokio::test]
    async fn rejects_query_without_endpoints() {
        let connector = MySqlBackendConnector::new();
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
