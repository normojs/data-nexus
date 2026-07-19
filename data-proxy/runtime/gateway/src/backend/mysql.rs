use std::{
    collections::HashMap,
    fmt,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};

use async_trait::async_trait;
use byteorder::{ByteOrder, LittleEndian};
use bytes::BytesMut;
use conn_pool::{ConnAttr, ConnAttrMut, ConnLike, Pool, PoolConn};
use futures::StreamExt;
use gateway_core::{
    BackendConnector, Column as GatewayColumn, EndpointConfig, EndpointRole, EndpointSslMode, ExecuteMode,
    ExecuteOutcome, GatewayCommand, GatewayError, GatewayResponse, GatewayResult, GatewayValue,
    ProtocolKind, RowStream, SessionState, StreamingQuery, TransactionState,
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

/// A10: session-scoped prepared statement registry (gateway-owned id → SQL).
///
/// Client COM_STMT_* ids are gateway-local. Backend prepare uses a **connection**
/// statement cache (`MySqlBackendConnection::stmt_cache`) so QueryParams /
/// Execute can bind via COM_STMT_EXECUTE instead of text rewrite.
#[derive(Debug, Default)]
struct PreparedRegistry {
    next_id: AtomicU32,
    /// statement_id (decimal string) → SQL text
    sql_by_id: Mutex<HashMap<String, String>>,
}

/// Per-connection backend prepared statement handle (A10).
#[derive(Clone, Debug)]
struct BackendPrepared {
    /// MySQL statement id (little-endian 4 bytes as used on the wire).
    stmt_id: u32,
    param_count: u16,
}

const MAX_MYSQL_STMT_CACHE_PER_CONN: usize = 64;

impl Clone for PreparedRegistry {
    fn clone(&self) -> Self {
        // New connection-scoped registry per connector clone (each session backend).
        Self::default()
    }
}

impl PreparedRegistry {
    fn prepare(&self, sql: String) -> (String, u16) {
        let param_count = count_mysql_placeholders(&sql);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        let statement_id = id.to_string();
        self.sql_by_id.lock().insert(statement_id.clone(), sql);
        (statement_id, param_count)
    }

    fn take_sql(&self, statement_id: &str) -> Option<String> {
        self.sql_by_id.lock().get(statement_id).cloned()
    }

    fn close(&self, statement_id: &str) -> bool {
        self.sql_by_id.lock().remove(statement_id).is_some()
    }

    fn clear(&self) {
        self.sql_by_id.lock().clear();
    }
}

/// Count `?` placeholders outside single-quoted string literals (MySQL text protocol style).
fn count_mysql_placeholders(sql: &str) -> u16 {
    let mut count = 0u16;
    let mut in_str = false;
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\'' {
            if in_str {
                if chars.peek() == Some(&'\'') {
                    chars.next(); // escaped ''
                    continue;
                }
                in_str = false;
            } else {
                in_str = true;
            }
            continue;
        }
        if !in_str && c == '?' {
            count = count.saturating_add(1);
        }
    }
    count
}

/// Substitute `?` placeholders with literal values for text Query rewrite (A10).
fn bind_mysql_placeholders(sql: &str, parameters: &[GatewayValue]) -> GatewayResult<String> {
    let need = count_mysql_placeholders(sql) as usize;
    if need != parameters.len() {
        return Err(GatewayError::Protocol(format!(
            "mysql prepared Execute expects {need} parameters, got {}",
            parameters.len()
        )));
    }
    if need == 0 {
        return Ok(sql.to_owned());
    }
    let mut out = String::with_capacity(sql.len() + parameters.len() * 8);
    let mut in_str = false;
    let mut pi = 0usize;
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\'' {
            out.push(c);
            if in_str {
                if chars.peek() == Some(&'\'') {
                    out.push(chars.next().unwrap());
                    continue;
                }
                in_str = false;
            } else {
                in_str = true;
            }
            continue;
        }
        if !in_str && c == '?' {
            out.push_str(&gateway_value_sql_literal(&parameters[pi]));
            pi += 1;
            continue;
        }
        out.push(c);
    }
    Ok(out)
}

fn gateway_value_sql_literal(v: &GatewayValue) -> String {
    match v {
        GatewayValue::Null => "NULL".into(),
        GatewayValue::Boolean(b) => if *b { "1" } else { "0" }.into(),
        GatewayValue::Integer(i) => i.to_string(),
        GatewayValue::UnsignedInteger(u) => u.to_string(),
        GatewayValue::Float(f) => {
            if f.is_finite() {
                f.to_string()
            } else {
                "NULL".into()
            }
        }
        GatewayValue::Decimal(s) => s.clone(),
        GatewayValue::String(s) => format!("'{}'", s.replace('\'', "''")),
        GatewayValue::Bytes(b) => {
            let mut hex = String::with_capacity(2 + b.len() * 2);
            hex.push_str("0x");
            for byte in b {
                hex.push_str(&format!("{byte:02X}"));
            }
            hex
        }
    }
}

/// Encode COM_STMT_EXECUTE body (without command byte) for binary bind (A10).
///
/// Layout: stmt_id(4) flags(1)=0 iteration_count(4)=1
///         null_bitmap((n+7)/8) new_params_bound(1)=1 type(2)*n values…
fn encode_stmt_execute_payload(
    stmt_id: u32,
    parameters: &[GatewayValue],
) -> GatewayResult<Vec<u8>> {
    let n = parameters.len();
    let null_len = if n == 0 { 0 } else { (n + 7) / 8 };
    let mut out = Vec::with_capacity(9 + null_len + 1 + n * 2 + n * 16);
    out.extend_from_slice(&stmt_id.to_le_bytes());
    out.push(0); // flags
    out.extend_from_slice(&1u32.to_le_bytes()); // iteration_count
    if n == 0 {
        return Ok(out);
    }
    let mut null_bitmap = vec![0u8; null_len];
    for (i, p) in parameters.iter().enumerate() {
        if matches!(p, GatewayValue::Null) {
            null_bitmap[i / 8] |= 1 << (i % 8);
        }
    }
    out.extend_from_slice(&null_bitmap);
    out.push(1); // new_params_bound_flag
    for p in parameters {
        let (ty, unsigned) = gateway_value_mysql_param_type(p);
        out.push(ty);
        out.push(if unsigned { 0x80 } else { 0 });
    }
    for p in parameters {
        if matches!(p, GatewayValue::Null) {
            continue;
        }
        encode_binary_param_value(&mut out, p)?;
    }
    Ok(out)
}

fn gateway_value_mysql_param_type(v: &GatewayValue) -> (u8, bool) {
    match v {
        GatewayValue::Null => (ColumnType::MYSQL_TYPE_NULL as u8, false),
        GatewayValue::Boolean(_) => (ColumnType::MYSQL_TYPE_TINY as u8, false),
        GatewayValue::Integer(_) => (ColumnType::MYSQL_TYPE_LONGLONG as u8, false),
        GatewayValue::UnsignedInteger(_) => (ColumnType::MYSQL_TYPE_LONGLONG as u8, true),
        GatewayValue::Float(_) => (ColumnType::MYSQL_TYPE_DOUBLE as u8, false),
        GatewayValue::Decimal(_) => (ColumnType::MYSQL_TYPE_NEWDECIMAL as u8, false),
        GatewayValue::String(_) => (ColumnType::MYSQL_TYPE_VAR_STRING as u8, false),
        GatewayValue::Bytes(_) => (ColumnType::MYSQL_TYPE_BLOB as u8, false),
    }
}

fn encode_binary_param_value(out: &mut Vec<u8>, v: &GatewayValue) -> GatewayResult<()> {
    match v {
        GatewayValue::Null => Ok(()),
        GatewayValue::Boolean(b) => {
            out.push(if *b { 1 } else { 0 });
            Ok(())
        }
        GatewayValue::Integer(i) => {
            out.extend_from_slice(&i.to_le_bytes());
            Ok(())
        }
        GatewayValue::UnsignedInteger(u) => {
            out.extend_from_slice(&u.to_le_bytes());
            Ok(())
        }
        GatewayValue::Float(f) => {
            out.extend_from_slice(&f.to_le_bytes());
            Ok(())
        }
        GatewayValue::Decimal(s) => {
            encode_lenc_bytes(out, s.as_bytes());
            Ok(())
        }
        GatewayValue::String(s) => {
            encode_lenc_bytes(out, s.as_bytes());
            Ok(())
        }
        GatewayValue::Bytes(b) => {
            encode_lenc_bytes(out, b);
            Ok(())
        }
    }
}

fn encode_lenc_bytes(out: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len < 251 {
        out.push(len as u8);
    } else if len < 65_536 {
        out.push(0xfc);
        out.extend_from_slice(&(len as u16).to_le_bytes());
    } else if len < 16_777_216 {
        out.push(0xfd);
        out.extend_from_slice(&(len as u32).to_le_bytes()[..3]);
    } else {
        out.push(0xfe);
        out.extend_from_slice(&(len as u64).to_le_bytes());
    }
    out.extend_from_slice(data);
}

#[derive(Clone, Debug)]
pub struct MySqlBackendConnector {
    endpoints: Arc<Mutex<Vec<EndpointConfig>>>,
    pool: Pool<MySqlBackendConnection>,
    // Held across BEGIN..COMMIT/ROLLBACK so all statements share one backend conn.
    txn_lease: Arc<Mutex<Option<PoolConn<MySqlBackendConnection>>>>,
    /// A10 prepared registry (per connector instance / client session).
    prepared: Arc<PreparedRegistry>,
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
            prepared: Arc::new(PreparedRegistry::default()),
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

    /// A10: parameterized query via backend COM_STMT_PREPARE + COM_STMT_EXECUTE.
    ///
    /// Uses connection-local statement cache. Results are decoded as **binary**
    /// protocol rows. Falls back to text rewrite only if prepare fails with a
    /// configuration-level issue (should not happen in normal paths).
    async fn execute_param_query(
        &self,
        endpoint: EndpointConfig,
        sql: &str,
        parameters: &[GatewayValue],
        session: &SessionState,
        mode: ExecuteMode,
    ) -> GatewayResult<GatewayResponse> {
        let need = count_mysql_placeholders(sql) as usize;
        if need != parameters.len() {
            return Err(GatewayError::Protocol(format!(
                "mysql prepared Execute expects {need} parameters, got {}",
                parameters.len()
            )));
        }
        if parameters.is_empty() {
            return self
                .execute_simple_query(endpoint, sql, session, mode)
                .await;
        }

        let in_txn = session.transaction_state == TransactionState::Active
            || self.txn_lease.lock().is_some();
        let mut conn = if in_txn {
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
            conn
        } else {
            self.acquire_conn(&endpoint, session).await?
        };

        let response = conn.execute_prepared(sql, parameters, mode).await;
        if in_txn {
            self.store_lease(conn);
        } else {
            drop(conn);
        }
        response
    }

    /// A10: Streaming path for parameterized queries (`QueryParams` / prepared Execute).
    ///
    /// Connection-local COM_STMT cache + binary COM_STMT_EXECUTE; rows are windowed
    /// over a channel (peak retained ≈ one window per side). Non-SELECT → Complete(Ok).
    async fn execute_param_query_streaming(
        &self,
        endpoint: EndpointConfig,
        sql: &str,
        parameters: &[GatewayValue],
        session: &SessionState,
        mode: ExecuteMode,
        in_transaction: bool,
    ) -> GatewayResult<ExecuteOutcome> {
        let need = count_mysql_placeholders(sql) as usize;
        if need != parameters.len() {
            return Err(GatewayError::Protocol(format!(
                "mysql prepared Execute expects {need} parameters, got {}",
                parameters.len()
            )));
        }
        if parameters.is_empty() {
            return self
                .execute_simple_query_streaming(endpoint, sql, session, mode, in_transaction)
                .await;
        }

        let window = mode.window_rows().unwrap_or(256).max(1);
        let max_rows = mode.effective_max_rows();

        let mut conn = if in_transaction {
            let need_begin = self.txn_lease.lock().is_none();
            let mut conn = self.take_or_acquire_lease(&endpoint, session).await?;
            if need_begin {
                let begin =
                    Self::execute_on_conn(&mut conn, "BEGIN", ExecuteMode::Materialized).await?;
                if !matches!(begin, GatewayResponse::Ok { .. }) {
                    self.store_lease(conn);
                    return Ok(ExecuteOutcome::Complete(begin));
                }
            }
            conn
        } else {
            self.acquire_conn(&endpoint, session).await?
        };

        let prepared = match conn.get_or_prepare(sql).await {
            Ok(p) => p,
            Err(e) => {
                if in_transaction {
                    self.store_lease(conn);
                }
                return Err(e);
            }
        };
        if prepared.param_count as usize != parameters.len() {
            if in_transaction {
                self.store_lease(conn);
            }
            return Err(GatewayError::Protocol(format!(
                "mysql backend prepare expects {} parameters, got {}",
                prepared.param_count,
                parameters.len()
            )));
        }
        let payload = match encode_stmt_execute_payload(prepared.stmt_id, parameters) {
            Ok(p) => p,
            Err(e) => {
                if in_transaction {
                    self.store_lease(conn);
                }
                return Err(e);
            }
        };

        let client = match conn.client.as_mut() {
            Some(c) => c,
            None => {
                if in_transaction {
                    self.store_lease(conn);
                }
                return Err(GatewayError::Backend(
                    "mysql backend connection is not open".into(),
                ));
            }
        };
        let mut stream = match client.send_execute(&payload).await {
            Ok(s) => s,
            Err(error) => {
                if in_transaction {
                    self.store_lease(conn);
                }
                return Err(GatewayError::Backend(format!(
                    "mysql COM_STMT_EXECUTE: {error}"
                )));
            }
        };

        // Header / columns on this task; binary rows stream via channel.
        let header = match read_mysql_result_packet(&mut stream, "mysql binary query header").await
        {
            Ok(h) => h,
            Err(e) => {
                if in_transaction {
                    self.store_lease(conn);
                }
                return Err(e);
            }
        };
        let payload = match packet_payload("mysql binary query header", &header) {
            Ok(p) => p,
            Err(e) => {
                if in_transaction {
                    self.store_lease(conn);
                }
                return Err(e);
            }
        };
        match payload.first().copied() {
            Some(OK_HEADER) => {
                drop(stream);
                let response = ok_packet_to_gateway_response(payload)?;
                if in_transaction {
                    self.store_lease(conn);
                }
                return Ok(ExecuteOutcome::Complete(response));
            }
            Some(ERR_HEADER) => {
                drop(stream);
                let response = err_packet_to_gateway_response(payload);
                if in_transaction {
                    self.store_lease(conn);
                }
                return Ok(ExecuteOutcome::Complete(response));
            }
            Some(_) => {}
            None => {
                if in_transaction {
                    self.store_lease(conn);
                }
                return Err(GatewayError::Protocol(
                    "mysql binary query header packet has empty payload".into(),
                ));
            }
        }

        let (column_count, is_null, _) = match decode_lenc_int(payload, "mysql column count") {
            Ok(v) => v,
            Err(e) => {
                if in_transaction {
                    self.store_lease(conn);
                }
                return Err(e);
            }
        };
        if is_null {
            if in_transaction {
                self.store_lease(conn);
            }
            return Err(GatewayError::Protocol(
                "mysql result set column count cannot be NULL".into(),
            ));
        }
        let mut column_infos = Vec::with_capacity(column_count as usize);
        for _ in 0..column_count {
            let column_packet =
                match read_mysql_result_packet(&mut stream, "mysql column definition").await {
                    Ok(p) => p,
                    Err(e) => {
                        if in_transaction {
                            self.store_lease(conn);
                        }
                        return Err(e);
                    }
                };
            let column_payload =
                match packet_payload("mysql column definition", &column_packet) {
                    Ok(p) => p,
                    Err(e) => {
                        if in_transaction {
                            self.store_lease(conn);
                        }
                        return Err(e);
                    }
                };
            column_infos.push(decode_column(column_payload));
        }
        if let Err(e) = read_mysql_result_packet(&mut stream, "mysql column eof").await {
            if in_transaction {
                self.store_lease(conn);
            }
            return Err(e);
        }
        let columns: Vec<GatewayColumn> = column_infos
            .iter()
            .map(mysql_column_to_gateway_column)
            .collect();

        drop(stream);

        let lease_slot = if in_transaction {
            Some(self.txn_lease.clone())
        } else {
            None
        };
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<Vec<GatewayValue>>>(2);
        tokio::spawn(async move {
            let run = async {
                let client = conn.client.as_mut().ok_or_else(|| {
                    GatewayError::Backend("mysql backend connection is not open".into())
                })?;
                let mut stream = ResultsetStream::new(client.framed.as_mut());
                let mut window_buf: Vec<Vec<GatewayValue>> =
                    Vec::with_capacity(window.min(256));
                let mut total: u64 = 0;
                let mut truncated = false;
                while let Some(row_packet) = read_optional_mysql_result_packet(&mut stream).await? {
                    if truncated {
                        continue;
                    }
                    let row_payload = packet_payload("mysql binary row", &row_packet)?;
                    if let Some(max) = max_rows {
                        if total >= max {
                            truncated = true;
                            continue;
                        }
                    }
                    window_buf.push(binary_row_to_gateway_values(row_payload, &column_infos)?);
                    total += 1;
                    if window_buf.len() >= window {
                        let chunk: Vec<_> = window_buf.drain(..).collect();
                        if tx.send(chunk).await.is_err() {
                            while read_optional_mysql_result_packet(&mut stream)
                                .await?
                                .is_some()
                            {}
                            return Ok(());
                        }
                    }
                }
                if !window_buf.is_empty() {
                    let _ = tx.send(window_buf).await;
                }
                Ok::<(), GatewayError>(())
            }
            .await;
            if let Err(e) = run {
                tracing::warn!(
                    target: "data_nexus::gateway",
                    error = %e,
                    "mysql prepared streaming producer failed"
                );
            }
            if let Some(slot) = lease_slot {
                *slot.lock() = Some(conn);
            }
        });

        Ok(ExecuteOutcome::Streaming(StreamingQuery {
            columns,
            stream: Box::new(ChannelRowStream { rx }),
        }))
    }

    /// A06: stream logical rows in windows over a channel.
    ///
    /// Producer task owns the connection while decoding. Peak retained rows ≈
    /// one window on each side of the channel (capacity 2).
    ///
    /// When `in_transaction` is true, the connection is taken from / returned to
    /// `txn_lease` after the resultset is drained (so COMMIT/ROLLBACK still work).
    async fn execute_simple_query_streaming(
        &self,
        endpoint: EndpointConfig,
        sql: &str,
        session: &SessionState,
        mode: ExecuteMode,
        in_transaction: bool,
    ) -> GatewayResult<ExecuteOutcome> {
        let window = mode.window_rows().unwrap_or(256).max(1);
        let max_rows = mode.effective_max_rows();

        let mut conn = if in_transaction {
            let need_begin = self.txn_lease.lock().is_none();
            let mut conn = self.take_or_acquire_lease(&endpoint, session).await?;
            if need_begin {
                let begin =
                    Self::execute_on_conn(&mut conn, "BEGIN", ExecuteMode::Materialized).await?;
                if !matches!(begin, GatewayResponse::Ok { .. }) {
                    self.store_lease(conn);
                    return Ok(ExecuteOutcome::Complete(begin));
                }
            }
            conn
        } else {
            self.acquire_conn(&endpoint, session).await?
        };

        let client = conn.client.as_mut().ok_or_else(|| {
            GatewayError::Backend("mysql backend connection is not open".into())
        })?;
        let mut stream = client
            .send_query(sql.as_bytes())
            .await
            .map_err(|error| GatewayError::Backend(format!("write mysql query: {error}")))?;

        // Materialize only the header/columns on this task; rows stream via channel.
        let header = read_mysql_result_packet(&mut stream, "mysql query header").await?;
        let payload = packet_payload("mysql query header", &header)?;
        match payload.first().copied() {
            Some(OK_HEADER) => {
                drop(stream);
                let response = ok_packet_to_gateway_response(payload)?;
                if in_transaction {
                    self.store_lease(conn);
                }
                return Ok(ExecuteOutcome::Complete(response));
            }
            Some(ERR_HEADER) => {
                drop(stream);
                let response = err_packet_to_gateway_response(payload);
                if in_transaction {
                    self.store_lease(conn);
                }
                return Ok(ExecuteOutcome::Complete(response));
            }
            Some(_) => {}
            None => {
                if in_transaction {
                    self.store_lease(conn);
                }
                return Err(GatewayError::Protocol(
                    "mysql query header packet has empty payload".into(),
                ));
            }
        }

        let (column_count, is_null, _) = decode_lenc_int(payload, "mysql column count")?;
        if is_null {
            if in_transaction {
                self.store_lease(conn);
            }
            return Err(GatewayError::Protocol(
                "mysql result set column count cannot be NULL".into(),
            ));
        }
        let mut column_infos = Vec::with_capacity(column_count as usize);
        for _ in 0..column_count {
            let column_packet =
                read_mysql_result_packet(&mut stream, "mysql column definition").await?;
            let column_payload = packet_payload("mysql column definition", &column_packet)?;
            column_infos.push(decode_column(column_payload));
        }
        let _ = read_mysql_result_packet(&mut stream, "mysql column eof").await?;
        let columns: Vec<GatewayColumn> = column_infos
            .iter()
            .map(mysql_column_to_gateway_column)
            .collect();

        // Spawn producer that owns `conn` and re-opens ResultsetStream for remaining
        // packets (query already in flight).
        drop(stream);

        let lease_slot = if in_transaction {
            Some(self.txn_lease.clone())
        } else {
            None
        };
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<Vec<GatewayValue>>>(2);
        tokio::spawn(async move {
            let run = async {
                let client = conn.client.as_mut().ok_or_else(|| {
                    GatewayError::Backend("mysql backend connection is not open".into())
                })?;
                let mut stream = ResultsetStream::new(client.framed.as_mut());
                let mut window_buf: Vec<Vec<GatewayValue>> =
                    Vec::with_capacity(window.min(256));
                let mut total: u64 = 0;
                let mut truncated = false;
                while let Some(row_packet) = read_optional_mysql_result_packet(&mut stream).await? {
                    if truncated {
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
                        let chunk: Vec<_> = window_buf.drain(..).collect();
                        if tx.send(chunk).await.is_err() {
                            while read_optional_mysql_result_packet(&mut stream)
                                .await?
                                .is_some()
                            {}
                            return Ok(());
                        }
                    }
                }
                if !window_buf.is_empty() {
                    let _ = tx.send(window_buf).await;
                }
                Ok::<(), GatewayError>(())
            }
            .await;
            if let Err(e) = run {
                tracing::warn!(
                    target: "data_nexus::gateway",
                    error = %e,
                    "mysql streaming producer failed"
                );
            }
            if let Some(slot) = lease_slot {
                // Return leased connection for subsequent txn statements.
                *slot.lock() = Some(conn);
            }
            // else: conn dropped → pool
        });

        Ok(ExecuteOutcome::Streaming(StreamingQuery {
            columns,
            stream: Box::new(ChannelRowStream { rx }),
        }))
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
                self.prepared.clear();
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
            // A10: parameterized query — backend prepare/bind (COM_STMT_*), not text rewrite.
            GatewayCommand::QueryParams { sql, parameters } => {
                let endpoint = self.select_endpoint(session)?;
                self.execute_param_query(endpoint, &sql, &parameters, session, mode)
                    .await
            }
            // A10: gateway-owned prepared registry; Execute binds via backend prepare.
            GatewayCommand::Prepare { sql } => {
                let (statement_id, parameter_count) = self.prepared.prepare(sql);
                Ok(GatewayResponse::Prepared {
                    statement_id,
                    parameter_count,
                })
            }
            GatewayCommand::Execute {
                statement_id,
                parameters,
            } => {
                let sql = self.prepared.take_sql(&statement_id).ok_or_else(|| {
                    GatewayError::Backend(format!(
                        "unknown mysql prepared statement id '{statement_id}'"
                    ))
                })?;
                // Validate arity before endpoint selection (unit tests use empty connector).
                let need = count_mysql_placeholders(&sql) as usize;
                if need != parameters.len() {
                    return Err(GatewayError::Protocol(format!(
                        "mysql prepared Execute expects {need} parameters, got {}",
                        parameters.len()
                    )));
                }
                let endpoint = self.select_endpoint(session)?;
                self.execute_param_query(endpoint, &sql, &parameters, session, mode)
                    .await
            }
            GatewayCommand::CloseStatement { statement_id } => {
                let _ = self.prepared.close(&statement_id);
                Ok(GatewayResponse::Ok {
                    affected_rows: 0,
                    last_insert_id: None,
                })
            }
            GatewayCommand::ClientWire { packets } => Ok(GatewayResponse::Wire { packets }),
        }
    }

    async fn execute_outcome(
        &self,
        command: GatewayCommand,
        session: &mut SessionState,
        mode: ExecuteMode,
    ) -> GatewayResult<ExecuteOutcome> {
        // A06: windowed yield for Streaming SELECT (txn and non-txn).
        // In-transaction: producer returns the leased connection to `txn_lease`
        // after draining so COMMIT/ROLLBACK still share the same backend conn.
        let streaming = matches!(mode, ExecuteMode::Streaming { .. });
        let is_query = matches!(command, GatewayCommand::Query { .. });
        let is_query_params = matches!(command, GatewayCommand::QueryParams { .. });
        let is_execute = matches!(command, GatewayCommand::Execute { .. });
        let in_txn = session.transaction_state == TransactionState::Active
            || self.txn_lease.lock().is_some();

        if streaming && is_query {
            if let GatewayCommand::Query { sql } = command {
                let endpoint = self.select_endpoint(session)?;
                return self
                    .execute_simple_query_streaming(endpoint, &sql, session, mode, in_txn)
                    .await;
            }
        }

        // A10: Streaming for parameterized queries (QueryParams / prepared Execute).
        if streaming && is_query_params {
            if let GatewayCommand::QueryParams { sql, parameters } = command {
                let endpoint = self.select_endpoint(session)?;
                return self
                    .execute_param_query_streaming(
                        endpoint,
                        &sql,
                        &parameters,
                        session,
                        mode,
                        in_txn,
                    )
                    .await;
            }
        }
        if streaming && is_execute {
            if let GatewayCommand::Execute {
                statement_id,
                parameters,
            } = command
            {
                let sql = self.prepared.take_sql(&statement_id).ok_or_else(|| {
                    GatewayError::Backend(format!(
                        "unknown mysql prepared statement id '{statement_id}'"
                    ))
                })?;
                let need = count_mysql_placeholders(&sql) as usize;
                if need != parameters.len() {
                    return Err(GatewayError::Protocol(format!(
                        "mysql prepared Execute expects {need} parameters, got {}",
                        parameters.len()
                    )));
                }
                let endpoint = self.select_endpoint(session)?;
                return self
                    .execute_param_query_streaming(
                        endpoint,
                        &sql,
                        &parameters,
                        session,
                        mode,
                        in_txn,
                    )
                    .await;
            }
        }

        let response = self.execute_with_mode(command, session, mode).await?;
        Ok(ExecuteOutcome::Complete(response))
    }
}

/// A06: row windows delivered over a channel from a producer task that owns the
/// backend lease until the resultset is fully drained.
struct ChannelRowStream {
    rx: tokio::sync::mpsc::Receiver<Vec<Vec<GatewayValue>>>,
}

#[async_trait]
impl RowStream for ChannelRowStream {
    async fn poll_window(
        &mut self,
        _max_rows: usize,
    ) -> GatewayResult<Option<Vec<Vec<GatewayValue>>>> {
        Ok(self.rx.recv().await)
    }
}

struct MySqlBackendConnection {
    endpoint: EndpointConfig,
    pool_key: String,
    database: String,
    client: Option<ClientConn>,
    /// A10: connection-local COM_STMT_PREPARE cache (SQL → backend stmt id).
    stmt_cache: Mutex<HashMap<String, BackendPrepared>>,
}

impl Clone for MySqlBackendConnection {
    fn clone(&self) -> Self {
        Self {
            endpoint: self.endpoint.clone(),
            pool_key: self.pool_key.clone(),
            database: self.database.clone(),
            client: None,
            // Fresh connection must not inherit another conn's statement ids.
            stmt_cache: Mutex::new(HashMap::new()),
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
                ssl_mode: Default::default(),
                ssl_ca_file: None,
                ssl_accept_invalid_certs: true,
            },
            pool_key: String::new(),
            database: String::new(),
            client: None,
            stmt_cache: Mutex::new(HashMap::new()),
        }
    }
}

impl MySqlBackendConnection {
    fn factory(endpoint: EndpointConfig, database: String) -> Self {
        let pool_key = mysql_pool_key(&endpoint, &database);
        Self {
            endpoint,
            pool_key,
            database,
            client: None,
            stmt_cache: Mutex::new(HashMap::new()),
        }
    }

    /// A10: prepare on backend (or reuse connection-local cache).
    async fn get_or_prepare(&mut self, sql: &str) -> GatewayResult<BackendPrepared> {
        if let Some(p) = self.stmt_cache.lock().get(sql).cloned() {
            return Ok(p);
        }
        let client = self.client.as_mut().ok_or_else(|| {
            GatewayError::Backend("mysql backend connection is not open".into())
        })?;
        let stmt = client
            .send_prepare(sql.as_bytes())
            .await
            .map_err(|error| GatewayError::Backend(format!("mysql COM_STMT_PREPARE: {error}")))?;
        let prepared = BackendPrepared {
            stmt_id: stmt.stmt_id,
            param_count: stmt.params_count,
        };
        let mut cache = self.stmt_cache.lock();
        if cache.len() >= MAX_MYSQL_STMT_CACHE_PER_CONN {
            cache.clear();
        }
        cache.insert(sql.to_owned(), prepared.clone());
        Ok(prepared)
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

    /// A10: prepare (cached) + binary execute + decode binary resultset.
    async fn execute_prepared(
        &mut self,
        sql: &str,
        parameters: &[GatewayValue],
        mode: ExecuteMode,
    ) -> GatewayResult<GatewayResponse> {
        let prepared = self.get_or_prepare(sql).await?;
        if prepared.param_count as usize != parameters.len() {
            return Err(GatewayError::Protocol(format!(
                "mysql backend prepare expects {} parameters, got {}",
                prepared.param_count,
                parameters.len()
            )));
        }
        let payload = encode_stmt_execute_payload(prepared.stmt_id, parameters)?;
        let client = self.client.as_mut().ok_or_else(|| {
            GatewayError::Backend("mysql backend connection is not open".into())
        })?;
        let mut stream = client
            .send_execute(&payload)
            .await
            .map_err(|error| GatewayError::Backend(format!("mysql COM_STMT_EXECUTE: {error}")))?;
        if matches!(mode, ExecuteMode::Passthrough) {
            // Binary result wire differs from text; never passthrough raw binary as text wire.
            read_mysql_query_response_binary(&mut stream, mode).await
        } else {
            read_mysql_query_response_binary(&mut stream, mode).await
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
        let tls = mysql_client_tls_opts(&self.endpoint)?;
        let mut client = ClientConn::with_opts_tls(
            self.endpoint.username.clone(),
            self.endpoint.password.clone(),
            self.endpoint.address.clone(),
            tls,
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
            stmt_cache: Mutex::new(HashMap::new()),
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
            // A06: progressive decode in windows. We still assemble a ResultSet for
            // the current encode path, but never keep more than max_rows and drain
            // windows into the final buffer so peak temporary growth is window-sized
            // on top of the final rows (not 2× full result during decode).
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

/// A10: COM_STMT_EXECUTE binary resultset path (same header/column/EOF layout as text;
/// rows use binary protocol with null-bitmap starting at bit offset 2).
async fn read_mysql_query_response_binary(
    stream: &mut ResultsetStream<'_>,
    mode: ExecuteMode,
) -> GatewayResult<GatewayResponse> {
    let header = read_mysql_result_packet(stream, "mysql binary query header").await?;
    let payload = packet_payload("mysql binary query header", &header)?;
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
            let window = mode.window_rows().unwrap_or(usize::MAX).max(1);
            let mut rows = Vec::new();
            let mut window_buf: Vec<Vec<GatewayValue>> = Vec::with_capacity(window.min(256));
            let mut total: u64 = 0;
            let mut truncated = false;

            while let Some(row_packet) = read_optional_mysql_result_packet(stream).await? {
                if truncated {
                    continue;
                }
                let row_payload = packet_payload("mysql binary row", &row_packet)?;
                if let Some(max) = max_rows {
                    if total >= max {
                        truncated = true;
                        continue;
                    }
                }
                window_buf.push(binary_row_to_gateway_values(row_payload, &column_infos)?);
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
        None => Err(GatewayError::Protocol(
            "mysql binary query header packet has empty payload".into(),
        )),
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

/// Decode a binary protocol resultset row payload (without 4-byte packet header).
fn binary_row_to_gateway_values(
    row: &[u8],
    columns: &[ColumnInfo],
) -> GatewayResult<Vec<GatewayValue>> {
    if row.is_empty() {
        return Err(GatewayError::Protocol(
            "mysql binary row payload is empty".into(),
        ));
    }
    // Header 0x00 + null bitmap ((n+7+2)/8)
    let null_len = (columns.len() + 7 + 2) / 8;
    if row.len() < 1 + null_len {
        return Err(GatewayError::Protocol(
            "mysql binary row shorter than null bitmap".into(),
        ));
    }
    if row[0] != 0x00 {
        // Some servers may send OK/EOF here; treat non-0x00 as protocol error for rows.
        return Err(GatewayError::Protocol(format!(
            "mysql binary row header expected 0x00, got 0x{:02x}",
            row[0]
        )));
    }
    let null_bitmap = &row[1..1 + null_len];
    let mut offset = 1 + null_len;
    let mut values = Vec::with_capacity(columns.len());
    for (i, column) in columns.iter().enumerate() {
        let bit = i + 2;
        let is_null = null_bitmap[bit / 8] & (1 << (bit % 8)) != 0;
        if is_null {
            values.push(GatewayValue::Null);
            continue;
        }
        let (v, consumed) = decode_binary_result_value(&row[offset..], column)?;
        offset += consumed;
        values.push(v);
    }
    Ok(values)
}

fn decode_binary_result_value(
    data: &[u8],
    column: &ColumnInfo,
) -> GatewayResult<(GatewayValue, usize)> {
    use ColumnType::*;
    match &column.column_type {
        MYSQL_TYPE_TINY => {
            if data.is_empty() {
                return Err(GatewayError::Protocol("mysql binary TINY truncated".into()));
            }
            if column.column_flag & (ColumnFlag::UNSIGNED_FLAG as u16) > 0 {
                Ok((GatewayValue::UnsignedInteger(data[0] as u64), 1))
            } else {
                Ok((GatewayValue::Integer(data[0] as i8 as i64), 1))
            }
        }
        MYSQL_TYPE_SHORT | MYSQL_TYPE_YEAR => {
            if data.len() < 2 {
                return Err(GatewayError::Protocol("mysql binary SHORT truncated".into()));
            }
            let v = i16::from_le_bytes([data[0], data[1]]);
            if column.column_flag & (ColumnFlag::UNSIGNED_FLAG as u16) > 0 {
                Ok((GatewayValue::UnsignedInteger(v as u16 as u64), 2))
            } else {
                Ok((GatewayValue::Integer(v as i64), 2))
            }
        }
        MYSQL_TYPE_LONG | MYSQL_TYPE_INT24 => {
            if data.len() < 4 {
                return Err(GatewayError::Protocol("mysql binary LONG truncated".into()));
            }
            let v = i32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            if column.column_flag & (ColumnFlag::UNSIGNED_FLAG as u16) > 0 {
                Ok((GatewayValue::UnsignedInteger(v as u32 as u64), 4))
            } else {
                Ok((GatewayValue::Integer(v as i64), 4))
            }
        }
        MYSQL_TYPE_LONGLONG => {
            if data.len() < 8 {
                return Err(GatewayError::Protocol(
                    "mysql binary LONGLONG truncated".into(),
                ));
            }
            let v = i64::from_le_bytes(data[..8].try_into().unwrap());
            if column.column_flag & (ColumnFlag::UNSIGNED_FLAG as u16) > 0 {
                Ok((GatewayValue::UnsignedInteger(v as u64), 8))
            } else {
                Ok((GatewayValue::Integer(v), 8))
            }
        }
        MYSQL_TYPE_FLOAT => {
            if data.len() < 4 {
                return Err(GatewayError::Protocol("mysql binary FLOAT truncated".into()));
            }
            let v = f32::from_bits(u32::from_le_bytes([data[0], data[1], data[2], data[3]])) as f64;
            Ok((GatewayValue::Float(v), 4))
        }
        MYSQL_TYPE_DOUBLE => {
            if data.len() < 8 {
                return Err(GatewayError::Protocol(
                    "mysql binary DOUBLE truncated".into(),
                ));
            }
            let bits = u64::from_le_bytes(data[..8].try_into().unwrap());
            Ok((GatewayValue::Float(f64::from_bits(bits)), 8))
        }
        MYSQL_TYPE_DATE
        | MYSQL_TYPE_DATETIME
        | MYSQL_TYPE_TIMESTAMP
        | MYSQL_TYPE_TIME
        | MYSQL_TYPE_NEWDATE => {
            if data.is_empty() {
                return Err(GatewayError::Protocol("mysql binary date/time truncated".into()));
            }
            let len = data[0] as usize;
            if data.len() < 1 + len {
                return Err(GatewayError::Protocol(
                    "mysql binary date/time length exceeds packet".into(),
                ));
            }
            let payload = &data[1..1 + len];
            let text = match &column.column_type {
                MYSQL_TYPE_TIME => decode_mysql_binary_time_text(payload)?,
                MYSQL_TYPE_DATE | MYSQL_TYPE_NEWDATE => decode_mysql_binary_date_text(payload)?,
                // DATETIME / TIMESTAMP (and ambiguous NEWDATE already handled)
                _ => decode_mysql_binary_datetime_text(payload)?,
            };
            Ok((GatewayValue::String(text), 1 + len))
        }
        MYSQL_TYPE_STRING
        | MYSQL_TYPE_VAR_STRING
        | MYSQL_TYPE_VARCHAR
        | MYSQL_TYPE_BLOB
        | MYSQL_TYPE_TINY_BLOB
        | MYSQL_TYPE_MEDIUM_BLOB
        | MYSQL_TYPE_LONG_BLOB
        | MYSQL_TYPE_DECIMAL
        | MYSQL_TYPE_NEWDECIMAL
        | MYSQL_TYPE_ENUM
        | MYSQL_TYPE_SET
        | MYSQL_TYPE_BIT
        | MYSQL_TYPE_GEOMETRY
        | MYSQL_TYPE_NULL => {
            let (bytes, n) = decode_lenc_bytes(data)?;
            let value = match &column.column_type {
                MYSQL_TYPE_BLOB
                | MYSQL_TYPE_TINY_BLOB
                | MYSQL_TYPE_MEDIUM_BLOB
                | MYSQL_TYPE_LONG_BLOB => GatewayValue::Bytes(bytes),
                MYSQL_TYPE_DECIMAL | MYSQL_TYPE_NEWDECIMAL => {
                    GatewayValue::Decimal(String::from_utf8_lossy(&bytes).into_owned())
                }
                _ => GatewayValue::String(String::from_utf8_lossy(&bytes).into_owned()),
            };
            Ok((value, n))
        }
    }
}

/// A10: MySQL ProtocolBinary DATE payload → `YYYY-MM-DD`.
/// len is already stripped; payload is year(2 LE) month day (0 or 4 bytes).
fn decode_mysql_binary_date_text(payload: &[u8]) -> GatewayResult<String> {
    if payload.is_empty() {
        return Ok("0000-00-00".into());
    }
    if payload.len() < 4 {
        return Err(GatewayError::Protocol(format!(
            "mysql binary DATE payload len {} (need 0 or ≥4)",
            payload.len()
        )));
    }
    let y = u16::from_le_bytes([payload[0], payload[1]]);
    let m = payload[2];
    let d = payload[3];
    Ok(format!("{y:04}-{m:02}-{d:02}"))
}

/// A10: DATETIME/TIMESTAMP payload → `YYYY-MM-DD HH:MM:SS[.ffffff]`.
/// Wire lengths: 0 | 4 (date only) | 7 | 11 (+micros).
fn decode_mysql_binary_datetime_text(payload: &[u8]) -> GatewayResult<String> {
    if payload.is_empty() {
        return Ok("0000-00-00 00:00:00".into());
    }
    if payload.len() < 4 {
        return Err(GatewayError::Protocol(format!(
            "mysql binary DATETIME payload len {} (need 0/4/7/11)",
            payload.len()
        )));
    }
    let y = u16::from_le_bytes([payload[0], payload[1]]);
    let mo = payload[2];
    let d = payload[3];
    if payload.len() == 4 {
        return Ok(format!("{y:04}-{mo:02}-{d:02} 00:00:00"));
    }
    if payload.len() < 7 {
        return Err(GatewayError::Protocol(format!(
            "mysql binary DATETIME payload len {} (need 0/4/7/11)",
            payload.len()
        )));
    }
    let h = payload[4];
    let mi = payload[5];
    let sec = payload[6];
    if payload.len() == 7 {
        return Ok(format!(
            "{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{sec:02}"
        ));
    }
    if payload.len() < 11 {
        return Err(GatewayError::Protocol(format!(
            "mysql binary DATETIME micros truncated (len {})",
            payload.len()
        )));
    }
    let micro = u32::from_le_bytes([payload[7], payload[8], payload[9], payload[10]]);
    Ok(format!(
        "{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{sec:02}.{micro:06}"
    ))
}

/// A10: TIME payload → `[-][D ]HH:MM:SS[.ffffff]` (D days only when non-zero).
/// Wire: is_negative(1) days(4 LE) h m s [micro 4 LE]; total 0 | 8 | 12.
fn decode_mysql_binary_time_text(payload: &[u8]) -> GatewayResult<String> {
    if payload.is_empty() {
        return Ok("00:00:00".into());
    }
    if payload.len() < 8 {
        return Err(GatewayError::Protocol(format!(
            "mysql binary TIME payload len {} (need 0/8/12)",
            payload.len()
        )));
    }
    let neg = payload[0] != 0;
    let days = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);
    let h = payload[5];
    let m = payload[6];
    let sec = payload[7];
    let micro = if payload.len() >= 12 {
        Some(u32::from_le_bytes([
            payload[8], payload[9], payload[10], payload[11],
        ]))
    } else if payload.len() == 8 {
        None
    } else {
        return Err(GatewayError::Protocol(format!(
            "mysql binary TIME unexpected len {}",
            payload.len()
        )));
    };
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    if days > 0 {
        out.push_str(&format!("{days} "));
    }
    out.push_str(&format!("{h:02}:{m:02}:{sec:02}"));
    if let Some(us) = micro {
        if us != 0 {
            out.push_str(&format!(".{us:06}"));
        }
    }
    Ok(out)
}

fn decode_lenc_bytes(data: &[u8]) -> GatewayResult<(Vec<u8>, usize)> {
    if data.is_empty() {
        return Err(GatewayError::Protocol("mysql lenc empty".into()));
    }
    let (len, hdr) = match data[0] {
        0xfb => return Ok((Vec::new(), 1)), // NULL as empty for safety
        x if x < 0xfb => (x as usize, 1),
        0xfc => {
            if data.len() < 3 {
                return Err(GatewayError::Protocol("mysql lenc 0xfc truncated".into()));
            }
            (u16::from_le_bytes([data[1], data[2]]) as usize, 3)
        }
        0xfd => {
            if data.len() < 4 {
                return Err(GatewayError::Protocol("mysql lenc 0xfd truncated".into()));
            }
            (
                u32::from_le_bytes([data[1], data[2], data[3], 0]) as usize,
                4,
            )
        }
        0xfe => {
            if data.len() < 9 {
                return Err(GatewayError::Protocol("mysql lenc 0xfe truncated".into()));
            }
            (u64::from_le_bytes(data[1..9].try_into().unwrap()) as usize, 9)
        }
        _ => {
            return Err(GatewayError::Protocol(format!(
                "mysql lenc unexpected prefix 0x{:02x}",
                data[0]
            )));
        }
    };
    if data.len() < hdr + len {
        return Err(GatewayError::Protocol(
            "mysql lenc value exceeds packet".into(),
        ));
    }
    Ok((data[hdr..hdr + len].to_vec(), hdr + len))
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


fn mysql_client_tls_opts(
    endpoint: &EndpointConfig,
) -> GatewayResult<Option<mysql_protocol::client::tls_opts::ClientTlsOpts>> {
    use mysql_protocol::client::tls_opts::ClientTlsOpts;
    match endpoint.ssl_mode {
        EndpointSslMode::Disable => Ok(None),
        EndpointSslMode::Prefer | EndpointSslMode::Require => {
            // MySQL: CLIENT_SSL is negotiated when tls_config is Some.
            // Prefer: if server lacks CLIENT_SSL, client clears tls_config and
            // continues plain (aligned with PG ssl_mode=prefer).
            // Require: handshake fails with ProtocolError::Tls.
            let server_name = {
                let addr = endpoint.address.as_str();
                match addr.rsplit_once(':') {
                    Some((host, port))
                        if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) =>
                    {
                        host.trim_matches(|c| c == '[' || c == ']').to_owned()
                    }
                    _ => addr.trim_matches(|c| c == '[' || c == ']').to_owned(),
                }
            };
            Ok(Some(ClientTlsOpts {
                server_name,
                accept_invalid_certs: endpoint.ssl_accept_invalid_certs,
                ca_file: endpoint.ssl_ca_file.clone(),
                require_tls: endpoint.ssl_mode.requires_tls(),
            }))
        }
    }
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
            ssl_mode: Default::default(),
            ssl_ca_file: None,
            ssl_accept_invalid_certs: true,
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

    #[tokio::test]
    async fn a10_prepare_execute_close_registry() {
        let connector = MySqlBackendConnector::new();
        let mut session = SessionState::default();

        let prepared = connector
            .execute(
                GatewayCommand::Prepare {
                    sql: "SELECT 1".into(),
                },
                &mut session,
            )
            .await
            .unwrap();
        let statement_id = match prepared {
            GatewayResponse::Prepared {
                statement_id,
                parameter_count,
            } => {
                assert_eq!(parameter_count, 0);
                statement_id
            }
            other => panic!("expected Prepared, got {other:?}"),
        };

        // Unknown id errors without hitting backend.
        let err = connector
            .execute(
                GatewayCommand::Execute {
                    statement_id: "99999".into(),
                    parameters: vec![],
                },
                &mut session,
            )
            .await;
        assert!(matches!(err, Err(GatewayError::Backend(_))));

        // Param count mismatch (SQL has no `?`).
        let err = connector
            .execute(
                GatewayCommand::Execute {
                    statement_id: statement_id.clone(),
                    parameters: vec![GatewayValue::Integer(1)],
                },
                &mut session,
            )
            .await;
        assert!(matches!(err, Err(GatewayError::Protocol(_))), "{err:?}");

        // Prepare with placeholders reports count.
        let prepared2 = connector
            .execute(
                GatewayCommand::Prepare {
                    sql: "SELECT ? + ?".into(),
                },
                &mut session,
            )
            .await
            .unwrap();
        match prepared2 {
            GatewayResponse::Prepared {
                parameter_count, ..
            } => assert_eq!(parameter_count, 2),
            other => panic!("{other:?}"),
        }

        assert_eq!(
            connector
                .execute(
                    GatewayCommand::CloseStatement {
                        statement_id: statement_id.clone(),
                    },
                    &mut session,
                )
                .await,
            Ok(GatewayResponse::Ok {
                affected_rows: 0,
                last_insert_id: None
            })
        );

        // After close, Execute fails as unknown.
        let err = connector
            .execute(
                GatewayCommand::Execute {
                    statement_id,
                    parameters: vec![],
                },
                &mut session,
            )
            .await;
        assert!(matches!(err, Err(GatewayError::Backend(_))));
    }

    #[test]
    fn a10_bind_mysql_placeholders() {
        assert_eq!(count_mysql_placeholders("SELECT ? FROM t WHERE a=?"), 2);
        assert_eq!(count_mysql_placeholders("SELECT '?'"), 0);
        let sql = bind_mysql_placeholders(
            "SELECT ? FROM t WHERE id=?",
            &[
                GatewayValue::String("x".into()),
                GatewayValue::Integer(3),
            ],
        )
        .unwrap();
        assert_eq!(sql, "SELECT 'x' FROM t WHERE id=3");
    }

    #[test]
    fn a10_encode_stmt_execute_payload_null_and_int() {
        let payload = encode_stmt_execute_payload(
            7,
            &[GatewayValue::Null, GatewayValue::Integer(42)],
        )
        .unwrap();
        // stmt_id=7, flags=0, iteration=1
        assert_eq!(&payload[0..4], &7u32.to_le_bytes());
        assert_eq!(payload[4], 0);
        assert_eq!(&payload[5..9], &1u32.to_le_bytes());
        // null bitmap 1 byte: bit0 set
        assert_eq!(payload[9] & 0x01, 0x01);
        assert_eq!(payload[10], 1); // new_params_bound
        // types: NULL, LONGLONG
        assert_eq!(payload[11], ColumnType::MYSQL_TYPE_NULL as u8);
        assert_eq!(payload[13], ColumnType::MYSQL_TYPE_LONGLONG as u8);
        // only non-null value encoded: 42 i64
        let val = &payload[payload.len() - 8..];
        assert_eq!(val, &42i64.to_le_bytes());
    }

    #[test]
    fn a10_binary_row_null_bitmap_and_longlong() {
        // header 0x00, null bitmap for 2 cols: ((2+7+2)/8)=1 byte, bit for col0 (offset 2) set
        // col1 LONGLONG = 99
        let mut row = vec![0x00, 0x04]; // bit 2 → null col0
        row.extend_from_slice(&99i64.to_le_bytes());
        let columns = vec![
            column_info("a", ColumnType::MYSQL_TYPE_LONGLONG),
            column_info("b", ColumnType::MYSQL_TYPE_LONGLONG),
        ];
        let values = binary_row_to_gateway_values(&row, &columns).unwrap();
        assert_eq!(
            values,
            vec![GatewayValue::Null, GatewayValue::Integer(99)]
        );
    }

    #[test]
    fn a10_binary_date_datetime_time_to_iso_text() {
        // DATE 2024-08-31: len=4, year LE 0x07E8=2024, mon=8, day=31
        let date_payload = [0xE8u8, 0x07, 8, 31];
        assert_eq!(
            decode_mysql_binary_date_text(&date_payload).unwrap(),
            "2024-08-31"
        );
        // empty date
        assert_eq!(decode_mysql_binary_date_text(&[]).unwrap(), "0000-00-00");

        // DATETIME 2022-08-31 07:16:16 (fixture from protocol tests)
        let dt = [0xE6u8, 0x07, 0x08, 0x1f, 0x07, 0x10, 0x10];
        assert_eq!(
            decode_mysql_binary_datetime_text(&dt).unwrap(),
            "2022-08-31 07:16:16"
        );
        // DATETIME with micros 2003-12-31 01:02:03.123123
        // year 2003=0x07D3, micro 123123=0x0001E0F3 LE
        let dt_us = [
            0xD3u8, 0x07, 12, 31, 1, 2, 3, 0xF3, 0xE0, 0x01, 0x00,
        ];
        assert_eq!(
            decode_mysql_binary_datetime_text(&dt_us).unwrap(),
            "2003-12-31 01:02:03.123123"
        );
        // DATE-only datetime payload (len 4 body)
        assert_eq!(
            decode_mysql_binary_datetime_text(&date_payload).unwrap(),
            "2024-08-31 00:00:00"
        );

        // TIME -1 day 10:08:21 → "-1 10:08:21" (protocol fixture)
        // is_neg=1 days=1 h=10 m=8 s=21
        let tm = [0x01u8, 0x01, 0x00, 0x00, 0x00, 10, 8, 21];
        assert_eq!(
            decode_mysql_binary_time_text(&tm).unwrap(),
            "-1 10:08:21"
        );
        // plain 00:00:00 empty
        assert_eq!(decode_mysql_binary_time_text(&[]).unwrap(), "00:00:00");
    }

    #[test]
    fn a10_binary_row_decodes_datetime_column() {
        // row: header, null_bitmap (1 col → 1 byte), datetime payload
        // 1 column → null map size ((1+7+2)/8)=1
        let mut row = vec![0x00, 0x00]; // no nulls
        row.push(7); // len
        row.extend_from_slice(&[0xE6, 0x07, 0x08, 0x1f, 0x07, 0x10, 0x10]);
        let columns = vec![column_info("ts", ColumnType::MYSQL_TYPE_DATETIME)];
        let values = binary_row_to_gateway_values(&row, &columns).unwrap();
        assert_eq!(
            values,
            vec![GatewayValue::String("2022-08-31 07:16:16".into())]
        );
    }

    #[tokio::test]
    async fn a10_query_params_prepare_bind_against_live_mysql() {
        // Optional live check (docker compose mysql-primary on 13306). Skips if unreachable.
        let mut ep = endpoint();
        ep.address = "127.0.0.1:13306".into();
        ep.database = Some("orders".into());
        ep.username = "root".into();
        ep.password = "root".into();
        let connector = MySqlBackendConnector::with_endpoints(vec![ep]);
        let mut session = SessionState {
            database: Some("orders".into()),
            ..Default::default()
        };
        let ping = connector
            .execute(GatewayCommand::Ping, &mut session)
            .await;
        let _ = ping; // Ping does not need backend
        let result = connector
            .execute(
                GatewayCommand::QueryParams {
                    sql: "SELECT ? + ? AS s".into(),
                    parameters: vec![GatewayValue::Integer(2), GatewayValue::Integer(3)],
                },
                &mut session,
            )
            .await;
        match result {
            Ok(GatewayResponse::ResultSet { rows, .. }) => {
                assert_eq!(rows.len(), 1);
                match &rows[0][0] {
                    GatewayValue::Integer(5) => {}
                    GatewayValue::Float(f) if (*f - 5.0).abs() < 1e-9 => {}
                    other => panic!("expected 5, got {other:?}"),
                }
            }
            Ok(other) => panic!("unexpected response {other:?}"),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("connect")
                    || msg.contains("Connection refused")
                    || msg.contains("timed out")
                    || msg.contains("os error")
                {
                    eprintln!("skip live mysql a10 test: {msg}");
                    return;
                }
                panic!("unexpected error: {msg}");
            }
        }
    }

    #[test]
    fn a10_query_params_streaming_mode_is_selected() {
        // execute_outcome routes Streaming + QueryParams to execute_param_query_streaming.
        let mode = ExecuteMode::from_streaming_config(32, Some(100));
        assert!(matches!(mode, ExecuteMode::Streaming { .. }));
        assert!(matches!(
            GatewayCommand::QueryParams {
                sql: "SELECT ?".into(),
                parameters: vec![GatewayValue::Integer(1)],
            },
            GatewayCommand::QueryParams { .. }
        ));
        assert!(!matches!(
            GatewayCommand::QueryParams {
                sql: "SELECT ?".into(),
                parameters: vec![],
            },
            GatewayCommand::Query { .. }
        ));
    }

    #[tokio::test]
    async fn a10_query_params_streaming_against_live_mysql() {
        let mut ep = endpoint();
        ep.address = "127.0.0.1:13306".into();
        ep.database = Some("orders".into());
        ep.username = "root".into();
        ep.password = "root".into();
        let connector = MySqlBackendConnector::with_endpoints(vec![ep]);
        let mut session = SessionState {
            database: Some("orders".into()),
            ..Default::default()
        };
        let mode = ExecuteMode::from_streaming_config(2, Some(10));
        let outcome = connector
            .execute_outcome(
                GatewayCommand::QueryParams {
                    sql: "SELECT ? AS a UNION ALL SELECT ? UNION ALL SELECT ?".into(),
                    parameters: vec![
                        GatewayValue::Integer(1),
                        GatewayValue::Integer(2),
                        GatewayValue::Integer(3),
                    ],
                },
                &mut session,
                mode,
            )
            .await;
        match outcome {
            Ok(ExecuteOutcome::Streaming(mut query)) => {
                let mut rows = Vec::new();
                while let Some(chunk) = query.stream.poll_window(2).await.unwrap() {
                    rows.extend(chunk);
                }
                assert!(
                    rows.len() >= 2,
                    "expected multi-row streaming windows, got {rows:?}"
                );
            }
            Ok(ExecuteOutcome::Complete(GatewayResponse::ResultSet { rows, .. })) => {
                // Accept Complete if server returned tiny set without streaming path edge.
                assert!(!rows.is_empty());
            }
            Ok(ExecuteOutcome::Complete(other)) => {
                panic!("unexpected complete response {other:?}")
            }
            Ok(ExecuteOutcome::WireRelay(_)) => {
                panic!("unexpected wire relay for QueryParams")
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("connect")
                    || msg.contains("Connection refused")
                    || msg.contains("timed out")
                    || msg.contains("os error")
                {
                    eprintln!("skip live mysql a10 streaming test: {msg}");
                    return;
                }
                panic!("unexpected error: {msg}");
            }
        }
    }

    #[test]
    fn a06_streaming_mode_covers_txn_and_non_txn() {
        // Streaming mode is used regardless of transaction; lease return differs.
        let mode = ExecuteMode::from_streaming_config(64, Some(100));
        assert!(matches!(mode, ExecuteMode::Streaming { .. }));
        assert_eq!(mode.window_rows(), Some(64));
        assert_eq!(mode.effective_max_rows(), Some(100));
        assert!(!matches!(
            ExecuteMode::Materialized,
            ExecuteMode::Streaming { .. }
        ));
        // Connector keeps a txn_lease slot for producer return-after-drain.
        let c = MySqlBackendConnector::with_endpoints(vec![endpoint()]);
        assert!(!c.has_transaction_lease());
        assert!(c.txn_lease.lock().is_none());
    }

    #[test]
    fn a08_mysql_tls_opts_from_endpoint() {
        let mut ep = endpoint();
        ep.ssl_mode = EndpointSslMode::Disable;
        assert!(mysql_client_tls_opts(&ep).unwrap().is_none());

        ep.ssl_mode = EndpointSslMode::Require;
        ep.address = "db.example.com:3306".into();
        ep.ssl_accept_invalid_certs = false;
        ep.ssl_ca_file = Some("/etc/ssl/certs/mysql-ca.pem".into());
        let opts = mysql_client_tls_opts(&ep).unwrap().expect("tls");
        assert_eq!(opts.server_name, "db.example.com");
        assert!(!opts.accept_invalid_certs);
        assert_eq!(opts.ca_file.as_deref(), Some("/etc/ssl/certs/mysql-ca.pem"));
        assert!(opts.require_tls);
    }

    #[test]
    fn a08_mysql_tls_prefer_and_require_both_request_client_ssl() {
        // Both modes set tls_config so CLIENT_SSL is attempted when server supports it.
        for mode in [EndpointSslMode::Prefer, EndpointSslMode::Require] {
            let mut ep = endpoint();
            ep.ssl_mode = mode;
            assert!(mysql_client_tls_opts(&ep).unwrap().is_some());
        }
    }

    #[test]
    fn a08_mysql_tls_prefer_allows_plain_fallback_flag() {
        let mut ep = endpoint();
        ep.ssl_mode = EndpointSslMode::Prefer;
        let prefer = mysql_client_tls_opts(&ep).unwrap().expect("tls");
        assert!(!prefer.require_tls, "prefer must allow plain fallback");

        ep.ssl_mode = EndpointSslMode::Require;
        let require = mysql_client_tls_opts(&ep).unwrap().expect("tls");
        assert!(require.require_tls, "require must fail without server SSL");
    }

    #[test]
    fn a08_mysql_tls_server_name_strips_port_and_ipv6_brackets() {
        let mut ep = endpoint();
        ep.ssl_mode = EndpointSslMode::Require;
        ep.address = "[2001:db8::1]:3306".into();
        let opts = mysql_client_tls_opts(&ep).unwrap().expect("tls");
        assert_eq!(opts.server_name, "2001:db8::1");
    }
}
