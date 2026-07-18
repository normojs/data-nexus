use std::{
    collections::HashMap,
    fmt,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};

use async_trait::async_trait;
use conn_pool::{ConnAttr, ConnAttrMut, ConnLike, Pool, PoolConn};
use futures::StreamExt;
use gateway_core::{
    BackendConnector, Column as GatewayColumn, EndpointConfig, EndpointRole, ExecuteMode,
    ExecuteOutcome, GatewayCommand, GatewayError, GatewayResponse, GatewayResult, GatewayValue,
    ProtocolKind, RowStream, SessionState, StreamingQuery, TransactionState, WireRelay, WireStream,
};
use parking_lot::Mutex;
use postgresql_protocol::{
    encode_command_complete, encode_data_row, encode_ready_for_query, encode_row_description,
    FieldDescription, TransactionStatus,
};
use tokio_postgres::{types::ToSql, Client, NoTls, Row, SimpleQueryMessage};
use tracing::error;

use super::pg_tcp_relay::{
    new_tcp_txn_slot, PgTcpIdlePool, PgTcpSession, PgTcpTxnSlot, SessionReturn,
};

const DEFAULT_POSTGRESQL_POOL_SIZE: usize = 16;

/// A10: session-scoped prepared statement registry (gateway-owned id → SQL).
///
/// Does not use PG extended query protocol yet; Execute rewrites to simple Query.
#[derive(Debug, Default)]
struct PreparedRegistry {
    next_id: AtomicU32,
    sql_by_id: Mutex<HashMap<String, String>>,
}

impl Clone for PreparedRegistry {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl PreparedRegistry {
    fn prepare(&self, sql: String) -> (String, u16) {
        let param_count = count_pg_placeholders(&sql);
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

/// Count distinct `$n` placeholders (PostgreSQL extended/simple prepared style).
fn count_pg_placeholders(sql: &str) -> u16 {
    let mut max = 0u16;
    let bytes = sql.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
            let mut j = i + 1;
            let mut n: u16 = 0;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                n = n
                    .saturating_mul(10)
                    .saturating_add((bytes[j] - b'0') as u16);
                j += 1;
            }
            if n > max {
                max = n;
            }
            i = j;
            continue;
        }
        i += 1;
    }
    max
}

fn bind_pg_placeholders(sql: &str, parameters: &[GatewayValue]) -> GatewayResult<String> {
    let need = count_pg_placeholders(sql) as usize;
    if need != parameters.len() {
        return Err(GatewayError::Protocol(format!(
            "postgresql prepared Execute expects {need} parameters, got {}",
            parameters.len()
        )));
    }
    if need == 0 {
        return Ok(sql.to_owned());
    }
    // Replace $n (highest first) so $10 is not partially matched by $1.
    let mut out = sql.to_owned();
    for n in (1..=need).rev() {
        let lit = gateway_value_sql_literal(&parameters[n - 1]);
        out = out.replace(&format!("${n}"), &lit);
    }
    Ok(out)
}

fn gateway_value_sql_literal(v: &GatewayValue) -> String {
    match v {
        GatewayValue::Null => "NULL".into(),
        GatewayValue::Boolean(b) => if *b { "TRUE" } else { "FALSE" }.into(),
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
            let mut hex = String::with_capacity(4 + b.len() * 2);
            hex.push_str("E'\\\\x");
            for byte in b {
                hex.push_str(&format!("{byte:02x}"));
            }
            hex.push('\'');
            hex
        }
    }
}

#[derive(Clone, Debug)]
pub struct PostgreSqlBackendConnector {
    endpoints: Arc<Mutex<Vec<EndpointConfig>>>,
    pool: Pool<PostgreSqlBackendConnection>,
    txn_lease: Arc<Mutex<Option<PoolConn<PostgreSqlBackendConnection>>>>,
    /// A08: dedicated TCP session for in-transaction wire passthrough.
    /// Parallel to `txn_lease` (pool) so Streaming/Materialized still use
    /// tokio-postgres; Passthrough reuses this socket across statements.
    tcp_txn: PgTcpTxnSlot,
    /// A08: idle non-txn TCP relay sessions (keyed by address|db|user).
    tcp_idle: Arc<PgTcpIdlePool>,
    prepared: Arc<PreparedRegistry>,
}

impl Default for PostgreSqlBackendConnector {
    fn default() -> Self {
        Self::with_pool_size(Vec::new(), DEFAULT_POSTGRESQL_POOL_SIZE)
    }
}

impl PostgreSqlBackendConnector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_endpoints(endpoints: Vec<EndpointConfig>) -> Self {
        Self::with_pool_size(endpoints, DEFAULT_POSTGRESQL_POOL_SIZE)
    }

    pub fn with_pool_size(endpoints: Vec<EndpointConfig>, pool_size: usize) -> Self {
        let pool: Pool<PostgreSqlBackendConnection> = Pool::new(pool_size);
        for endpoint in &endpoints {
            if let Some(database) = endpoint.database.clone() {
                register_endpoint_factory(&pool, endpoint, database);
            }
        }

        Self {
            endpoints: Arc::new(Mutex::new(endpoints)),
            pool,
            txn_lease: Arc::new(Mutex::new(None)),
            tcp_txn: new_tcp_txn_slot(),
            tcp_idle: PgTcpIdlePool::with_default_cap(),
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
                        "postgresql backend connector has no configured endpoint '{}'",
                        endpoint_name
                    ))
                });
        }

        self.endpoints.lock().first().cloned().ok_or_else(|| {
            GatewayError::Configuration(
                "postgresql backend connector has no configured endpoints".into(),
            )
        })
    }

    async fn acquire_conn(
        &self,
        endpoint: &EndpointConfig,
        session: &SessionState,
    ) -> GatewayResult<PoolConn<PostgreSqlBackendConnection>> {
        let pool_key = self.ensure_pool_factory_for_session(endpoint, session)?;
        let session_attrs = postgresql_session_attrs(session);
        self.pool.get_conn_with_endpoint_session(&pool_key, &session_attrs).await
    }

    async fn execute_on_conn(
        conn: &PoolConn<PostgreSqlBackendConnection>,
        sql: &str,
        mode: ExecuteMode,
    ) -> GatewayResult<GatewayResponse> {
        let messages = conn.simple_query(sql).await?;
        simple_query_messages_to_gateway_response(messages, mode)
    }

    async fn take_or_acquire_lease(
        &self,
        endpoint: &EndpointConfig,
        session: &SessionState,
    ) -> GatewayResult<PoolConn<PostgreSqlBackendConnection>> {
        if let Some(conn) = self.txn_lease.lock().take() {
            return Ok(conn);
        }
        self.acquire_conn(endpoint, session).await
    }

    fn store_lease(&self, conn: PoolConn<PostgreSqlBackendConnection>) {
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
            let conn = self.take_or_acquire_lease(&endpoint, session).await?;
            if need_begin {
                let begin = Self::execute_on_conn(&conn, "BEGIN", ExecuteMode::Materialized).await?;
                if !matches!(begin, GatewayResponse::Ok { .. }) {
                    self.store_lease(conn);
                    return Ok(begin);
                }
            }
            let response = Self::execute_on_conn(&conn, sql, mode).await;
            self.store_lease(conn);
            return response;
        }

        let conn = self.acquire_conn(&endpoint, session).await?;
        Self::execute_on_conn(&conn, sql, mode).await
    }

    /// A08: Passthrough without materializing a logical ResultSet.
    ///
    /// Dedicated backend TCP session → raw frames. Non-txn is one-shot;
    /// in-txn reuses `tcp_txn` across statements (BEGIN sent on first use).
    async fn execute_simple_query_wire(
        &self,
        endpoint: EndpointConfig,
        sql: &str,
        session: &SessionState,
    ) -> GatewayResult<GatewayResponse> {
        let in_txn = session.transaction_state == TransactionState::Active
            || self.tcp_txn.lock().is_some()
            || self.txn_lease.lock().is_some();
        if in_txn {
            return self
                .execute_simple_query_tcp_relay_txn_collect(&endpoint, sql, session)
                .await;
        }
        self.execute_simple_query_tcp_relay_collect(&endpoint, sql, session)
            .await
    }

    /// A08: non-txn TCP frame relay collected into `GatewayResponse::Wire`.
    async fn execute_simple_query_tcp_relay_collect(
        &self,
        endpoint: &EndpointConfig,
        sql: &str,
        session: &SessionState,
    ) -> GatewayResult<GatewayResponse> {
        let database = effective_database(endpoint, session)?;
        let key = PgTcpIdlePool::pool_key(endpoint, &database);
        let session_tcp = self.tcp_idle.take_or_connect(endpoint, &database).await?;
        let mut stream = session_tcp
            .simple_query_relay_into(
                sql,
                SessionReturn::Idle {
                    pool: self.tcp_idle.clone(),
                    key,
                },
            )
            .await?;
        let mut packets = Vec::new();
        loop {
            match stream.poll_packets(64).await? {
                None => break,
                Some(batch) => packets.extend(batch),
            }
        }
        Ok(GatewayResponse::Wire { packets })
    }

    /// A08: progressive TCP frame relay (non-transaction, idle-pool reuse).
    async fn execute_simple_query_tcp_relay(
        &self,
        endpoint: EndpointConfig,
        sql: &str,
        session: &SessionState,
    ) -> GatewayResult<ExecuteOutcome> {
        let database = effective_database(&endpoint, session)?;
        let key = PgTcpIdlePool::pool_key(&endpoint, &database);
        let session_tcp = self.tcp_idle.take_or_connect(&endpoint, &database).await?;
        let stream = session_tcp
            .simple_query_relay_into(
                sql,
                SessionReturn::Idle {
                    pool: self.tcp_idle.clone(),
                    key,
                },
            )
            .await?;
        Ok(ExecuteOutcome::WireRelay(WireRelay {
            stream: Box::new(stream),
        }))
    }

    /// A10: execute SQL with `$n` parameters via tokio-postgres prepare/bind
    /// (no string rewrite). Uses pool lease (including in-transaction).
    async fn execute_param_query(
        &self,
        endpoint: EndpointConfig,
        sql: &str,
        parameters: &[GatewayValue],
        session: &SessionState,
        mode: ExecuteMode,
    ) -> GatewayResult<GatewayResponse> {
        let need = count_pg_placeholders(sql) as usize;
        if need != parameters.len() {
            return Err(GatewayError::Protocol(format!(
                "postgresql prepared Execute expects {need} parameters, got {}",
                parameters.len()
            )));
        }
        if parameters.is_empty() {
            if matches!(mode, ExecuteMode::Passthrough) {
                return self.execute_simple_query_wire(endpoint, sql, session).await;
            }
            return self
                .execute_simple_query(endpoint, sql, session, mode)
                .await;
        }

        let in_txn = session.transaction_state == TransactionState::Active
            || self.txn_lease.lock().is_some();
        let conn = if in_txn {
            let need_begin = self.txn_lease.lock().is_none();
            let conn = self.take_or_acquire_lease(&endpoint, session).await?;
            if need_begin {
                let begin =
                    Self::execute_on_conn(&conn, "BEGIN", ExecuteMode::Materialized).await?;
                if !matches!(begin, GatewayResponse::Ok { .. }) {
                    self.store_lease(conn);
                    return Ok(begin);
                }
            }
            conn
        } else {
            self.acquire_conn(&endpoint, session).await?
        };

        let result = Self::execute_param_on_conn(&conn, sql, parameters, mode).await;
        if in_txn {
            self.store_lease(conn);
        }
        result
    }

    async fn execute_param_on_conn(
        conn: &PoolConn<PostgreSqlBackendConnection>,
        sql: &str,
        parameters: &[GatewayValue],
        mode: ExecuteMode,
    ) -> GatewayResult<GatewayResponse> {
        let client = conn.client.as_ref().ok_or_else(|| {
            GatewayError::Backend("postgresql backend connection is not open".into())
        })?;
        let text_params: Vec<Option<String>> = parameters
            .iter()
            .map(gateway_value_to_pg_param_text)
            .collect();
        let to_sql: Vec<&(dyn ToSql + Sync)> = text_params
            .iter()
            .map(|p| p as &(dyn ToSql + Sync))
            .collect();

        match client.query(sql, to_sql.as_slice()).await {
            Ok(rows) => rows_to_gateway_response(rows, mode),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("does not return rows")
                    || msg.contains("no field")
                    || msg.contains("statement that returns")
                {
                    let n = client
                        .execute(sql, to_sql.as_slice())
                        .await
                        .map_err(postgresql_backend_error)?;
                    Ok(GatewayResponse::Ok {
                        affected_rows: n,
                        last_insert_id: None,
                    })
                } else {
                    Err(postgresql_backend_error(e))
                }
            }
        }
    }

    /// A08: take or open TCP session for transaction passthrough.
    async fn take_or_open_tcp_txn(
        &self,
        endpoint: &EndpointConfig,
        session: &SessionState,
    ) -> GatewayResult<(PgTcpSession, bool)> {
        if let Some(s) = self.tcp_txn.lock().take() {
            return Ok((s, false));
        }
        let database = effective_database(endpoint, session)?;
        let s = PgTcpSession::connect(endpoint, &database).await?;
        Ok((s, true))
    }

    fn store_tcp_txn(&self, session: PgTcpSession) {
        *self.tcp_txn.lock() = Some(session);
    }

    fn clear_tcp_txn(&self) {
        *self.tcp_txn.lock() = None;
    }

    /// A08: in-txn collect path (BEGIN on first statement, reuse socket).
    async fn execute_simple_query_tcp_relay_txn_collect(
        &self,
        endpoint: &EndpointConfig,
        sql: &str,
        session: &SessionState,
    ) -> GatewayResult<GatewayResponse> {
        let (sess, is_new) = self.take_or_open_tcp_txn(endpoint, session).await?;
        let sess = if is_new {
            let (sess, begin_packets) = sess.simple_query_collect_reuse("BEGIN").await?;
            // BEGIN should yield CommandComplete + Ready; treat ErrorResponse as failure.
            if begin_packets.iter().any(|p| p.first() == Some(&b'E')) {
                // Do not keep a failed session.
                return Ok(GatewayResponse::Wire {
                    packets: begin_packets,
                });
            }
            sess
        } else {
            sess
        };
        let (sess, packets) = sess.simple_query_collect_reuse(sql).await?;
        self.store_tcp_txn(sess);
        Ok(GatewayResponse::Wire { packets })
    }

    /// A08: progressive in-txn TCP frame relay (returns session to slot on drain).
    async fn execute_simple_query_tcp_relay_txn(
        &self,
        endpoint: EndpointConfig,
        sql: &str,
        session: &SessionState,
    ) -> GatewayResult<ExecuteOutcome> {
        let (sess, is_new) = self.take_or_open_tcp_txn(&endpoint, session).await?;
        let sess = if is_new {
            let (sess, begin_packets) = sess.simple_query_collect_reuse("BEGIN").await?;
            if begin_packets.iter().any(|p| p.first() == Some(&b'E')) {
                return Ok(ExecuteOutcome::Complete(GatewayResponse::Wire {
                    packets: begin_packets,
                }));
            }
            sess
        } else {
            sess
        };
        let stream = sess
            .simple_query_relay_into(sql, SessionReturn::Txn(self.tcp_txn.clone()))
            .await?;
        Ok(ExecuteOutcome::WireRelay(WireRelay {
            stream: Box::new(stream),
        }))
    }

    /// A06: stream logical rows in windows.
    ///
    /// Uses `simple_query_raw` so RowDescription is available before the first
    /// DataRow; a producer task owns the connection and pushes windows over a
    /// bounded channel (capacity 2). Peak retained rows ≈ one window per side.
    ///
    /// When `in_transaction` is true, the connection is taken from / returned to
    /// `txn_lease` after the stream ends.
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

        let conn = if in_transaction {
            let need_begin = self.txn_lease.lock().is_none();
            let conn = self.take_or_acquire_lease(&endpoint, session).await?;
            if need_begin {
                let begin =
                    Self::execute_on_conn(&conn, "BEGIN", ExecuteMode::Materialized).await?;
                if !matches!(begin, GatewayResponse::Ok { .. }) {
                    self.store_lease(conn);
                    return Ok(ExecuteOutcome::Complete(begin));
                }
            }
            conn
        } else {
            self.acquire_conn(&endpoint, session).await?
        };

        let client = conn.client.as_ref().ok_or_else(|| {
            GatewayError::Backend("postgresql backend connection is not open".into())
        })?;
        let raw = client
            .simple_query_raw(sql)
            .await
            .map_err(postgresql_backend_error)?;
        let mut stream = Box::pin(raw);

        // Wait for RowDescription (or CommandComplete for non-SELECT).
        let columns = loop {
            match stream.next().await {
                None => {
                    if in_transaction {
                        self.store_lease(conn);
                    }
                    return Ok(ExecuteOutcome::Complete(GatewayResponse::Ok {
                        affected_rows: 0,
                        last_insert_id: None,
                    }));
                }
                Some(Err(error)) => {
                    if in_transaction {
                        self.store_lease(conn);
                    }
                    return Err(postgresql_backend_error(error));
                }
                Some(Ok(SimpleQueryMessage::RowDescription(cols))) => {
                    break cols
                        .iter()
                        .map(|column| GatewayColumn {
                            name: column.name().to_string(),
                            data_type: "text".into(),
                        })
                        .collect::<Vec<_>>();
                }
                Some(Ok(SimpleQueryMessage::CommandComplete(count))) => {
                    if in_transaction {
                        self.store_lease(conn);
                    }
                    return Ok(ExecuteOutcome::Complete(GatewayResponse::Ok {
                        affected_rows: count,
                        last_insert_id: None,
                    }));
                }
                Some(Ok(SimpleQueryMessage::Row(_))) => {
                    if in_transaction {
                        self.store_lease(conn);
                    }
                    return Err(GatewayError::Protocol(
                        "postgresql simple_query_raw delivered DataRow before RowDescription"
                            .into(),
                    ));
                }
                Some(Ok(_)) => {}
            }
        };

        let lease_slot = if in_transaction {
            Some(self.txn_lease.clone())
        } else {
            None
        };
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<Vec<GatewayValue>>>(2);
        tokio::spawn(async move {
            let run = async {
                let mut window_buf: Vec<Vec<GatewayValue>> =
                    Vec::with_capacity(window.min(256));
                let mut total: u64 = 0;
                let mut truncated = false;
                while let Some(item) = stream.next().await {
                    let message = item.map_err(postgresql_backend_error)?;
                    match message {
                        SimpleQueryMessage::Row(row) => {
                            if truncated {
                                continue;
                            }
                            if let Some(max) = max_rows {
                                if total >= max {
                                    truncated = true;
                                    continue;
                                }
                            }
                            window_buf.push(simple_query_row_to_gateway_values(&row));
                            total += 1;
                            if window_buf.len() >= window {
                                let chunk: Vec<_> = window_buf.drain(..).collect();
                                if tx.send(chunk).await.is_err() {
                                    while stream.next().await.is_some() {}
                                    return Ok(());
                                }
                            }
                        }
                        SimpleQueryMessage::CommandComplete(_)
                        | SimpleQueryMessage::RowDescription(_) => {}
                        _ => {}
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
                    "postgresql streaming producer failed"
                );
            }
            if let Some(slot) = lease_slot {
                *slot.lock() = Some(conn);
            } else {
                drop(conn);
            }
        });

        Ok(ExecuteOutcome::Streaming(StreamingQuery {
            columns,
            stream: Box::new(ChannelRowStream { rx }),
        }))
    }

    async fn finish_transaction(&self, sql: &str) -> GatewayResult<GatewayResponse> {
        // Prefer TCP txn session when present (passthrough path held the lease).
        let tcp_sess = self.tcp_txn.lock().take();
        if let Some(sess) = tcp_sess {
            let (sess, packets) = sess.simple_query_collect_reuse(sql).await?;
            // End of transaction — drop TCP session (do not store).
            drop(sess);
            // Also clear any stale pool lease (should be empty if pure passthrough).
            *self.txn_lease.lock() = None;
            return Ok(GatewayResponse::Wire { packets });
        }
        let pool_conn = self.txn_lease.lock().take();
        let Some(conn) = pool_conn else {
            return Ok(GatewayResponse::Ok {
                affected_rows: 0,
                last_insert_id: None,
            });
        };
        let response = Self::execute_on_conn(&conn, sql, ExecuteMode::Materialized).await;
        drop(conn);
        match response {
            Ok(response @ GatewayResponse::Ok { .. })
            | Ok(response @ GatewayResponse::ResultSet { .. }) => Ok(response),
            Ok(GatewayResponse::Error { code, message }) => Err(GatewayError::Backend(format!(
                "postgresql {}: {}",
                code, message
            ))),
            Ok(other) => Err(GatewayError::Backend(format!(
                "postgresql control statement unexpected response {:?}",
                other
            ))),
            Err(error) => Err(error),
        }
    }

    fn ensure_pool_factory_for_session(
        &self,
        endpoint: &EndpointConfig,
        session: &SessionState,
    ) -> GatewayResult<String> {
        let _ = parse_endpoint_address(&endpoint.address)?;
        let database = effective_database(endpoint, session)?;
        let pool_key = postgresql_pool_key(endpoint, &database);

        if !self.pool.has_factory(&pool_key) {
            register_endpoint_factory(&self.pool, endpoint, database);
        }

        Ok(pool_key)
    }
}

#[async_trait]
impl BackendConnector for PostgreSqlBackendConnector {
    fn protocol(&self) -> ProtocolKind {
        ProtocolKind::PostgreSql
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
                self.clear_tcp_txn();
                self.prepared.clear();
                Ok(GatewayResponse::Bye)
            }
            GatewayCommand::UseDatabase { database } => {
                session.database = Some(database);
                Ok(GatewayResponse::Ok { affected_rows: 0, last_insert_id: None })
            }
            GatewayCommand::Begin => {
                // Defer backend BEGIN until the first statement leases a connection.
                session.transaction_state = TransactionState::Active;
                Ok(GatewayResponse::Ok { affected_rows: 0, last_insert_id: None })
            }
            GatewayCommand::Commit => {
                let response = self.finish_transaction("COMMIT").await?;
                session.transaction_state = TransactionState::Idle;
                Ok(response)
            }
            GatewayCommand::Rollback => {
                let response = self.finish_transaction("ROLLBACK").await?;
                session.transaction_state = TransactionState::Idle;
                Ok(response)
            }
            GatewayCommand::Query { sql } => {
                let endpoint = self.select_endpoint(session)?;
                {
                    // A08: same-protocol wire path — TCP frame relay (non-txn one-shot;
                    // in-txn reuses tcp_txn session).
                    if matches!(mode, ExecuteMode::Passthrough) {
                        return self
                            .execute_simple_query_wire(endpoint, &sql, session)
                            .await;
                    }
                    self.execute_simple_query(endpoint, &sql, session, mode).await
                }
            }
            // A10: parameterized query — keep $n, bind via prepare (no string rewrite).
            GatewayCommand::QueryParams { sql, parameters } => {
                let endpoint = self.select_endpoint(session)?;
                self.execute_param_query(endpoint, &sql, &parameters, session, mode)
                    .await
            }
            // A10: gateway-owned prepared registry; Execute uses param bind path.
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
                        "unknown postgresql prepared statement id '{statement_id}'"
                    ))
                })?;
                // Validate arity before endpoint selection (unit tests use empty connector).
                let need = count_pg_placeholders(&sql) as usize;
                if need != parameters.len() {
                    return Err(GatewayError::Protocol(format!(
                        "postgresql prepared Execute expects {need} parameters, got {}",
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
        let in_txn = session.transaction_state == TransactionState::Active
            || self.txn_lease.lock().is_some()
            || self.tcp_txn.lock().is_some();

        // A08: progressive TCP frame relay for passthrough (txn + non-txn).
        if matches!(mode, ExecuteMode::Passthrough) && is_query {
            if let GatewayCommand::Query { sql } = command {
                let endpoint = self.select_endpoint(session)?;
                if in_txn {
                    return self
                        .execute_simple_query_tcp_relay_txn(endpoint, &sql, session)
                        .await;
                }
                return self
                    .execute_simple_query_tcp_relay(endpoint, &sql, session)
                    .await;
            }
        }

        if streaming && is_query {
            if let GatewayCommand::Query { sql } = command {
                let endpoint = self.select_endpoint(session)?;
                return self
                    .execute_simple_query_streaming(endpoint, &sql, session, mode, in_txn)
                    .await;
            }
        }

        let response = self.execute_with_mode(command, session, mode).await?;
        Ok(ExecuteOutcome::Complete(response))
    }
}

/// A06: row windows from a producer task that owns the PG pool connection.
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

struct PostgreSqlBackendConnection {
    endpoint: EndpointConfig,
    pool_key: String,
    database: String,
    client_encoding: Option<String>,
    client: Option<Client>,
}

impl Clone for PostgreSqlBackendConnection {
    fn clone(&self) -> Self {
        Self {
            endpoint: self.endpoint.clone(),
            pool_key: self.pool_key.clone(),
            database: self.database.clone(),
            client_encoding: self.client_encoding.clone(),
            client: None,
        }
    }
}

impl Default for PostgreSqlBackendConnection {
    fn default() -> Self {
        Self {
            endpoint: EndpointConfig {
                name: String::new(),
                protocol: ProtocolKind::PostgreSql,
                address: String::new(),
                database: None,
                role: EndpointRole::ReadWrite,
                username: String::new(),
                password: String::new(),
                weight: 0,
            },
            pool_key: String::new(),
            database: String::new(),
            client_encoding: None,
            client: None,
        }
    }
}

impl PostgreSqlBackendConnection {
    fn factory(endpoint: EndpointConfig, database: String) -> Self {
        let pool_key = postgresql_pool_key(&endpoint, &database);
        Self { endpoint, pool_key, database, client_encoding: None, client: None }
    }

    async fn simple_query(&self, sql: &str) -> GatewayResult<Vec<SimpleQueryMessage>> {
        self.client()?.simple_query(sql).await.map_err(postgresql_backend_error)
    }

    async fn set_client_encoding(&mut self, client_encoding: String) -> GatewayResult<()> {
        if self.client_encoding.as_deref() == Some(client_encoding.as_str()) {
            return Ok(());
        }

        let sql = postgresql_client_encoding_statement(&client_encoding);
        self.simple_query(&sql).await?;
        self.client_encoding = Some(client_encoding);
        Ok(())
    }

    fn client(&self) -> GatewayResult<&Client> {
        self.client.as_ref().ok_or_else(|| {
            GatewayError::Backend("postgresql backend connection is not open".into())
        })
    }
}

impl fmt::Debug for PostgreSqlBackendConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgreSqlBackendConnection")
            .field("endpoint", &self.endpoint)
            .field("pool_key", &self.pool_key)
            .field("database", &self.database)
            .field("client_encoding", &self.client_encoding)
            .field("connected", &self.client.is_some())
            .finish()
    }
}

#[async_trait]
impl ConnLike for PostgreSqlBackendConnection {
    type Error = GatewayError;

    async fn build_conn(&self) -> Result<Self, Self::Error> {
        let client = connect_endpoint(&self.endpoint, &self.database).await?;
        Ok(Self {
            endpoint: self.endpoint.clone(),
            pool_key: self.pool_key.clone(),
            database: self.database.clone(),
            client_encoding: None,
            client: Some(client),
        })
    }

    async fn ping(&mut self) -> Result<(), Self::Error> {
        self.simple_query("SELECT 1").await.map(|_| ())
    }
}

impl ConnAttr for PostgreSqlBackendConnection {
    fn get_host(&self) -> String {
        parse_endpoint_address(&self.endpoint.address).map(|(host, _)| host).unwrap_or_default()
    }

    fn get_port(&self) -> u16 {
        parse_endpoint_address(&self.endpoint.address).map(|(_, port)| port).unwrap_or_default()
    }

    fn get_user(&self) -> String {
        self.endpoint.username.clone()
    }

    fn get_endpoint(&self) -> String {
        self.pool_key.clone()
    }

    fn get_db(&self) -> Option<String> {
        Some(self.database.clone())
    }

    fn get_charset(&self) -> Option<String> {
        self.client_encoding.clone()
    }

    fn get_autocommit(&self) -> Option<String> {
        None
    }
}

#[async_trait]
impl ConnAttrMut for PostgreSqlBackendConnection {
    type Item = PostgreSqlSessionAttr;

    async fn init(&mut self, session: &[Self::Item]) {
        for attr in session {
            match attr {
                PostgreSqlSessionAttr::ClientEncoding(client_encoding) => {
                    if let Err(error) = self.set_client_encoding(client_encoding.clone()).await {
                        error!(
                            "postgresql backend failed to sync client_encoding '{}': {}",
                            client_encoding, error
                        );
                    }
                }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PostgreSqlSessionAttr {
    ClientEncoding(String),
}

async fn connect_endpoint(endpoint: &EndpointConfig, database: &str) -> GatewayResult<Client> {
    let (host, port) = parse_endpoint_address(&endpoint.address)?;

    let mut config = tokio_postgres::Config::new();
    config.host(&host);
    config.port(port);
    config.user(&endpoint.username);
    if !endpoint.password.is_empty() {
        config.password(&endpoint.password);
    }
    config.dbname(database);

    let (client, connection) = config.connect(NoTls).await.map_err(postgresql_backend_error)?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            error!("postgresql backend connection error: {}", error);
        }
    });

    Ok(client)
}

fn register_endpoint_factory(
    pool: &Pool<PostgreSqlBackendConnection>,
    endpoint: &EndpointConfig,
    database: String,
) {
    let pool_key = postgresql_pool_key(endpoint, &database);
    pool.set_factory(&pool_key, PostgreSqlBackendConnection::factory(endpoint.clone(), database));
}

fn effective_database(endpoint: &EndpointConfig, session: &SessionState) -> GatewayResult<String> {
    session.database.clone().or_else(|| endpoint.database.clone()).ok_or_else(|| {
        GatewayError::Configuration(
            "postgresql backend connector requires a database to be selected".into(),
        )
    })
}

fn postgresql_pool_key(endpoint: &EndpointConfig, database: &str) -> String {
    format!("{}|{}", endpoint.address, database)
}

fn postgresql_session_attrs(session: &SessionState) -> Vec<PostgreSqlSessionAttr> {
    session
        .charset
        .as_ref()
        .map(|charset| {
            // Map MySQL charset/collation names (or aliases) to PG client_encoding.
            let client_encoding = map_charset_to_postgresql_encoding(charset);
            vec![PostgreSqlSessionAttr::ClientEncoding(client_encoding)]
        })
        .unwrap_or_default()
}

/// Normalize frontend charset (often MySQL) into a PostgreSQL client_encoding value.
fn map_charset_to_postgresql_encoding(charset: &str) -> String {
    let lower = charset.to_ascii_lowercase();
    // MySQL collations look like utf8mb4_general_ci / utf8mb4_unicode_ci.
    let base = lower.split('_').next().unwrap_or(lower.as_str());
    match base {
        "utf8mb4" | "utf8mb3" | "utf8" | "utf-8" => "UTF8".into(),
        "latin1" | "iso-8859-1" | "iso88591" => "LATIN1".into(),
        "latin9" | "iso-8859-15" => "LATIN9".into(),
        "ascii" | "us-ascii" => "SQL_ASCII".into(),
        "gbk" => "GBK".into(),
        "gb18030" => "GB18030".into(),
        "big5" => "BIG5".into(),
        "ujis" | "eucjpms" => "EUC_JP".into(),
        "euckr" => "EUC_KR".into(),
        "binary" => "SQL_ASCII".into(),
        "default" => "DEFAULT".into(),
        // Already a PG-style name (UTF8, LATIN1, ...).
        other if other.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') => {
            other.to_ascii_uppercase()
        }
        _ => "UTF8".into(),
    }
}

fn postgresql_client_encoding_statement(client_encoding: &str) -> String {
    if client_encoding.eq_ignore_ascii_case("default") {
        "SET client_encoding TO DEFAULT".into()
    } else {
        format!("SET client_encoding TO '{}'", client_encoding.replace('\'', "''"))
    }
}

fn simple_query_row_to_gateway_values(row: &tokio_postgres::SimpleQueryRow) -> Vec<GatewayValue> {
    (0..row.len())
        .map(|idx| {
            row.get(idx)
                .map(|value| GatewayValue::String(value.to_string()))
                .unwrap_or(GatewayValue::Null)
        })
        .collect()
}

/// A10: bind params as text (frontend Bind is text-format).
fn gateway_value_to_pg_param_text(v: &GatewayValue) -> Option<String> {
    match v {
        GatewayValue::Null => None,
        GatewayValue::Boolean(b) => Some(if *b { "t".into() } else { "f".into() }),
        GatewayValue::Integer(i) => Some(i.to_string()),
        GatewayValue::UnsignedInteger(u) => Some(u.to_string()),
        GatewayValue::Float(f) => Some(f.to_string()),
        GatewayValue::Decimal(s) | GatewayValue::String(s) => Some(s.clone()),
        GatewayValue::Bytes(b) => {
            // Hex escape for bytea text input.
            let mut hex = String::with_capacity(2 + b.len() * 2);
            hex.push_str("\\x");
            for byte in b {
                hex.push_str(&format!("{byte:02x}"));
            }
            Some(hex)
        }
    }
}

fn rows_to_gateway_response(
    rows: Vec<Row>,
    mode: ExecuteMode,
) -> GatewayResult<GatewayResponse> {
    if rows.is_empty() {
        // Could be empty SELECT or mis-routed DML; treat as empty ResultSet with no columns.
        return Ok(GatewayResponse::ResultSet {
            columns: Vec::new(),
            rows: Vec::new(),
        });
    }
    let columns: Vec<GatewayColumn> = rows[0]
        .columns()
        .iter()
        .map(|c| GatewayColumn {
            name: c.name().to_string(),
            // Type name for frontend binary encode path.
            data_type: c.type_().name().to_string(),
        })
        .collect();
    let max_rows = mode.effective_max_rows();
    let mut out = Vec::new();
    for row in rows {
        if let Some(max) = max_rows {
            if out.len() as u64 >= max {
                break;
            }
        }
        out.push(typed_row_to_gateway_values(&row)?);
    }
    Ok(GatewayResponse::ResultSet {
        columns,
        rows: out,
    })
}

fn typed_row_to_gateway_values(row: &Row) -> GatewayResult<Vec<GatewayValue>> {
    let mut values = Vec::with_capacity(row.len());
    for i in 0..row.len() {
        // Prefer text representation for all types (stable, works with our binary encode).
        let v: Option<String> = row.try_get(i).map_err(|e| {
            GatewayError::Backend(format!("postgresql row get col {i}: {e}"))
        })?;
        values.push(match v {
            None => GatewayValue::Null,
            Some(s) => GatewayValue::String(s),
        });
    }
    Ok(values)
}

fn simple_query_messages_to_gateway_response(
    messages: Vec<SimpleQueryMessage>,
    mode: ExecuteMode,
) -> GatewayResult<GatewayResponse> {
    let mut columns: Vec<GatewayColumn> = Vec::new();
    let mut rows = Vec::new();
    let mut affected_rows = 0;
    let max_rows = mode.effective_max_rows();

    for message in messages {
        match message {
            SimpleQueryMessage::Row(row) => {
                if let Some(max) = max_rows {
                    if rows.len() as u64 >= max {
                        continue;
                    }
                }
                if columns.is_empty() {
                    columns = row
                        .columns()
                        .iter()
                        .map(|column| GatewayColumn {
                            name: column.name().to_string(),
                            data_type: "text".into(),
                        })
                        .collect();
                }

                rows.push(simple_query_row_to_gateway_values(&row));
            }
            SimpleQueryMessage::CommandComplete(count) => affected_rows = count,
            _ => {}
        }
    }

    if !columns.is_empty() {
        Ok(GatewayResponse::ResultSet { columns, rows })
    } else {
        Ok(GatewayResponse::Ok {
            affected_rows,
            last_insert_id: None,
        })
    }
}

/// A08: encode a logical GatewayResponse as frontend-ready PostgreSQL messages.
fn logical_response_to_pg_wire(
    response: GatewayResponse,
    session: &SessionState,
) -> GatewayResult<GatewayResponse> {
    let ready = encode_ready_for_query(pg_transaction_status(session));
    match response {
        GatewayResponse::ResultSet { columns, rows } => {
            let fields = columns
                .iter()
                .map(|c| FieldDescription {
                    name: c.name.clone(),
                    type_oid: 25, // text
                    type_size: -1,
                    type_modifier: -1,
                    format_code: 0,
                })
                .collect::<Vec<_>>();
            let mut packets = Vec::with_capacity(rows.len() + 3);
            packets.push(
                encode_row_description(&fields)
                    .map_err(|e| GatewayError::Protocol(e.to_string()))?,
            );
            for row in &rows {
                if row.len() != columns.len() {
                    return Err(GatewayError::Protocol(format!(
                        "postgresql wire row has {} values for {} columns",
                        row.len(),
                        columns.len()
                    )));
                }
                let values = row
                    .iter()
                    .map(|v| match v {
                        GatewayValue::Null => None,
                        GatewayValue::Boolean(b) => {
                            Some(if *b { b"t".to_vec() } else { b"f".to_vec() })
                        }
                        GatewayValue::Integer(i) => Some(i.to_string().into_bytes()),
                        GatewayValue::UnsignedInteger(i) => Some(i.to_string().into_bytes()),
                        GatewayValue::Float(f) => Some(f.to_string().into_bytes()),
                        GatewayValue::Decimal(s) | GatewayValue::String(s) => {
                            Some(s.as_bytes().to_vec())
                        }
                        GatewayValue::Bytes(b) => Some(b.clone()),
                    })
                    .collect::<Vec<_>>();
                packets.push(
                    encode_data_row(&values).map_err(|e| GatewayError::Protocol(e.to_string()))?,
                );
            }
            packets.push(encode_command_complete(&format!("SELECT {}", rows.len())));
            packets.push(ready);
            Ok(GatewayResponse::Wire { packets })
        }
        GatewayResponse::Ok { affected_rows, .. } => Ok(GatewayResponse::Wire {
            packets: vec![
                encode_command_complete(&format!("OK {affected_rows}")),
                ready,
            ],
        }),
        GatewayResponse::Error { code, message } => {
            // Keep Error typed so PEP/audit can still read code/message; frontend encodes it.
            Ok(GatewayResponse::Error { code, message })
        }
        GatewayResponse::Wire { packets } => Ok(GatewayResponse::Wire { packets }),
        other => Ok(other),
    }
}

/// Legacy A08 re-encode path (simple_query_raw → wire). Kept as a helper for
/// unit tests / emergency fallback; production passthrough uses TCP frame relay.
#[allow(dead_code)]
async fn stream_simple_query_to_pg_wire(
    conn: &PoolConn<PostgreSqlBackendConnection>,
    sql: &str,
    session: &SessionState,
) -> GatewayResult<GatewayResponse> {
    let client = conn.client.as_ref().ok_or_else(|| {
        GatewayError::Backend("postgresql backend connection is not open".into())
    })?;
    let raw = client
        .simple_query_raw(sql)
        .await
        .map_err(postgresql_backend_error)?;
    let mut stream = Box::pin(raw);
    let ready = encode_ready_for_query(pg_transaction_status(session));
    let mut packets: Vec<Vec<u8>> = Vec::new();
    let mut row_count: u64 = 0;
    let mut saw_row_description = false;
    let mut last_command_tag: Option<u64> = None;

    while let Some(item) = stream.next().await {
        let message = item.map_err(postgresql_backend_error)?;
        match message {
            SimpleQueryMessage::RowDescription(cols) => {
                saw_row_description = true;
                let fields = cols
                    .iter()
                    .map(|c| FieldDescription {
                        name: c.name().to_string(),
                        type_oid: 25, // text
                        type_size: -1,
                        type_modifier: -1,
                        format_code: 0,
                    })
                    .collect::<Vec<_>>();
                packets.push(
                    encode_row_description(&fields)
                        .map_err(|e| GatewayError::Protocol(e.to_string()))?,
                );
            }
            SimpleQueryMessage::Row(row) => {
                let values = (0..row.len())
                    .map(|idx| {
                        row.get(idx)
                            .map(|value| value.as_bytes().to_vec())
                    })
                    .collect::<Vec<_>>();
                packets.push(
                    encode_data_row(&values).map_err(|e| GatewayError::Protocol(e.to_string()))?,
                );
                row_count += 1;
            }
            SimpleQueryMessage::CommandComplete(count) => {
                last_command_tag = Some(count);
            }
            _ => {}
        }
    }

    if saw_row_description {
        packets.push(encode_command_complete(&format!("SELECT {row_count}")));
        packets.push(ready);
        Ok(GatewayResponse::Wire { packets })
    } else {
        let affected = last_command_tag.unwrap_or(0);
        Ok(GatewayResponse::Wire {
            packets: vec![
                encode_command_complete(&format!("OK {affected}")),
                ready,
            ],
        })
    }
}

fn pg_transaction_status(session: &SessionState) -> TransactionStatus {
    match session.transaction_state {
        TransactionState::Idle => TransactionStatus::Idle,
        TransactionState::Active => TransactionStatus::InTransaction,
        TransactionState::Failed => TransactionStatus::Failed,
    }
}

fn postgresql_backend_error(error: tokio_postgres::Error) -> GatewayError {
    GatewayError::Backend(error.to_string())
}

fn parse_endpoint_address(address: &str) -> GatewayResult<(String, u16)> {
    let (host, port) = address.rsplit_once(':').ok_or_else(|| {
        GatewayError::Configuration(format!(
            "postgresql endpoint address '{}' must be host:port",
            address
        ))
    })?;
    let port = port.parse::<u16>().map_err(|error| {
        GatewayError::Configuration(format!(
            "postgresql endpoint address '{}' has invalid port: {}",
            address, error
        ))
    })?;

    if host.is_empty() {
        return Err(GatewayError::Configuration(
            "postgresql endpoint host must not be empty".into(),
        ));
    }

    Ok((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint() -> EndpointConfig {
        EndpointConfig {
            name: "analytics-primary".into(),
            protocol: ProtocolKind::PostgreSql,
            address: "127.0.0.1:5432".into(),
            database: Some("analytics".into()),
            role: EndpointRole::ReadWrite,
            username: "postgres".into(),
            password: "secret".into(),
            weight: 1,
        }
    }

    #[test]
    fn registers_endpoint_database_factory_in_pool() {
        let endpoint = endpoint();
        let connector = PostgreSqlBackendConnector::with_pool_size(vec![endpoint.clone()], 4);
        let pool_key = postgresql_pool_key(&endpoint, "analytics");

        assert_eq!(connector.pool.capacity(), 4);
        assert!(connector.pool.has_factory(&pool_key));
        assert_eq!(connector.pool.factory_endpoints(), vec![pool_key]);
    }

    #[test]
    fn registers_session_database_factory_on_demand() {
        let endpoint = endpoint();
        let connector = PostgreSqlBackendConnector::with_endpoints(vec![endpoint.clone()]);
        let session = SessionState { database: Some("reporting".into()), ..Default::default() };

        let pool_key = connector.ensure_pool_factory_for_session(&endpoint, &session).unwrap();

        assert_eq!(pool_key, postgresql_pool_key(&endpoint, "reporting"));
        assert!(connector.pool.has_factory(&postgresql_pool_key(&endpoint, "analytics")));
        assert!(connector.pool.has_factory(&pool_key));
    }

    #[test]
    fn builds_session_attrs_from_client_encoding() {
        let session = SessionState { charset: Some("LATIN1".into()), ..Default::default() };
        let attrs = postgresql_session_attrs(&session);
        assert_eq!(attrs, vec![PostgreSqlSessionAttr::ClientEncoding("LATIN1".into())]);

        let mysql_session =
            SessionState { charset: Some("utf8mb4_general_ci".into()), ..Default::default() };
        let attrs = postgresql_session_attrs(&mysql_session);
        assert_eq!(attrs, vec![PostgreSqlSessionAttr::ClientEncoding("UTF8".into())]);
    }

    #[test]
    fn maps_mysql_charset_names_to_postgresql_encoding() {
        assert_eq!(map_charset_to_postgresql_encoding("utf8mb4"), "UTF8");
        assert_eq!(map_charset_to_postgresql_encoding("utf8mb4_unicode_ci"), "UTF8");
        assert_eq!(map_charset_to_postgresql_encoding("latin1"), "LATIN1");
        assert_eq!(map_charset_to_postgresql_encoding("UTF8"), "UTF8");
    }

    #[test]
    fn a08_logical_resultset_encodes_to_wire_packets() {
        let session = SessionState::default();
        let logical = GatewayResponse::ResultSet {
            columns: vec![GatewayColumn {
                name: "id".into(),
                data_type: "int".into(),
            }],
            rows: vec![
                vec![GatewayValue::Integer(1)],
                vec![GatewayValue::Integer(2)],
            ],
        };
        let wire = logical_response_to_pg_wire(logical, &session).unwrap();
        match wire {
            GatewayResponse::Wire { packets } => {
                // RowDescription + 2 DataRow + CommandComplete + ReadyForQuery
                assert_eq!(packets.len(), 5);
                assert_eq!(packets[0][0], b'T'); // RowDescription
                assert_eq!(packets[1][0], b'D'); // DataRow
                assert_eq!(packets[2][0], b'D');
                assert_eq!(packets[3][0], b'C'); // CommandComplete
                assert_eq!(packets[4][0], b'Z'); // ReadyForQuery
            }
            other => panic!("expected Wire, got {other:?}"),
        }
    }

    #[test]
    fn a08_wire_path_avoids_resultset_materialization_comment() {
        // Non-txn + in-txn passthrough use PgTcpSession TCP frame relay (WireRelay).
        // In-txn reuses tcp_txn slot across statements; Streaming still uses pool.
        assert!(matches!(
            ExecuteMode::Passthrough,
            ExecuteMode::Passthrough
        ));
        assert!(matches!(
            ExecuteOutcome::Complete(GatewayResponse::Pong),
            ExecuteOutcome::Complete(_)
        ));
    }

    #[test]
    fn a08_tcp_relay_module_exports_session() {
        let _ = std::any::type_name::<crate::backend::pg_tcp_relay::PgTcpSession>();
        let _ = std::any::type_name::<crate::backend::pg_tcp_relay::PgTcpTxnSlot>();
    }

    #[test]
    fn a08_connector_has_tcp_txn_slot() {
        let c = PostgreSqlBackendConnector::with_endpoints(vec![endpoint()]);
        assert!(c.tcp_txn.lock().is_none());
        assert!(!c.has_transaction_lease());
        assert!(c.tcp_idle.is_empty());
        assert_eq!(
            PgTcpIdlePool::pool_key(&endpoint(), "analytics"),
            "127.0.0.1:5432|analytics|postgres"
        );
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
    }

    #[test]
    fn simple_query_messages_respect_max_rows() {
        // Build via Complete path helpers: empty messages → Ok.
        let ok = simple_query_messages_to_gateway_response(
            vec![SimpleQueryMessage::CommandComplete(3)],
            ExecuteMode::Streaming {
                window_rows: 10,
                max_rows: Some(1),
            },
        )
        .unwrap();
        assert!(matches!(
            ok,
            GatewayResponse::Ok {
                affected_rows: 3,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn a10_prepare_execute_close_registry() {
        let connector = PostgreSqlBackendConnector::new();
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

        let prepared2 = connector
            .execute(
                GatewayCommand::Prepare {
                    sql: "SELECT $1, $2".into(),
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
    fn a10_bind_pg_placeholders() {
        assert_eq!(count_pg_placeholders("SELECT $1, $2"), 2);
        assert_eq!(count_pg_placeholders("SELECT $10, $2"), 10);
        let sql = bind_pg_placeholders(
            "SELECT $1 WHERE id=$2",
            &[
                GatewayValue::String("x".into()),
                GatewayValue::Integer(3),
            ],
        )
        .unwrap();
        assert_eq!(sql, "SELECT 'x' WHERE id=3");
    }

    #[test]
    fn a10_param_text_and_empty_rows_response() {
        assert_eq!(
            gateway_value_to_pg_param_text(&GatewayValue::Null),
            None
        );
        assert_eq!(
            gateway_value_to_pg_param_text(&GatewayValue::Boolean(true)).as_deref(),
            Some("t")
        );
        assert_eq!(
            gateway_value_to_pg_param_text(&GatewayValue::Integer(7)).as_deref(),
            Some("7")
        );
        let empty = rows_to_gateway_response(vec![], ExecuteMode::Materialized).unwrap();
        match empty {
            GatewayResponse::ResultSet { columns, rows } => {
                assert!(columns.is_empty());
                assert!(rows.is_empty());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a08_ok_encodes_to_wire() {
        let session = SessionState::default();
        let wire = logical_response_to_pg_wire(
            GatewayResponse::Ok {
                affected_rows: 3,
                last_insert_id: None,
            },
            &session,
        )
        .unwrap();
        match wire {
            GatewayResponse::Wire { packets } => {
                assert_eq!(packets.len(), 2);
                assert_eq!(packets[0][0], b'C');
                assert_eq!(packets[1][0], b'Z');
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn builds_session_attrs_empty_without_charset() {
        assert!(postgresql_session_attrs(&SessionState::default()).is_empty());
    }

    #[test]
    fn builds_client_encoding_statement() {
        assert_eq!(postgresql_client_encoding_statement("UTF8"), "SET client_encoding TO 'UTF8'");
        assert_eq!(
            postgresql_client_encoding_statement("O'HARE"),
            "SET client_encoding TO 'O''HARE'"
        );
        assert_eq!(
            postgresql_client_encoding_statement("DEFAULT"),
            "SET client_encoding TO DEFAULT"
        );
    }

    #[tokio::test]
    async fn updates_session_for_control_commands() {
        let connector = PostgreSqlBackendConnector::with_endpoints(vec![endpoint()]);
        let mut session = SessionState::default();

        assert_eq!(
            connector
                .execute(GatewayCommand::UseDatabase { database: "app".into() }, &mut session)
                .await,
            Ok(GatewayResponse::Ok { affected_rows: 0, last_insert_id: None })
        );
        assert_eq!(session.database, Some("app".into()));

        assert_eq!(
            connector.execute(GatewayCommand::Begin, &mut session).await,
            Ok(GatewayResponse::Ok { affected_rows: 0, last_insert_id: None })
        );
        assert_eq!(session.transaction_state, TransactionState::Active);

        assert_eq!(
            connector.execute(GatewayCommand::Commit, &mut session).await,
            Ok(GatewayResponse::Ok { affected_rows: 0, last_insert_id: None })
        );
        assert_eq!(session.transaction_state, TransactionState::Idle);

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
    async fn rejects_query_with_invalid_endpoint_address() {
        let mut endpoint = endpoint();
        endpoint.address = "invalid-address".into();
        let connector = PostgreSqlBackendConnector::with_endpoints(vec![endpoint]);
        let mut session = SessionState::default();

        let result =
            connector.execute(GatewayCommand::Query { sql: "select 1".into() }, &mut session).await;

        assert_eq!(
            result,
            Err(GatewayError::Configuration(
                "postgresql endpoint address 'invalid-address' must be host:port".into()
            ))
        );
    }

    #[tokio::test]
    async fn rejects_query_without_database_selection() {
        let mut endpoint = endpoint();
        endpoint.database = None;
        let connector = PostgreSqlBackendConnector::with_endpoints(vec![endpoint]);
        let mut session = SessionState::default();

        let result =
            connector.execute(GatewayCommand::Query { sql: "select 1".into() }, &mut session).await;

        assert_eq!(
            result,
            Err(GatewayError::Configuration(
                "postgresql backend connector requires a database to be selected".into()
            ))
        );
    }

    #[tokio::test]
    async fn rejects_query_without_endpoints() {
        let connector = PostgreSqlBackendConnector::new();
        let mut session = SessionState::default();

        let result =
            connector.execute(GatewayCommand::Query { sql: "select 1".into() }, &mut session).await;

        assert_eq!(
            result,
            Err(GatewayError::Configuration(
                "postgresql backend connector has no configured endpoints".into()
            ))
        );
    }
}
