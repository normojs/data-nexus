//! A08: PostgreSQL same-protocol TCP frame relay.
//!
//! Opens a dedicated backend TCP session (startup + auth), sends simple Query
//! frames, and yields raw backend messages (tag + length + body) until
//! ReadyForQuery. Peak retained bytes ≈ one read buffer / batch.
//!
//! Scope (honest):
//! - simple Query only (not extended protocol)
//! - reusable session for in-transaction multi-statement passthrough
//! - **non-txn idle pool** (per address|db|user, capped) to avoid connect/auth
//!   every passthrough query
//! - cleartext / MD5 / SCRAM-SHA-256 auth; no SSL to backend
//! - not shared with the tokio-postgres pool (parallel lease)

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::BytesMut;
use fallible_iterator::FallibleIterator;
use gateway_core::{EndpointConfig, GatewayError, GatewayResult, WireStream};
use parking_lot::Mutex;
use postgres_protocol::authentication::md5_hash;
use postgres_protocol::authentication::sasl::{ChannelBinding, ScramSha256, SCRAM_SHA_256};
use postgres_protocol::message::backend::Message;
use postgres_protocol::message::frontend;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Default max idle TCP relay sessions per pool key (A08).
pub const DEFAULT_TCP_IDLE_MAX_PER_KEY: usize = 4;

/// Authenticated backend socket ready for simple-query relay (reusable).
pub struct PgTcpSession {
    stream: TcpStream,
    read_buf: BytesMut,
}

impl std::fmt::Debug for PgTcpSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgTcpSession")
            .field("read_buf_len", &self.read_buf.len())
            .finish_non_exhaustive()
    }
}

/// Slot for holding a TCP session across transaction statements (A08).
pub type PgTcpTxnSlot = Arc<Mutex<Option<PgTcpSession>>>;

pub fn new_tcp_txn_slot() -> PgTcpTxnSlot {
    Arc::new(Mutex::new(None))
}

/// Where to put the session after a simple-query response ends (A08).
#[derive(Clone)]
pub enum SessionReturn {
    /// Drop TCP when done (legacy one-shot).
    Drop,
    /// In-transaction reuse slot.
    Txn(PgTcpTxnSlot),
    /// Non-txn idle pool (keyed by address|db|user).
    Idle {
        pool: Arc<PgTcpIdlePool>,
        key: String,
    },
}

/// Small process-local idle pool for non-transaction TCP relay sessions.
#[derive(Debug)]
pub struct PgTcpIdlePool {
    max_per_key: usize,
    idle: Mutex<HashMap<String, VecDeque<PgTcpSession>>>,
}

impl PgTcpIdlePool {
    pub fn new(max_per_key: usize) -> Self {
        Self {
            max_per_key: max_per_key.max(1),
            idle: Mutex::new(HashMap::new()),
        }
    }

    pub fn with_default_cap() -> Arc<Self> {
        Arc::new(Self::new(DEFAULT_TCP_IDLE_MAX_PER_KEY))
    }

    pub fn pool_key(endpoint: &EndpointConfig, database: &str) -> String {
        format!(
            "{}|{}|{}",
            endpoint.address, database, endpoint.username
        )
    }

    pub fn len(&self) -> usize {
        self.idle.lock().values().map(|q| q.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn max_per_key(&self) -> usize {
        self.max_per_key
    }

    pub fn take(&self, key: &str) -> Option<PgTcpSession> {
        let mut g = self.idle.lock();
        g.get_mut(key).and_then(|q| q.pop_front())
    }

    pub fn put(&self, key: String, session: PgTcpSession) {
        let mut g = self.idle.lock();
        let q = g.entry(key).or_default();
        if q.len() >= self.max_per_key {
            // Drop oldest overflow (and this new one stays; pop front first).
            let _ = q.pop_front();
        }
        q.push_back(session);
    }

    pub async fn take_or_connect(
        self: &Arc<Self>,
        endpoint: &EndpointConfig,
        database: &str,
    ) -> GatewayResult<PgTcpSession> {
        let key = Self::pool_key(endpoint, database);
        if let Some(s) = self.take(&key) {
            return Ok(s);
        }
        PgTcpSession::connect(endpoint, database).await
    }
}

impl PgTcpSession {
    pub async fn connect(
        endpoint: &EndpointConfig,
        database: &str,
    ) -> GatewayResult<Self> {
        let mut stream = TcpStream::connect(&endpoint.address)
            .await
            .map_err(|e| GatewayError::Backend(format!("pg tcp connect: {e}")))?;
        stream
            .set_nodelay(true)
            .map_err(|e| GatewayError::Backend(format!("pg tcp nodelay: {e}")))?;

        let mut params: Vec<(&str, &str)> = vec![
            ("user", endpoint.username.as_str()),
            ("database", database),
            ("client_encoding", "UTF8"),
        ];
        // application_name helps operators distinguish relay sessions.
        params.push(("application_name", "data-nexus-a08-relay"));

        let mut out = BytesMut::new();
        frontend::startup_message(params.into_iter(), &mut out)
            .map_err(|e| GatewayError::Backend(format!("pg startup encode: {e}")))?;
        stream
            .write_all(&out)
            .await
            .map_err(|e| GatewayError::Backend(format!("pg startup write: {e}")))?;

        let mut session = Self {
            stream,
            read_buf: BytesMut::with_capacity(16 * 1024),
        };
        session.authenticate(&endpoint.username, &endpoint.password).await?;
        Ok(session)
    }

    async fn authenticate(&mut self, username: &str, password: &str) -> GatewayResult<()> {
        let mut scram: Option<ScramSha256> = None;
        loop {
            let msg = self
                .next_message()
                .await?
                .ok_or_else(|| GatewayError::Backend("pg auth: connection closed".into()))?;
            match msg {
                Message::AuthenticationOk => {
                    // Drain ParameterStatus / BackendKeyData until ReadyForQuery.
                    self.drain_until_ready().await?;
                    return Ok(());
                }
                Message::AuthenticationCleartextPassword => {
                    let mut out = BytesMut::new();
                    frontend::password_message(password.as_bytes(), &mut out).map_err(|e| {
                        GatewayError::Backend(format!("pg cleartext password encode: {e}"))
                    })?;
                    self.stream
                        .write_all(&out)
                        .await
                        .map_err(|e| GatewayError::Backend(format!("pg password write: {e}")))?;
                }
                Message::AuthenticationMd5Password(body) => {
                    let hash = md5_hash(username.as_bytes(), password.as_bytes(), body.salt());
                    let mut out = BytesMut::new();
                    frontend::password_message(hash.as_bytes(), &mut out).map_err(|e| {
                        GatewayError::Backend(format!("pg md5 password encode: {e}"))
                    })?;
                    self.stream
                        .write_all(&out)
                        .await
                        .map_err(|e| GatewayError::Backend(format!("pg password write: {e}")))?;
                }
                Message::AuthenticationSasl(body) => {
                    let mut has_scram = false;
                    let mut mechs = body.mechanisms();
                    while let Some(m) = mechs.next().map_err(|e| {
                        GatewayError::Backend(format!("pg sasl mechanisms: {e}"))
                    })? {
                        if m == SCRAM_SHA_256 {
                            has_scram = true;
                            break;
                        }
                    }
                    if !has_scram {
                        return Err(GatewayError::Backend(
                            "pg auth: server did not offer SCRAM-SHA-256".into(),
                        ));
                    }
                    let s = ScramSha256::new(password.as_bytes(), ChannelBinding::unsupported());
                    let mut out = BytesMut::new();
                    frontend::sasl_initial_response(SCRAM_SHA_256, s.message(), &mut out)
                        .map_err(|e| {
                            GatewayError::Backend(format!("pg sasl initial encode: {e}"))
                        })?;
                    self.stream.write_all(&out).await.map_err(|e| {
                        GatewayError::Backend(format!("pg sasl initial write: {e}"))
                    })?;
                    scram = Some(s);
                }
                Message::AuthenticationSaslContinue(body) => {
                    let s = scram.as_mut().ok_or_else(|| {
                        GatewayError::Backend("pg auth: SASL continue without initial".into())
                    })?;
                    s.update(body.data())
                        .map_err(|e| GatewayError::Backend(format!("pg sasl update: {e}")))?;
                    let mut out = BytesMut::new();
                    frontend::sasl_response(s.message(), &mut out).map_err(|e| {
                        GatewayError::Backend(format!("pg sasl response encode: {e}"))
                    })?;
                    self.stream
                        .write_all(&out)
                        .await
                        .map_err(|e| GatewayError::Backend(format!("pg sasl response write: {e}")))?;
                }
                Message::AuthenticationSaslFinal(body) => {
                    let s = scram.as_mut().ok_or_else(|| {
                        GatewayError::Backend("pg auth: SASL final without state".into())
                    })?;
                    s.finish(body.data())
                        .map_err(|e| GatewayError::Backend(format!("pg sasl finish: {e}")))?;
                }
                Message::ErrorResponse(body) => {
                    let detail = format_error_fields(body);
                    return Err(GatewayError::Backend(format!("pg auth error: {detail}")));
                }
                Message::NoticeResponse(_) => {
                    // ignore notices during auth
                }
                other => {
                    return Err(GatewayError::Backend(format!(
                        "pg auth: unexpected message tag during handshake ({})",
                        message_tag(&other)
                    )));
                }
            }
        }
    }

    async fn drain_until_ready(&mut self) -> GatewayResult<()> {
        loop {
            let msg = self
                .next_message()
                .await?
                .ok_or_else(|| GatewayError::Backend("pg auth: closed before ReadyForQuery".into()))?;
            match msg {
                Message::ReadyForQuery(_) => return Ok(()),
                Message::ParameterStatus(_) | Message::BackendKeyData(_) | Message::NoticeResponse(_) => {
                }
                Message::ErrorResponse(body) => {
                    let detail = format_error_fields(body);
                    return Err(GatewayError::Backend(format!(
                        "pg auth post-ok error: {detail}"
                    )));
                }
                other => {
                    return Err(GatewayError::Backend(format!(
                        "pg auth: unexpected post-ok message ({})",
                        message_tag(&other)
                    )));
                }
            }
        }
    }

    /// Send simple Query and return a stream that yields raw frames until ReadyForQuery.
    ///
    /// Consumes `self`. Prefer [`simple_query_relay_into`] when the session must
    /// be returned after drain.
    pub async fn simple_query_relay(self, sql: &str) -> GatewayResult<PgTcpWireStream> {
        self.simple_query_relay_into(sql, SessionReturn::Drop).await
    }

    /// Send simple Query; when the response ends, apply [`SessionReturn`].
    pub async fn simple_query_relay_into(
        mut self,
        sql: &str,
        return_to: SessionReturn,
    ) -> GatewayResult<PgTcpWireStream> {
        let mut out = BytesMut::new();
        frontend::query(sql, &mut out)
            .map_err(|e| GatewayError::Backend(format!("pg query encode: {e}")))?;
        self.stream
            .write_all(&out)
            .await
            .map_err(|e| GatewayError::Backend(format!("pg query write: {e}")))?;
        Ok(PgTcpWireStream {
            session: Some(self),
            return_to,
            done: false,
        })
    }

    /// Run a simple query and fully drain frames into a packet vec (keeps session).
    pub async fn simple_query_collect_reuse(
        self,
        sql: &str,
    ) -> GatewayResult<(Self, Vec<Vec<u8>>)> {
        let slot = new_tcp_txn_slot();
        let mut stream = self
            .simple_query_relay_into(sql, SessionReturn::Txn(slot.clone()))
            .await?;
        let mut packets = Vec::new();
        loop {
            match stream.poll_packets(64).await? {
                None => break,
                Some(batch) => packets.extend(batch),
            }
        }
        let session = slot.lock().take().ok_or_else(|| {
            GatewayError::Backend("pg tcp collect_reuse: session not returned".into())
        })?;
        Ok((session, packets))
    }

    /// Read the next complete backend message and return its raw frame bytes.
    async fn next_raw_frame(&mut self) -> GatewayResult<Option<Vec<u8>>> {
        loop {
            if let Some(frame) = try_split_frame(&mut self.read_buf)? {
                return Ok(Some(frame));
            }
            let mut tmp = [0u8; 16 * 1024];
            let n = self
                .stream
                .read(&mut tmp)
                .await
                .map_err(|e| GatewayError::Backend(format!("pg tcp read: {e}")))?;
            if n == 0 {
                if self.read_buf.is_empty() {
                    return Ok(None);
                }
                return Err(GatewayError::Backend(
                    "pg tcp: connection closed mid-message".into(),
                ));
            }
            self.read_buf.extend_from_slice(&tmp[..n]);
        }
    }

    async fn next_message(&mut self) -> GatewayResult<Option<Message>> {
        loop {
            match Message::parse(&mut self.read_buf)
                .map_err(|e| GatewayError::Backend(format!("pg message parse: {e}")))?
            {
                Some(msg) => return Ok(Some(msg)),
                None => {
                    let mut tmp = [0u8; 8 * 1024];
                    let n = self
                        .stream
                        .read(&mut tmp)
                        .await
                        .map_err(|e| GatewayError::Backend(format!("pg tcp read: {e}")))?;
                    if n == 0 {
                        if self.read_buf.is_empty() {
                            return Ok(None);
                        }
                        return Err(GatewayError::Backend(
                            "pg tcp: connection closed mid-message".into(),
                        ));
                    }
                    self.read_buf.extend_from_slice(&tmp[..n]);
                }
            }
        }
    }
}

/// Progressive wire frames for one simple-query response (ends at ReadyForQuery).
pub struct PgTcpWireStream {
    session: Option<PgTcpSession>,
    return_to: SessionReturn,
    done: bool,
}

impl PgTcpWireStream {
    fn finish_session(&mut self) {
        if let Some(sess) = self.session.take() {
            match &self.return_to {
                SessionReturn::Drop => {
                    // drop → TCP close
                }
                SessionReturn::Txn(slot) => {
                    *slot.lock() = Some(sess);
                }
                SessionReturn::Idle { pool, key } => {
                    pool.put(key.clone(), sess);
                }
            }
        }
    }
}

impl Drop for PgTcpWireStream {
    fn drop(&mut self) {
        // Mid-stream abort still returns the session so COMMIT/ROLLBACK or idle
        // reuse can continue (caller may drop a bad session by clearing pool).
        self.finish_session();
    }
}

#[async_trait]
impl WireStream for PgTcpWireStream {
    async fn poll_packets(
        &mut self,
        max_packets: usize,
    ) -> GatewayResult<Option<Vec<Vec<u8>>>> {
        if self.done {
            return Ok(None);
        }
        let max = max_packets.max(1);
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| GatewayError::Backend("pg relay session missing".into()))?;

        let mut batch = Vec::with_capacity(max.min(8));
        while batch.len() < max {
            let frame = match session.next_raw_frame().await? {
                Some(f) => f,
                None => {
                    self.done = true;
                    self.finish_session();
                    break;
                }
            };
            let is_ready = frame.first() == Some(&b'Z');
            batch.push(frame);
            if is_ready {
                self.done = true;
                self.finish_session();
                break;
            }
        }
        if batch.is_empty() {
            Ok(None)
        } else {
            Ok(Some(batch))
        }
    }
}

/// Split one complete PG message frame from `buf` without semantic parse.
fn try_split_frame(buf: &mut BytesMut) -> GatewayResult<Option<Vec<u8>>> {
    if buf.len() < 5 {
        return Ok(None);
    }
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    if len < 4 {
        return Err(GatewayError::Protocol(format!(
            "pg frame: invalid length {len}"
        )));
    }
    let total = 1 + len;
    if buf.len() < total {
        return Ok(None);
    }
    let frame = buf.split_to(total).to_vec();
    Ok(Some(frame))
}

fn format_error_fields(body: postgres_protocol::message::backend::ErrorResponseBody) -> String {
    let mut fields = body.fields();
    let mut parts = Vec::new();
    while let Ok(Some(f)) = fields.next() {
        let t = f.type_() as char;
        let v = String::from_utf8_lossy(f.value_bytes());
        parts.push(format!("{t}={v}"));
    }
    if parts.is_empty() {
        "unknown".into()
    } else {
        parts.join(" ")
    }
}

fn message_tag(msg: &Message) -> char {
    match msg {
        Message::AuthenticationOk
        | Message::AuthenticationCleartextPassword
        | Message::AuthenticationMd5Password(_)
        | Message::AuthenticationSasl(_)
        | Message::AuthenticationSaslContinue(_)
        | Message::AuthenticationSaslFinal(_) => 'R',
        Message::ParameterStatus(_) => 'S',
        Message::BackendKeyData(_) => 'K',
        Message::ReadyForQuery(_) => 'Z',
        Message::ErrorResponse(_) => 'E',
        Message::NoticeResponse(_) => 'N',
        Message::RowDescription(_) => 'T',
        Message::DataRow(_) => 'D',
        Message::CommandComplete(_) => 'C',
        Message::EmptyQueryResponse => 'I',
        _ => '?',
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a08_try_split_frame_ready_for_query() {
        // Z + len=5 + status 'I'
        let mut buf = BytesMut::from(&b"Z\x00\x00\x00\x05I"[..]);
        let frame = try_split_frame(&mut buf).unwrap().expect("frame");
        assert_eq!(frame, b"Z\x00\x00\x00\x05I");
        assert!(buf.is_empty());
        assert!(try_split_frame(&mut buf).unwrap().is_none());
    }

    #[test]
    fn a08_try_split_frame_partial() {
        let mut buf = BytesMut::from(&b"D\x00\x00\x00\x10"[..]); // need 1+16 bytes
        assert!(try_split_frame(&mut buf).unwrap().is_none());
        buf.extend_from_slice(&[0u8; 12]); // still short by 0? len=16 means 16 body incl. the 4-byte len field → total 17
        // body after tag is 16 bytes; we had 4 length bytes + 12 = 16 body → complete
        let frame = try_split_frame(&mut buf).unwrap().expect("complete");
        assert_eq!(frame.len(), 17);
        assert_eq!(frame[0], b'D');
    }

    #[test]
    fn a08_try_split_rejects_short_len() {
        let mut buf = BytesMut::from(&b"Z\x00\x00\x00\x03X"[..]);
        let err = try_split_frame(&mut buf).unwrap_err();
        assert!(matches!(err, GatewayError::Protocol(_)));
    }

    #[test]
    fn a08_query_encode_starts_with_q() {
        let mut out = BytesMut::new();
        frontend::query("SELECT 1", &mut out).unwrap();
        assert_eq!(out[0], b'Q');
    }

    #[test]
    fn a08_tcp_txn_slot_roundtrip() {
        let slot = new_tcp_txn_slot();
        assert!(slot.lock().is_none());
        // Slot type is usable as Arc shared across connector + stream.
        let slot2 = slot.clone();
        assert!(slot2.lock().is_none());
    }

    #[test]
    fn a08_idle_pool_key_and_cap() {
        let pool = PgTcpIdlePool::new(2);
        let ep = EndpointConfig {
            name: "p".into(),
            protocol: gateway_core::ProtocolKind::PostgreSql,
            address: "127.0.0.1:5432".into(),
            database: Some("db".into()),
            role: gateway_core::EndpointRole::ReadWrite,
            username: "u".into(),
            password: "x".into(),
            weight: 1,
        };
        let key = PgTcpIdlePool::pool_key(&ep, "db");
        assert_eq!(key, "127.0.0.1:5432|db|u");
        assert!(pool.is_empty());
        // put without real TCP: we only test map bookkeeping via take on empty.
        assert!(pool.take(&key).is_none());
        assert_eq!(pool.max_per_key(), 2);
    }

    #[test]
    fn a08_session_return_variants_are_constructible() {
        let slot = new_tcp_txn_slot();
        let _ = SessionReturn::Drop;
        let _ = SessionReturn::Txn(slot);
        let pool = PgTcpIdlePool::with_default_cap();
        let _ = SessionReturn::Idle {
            pool,
            key: "k".into(),
        };
    }
}
