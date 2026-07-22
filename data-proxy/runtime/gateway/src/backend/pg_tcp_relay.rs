//! A08: PostgreSQL same-protocol TCP frame relay.
//!
//! Opens a dedicated backend TCP session (startup + auth), sends simple Query
//! **or re-encoded extended** (Parse/Bind/Execute/Sync) frames, and yields raw
//! backend messages (tag + length + body) until ReadyForQuery. Peak retained
//! bytes ≈ one read buffer / batch.
//!
//! Scope (honest):
//! - simple Query TCP relay
//! - **extended text-bind re-encode** on backend TCP (not original client Parse/Bind
//!   frames; gateway rebuilds P/B/E/S with text params)
//! - reusable session for in-transaction multi-statement passthrough
//! - **non-txn idle pool** (per address|db|user, capped + **idle TTL**) to avoid
//!   connect/auth every passthrough query
//! - cleartext / MD5 / SCRAM-SHA-256 auth; TLS via ssl_mode + optional CA pin
//! - not shared with the tokio-postgres pool (parallel lease)
//! - idle TTL + **optional active health probe** (SELECT 1) on take

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::BytesMut;
use fallible_iterator::FallibleIterator;
use gateway_core::{EndpointConfig, EndpointSslMode, GatewayError, GatewayResult, WireStream};
use parking_lot::Mutex;
use postgres_protocol::authentication::md5_hash;
use postgres_protocol::authentication::sasl::{ChannelBinding, ScramSha256, SCRAM_SHA_256};
use postgres_protocol::message::backend::Message;
use postgres_protocol::message::frontend;
use postgres_protocol::IsNull;
use postgresql_protocol::encode_ssl_request;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_native_tls::TlsStream;

/// Default max idle TCP relay sessions per pool key (A08).
pub const DEFAULT_TCP_IDLE_MAX_PER_KEY: usize = 4;
/// Default max age of an idle TCP relay session before it is discarded (A08).
pub const DEFAULT_TCP_IDLE_TTL: Duration = Duration::from_secs(30);
/// Default budget for an idle health probe (`SELECT 1`) before discarding (A08).
pub const DEFAULT_TCP_IDLE_PROBE_TIMEOUT: Duration = Duration::from_millis(500);

struct IdleEntry {
    session: PgTcpSession,
    idle_since: Instant,
}

impl std::fmt::Debug for IdleEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdleEntry")
            .field("idle_since", &self.idle_since)
            .field("session", &self.session)
            .finish()
    }
}

/// Authenticated backend socket ready for simple-query relay (reusable).
///
/// A08: may be plain TCP or TLS (`EndpointSslMode`).
pub struct PgTcpSession {
    stream: PgBackendStream,
    read_buf: BytesMut,
}

enum PgBackendStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl PgBackendStream {
    async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Plain(s) => s.write_all(data).await,
            Self::Tls(s) => s.write_all(data).await,
        }
    }

    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(buf).await,
            Self::Tls(s) => s.read(buf).await,
        }
    }
}

impl std::fmt::Debug for PgTcpSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgTcpSession")
            .field("read_buf_len", &self.read_buf.len())
            .field(
                "tls",
                &matches!(self.stream, PgBackendStream::Tls(_)),
            )
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
    /// A08: multi-Execute client-frame unit held open (no Sync sent yet).
    Hold(PgTcpTxnSlot),
}

/// Small process-local idle pool for non-transaction TCP relay sessions.
#[derive(Debug)]
pub struct PgTcpIdlePool {
    max_per_key: usize,
    idle_ttl: Duration,
    /// When true (default), run `SELECT 1` before reusing an idle session.
    health_probe: bool,
    probe_timeout: Duration,
    idle: Mutex<HashMap<String, VecDeque<IdleEntry>>>,
}

impl PgTcpIdlePool {
    pub fn new(max_per_key: usize) -> Self {
        Self::with_ttl(max_per_key, DEFAULT_TCP_IDLE_TTL)
    }

    pub fn with_ttl(max_per_key: usize, idle_ttl: Duration) -> Self {
        Self {
            max_per_key: max_per_key.max(1),
            // Zero TTL means "never reuse" (every put is immediately expired).
            idle_ttl,
            health_probe: true,
            probe_timeout: DEFAULT_TCP_IDLE_PROBE_TIMEOUT,
            idle: Mutex::new(HashMap::new()),
        }
    }

    pub fn with_default_cap() -> Arc<Self> {
        Arc::new(Self::new(DEFAULT_TCP_IDLE_MAX_PER_KEY))
    }

    /// Disable active health probe (TTL-only). Useful for unit tests without a live PG.
    pub fn without_health_probe(mut self) -> Self {
        self.health_probe = false;
        self
    }

    pub fn health_probe_enabled(&self) -> bool {
        self.health_probe
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

    pub fn idle_ttl(&self) -> Duration {
        self.idle_ttl
    }

    /// Pop the oldest non-expired session for `key`. Expired entries are dropped.
    pub fn take(&self, key: &str) -> Option<PgTcpSession> {
        let mut g = self.idle.lock();
        let q = g.get_mut(key)?;
        let now = Instant::now();
        while let Some(entry) = q.pop_front() {
            if now.duration_since(entry.idle_since) <= self.idle_ttl {
                if q.is_empty() {
                    g.remove(key);
                }
                return Some(entry.session);
            }
            // else: expired — drop and continue
        }
        g.remove(key);
        None
    }

    pub fn put(&self, key: String, session: PgTcpSession) {
        self.put_at(key, session, Instant::now());
    }

    fn put_at(&self, key: String, session: PgTcpSession, idle_since: Instant) {
        let mut g = self.idle.lock();
        // Drop expired tails before inserting.
        if let Some(q) = g.get_mut(&key) {
            let now = Instant::now();
            while let Some(front) = q.front() {
                if now.duration_since(front.idle_since) > self.idle_ttl {
                    let _ = q.pop_front();
                } else {
                    break;
                }
            }
        }
        let q = g.entry(key).or_default();
        if q.len() >= self.max_per_key {
            // Drop oldest overflow.
            let _ = q.pop_front();
        }
        q.push_back(IdleEntry {
            session,
            idle_since,
        });
    }

    /// Test-only: insert with a custom idle_since (no real TCP required if session
    /// is never used for IO — only for pool bookkeeping tests).
    #[cfg(test)]
    fn put_for_test(&self, key: String, session: PgTcpSession, idle_since: Instant) {
        self.put_at(key, session, idle_since);
    }

    /// Drop all expired idle sessions across keys (best-effort housekeeping).
    pub fn purge_expired(&self) -> usize {
        let mut g = self.idle.lock();
        let now = Instant::now();
        let mut dropped = 0usize;
        g.retain(|_, q| {
            let before = q.len();
            q.retain(|e| now.duration_since(e.idle_since) <= self.idle_ttl);
            dropped += before.saturating_sub(q.len());
            !q.is_empty()
        });
        dropped
    }

    pub async fn take_or_connect(
        self: &Arc<Self>,
        endpoint: &EndpointConfig,
        database: &str,
    ) -> GatewayResult<PgTcpSession> {
        let key = Self::pool_key(endpoint, database);
        // Try a few idle candidates; discard unhealthy / timed-out ones.
        for _ in 0..self.max_per_key {
            let Some(sess) = self.take(&key) else {
                break;
            };
            if !self.health_probe {
                return Ok(sess);
            }
            match sess.health_check(self.probe_timeout).await {
                Ok(sess) => return Ok(sess),
                Err(e) => {
                    tracing::debug!(
                        target: "data_nexus::gateway",
                        error = %e,
                        pool_key = %key,
                        "A08 idle TCP health probe failed; discarding session"
                    );
                    // sess dropped
                }
            }
        }
        PgTcpSession::connect(endpoint, database).await
    }
}

impl PgTcpSession {
    pub async fn connect(
        endpoint: &EndpointConfig,
        database: &str,
    ) -> GatewayResult<Self> {
        let tcp = TcpStream::connect(&endpoint.address)
            .await
            .map_err(|e| GatewayError::Backend(format!("pg tcp connect: {e}")))?;
        tcp.set_nodelay(true)
            .map_err(|e| GatewayError::Backend(format!("pg tcp nodelay: {e}")))?;

        let stream = maybe_upgrade_tls(tcp, endpoint).await?;

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
        let mut session = Self {
            stream,
            read_buf: BytesMut::with_capacity(16 * 1024),
        };
        session
            .stream
            .write_all(&out)
            .await
            .map_err(|e| GatewayError::Backend(format!("pg startup write: {e}")))?;
        session
            .authenticate(&endpoint.username, &endpoint.password)
            .await?;
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
            stop_before_ready: false,
        })
    }

    /// A08: forward original client extended frames then Sync; stream until ReadyForQuery.
    ///
    /// `client_frames` should be the raw client Parse/Bind[/Describe]/ies]/Execute
    /// messages for one unit. This method appends Sync so the backend unit completes.
    /// Unlike re-encoded text-bind, these bytes are the **client's** frames (true
    /// original-frame TCP relay for that unit). Multi-Execute pages that need hold
    /// still use Streaming elsewhere; this path is one-shot per collected unit.
    pub async fn client_frames_relay_into(
        mut self,
        client_frames: &[Vec<u8>],
        return_to: SessionReturn,
    ) -> GatewayResult<PgTcpWireStream> {
        if client_frames.is_empty() {
            return Err(GatewayError::Backend(
                "pg client frame relay: empty frame list".into(),
            ));
        }
        let mut out = BytesMut::with_capacity(
            client_frames.iter().map(|f| f.len()).sum::<usize>() + 32,
        );
        // If the client unit omitted Describe, inject Describe(portal) after Bind so
        // multi-column SELECTs still emit RowDescription. Portal name is taken from
        // the Bind frame (empty string = unnamed).
        let mut saw_describe = false;
        let mut bound_portal: Option<String> = None;
        for f in client_frames {
            let tag = f.first().copied();
            if tag == Some(b'D') {
                saw_describe = true;
            }
            if tag == Some(b'B') && f.len() > 5 {
                // Bind body starts at offset 5: portal cstring.
                if let Some(end) = f[5..].iter().position(|&b| b == 0) {
                    let name = String::from_utf8_lossy(&f[5..5 + end]).into_owned();
                    bound_portal = Some(name);
                }
            }
            if bound_portal.is_some() && !saw_describe && tag == Some(b'E') {
                let portal = bound_portal.as_deref().unwrap_or("");
                frontend::describe(b'P', portal, &mut out).map_err(|e| {
                    GatewayError::Backend(format!("pg client-frame describe inject: {e}"))
                })?;
                saw_describe = true;
            }
            out.extend_from_slice(f);
        }
        if bound_portal.is_some() && !saw_describe {
            let portal = bound_portal.as_deref().unwrap_or("");
            frontend::describe(b'P', portal, &mut out).map_err(|e| {
                GatewayError::Backend(format!("pg client-frame describe inject: {e}"))
            })?;
        }
        frontend::sync(&mut out);
        self.stream
            .write_all(&out)
            .await
            .map_err(|e| GatewayError::Backend(format!("pg client frame write: {e}")))?;
        Ok(PgTcpWireStream {
            session: Some(self),
            return_to,
            done: false,
            stop_before_ready: false,
        })
    }

    /// A08: client-frame unit without Sync — for multi-Execute pages (PortalSuspended).
    ///
    /// Streams until CommandComplete / PortalSuspended / ErrorResponse, then holds
    /// the TCP session (use [`SessionReturn::Hold`]). Caller must later send more
    /// Execute frames or Sync via the held session.
    pub async fn client_frames_relay_hold_into(
        mut self,
        client_frames: &[Vec<u8>],
        return_to: SessionReturn,
    ) -> GatewayResult<PgTcpWireStream> {
        if client_frames.is_empty() {
            return Err(GatewayError::Backend(
                "pg client frame hold relay: empty frame list".into(),
            ));
        }
        let mut out = BytesMut::with_capacity(
            client_frames.iter().map(|f| f.len()).sum::<usize>() + 32,
        );
        let mut saw_describe = false;
        let mut bound_portal: Option<String> = None;
        for f in client_frames {
            let tag = f.first().copied();
            if tag == Some(b'D') {
                saw_describe = true;
            }
            if tag == Some(b'B') && f.len() > 5 {
                if let Some(end) = f[5..].iter().position(|&b| b == 0) {
                    let name = String::from_utf8_lossy(&f[5..5 + end]).into_owned();
                    bound_portal = Some(name);
                }
            }
            if bound_portal.is_some() && !saw_describe && tag == Some(b'E') {
                let portal = bound_portal.as_deref().unwrap_or("");
                frontend::describe(b'P', portal, &mut out).map_err(|e| {
                    GatewayError::Backend(format!("pg client-frame describe inject: {e}"))
                })?;
                saw_describe = true;
            }
            out.extend_from_slice(f);
        }
        if bound_portal.is_some() && !saw_describe {
            let portal = bound_portal.as_deref().unwrap_or("");
            frontend::describe(b'P', portal, &mut out).map_err(|e| {
                GatewayError::Backend(format!("pg client-frame describe inject: {e}"))
            })?;
        }
        self.stream
            .write_all(&out)
            .await
            .map_err(|e| GatewayError::Backend(format!("pg client frame hold write: {e}")))?;
        // Flush so PortalSuspended / CommandComplete is delivered without Sync.
        let mut flush_buf = BytesMut::with_capacity(5);
        frontend::flush(&mut flush_buf);
        self.stream
            .write_all(&flush_buf)
            .await
            .map_err(|e| GatewayError::Backend(format!("pg client frame hold flush: {e}")))?;
        Ok(PgTcpWireStream {
            session: Some(self),
            return_to,
            done: false,
            stop_before_ready: true,
        })
    }

    /// A08: send only client Execute frame(s) on a held session (multi-Execute page).
    pub async fn client_execute_relay_hold_into(
        mut self,
        execute_frames: &[Vec<u8>],
        return_to: SessionReturn,
    ) -> GatewayResult<PgTcpWireStream> {
        if execute_frames.is_empty() {
            return Err(GatewayError::Backend(
                "pg client execute hold relay: empty".into(),
            ));
        }
        let mut out = BytesMut::with_capacity(execute_frames.iter().map(|f| f.len()).sum::<usize>() + 5);
        for f in execute_frames {
            out.extend_from_slice(f);
        }
        frontend::flush(&mut out);
        self.stream
            .write_all(&out)
            .await
            .map_err(|e| GatewayError::Backend(format!("pg client execute write: {e}")))?;
        Ok(PgTcpWireStream {
            session: Some(self),
            return_to,
            done: false,
            stop_before_ready: true,
        })
    }

    /// A08: Sync on held client-frame session → stream until ReadyForQuery.
    pub async fn client_sync_relay_into(
        mut self,
        return_to: SessionReturn,
    ) -> GatewayResult<PgTcpWireStream> {
        let mut out = BytesMut::with_capacity(5);
        frontend::sync(&mut out);
        self.stream
            .write_all(&out)
            .await
            .map_err(|e| GatewayError::Backend(format!("pg client sync write: {e}")))?;
        Ok(PgTcpWireStream {
            session: Some(self),
            return_to,
            done: false,
            stop_before_ready: false,
        })
    }

    /// A08: re-encode extended text-bind unit on backend TCP (Parse/Bind/Describe/Execute/Sync).
    ///
    /// Uses **unnamed** statement/portal so idle pool reuse stays safe. Params are
    /// already text-serializable (`None` = SQL NULL). Empty result_formats ⇒ all text
    /// columns. Describe(portal) is included so RowDescription is available without a
    /// separate client Describe. This is **not** original client frame relay — gateway
    /// rebuilds P/B/D/E/S. Callers serving a client extended unit should strip backend
    /// ParseComplete/BindComplete/ReadyForQuery (`1`/`2`/`Z`).
    pub async fn extended_text_bind_relay_into(
        mut self,
        sql: &str,
        text_params: &[Option<Vec<u8>>],
        return_to: SessionReturn,
    ) -> GatewayResult<PgTcpWireStream> {
        let mut out = BytesMut::with_capacity(64 + sql.len() + text_params.len() * 16);
        // Unnamed statement; no forced param OIDs (backend infers / text).
        frontend::parse("", sql, std::iter::empty::<u32>(), &mut out)
            .map_err(|e| GatewayError::Backend(format!("pg extended parse encode: {e}")))?;
        let formats = std::iter::repeat(0i16).take(text_params.len());
        let values = text_params.iter().map(|p| p.as_ref());
        frontend::bind(
            "",
            "",
            formats,
            values,
            |v, buf| {
                match v {
                    None => Ok(IsNull::Yes),
                    Some(bytes) => {
                        buf.extend_from_slice(bytes);
                        Ok(IsNull::No)
                    }
                }
            },
            // Empty ⇒ all result columns use text format (not "only first column").
            std::iter::empty::<i16>(),
            &mut out,
        )
        .map_err(|_e| {
            GatewayError::Backend("pg extended bind encode failed".into())
        })?;
        // Describe portal so Execute path yields RowDescription for multi-column SELECTs
        // even when the client skipped Describe (common in raw-frame smokes).
        frontend::describe(b'P', "", &mut out)
            .map_err(|e| GatewayError::Backend(format!("pg extended describe encode: {e}")))?;
        frontend::execute("", 0, &mut out)
            .map_err(|e| GatewayError::Backend(format!("pg extended execute encode: {e}")))?;
        frontend::sync(&mut out);
        self.stream
            .write_all(&out)
            .await
            .map_err(|e| GatewayError::Backend(format!("pg extended write: {e}")))?;
        Ok(PgTcpWireStream {
            session: Some(self),
            return_to,
            done: false,
            stop_before_ready: false,
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

    /// A08: lightweight health probe for idle reuse — `SELECT 1` until ReadyForQuery.
    ///
    /// Fails on ErrorResponse, timeout, or unexpected close. Always drains to
    /// Ready on success so the session is reusable for the next real query.
    pub async fn health_check(mut self, budget: Duration) -> GatewayResult<Self> {
        match timeout(budget, self.health_check_inner()).await {
            Ok(Ok(())) => Ok(self),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(GatewayError::Backend(
                "pg tcp health probe timed out".into(),
            )),
        }
    }

    async fn health_check_inner(&mut self) -> GatewayResult<()> {
        let mut out = BytesMut::new();
        frontend::query("SELECT 1", &mut out)
            .map_err(|e| GatewayError::Backend(format!("pg health query encode: {e}")))?;
        self.stream
            .write_all(&out)
            .await
            .map_err(|e| GatewayError::Backend(format!("pg health query write: {e}")))?;

        let mut saw_ready = false;
        while let Some(frame) = self.next_raw_frame().await? {
            match frame.first().copied() {
                Some(b'E') => {
                    return Err(GatewayError::Backend(
                        "pg tcp health probe: ErrorResponse".into(),
                    ));
                }
                Some(b'Z') => {
                    saw_ready = true;
                    break;
                }
                Some(_) => {}
                None => {
                    return Err(GatewayError::Backend(
                        "pg tcp health probe: empty frame".into(),
                    ));
                }
            }
        }
        if !saw_ready {
            return Err(GatewayError::Backend(
                "pg tcp health probe: closed before ReadyForQuery".into(),
            ));
        }
        Ok(())
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

/// Progressive wire frames for one backend response unit.
///
/// Default: ends at ReadyForQuery. With `stop_before_ready`, ends after
/// CommandComplete / PortalSuspended / ErrorResponse without consuming Z
/// (multi-Execute client-frame hold — session returned via Hold slot).
pub struct PgTcpWireStream {
    session: Option<PgTcpSession>,
    return_to: SessionReturn,
    done: bool,
    /// When true, do not wait for / include ReadyForQuery; stop after C/s/E.
    stop_before_ready: bool,
}

impl PgTcpWireStream {
    fn finish_session(&mut self) {
        if let Some(sess) = self.session.take() {
            match &self.return_to {
                SessionReturn::Drop => {
                    // drop → TCP close
                }
                SessionReturn::Txn(slot) | SessionReturn::Hold(slot) => {
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
            let tag = frame.first().copied();
            let is_ready = tag == Some(b'Z');
            if self.stop_before_ready && is_ready {
                // Should not normally arrive (no Sync); leave Z for next Sync drain.
                // Put frame back by not supporting unread — Sync path expects clean.
                // If Z appears early, treat as unit end and include it.
                batch.push(frame);
                self.done = true;
                self.finish_session();
                break;
            }
            batch.push(frame);
            if self.stop_before_ready {
                // End page at CommandComplete / PortalSuspended / ErrorResponse.
                if matches!(tag, Some(b'C' | b's' | b'E')) {
                    self.done = true;
                    self.finish_session();
                    break;
                }
            } else if is_ready {
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


/// A08: optional TLS upgrade after TCP connect (PostgreSQL SSLRequest).
///
/// `disable` → plain. `prefer` → try SSL, fall back to plain on server "N".
/// `require` → must get "S" and complete TLS handshake.
///
/// Certificate policy comes from `endpoint.ssl_accept_invalid_certs` /
/// `endpoint.ssl_ca_file` (see [`crate::backend::pg_tls`]).
async fn maybe_upgrade_tls(
    mut tcp: TcpStream,
    endpoint: &EndpointConfig,
) -> GatewayResult<PgBackendStream> {
    let mode = endpoint.ssl_mode;
    if !mode.wants_tls() {
        return Ok(PgBackendStream::Plain(tcp));
    }
    let req = encode_ssl_request();
    tcp.write_all(&req)
        .await
        .map_err(|e| GatewayError::Backend(format!("pg SSLRequest write: {e}")))?;
    let mut ans = [0u8; 1];
    tcp.read_exact(&mut ans)
        .await
        .map_err(|e| GatewayError::Backend(format!("pg SSLRequest read: {e}")))?;
    match ans[0] {
        b'S' => {
            let connector = crate::backend::pg_tls::build_native_tls_connector(endpoint)?;
            let connector = tokio_native_tls::TlsConnector::from(connector);
            let host = crate::backend::pg_tls::tls_server_name(endpoint);
            let tls = connector
                .connect(&host, tcp)
                .await
                .map_err(|e| GatewayError::Backend(format!("pg tls handshake: {e}")))?;
            Ok(PgBackendStream::Tls(Box::new(tls)))
        }
        b'N' => {
            if mode.requires_tls() {
                return Err(GatewayError::Backend(
                    "postgresql endpoint ssl_mode=require but server refused SSL".into(),
                ));
            }
            Ok(PgBackendStream::Plain(tcp))
        }
        other => Err(GatewayError::Backend(format!(
            "postgresql SSLRequest unexpected response 0x{other:02x}"
        ))),
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
        let pool = PgTcpIdlePool::new(2).without_health_probe();
        let ep = EndpointConfig {
            name: "p".into(),
            protocol: gateway_core::ProtocolKind::PostgreSql,
            address: "127.0.0.1:5432".into(),
            database: Some("db".into()),
            role: gateway_core::EndpointRole::ReadWrite,
            username: "u".into(),
            password: "x".into(),
            weight: 1,
            ssl_mode: Default::default(),
            ssl_ca_file: None,
            ssl_accept_invalid_certs: true,
        };
        let key = PgTcpIdlePool::pool_key(&ep, "db");
        assert_eq!(key, "127.0.0.1:5432|db|u");
        assert!(pool.is_empty());
        assert!(pool.take(&key).is_none());
        assert_eq!(pool.max_per_key(), 2);
        assert_eq!(pool.idle_ttl(), DEFAULT_TCP_IDLE_TTL);
        assert!(!pool.health_probe_enabled());
    }

    #[test]
    fn a08_idle_pool_ttl_expires_entries() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            async fn dummy_session() -> PgTcpSession {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                let accept = tokio::spawn(async move {
                    let _ = listener.accept().await;
                });
                let stream = TcpStream::connect(addr).await.unwrap();
                let _ = accept.await;
                PgTcpSession {
                    stream: PgBackendStream::Plain(stream),
                    read_buf: BytesMut::new(),
                }
            }

            // Zero TTL: put then take must miss (immediately expired).
            let pool = PgTcpIdlePool::with_ttl(2, Duration::from_secs(0)).without_health_probe();
            pool.put_for_test("k".into(), dummy_session().await, Instant::now());
            assert!(
                pool.take("k").is_none(),
                "zero TTL must not reuse idle sessions"
            );

            // Non-zero TTL: fresh entry is reusable; aged entry is dropped.
            let pool2 = PgTcpIdlePool::with_ttl(2, Duration::from_secs(60)).without_health_probe();
            pool2.put_for_test("k".into(), dummy_session().await, Instant::now());
            assert!(pool2.take("k").is_some());
            assert!(pool2.is_empty());

            let aged = Instant::now() - Duration::from_secs(120);
            pool2.put_for_test("k".into(), dummy_session().await, aged);
            assert!(
                pool2.take("k").is_none(),
                "entry older than TTL must be discarded"
            );

            // purge_expired drops without take
            pool2.put_for_test("k".into(), dummy_session().await, aged);
            assert_eq!(pool2.purge_expired(), 1);
            assert!(pool2.is_empty());
        });
    }

    #[test]
    fn a08_health_check_fails_on_dead_socket() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let accept = tokio::spawn(async move {
                let (s, _) = listener.accept().await.unwrap();
                // Close immediately — probe write/read must fail.
                drop(s);
            });
            let stream = TcpStream::connect(addr).await.unwrap();
            let _ = accept.await;
            let sess = PgTcpSession {
                stream: PgBackendStream::Plain(stream),
                read_buf: BytesMut::new(),
            };
            let err = sess
                .health_check(Duration::from_millis(200))
                .await
                .expect_err("dead peer");
            let msg = err.to_string();
            assert!(
                msg.contains("health") || msg.contains("closed") || msg.contains("tcp"),
                "err={msg}"
            );
        });
    }

    #[test]
    fn a08_session_return_variants_are_constructible() {
        let slot = new_tcp_txn_slot();
        let _ = SessionReturn::Drop;
        let _ = SessionReturn::Txn(slot);
        let pool = PgTcpIdlePool::with_default_cap();
        assert_eq!(pool.idle_ttl(), DEFAULT_TCP_IDLE_TTL);
        assert!(pool.health_probe_enabled());
        let _ = SessionReturn::Idle {
            pool,
            key: "k".into(),
        };
    }

    #[test]
    fn a08_ssl_mode_helpers() {
        use gateway_core::EndpointSslMode;
        assert!(!EndpointSslMode::Disable.wants_tls());
        assert!(EndpointSslMode::Prefer.wants_tls());
        assert!(EndpointSslMode::Require.requires_tls());
        assert_eq!(EndpointSslMode::Disable.as_str(), "disable");
        assert_eq!(EndpointSslMode::Prefer.as_str(), "prefer");
        assert_eq!(EndpointSslMode::Require.as_str(), "require");
    }

    #[tokio::test]
    async fn a08_ssl_prefer_falls_back_when_server_rejects() {
        use gateway_core::EndpointSslMode;
        // Fake server: accept TCP, answer SSLRequest with 'N', then close.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 8];
            use tokio::io::AsyncReadExt;
            let _ = s.read_exact(&mut buf).await;
            use tokio::io::AsyncWriteExt;
            let _ = s.write_all(b"N").await;
            // leave open briefly for startup attempt or just drop
            drop(s);
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut ep = endpoint();
        ep.ssl_mode = EndpointSslMode::Prefer;
        ep.address = addr.to_string();
        let stream = maybe_upgrade_tls(tcp, &ep).await.unwrap();
        assert!(matches!(stream, PgBackendStream::Plain(_)));
        let _ = server.await;
    }

    #[tokio::test]
    async fn a08_ssl_require_fails_when_server_rejects() {
        use gateway_core::EndpointSslMode;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 8];
            use tokio::io::AsyncReadExt;
            let _ = s.read_exact(&mut buf).await;
            use tokio::io::AsyncWriteExt;
            let _ = s.write_all(b"N").await;
            drop(s);
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut ep = endpoint();
        ep.ssl_mode = EndpointSslMode::Require;
        ep.address = addr.to_string();
        let err = maybe_upgrade_tls(tcp, &ep).await;
        assert!(err.is_err(), "require must fail");
        let msg = err.err().unwrap().to_string();
        assert!(msg.contains("require") || msg.contains("refused"), "err={msg}");
        let _ = server.await;
    }

    fn endpoint() -> EndpointConfig {
        EndpointConfig {
            name: "analytics-primary".into(),
            protocol: gateway_core::ProtocolKind::PostgreSql,
            address: "127.0.0.1:5432".into(),
            database: Some("analytics".into()),
            role: gateway_core::EndpointRole::ReadWrite,
            username: "postgres".into(),
            password: "postgres".into(),
            weight: 1,
            ssl_mode: Default::default(),
            ssl_ca_file: None,
            ssl_accept_invalid_certs: true,
        }
    }
}
