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
    collections::BTreeMap,
    sync::Arc,
    time::Instant,
};

use conn_pool::Pool;
use gateway_core::{GatewayConfig, GatewayError, GatewayResult, ProtocolKind};
use mysql_protocol::client::conn::ClientConn;
use parking_lot::Mutex;
use pisa_error::error::{Error, ErrorKind};
use proxy::{
    factory::{
        PoolEndpointRefresh, PoolEndpointSnapshot, PoolRefresh, PoolRefresher, PoolSnapshot,
        PoolSnapshotter, SessionEntrySnapshot, SessionSnapshot, SessionSnapshotter, ShutdownHandle,
        StartSource,
    },
    listener::Listener,
    proxy::Proxy,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error};

use crate::{
    core_engine::{CoreGatewayConnection, CoreGatewayListenerPlan, CoreGatewayRuntimePlan},
    frontend::{
        mysql::MySqlFrontendProtocol,
        postgresql::PostgreSqlFrontendProtocol,
    },
    server::metrics::*,
};

const DEFAULT_CORE_POOL_SIZE: usize = 64;

#[derive(Default)]
pub struct GatewayRuntime {
    pub pisa_version: String,
    pub core_plan: Option<CoreGatewayRuntimePlan>,
    /// Listener this runtime instance serves.
    pub listener_name: Option<String>,
    pub pool_size: usize,
    pub shutdown_handle: ShutdownHandle,
    pub pool: Option<Pool<ClientConn>>,
    pub sessions: Option<SessionRegistry>,
}

impl GatewayRuntime {
    pub fn from_core_config(config: &GatewayConfig) -> GatewayResult<Self> {
        let listener_name =
            config.listeners.first().map(|listener| listener.name.as_str()).ok_or_else(|| {
                GatewayError::Configuration(
                    "gateway config must contain at least one listener".into(),
                )
            })?;
        Self::from_core_config_for_listener(config, listener_name)
    }

    pub fn from_core_config_for_listener(
        config: &GatewayConfig,
        listener_name: &str,
    ) -> GatewayResult<Self> {
        let core_plan = CoreGatewayRuntimePlan::from_config(config)?;
        if core_plan.listener(listener_name).is_none() {
            return Err(GatewayError::Configuration(format!(
                "gateway config has no listener '{}'",
                listener_name
            )));
        }

        let pool_size = DEFAULT_CORE_POOL_SIZE;
        Ok(Self {
            core_plan: Some(core_plan),
            listener_name: Some(listener_name.to_owned()),
            pool_size,
            pool: Some(Pool::<ClientConn>::new(pool_size)),
            ..Default::default()
        })
    }

    pub fn set_core_config(&mut self, config: &GatewayConfig) -> GatewayResult<()> {
        self.core_plan = Some(CoreGatewayRuntimePlan::from_config(config)?);
        Ok(())
    }

    pub fn core_plan(&self) -> Option<&CoreGatewayRuntimePlan> {
        self.core_plan.as_ref()
    }

    pub fn listener_name(&self) -> Option<&str> {
        self.listener_name.as_deref()
    }

    pub fn build_core_connection(
        &self,
        listener_name: &str,
    ) -> GatewayResult<CoreGatewayConnection> {
        let plan = self.core_plan.as_ref().ok_or_else(|| {
            GatewayError::Configuration("gateway runtime has no v2 core config".into())
        })?;
        plan.build_connection(listener_name)
    }

    fn core_listener_plan(&self) -> Option<&CoreGatewayListenerPlan> {
        let plan = self.core_plan.as_ref()?;
        if let Some(name) = self.listener_name.as_deref() {
            if let Some(listener) = plan.listener(name) {
                return Some(listener);
            }
        }
        plan.listeners().first()
    }

    fn effective_pool_size(&self) -> usize {
        if self.pool_size > 0 {
            self.pool_size
        } else {
            DEFAULT_CORE_POOL_SIZE
        }
    }

    fn configured_endpoint_addresses(&self) -> Vec<String> {
        self.core_listener_plan()
            .map(|plan| plan.endpoints().iter().map(|endpoint| endpoint.address.clone()).collect())
            .unwrap_or_default()
    }

    fn build_listener_config(&self) -> Result<Listener, Error> {
        let plan = self.core_listener_plan().ok_or_else(|| {
            runtime_configuration_error(
                "core listener plan must exist for native gateway runtime",
            )
        })?;
        Ok(Listener {
            name: plan.listener().name.clone(),
            protocol: protocol_name(&plan.listener().protocol).to_owned(),
            listen_addr: plan.listener().listen_addr.clone(),
            server_version: match plan.listener().protocol {
                ProtocolKind::MySql => "8.0".into(),
                ProtocolKind::PostgreSql => "14.0".into(),
            },
        })
    }

    pub fn pool_snapshotter(&mut self) -> PoolSnapshotter {
        let pool_size = self.effective_pool_size();
        let pool = self.pool.get_or_insert_with(|| Pool::<ClientConn>::new(pool_size)).clone();
        let configured_endpoints = self.configured_endpoint_addresses();

        Arc::new(move || build_pool_snapshot(&pool, &configured_endpoints))
    }

    pub fn pool_refresher(&mut self) -> PoolRefresher {
        let pool_size = self.effective_pool_size();
        let pool = self.pool.get_or_insert_with(|| Pool::<ClientConn>::new(pool_size)).clone();
        let configured_endpoints = self.configured_endpoint_addresses();

        Arc::new(move || refresh_pool(&pool, &configured_endpoints))
    }

    pub fn session_snapshotter(&mut self) -> SessionSnapshotter {
        let registry = self.sessions.get_or_insert_with(SessionRegistry::default).clone();

        Arc::new(move || registry.snapshot())
    }

    async fn start_core_listener(&mut self) -> Result<StartSource, Error> {
        let core_plan = self.core_plan.clone().ok_or_else(|| {
            runtime_configuration_error("gateway core runtime requires v2 core config")
        })?;
        let listener_plan = self.core_listener_plan().ok_or_else(|| {
            runtime_configuration_error("gateway core runtime requires a resolved listener plan")
        })?;

        let protocol = listener_plan.listener().protocol.clone();
        let listener_name = listener_plan.listener().name.clone();
        let listen_addr = listener_plan.listener().listen_addr.clone();
        let server_version = match protocol {
            ProtocolKind::MySql => "8.0".to_owned(),
            ProtocolKind::PostgreSql => "14.0".to_owned(),
        };
        let auth_database = listener_plan.default_database().unwrap_or_default().to_owned();
        let (auth_user, auth_password) = listener_plan
            .auth_user()
            .cloned()
            .unwrap_or_else(|| ("root".to_owned(), "root".to_owned()));
        let protocol_label = protocol_name(&protocol).to_owned();

        let mut proxy = Proxy {
            listener: Listener {
                name: listener_name.clone(),
                protocol: protocol_label.clone(),
                listen_addr,
                server_version: server_version.clone(),
            },
            app: Default::default(),
            backend_nodes: Vec::new(),
            nodes: Vec::new(),
        };

        let listener = proxy.build_listener().map_err(ErrorKind::Io)?;
        let session_registry = self.sessions.get_or_insert_with(SessionRegistry::default).clone();
        let mut start_source = StartSource::new(self.shutdown_handle.clone());

        loop {
            let socket = tokio::select! {
                _ = self.shutdown_handle.cancelled() => {
                    debug!("gateway '{}' shutdown requested", listener_name);
                    break;
                }
                accepted = proxy.accept(&listener) => {
                    accepted.map_err(ErrorKind::Io)?
                }
            };

            let core_plan = core_plan.clone();
            let listener_name = listener_name.clone();
            let server_version = server_version.clone();
            let auth_user = auth_user.clone();
            let auth_password = auth_password.clone();
            let auth_database = auth_database.clone();
            let session_registry = session_registry.clone();
            let peer_addr = socket.peer_addr().ok().map(|addr| addr.to_string());
            let protocol = protocol.clone();

            let join_handle = tokio::spawn(async move {
                match protocol {
                    ProtocolKind::PostgreSql => {
                        run_postgresql_core_session(
                            socket,
                            core_plan,
                            listener_name,
                            server_version,
                            session_registry,
                            peer_addr,
                        )
                        .await;
                    }
                    ProtocolKind::MySql => {
                        run_mysql_core_session(
                            socket,
                            core_plan,
                            listener_name,
                            server_version,
                            auth_user,
                            auth_password,
                            auth_database,
                            session_registry,
                            peer_addr,
                        )
                        .await;
                    }
                }
            });

            start_source.thread_handles.push(join_handle);
        }

        // Graceful shutdown: stop accepting, then wait for in-flight sessions.
        let session_handles = std::mem::take(&mut start_source.thread_handles);
        let outstanding = session_handles.len();
        if outstanding > 0 {
            debug!(
                "gateway '{}' waiting for {} in-flight session(s) after accept loop exit",
                listener_name, outstanding
            );
        }
        for handle in session_handles {
            if let Err(error) = handle.await {
                error!(
                    "gateway '{}' session task stopped with error: {}",
                    listener_name, error
                );
            }
        }
        debug!("gateway '{}' session drain complete", listener_name);

        Ok(start_source)
    }
}

fn runtime_configuration_error(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::Runtime(Box::new(GatewayError::Configuration(message.into()))))
}

const MAX_POSTGRESQL_FRONTEND_MESSAGE_LEN: usize = 16 * 1024 * 1024;
const MAX_MYSQL_FRONTEND_PAYLOAD_LEN: usize = 16 * 1024 * 1024;

async fn run_mysql_core_session(
    socket: tokio::net::TcpStream,
    core_plan: CoreGatewayRuntimePlan,
    listener_name: String,
    server_version: String,
    auth_user: String,
    auth_password: String,
    auth_database: String,
    session_registry: SessionRegistry,
    peer_addr: Option<String>,
) {
    use futures::{SinkExt, StreamExt};
    use mysql_protocol::{
        server::codec::{make_err_packet, CommonPacket, PacketSend},
        server::err::MySQLError,
        session::Session,
    };

    let frontend = MySqlFrontendProtocol::new(
        auth_user.clone(),
        auth_password,
        auth_database,
        server_version,
    );
    let mut framed = match frontend.handshake(socket).await {
        Ok(framed) => framed,
        Err(error) => {
            error!("mysql handshake error {:?}", error);
            return;
        }
    };

    let mut connection = match core_plan.build_connection(&listener_name) {
        Ok(connection) => connection,
        Err(error) => {
            error!("mysql core connection build error {:?}", error);
            return;
        }
    };

    let handshake_session = framed.codec_mut().get_session();
    let mut session = connection.session().clone();
    if !auth_user.is_empty() {
        session.user = Some(auth_user);
    }
    if let Some(database) = handshake_session.get_db() {
        session.database = Some(database);
    }
    if let Some(charset) = handshake_session.get_charset() {
        session.charset = Some(charset);
    }
    if let Some(autocommit) = handshake_session.get_autocommit() {
        session.autocommit = Some(autocommit == "1" || autocommit.eq_ignore_ascii_case("true"));
    }

    *connection.session_mut() = session.clone();

    let _session_registration = session_registry.register(SessionEntrySnapshot {
        id: 0,
        listener: listener_name.clone(),
        peer_addr,
        frontend_protocol: protocol_name(&ProtocolKind::MySql).to_owned(),
        database: session.database.clone(),
    });

    while let Some(frame) = framed.next().await {
        let frame = match frame {
            Ok(frame) => frame,
            Err(error) => {
                error!("mysql frontend frame read error {:?}", error);
                break;
            }
        };

        if frame.len() > MAX_MYSQL_FRONTEND_PAYLOAD_LEN {
            error!(
                "mysql frontend payload length {} exceeds limit {}",
                frame.len(),
                MAX_MYSQL_FRONTEND_PAYLOAD_LEN
            );
            break;
        }

        let terminate = frame.first() == Some(&mysql_protocol::mysql_const::COM_QUIT);

        // Command metrics are recorded inside CoreGatewayConnection::handle_frame.
        let packets = match connection.handle_frame(&frame).await {
            Ok(packets) => packets,
            Err(error) => {
                let err_info = make_err_packet(MySQLError::new(
                    1105,
                    b"HY000".to_vec(),
                    error.to_string(),
                ));
                if let Err(send_error) = framed
                    .send(PacketSend::Encode::<Box<[u8]>>(err_info[4..].into()))
                    .await
                {
                    error!("mysql error response write failed {:?}", send_error);
                }
                framed.codec_mut().reset_seq();
                continue;
            }
        };

        for packet in packets {
            if let Err(error) =
                framed.send(PacketSend::Encode::<Box<[u8]>>(packet.into())).await
            {
                error!("mysql response write error {:?}", error);
                return;
            }
        }
        framed.codec_mut().reset_seq();

        if terminate {
            break;
        }
    }
}

async fn run_postgresql_core_session(
    socket: tokio::net::TcpStream,
    core_plan: CoreGatewayRuntimePlan,
    listener_name: String,
    server_version: String,
    session_registry: SessionRegistry,
    peer_addr: Option<String>,
) {
    let frontend = PostgreSqlFrontendProtocol::new(server_version);
    let handshake = match frontend.handshake(socket).await {
        Ok(handshake) => handshake,
        Err(error) => {
            error!("postgresql handshake error {:?}", error);
            return;
        }
    };

    let mut stream = handshake.stream;
    let mut connection = match core_plan.build_connection(&listener_name) {
        Ok(connection) => connection,
        Err(error) => {
            error!("postgresql core connection build error {:?}", error);
            return;
        }
    };
    let mut session = handshake.session;
    if session.database.is_none() {
        session.database = connection.session().database.clone();
    }
    if session.backend_endpoint.is_none() {
        session.backend_endpoint = connection.session().backend_endpoint.clone();
    }
    *connection.session_mut() = session.clone();

    let _session_registration = session_registry.register(SessionEntrySnapshot {
        id: 0,
        listener: listener_name,
        peer_addr,
        frontend_protocol: protocol_name(&ProtocolKind::PostgreSql).to_owned(),
        database: session.database.clone(),
    });

    loop {
        let frame = match read_postgresql_frontend_frame(&mut stream).await {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(error) => {
                error!("postgresql frontend frame read error {:?}", error);
                break;
            }
        };
        let terminate = frame.first() == Some(&b'X');

        // Command metrics are recorded inside CoreGatewayConnection::handle_frame.
        let packets = match connection.handle_frame(&frame).await {
            Ok(packets) => packets,
            Err(error) => {
                error!("postgresql core frame handling error {:?}", error);
                break;
            }
        };

        for packet in packets {
            if let Err(error) = stream.write_all(&packet).await {
                error!("postgresql response write error {:?}", error);
                return;
            }
        }
        if let Err(error) = stream.flush().await {
            error!("postgresql response flush error {:?}", error);
            return;
        }

        if terminate {
            break;
        }
    }
}

async fn read_postgresql_frontend_frame<S>(stream: &mut S) -> GatewayResult<Option<Vec<u8>>>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0; 5];
    match stream.read_exact(&mut header).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => {
            return Err(GatewayError::Protocol(format!(
                "postgresql read frontend frame header failed: {}",
                error
            )));
        }
    }

    let len = i32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    if len < 4 {
        return Err(GatewayError::Protocol(format!(
            "invalid postgresql frontend message length {}",
            len
        )));
    }

    let len = len as usize;
    if len + 1 > MAX_POSTGRESQL_FRONTEND_MESSAGE_LEN {
        return Err(GatewayError::Protocol(format!(
            "postgresql frontend message length {} exceeds limit {}",
            len + 1,
            MAX_POSTGRESQL_FRONTEND_MESSAGE_LEN
        )));
    }

    let mut frame = vec![0; len + 1];
    frame[..5].copy_from_slice(&header);
    stream.read_exact(&mut frame[5..]).await.map_err(|error| {
        GatewayError::Protocol(format!("postgresql read frontend frame body failed: {}", error))
    })?;

    Ok(Some(frame))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GatewayMetricLabels {
    listener: String,
    service: String,
    frontend_protocol: String,
    backend_protocol: String,
    endpoint: String,
}

impl GatewayMetricLabels {
    fn from_plan(
        core_plan: &CoreGatewayRuntimePlan,
        listener_name: &str,
        backend_endpoint: Option<&str>,
    ) -> Self {
        if let Some(plan) = core_plan.listener(listener_name) {
            return Self {
                listener: plan.listener().name.clone(),
                service: plan.service().name.clone(),
                frontend_protocol: protocol_name(&plan.listener().protocol).to_owned(),
                backend_protocol: protocol_name(&plan.service().backend_protocol).to_owned(),
                endpoint: plan
                    .endpoints()
                    .iter()
                    .find(|endpoint| {
                        backend_endpoint
                            .map(|backend_endpoint| endpoint.name == backend_endpoint)
                            .unwrap_or(false)
                    })
                    .or_else(|| plan.endpoints().first())
                    .map(|endpoint| endpoint.address.clone())
                    .unwrap_or_default(),
            };
        }

        Self {
            listener: listener_name.to_owned(),
            service: listener_name.to_owned(),
            frontend_protocol: protocol_name(&ProtocolKind::PostgreSql).to_owned(),
            backend_protocol: protocol_name(&ProtocolKind::PostgreSql).to_owned(),
            endpoint: String::new(),
        }
    }

    fn values<'a>(&'a self, command_type: &'a str) -> [&'a str; 6] {
        [
            self.listener.as_str(),
            self.service.as_str(),
            self.frontend_protocol.as_str(),
            self.backend_protocol.as_str(),
            command_type,
            self.endpoint.as_str(),
        ]
    }
}

fn protocol_name(protocol: &ProtocolKind) -> &'static str {
    match protocol {
        ProtocolKind::MySql => "mysql",
        ProtocolKind::PostgreSql => "postgresql",
    }
}


fn build_pool_snapshot(pool: &Pool<ClientConn>, configured_endpoints: &[String]) -> PoolSnapshot {
    let endpoints = known_pool_endpoints(pool, configured_endpoints);

    PoolSnapshot {
        capacity: pool.capacity(),
        endpoints: endpoints
            .into_iter()
            .map(|endpoint| PoolEndpointSnapshot {
                configured: configured_endpoints.contains(&endpoint),
                factory_registered: pool.has_factory(&endpoint),
                idle_connections: pool.len(&endpoint),
                capacity: pool.capacity(),
                endpoint,
            })
            .collect(),
    }
}

fn refresh_pool(pool: &Pool<ClientConn>, configured_endpoints: &[String]) -> PoolRefresh {
    let endpoints = known_pool_endpoints(pool, configured_endpoints);

    PoolRefresh {
        endpoints: endpoints
            .into_iter()
            .map(|endpoint| {
                let idle_connections_closed = pool.refresh_endpoint(&endpoint);
                PoolEndpointRefresh {
                    configured: configured_endpoints.contains(&endpoint),
                    factory_registered: pool.has_factory(&endpoint),
                    remaining_idle_connections: pool.len(&endpoint),
                    capacity: pool.capacity(),
                    endpoint,
                    idle_connections_closed,
                }
            })
            .collect(),
    }
}

fn known_pool_endpoints(pool: &Pool<ClientConn>, configured_endpoints: &[String]) -> Vec<String> {
    let mut endpoints = configured_endpoints.to_vec();
    endpoints.extend(pool.factory_endpoints());
    endpoints.extend(pool.pooled_endpoints());
    endpoints.sort();
    endpoints.dedup();
    endpoints
}

#[derive(Clone, Default)]
pub struct SessionRegistry {
    inner: Arc<Mutex<SessionRegistryInner>>,
}

#[derive(Default)]
struct SessionRegistryInner {
    next_id: u64,
    sessions: BTreeMap<u64, SessionEntrySnapshot>,
}

impl SessionRegistry {
    pub fn register(&self, mut session: SessionEntrySnapshot) -> SessionRegistration {
        let mut inner = self.inner.lock();
        inner.next_id += 1;
        let id = inner.next_id;
        session.id = id;
        inner.sessions.insert(id, session);

        SessionRegistration { registry: self.clone(), id }
    }

    pub fn snapshot(&self) -> SessionSnapshot {
        let inner = self.inner.lock();

        SessionSnapshot { sessions: inner.sessions.values().cloned().collect() }
    }

    fn remove(&self, id: u64) {
        self.inner.lock().sessions.remove(&id);
    }
}

pub struct SessionRegistration {
    registry: SessionRegistry,
    id: u64,
}

impl Drop for SessionRegistration {
    fn drop(&mut self) {
        self.registry.remove(self.id);
    }
}


#[async_trait::async_trait]
impl proxy::factory::Proxy for GatewayRuntime {
    /// Run the accept loop until shutdown is requested, then drain sessions.
    async fn start(&mut self) -> Result<StartSource, Error> {
        if self.core_plan.is_none() {
            return Err(runtime_configuration_error(
                "gateway runtime requires v2 core config; legacy ProxyConfig startup is removed",
            ));
        }
        self.start_core_listener().await
    }

    /// Request graceful shutdown: stop accepting new connections.
    /// In-flight sessions are drained by `start()` after the accept loop exits.
    async fn stop(&mut self) -> Result<(), Error> {
        self.shutdown_handle.shutdown();
        Ok(())
    }

    fn shutdown_handle(&self) -> ShutdownHandle {
        self.shutdown_handle.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use gateway_core::{
        EndpointConfig, EndpointRole, GatewayConfig, ListenerConfig, ProtocolKind, ServiceConfig,
    };
    use proxy::factory::Proxy as _;

    use super::*;

    fn mysql_config() -> GatewayConfig {
        GatewayConfig {
            listeners: vec![ListenerConfig {
                name: "mysql-listener".into(),
                listen_addr: "127.0.0.1:3307".into(),
                protocol: ProtocolKind::MySql,
                service: "orders".into(),
                auth_policy: None,
            }],
            services: vec![ServiceConfig {
                name: "orders".into(),
                backend_protocol: ProtocolKind::MySql,
                endpoints: vec!["orders-primary".into()],
                route_policy: None,
                plugin_policies: vec![],
                translation_policy: None,
            }],
            endpoints: vec![EndpointConfig {
                name: "orders-primary".into(),
                protocol: ProtocolKind::MySql,
                address: "127.0.0.1:3306".into(),
                database: Some("orders_db".into()),
                role: EndpointRole::ReadWrite,
                username: "root".into(),
                password: "backend-secret".into(),
                weight: 1,
            }],
            ..GatewayConfig::default()
        }
    }

    fn postgresql_config() -> GatewayConfig {
        GatewayConfig {
            listeners: vec![ListenerConfig {
                name: "postgresql-listener".into(),
                listen_addr: "127.0.0.1:5433".into(),
                protocol: ProtocolKind::PostgreSql,
                service: "analytics".into(),
                auth_policy: None,
            }],
            services: vec![ServiceConfig {
                name: "analytics".into(),
                backend_protocol: ProtocolKind::PostgreSql,
                endpoints: vec!["analytics-primary".into()],
                route_policy: None,
                plugin_policies: vec![],
                translation_policy: None,
            }],
            endpoints: vec![EndpointConfig {
                name: "analytics-primary".into(),
                protocol: ProtocolKind::PostgreSql,
                address: "127.0.0.1:5432".into(),
                database: Some("analytics_db".into()),
                role: EndpointRole::ReadWrite,
                username: "postgres".into(),
                password: "backend-secret".into(),
                weight: 1,
            }],
            ..GatewayConfig::default()
        }
    }

    #[test]
    fn builds_core_connection_from_v2_config() {
        let runtime = GatewayRuntime::from_core_config(&mysql_config()).unwrap();

        let connection = runtime.build_core_connection("mysql-listener").unwrap();

        assert_eq!(connection.frontend_protocol(), ProtocolKind::MySql);
        assert_eq!(connection.backend_protocol(), ProtocolKind::MySql);
        assert_eq!(connection.session().database, Some("orders_db".into()));
        assert_eq!(runtime.listener_name(), Some("mysql-listener"));
        assert_eq!(runtime.pool_size, 64);
    }

    #[test]
    fn native_runtime_keeps_core_plan_without_legacy_nodes() {
        let runtime = GatewayRuntime::from_core_config(&mysql_config()).unwrap();
        let plan = runtime.core_plan().unwrap().listener("mysql-listener").unwrap();

        assert_eq!(plan.listener().listen_addr, "127.0.0.1:3307");
        assert_eq!(plan.default_database(), Some("orders_db"));
        assert_eq!(plan.endpoints().len(), 1);
        assert_eq!(plan.endpoints()[0].address, "127.0.0.1:3306");
        assert_eq!(runtime.configured_endpoint_addresses(), vec!["127.0.0.1:3306".to_string()]);
    }

    #[test]
    fn builds_listener_from_core_plan() {
        let runtime = GatewayRuntime::from_core_config(&mysql_config()).unwrap();
        let listener = runtime.build_listener_config().unwrap();

        assert_eq!(listener.name, "mysql-listener");
        assert_eq!(listener.listen_addr, "127.0.0.1:3307");
        assert_eq!(listener.protocol, "mysql");
        assert_eq!(listener.server_version, "8.0");
    }

    #[test]
    fn builds_postgresql_core_runtime_from_v2_config() {
        let runtime = GatewayRuntime::from_core_config_for_listener(
            &postgresql_config(),
            "postgresql-listener",
        )
        .unwrap();

        assert_eq!(runtime.listener_name(), Some("postgresql-listener"));
        assert_eq!(runtime.pool_size, 64);

        let connection = runtime.build_core_connection("postgresql-listener").unwrap();
        assert_eq!(connection.frontend_protocol(), ProtocolKind::PostgreSql);
        assert_eq!(connection.backend_protocol(), ProtocolKind::PostgreSql);
        assert_eq!(connection.session().database, Some("analytics_db".into()));
    }

    #[tokio::test]
    async fn start_rejects_runtime_without_core_plan() {
        let mut runtime = GatewayRuntime::default();
        let error = match proxy::factory::Proxy::start(&mut runtime).await {
            Ok(_) => panic!("missing core plan should fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("requires v2 core config"));
    }

    #[test]
    fn metric_labels_include_service_protocols_and_endpoint() {
        let core_plan = CoreGatewayRuntimePlan::from_config(&postgresql_config()).unwrap();

        let labels = GatewayMetricLabels::from_plan(&core_plan, "postgresql-listener", None);

        assert_eq!(
            labels,
            GatewayMetricLabels {
                listener: "postgresql-listener".into(),
                service: "analytics".into(),
                frontend_protocol: "postgresql".into(),
                backend_protocol: "postgresql".into(),
                endpoint: "127.0.0.1:5432".into(),
            }
        );
        assert_eq!(
            labels.values("QUERY"),
            [
                "postgresql-listener",
                "analytics",
                "postgresql",
                "postgresql",
                "QUERY",
                "127.0.0.1:5432",
            ]
        );
    }


    #[test]
    fn reports_missing_core_config() {
        let runtime = GatewayRuntime::default();

        let error = match runtime.build_core_connection("mysql-listener") {
            Ok(_) => panic!("runtime should require v2 core config"),
            Err(error) => error,
        };

        assert_eq!(
            error,
            GatewayError::Configuration("gateway runtime has no v2 core config".into())
        );
    }

    #[tokio::test]
    async fn stop_requests_shutdown() {
        let mut runtime = GatewayRuntime::from_core_config(&mysql_config()).unwrap();
        let shutdown_handle = runtime.shutdown_handle();

        proxy::factory::Proxy::stop(&mut runtime).await.unwrap();

        assert!(shutdown_handle.is_shutdown_requested());
    }

    #[tokio::test]
    async fn start_returns_when_shutdown_is_requested() {
        let mut config = mysql_config();
        config.listeners[0].listen_addr = "127.0.0.1:0".into();
        let mut runtime = GatewayRuntime::from_core_config(&config).unwrap();
        let shutdown_handle = runtime.shutdown_handle();
        shutdown_handle.shutdown();

        let start_source = tokio::time::timeout(
            Duration::from_secs(1),
            proxy::factory::Proxy::start(&mut runtime),
        )
        .await
        .expect("shutdown should stop the accept loop")
        .unwrap();

        assert!(start_source.shutdown_handle.is_shutdown_requested());
        assert!(start_source.thread_handles.is_empty());
    }

    #[tokio::test]
    async fn postgresql_start_returns_when_shutdown_is_requested() {
        let mut config = postgresql_config();
        config.listeners[0].listen_addr = "127.0.0.1:0".into();
        let mut runtime =
            GatewayRuntime::from_core_config_for_listener(&config, "postgresql-listener").unwrap();
        let shutdown_handle = runtime.shutdown_handle();
        shutdown_handle.shutdown();

        let start_source = tokio::time::timeout(
            Duration::from_secs(1),
            proxy::factory::Proxy::start(&mut runtime),
        )
        .await
        .expect("shutdown should stop the postgresql accept loop")
        .unwrap();

        assert!(start_source.shutdown_handle.is_shutdown_requested());
        assert!(start_source.thread_handles.is_empty());
    }

    #[test]
    fn pool_snapshot_reports_configured_endpoints_before_connections() {
        let mut runtime = GatewayRuntime::from_core_config(&mysql_config()).unwrap();
        let snapshotter = runtime.pool_snapshotter();

        let snapshot = snapshotter();

        assert_eq!(snapshot.capacity, 64);
        assert_eq!(snapshot.endpoints.len(), 1);
        assert_eq!(snapshot.endpoints[0].endpoint, "127.0.0.1:3306");
        assert!(snapshot.endpoints[0].configured);
        assert!(!snapshot.endpoints[0].factory_registered);
        assert_eq!(snapshot.endpoints[0].idle_connections, 0);
    }

    #[test]
    fn session_registry_tracks_active_sessions_until_guard_drops() {
        let registry = SessionRegistry::default();
        let registration = registry.register(SessionEntrySnapshot {
            id: 0,
            listener: "mysql-listener".to_string(),
            peer_addr: Some("127.0.0.1:52144".to_string()),
            frontend_protocol: "mysql".to_string(),
            database: Some("orders_db".to_string()),
        });

        let snapshot = registry.snapshot();
        assert_eq!(snapshot.sessions.len(), 1);
        assert_eq!(snapshot.sessions[0].id, 1);
        assert_eq!(snapshot.sessions[0].listener, "mysql-listener");
        assert_eq!(snapshot.sessions[0].peer_addr.as_deref(), Some("127.0.0.1:52144"));

        drop(registration);

        assert!(registry.snapshot().sessions.is_empty());
    }
}
