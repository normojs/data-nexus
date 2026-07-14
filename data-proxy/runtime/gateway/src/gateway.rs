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
    sync::{atomic::AtomicU32, Arc},
    time::Instant,
};

use common::ast_cache::ParserAstCache;
use conn_pool::Pool;
use endpoint::endpoint::Endpoint;
use gateway_core::{
    EndpointConfig, EndpointRole, GatewayConfig, GatewayError, GatewayResult, ProtocolKind,
};
use indexmap::IndexMap;
use loadbalance::balance::{AlgorithmName, Balance, LoadBalance};
use mysql_parser::parser::Parser;
use mysql_protocol::client::conn::ClientConn;
use parking_lot::Mutex;
use pisa_error::error::{Error, ErrorKind};
use plugin::build_phase::PluginPhase;
use proxy::{
    factory::{
        PoolEndpointRefresh, PoolEndpointSnapshot, PoolRefresh, PoolRefresher, PoolSnapshot,
        PoolSnapshotter, SessionEntrySnapshot, SessionSnapshot, SessionSnapshotter, ShutdownHandle,
        StartSource,
    },
    listener::Listener,
    proxy::{Proxy, ProxyConfig, UniSQLNode},
};
use strategy::{
    config::{
        GenericRule, NodeGroup, ReadWriteSplitting, ReadWriteSplittingRule,
        ReadWriteSplittingStatic, TargetRole,
    },
    readwritesplitting::ReadWriteEndpoint,
    route::RouteStrategy,
    sharding_rewrite::{ShardingRewrite, ShardingRewriteOutput},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error};

use crate::{
    backend::mysql::MySqlBackendConnector,
    core_engine::{CoreGatewayConnection, CoreGatewayListenerPlan, CoreGatewayRuntimePlan},
    frontend::{
        mysql::{MySqlFrontendConnection, MySqlFrontendProtocol, ReqContext},
        postgresql::PostgreSqlFrontendProtocol,
    },
    server::{metrics::*, stmt_cache::StmtCache},
    transaction_fsm::*,
};

#[derive(Default)]
pub struct GatewayRuntime {
    pub proxy_config: ProxyConfig,
    pub node_group: Option<NodeGroup>,
    pub nodes: Vec<UniSQLNode>,
    pub pisa_version: String,
    pub core_plan: Option<CoreGatewayRuntimePlan>,
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
        let listener_plan = core_plan.listener(listener_name).ok_or_else(|| {
            GatewayError::Configuration(format!(
                "gateway config has no listener '{}'",
                listener_name
            ))
        })?;
        let proxy_config = legacy_proxy_config_from_core_plan(listener_plan)?;
        let nodes = legacy_nodes_from_core_plan(listener_plan)?;
        let pool = Some(Pool::<ClientConn>::new(proxy_config.pool_size as usize));

        Ok(Self { proxy_config, nodes, core_plan: Some(core_plan), pool, ..Default::default() })
    }

    pub fn set_core_config(&mut self, config: &GatewayConfig) -> GatewayResult<()> {
        self.core_plan = Some(CoreGatewayRuntimePlan::from_config(config)?);
        Ok(())
    }

    pub fn core_plan(&self) -> Option<&CoreGatewayRuntimePlan> {
        self.core_plan.as_ref()
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
        self.core_plan.as_ref().and_then(|plan| plan.listener(&self.proxy_config.name))
    }

    fn frontend_protocol_name(&self) -> String {
        self.core_listener_plan()
            .map(|plan| protocol_name(&plan.listener().protocol).to_owned())
            .unwrap_or_else(|| self.proxy_config.node_type.clone())
    }

    fn service_name(&self) -> String {
        self.core_listener_plan()
            .map(|plan| plan.service().name.clone())
            .unwrap_or_else(|| self.proxy_config.name.clone())
    }

    #[allow(deprecated)]
    fn backend_protocol_name(&self) -> String {
        self.core_listener_plan()
            .map(|plan| protocol_name(&plan.service().backend_protocol).to_owned())
            .unwrap_or_else(|| self.proxy_config.backend_type.clone())
    }

    #[allow(deprecated)]
    fn build_listener_config(&self) -> Listener {
        Listener {
            name: self.proxy_config.name.clone(),
            node_type: self.frontend_protocol_name(),
            backend_type: self.backend_protocol_name(),
            listen_addr: self.proxy_config.listen_addr.clone(),
            server_version: self.proxy_config.server_version.clone(),
        }
    }

    // 构建路由
    fn build_route(&self) -> Result<RouteStrategy, Error> {
        let length = self.nodes.len();
        let (mut rw, mut ro) = (Vec::with_capacity(length), Vec::with_capacity(length));
        for node in &self.nodes {
            let ep = Endpoint::from(node.clone());
            match node.role {
                TargetRole::Read => ro.push(ep),
                TargetRole::ReadWrite => rw.push(ep),
            }
        }

        // 路由策略
        let strategy = if let Some(read_write_splitting) = &self.proxy_config.read_write_splitting {
            let rw_endpoint = ReadWriteEndpoint { read: ro, readwrite: rw };
            RouteStrategy::new(
                read_write_splitting.clone(),
                &self.node_group,
                rw_endpoint,
                self.proxy_config.sharding.is_some(),
            )
            .map_err(|e| Error::new(ErrorKind::Runtime(e.into())))?
        } else {
            //let rw_endpoint = ReadWriteEndpoint { read: ro, readwrite: rw };
            let simple_loadbalance = self.proxy_config.simple_loadbalance.as_ref().ok_or_else(|| {
                runtime_configuration_error(format!(
                    "gateway '{}' requires simple_loadbalance when read_write_splitting is not configured",
                    self.proxy_config.name
                ))
            })?;
            let balance_type = simple_loadbalance.balance_type.clone();
            let mut balance = Balance.build_balance(balance_type);
            rw.append(&mut ro);
            for ep in rw.into_iter() {
                balance.add(ep)
            }

            if let Some(sharding) = &self.proxy_config.sharding {
                let has_strategy = sharding.iter().all(|x| {
                    x.table_strategy.is_some()
                        || x.database_strategy.is_some()
                        || x.database_table_strategy.is_some()
                });
                if has_strategy {
                    RouteStrategy::new_with_sharding_only(balance)
                } else {
                    RouteStrategy::new_with_simple_route(balance)
                }
            } else {
                RouteStrategy::new_with_simple_route(balance)
            }
        };

        Ok(strategy)
    } // end build route

    fn build_sharding_rewriter(&self) -> Option<ShardingRewrite> {
        let config = self.proxy_config.sharding.clone()?;

        let has_strategy = config.iter().all(|x| {
            x.table_strategy.is_some()
                || x.database_strategy.is_some()
                || x.database_table_strategy.is_some()
        });
        if !has_strategy {
            return None;
        }

        let mut endpoints: Vec<Endpoint> = vec![];
        for node in &self.nodes {
            let endpoint = Endpoint::from(node.clone());
            endpoints.push(endpoint);
        }

        let has_rw = self.proxy_config.read_write_splitting.is_some();

        Some(ShardingRewrite::new(config, endpoints, self.node_group.clone(), has_rw))
    }

    pub fn pool_snapshotter(&mut self) -> PoolSnapshotter {
        let pool = self
            .pool
            .get_or_insert_with(|| Pool::<ClientConn>::new(self.proxy_config.pool_size as usize))
            .clone();
        let configured_endpoints = configured_pool_endpoints(&self.nodes);

        Arc::new(move || build_pool_snapshot(&pool, &configured_endpoints))
    }

    pub fn pool_refresher(&mut self) -> PoolRefresher {
        let pool = self
            .pool
            .get_or_insert_with(|| Pool::<ClientConn>::new(self.proxy_config.pool_size as usize))
            .clone();
        let configured_endpoints = configured_pool_endpoints(&self.nodes);

        Arc::new(move || refresh_pool(&pool, &configured_endpoints))
    }

    pub fn session_snapshotter(&mut self) -> SessionSnapshotter {
        let registry = self.sessions.get_or_insert_with(SessionRegistry::default).clone();

        Arc::new(move || registry.snapshot())
    }

    async fn start_postgresql_core(&mut self) -> Result<StartSource, Error> {
        let listener_config = self.build_listener_config();

        let mut proxy = Proxy {
            listener: listener_config,
            app: self.proxy_config.clone(),
            backend_nodes: self.nodes.clone(),
            nodes: self.nodes.clone(),
        };

        let listener = proxy.build_listener().map_err(ErrorKind::Io)?;
        let core_plan = self.core_plan.clone().ok_or_else(|| {
            runtime_configuration_error("postgresql gateway runtime requires v2 core config")
        })?;
        let listener_name = self.proxy_config.name.clone();
        let server_version = self.proxy_config.server_version.clone();
        let session_registry = self.sessions.get_or_insert_with(SessionRegistry::default).clone();
        let mut start_source = StartSource::new(self.shutdown_handle.clone());

        loop {
            let socket = tokio::select! {
                _ = self.shutdown_handle.cancelled() => {
                    debug!("postgresql gateway '{}' shutdown requested", self.proxy_config.name);
                    break;
                }
                accepted = proxy.accept(&listener) => {
                    accepted.map_err(ErrorKind::Io)?
                }
            };

            let core_plan = core_plan.clone();
            let listener_name = listener_name.clone();
            let server_version = server_version.clone();
            let session_registry = session_registry.clone();
            let peer_addr = socket.peer_addr().ok().map(|addr| addr.to_string());

            let join_handle = tokio::spawn(async move {
                run_postgresql_core_session(
                    socket,
                    core_plan,
                    listener_name,
                    server_version,
                    session_registry,
                    peer_addr,
                )
                .await;
            });

            start_source.thread_handles.push(join_handle);
        }

        Ok(start_source)
    }
}

fn runtime_configuration_error(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::Runtime(Box::new(GatewayError::Configuration(message.into()))))
}

const MAX_POSTGRESQL_FRONTEND_MESSAGE_LEN: usize = 16 * 1024 * 1024;

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
    let metric_labels = GatewayMetricLabels::from_plan(
        &core_plan,
        &listener_name,
        session.backend_endpoint.as_deref(),
    );
    let metrics_collector = MySQLServerMetricsCollector;
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
        let collect_query_metrics = frame.first() == Some(&b'Q');
        let started_at = Instant::now();

        if collect_query_metrics {
            let labels = metric_labels.values("QUERY");
            metrics_collector.set_sql_under_processing_inc(&labels);
        }

        let packets = match connection.handle_frame(&frame).await {
            Ok(packets) => packets,
            Err(error) => {
                if collect_query_metrics {
                    let labels = metric_labels.values("QUERY");
                    metrics_collector.set_sql_under_processing_dec(&labels);
                    metrics_collector.set_sql_processed_total(&labels);
                    metrics_collector
                        .set_sql_processed_duration(&labels, started_at.elapsed().as_secs_f64());
                }
                error!("postgresql core frame handling error {:?}", error);
                break;
            }
        };

        if collect_query_metrics {
            let labels = metric_labels.values("QUERY");
            metrics_collector.set_sql_under_processing_dec(&labels);
            metrics_collector.set_sql_processed_total(&labels);
            metrics_collector
                .set_sql_processed_duration(&labels, started_at.elapsed().as_secs_f64());
        }

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

#[allow(deprecated)]
fn legacy_proxy_config_from_core_plan(
    plan: &CoreGatewayListenerPlan,
) -> GatewayResult<ProxyConfig> {
    if plan.listener().protocol != plan.service().backend_protocol {
        return Err(GatewayError::Unsupported(format!(
            "{:?} listener '{}' with {:?} service '{}' cannot run in the gateway runtime yet",
            plan.listener().protocol,
            plan.listener().name,
            plan.service().backend_protocol,
            plan.service().name
        )));
    }

    let read_write_splitting = if is_read_write_splitting_policy(plan.route_policy_kind()) {
        Some(default_read_write_splitting())
    } else {
        None
    };

    Ok(ProxyConfig {
        name: plan.listener().name.clone(),
        node_type: protocol_name(&plan.listener().protocol).into(),
        backend_type: protocol_name(&plan.service().backend_protocol).into(),
        listen_addr: plan.listener().listen_addr.clone(),
        db: plan.default_database().unwrap_or_default().into(),
        pool_size: 64,
        server_version: match plan.listener().protocol {
            ProtocolKind::MySql => "8.0".into(),
            ProtocolKind::PostgreSql => "14.0".into(),
        },
        simple_loadbalance: Some(proxy::proxy::ProxySimpleLoadBalance {
            balance_type: simple_load_balance_algorithm_name(plan.route_policy_kind()),
            nodes: plan.endpoints().iter().map(|endpoint| endpoint.name.clone()).collect(),
        }),
        read_write_splitting,
        ..ProxyConfig::default()
    })
}

fn default_read_write_splitting() -> ReadWriteSplitting {
    ReadWriteSplitting {
        statics: Some(ReadWriteSplittingStatic {
            default_target: TargetRole::ReadWrite,
            rules: vec![ReadWriteSplittingRule::Generic(GenericRule {
                name: "generic-read-write".into(),
                rule_type: "generic".into(),
                algorithm_name: AlgorithmName::Random,
                node_group_name: vec![],
            })],
        }),
        dynamic: None,
    }
}

fn is_read_write_splitting_policy(kind: Option<&str>) -> bool {
    matches!(kind.map(normalize_policy_kind).as_deref(), Some("readwritesplitting"))
}

fn normalize_policy_kind(kind: &str) -> String {
    kind.chars()
        .filter(|char| *char != '_' && *char != '-')
        .flat_map(|char| char.to_lowercase())
        .collect()
}

fn simple_load_balance_algorithm_name(kind: Option<&str>) -> AlgorithmName {
    match kind.map(|kind| kind.to_ascii_lowercase()) {
        Some(kind) if kind == "round_robin" || kind == "round-robin" || kind == "roundrobin" => {
            AlgorithmName::RoundRobin
        }
        _ => AlgorithmName::Random,
    }
}

fn legacy_nodes_from_core_plan(plan: &CoreGatewayListenerPlan) -> GatewayResult<Vec<UniSQLNode>> {
    plan.endpoints().iter().map(legacy_node_from_endpoint).collect()
}

fn legacy_node_from_endpoint(endpoint: &EndpointConfig) -> GatewayResult<UniSQLNode> {
    let (host, port) = parse_endpoint_address(&endpoint.address)?;

    Ok(UniSQLNode {
        version: String::new(),
        node_type: protocol_name(&endpoint.protocol).into(),
        name: endpoint.name.clone(),
        db: endpoint.database.clone().unwrap_or_default(),
        user: endpoint.username.clone(),
        password: endpoint.password.clone(),
        host,
        port,
        weight: endpoint.weight as i64,
        role: target_role_from_endpoint_role(&endpoint.role),
    })
}

fn target_role_from_endpoint_role(role: &EndpointRole) -> TargetRole {
    match role {
        EndpointRole::Read => TargetRole::Read,
        EndpointRole::ReadWrite => TargetRole::ReadWrite,
    }
}

fn parse_endpoint_address(address: &str) -> GatewayResult<(String, u32)> {
    let (host, port) = address.rsplit_once(':').ok_or_else(|| {
        GatewayError::Configuration(format!("endpoint address '{}' must include a port", address))
    })?;
    let port = port.parse::<u32>().map_err(|error| {
        GatewayError::Configuration(format!(
            "endpoint address '{}' has invalid port: {}",
            address, error
        ))
    })?;

    Ok((host.into(), port))
}

fn protocol_name(protocol: &ProtocolKind) -> &'static str {
    match protocol {
        ProtocolKind::MySql => "mysql",
        ProtocolKind::PostgreSql => "postgresql",
    }
}

fn configured_pool_endpoints(nodes: &[UniSQLNode]) -> Vec<String> {
    let mut endpoints =
        nodes.iter().map(|node| Endpoint::from(node.clone()).addr).collect::<Vec<_>>();
    endpoints.sort();
    endpoints.dedup();
    endpoints
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

fn optional_database(database: &str) -> Option<String> {
    if database.is_empty() {
        None
    } else {
        Some(database.to_owned())
    }
}

#[async_trait::async_trait]
impl proxy::factory::Proxy for GatewayRuntime {
    // TODO：优雅退出
    // 1、关闭监听
    // 2、等待处理连接的线程结束
    // thread_handld:ThreadHandld<()>;

    // 3、退出循环

    // async fn start(&mut self, &mut start_source: StartSource) -> Result<StartSource, Error> {
    async fn start(&mut self) -> Result<StartSource, Error> {
        if self
            .core_listener_plan()
            .map(|plan| plan.listener().protocol == ProtocolKind::PostgreSql)
            .unwrap_or(false)
        {
            return self.start_postgresql_core().await;
        }

        let listener = self.build_listener_config();

        let mut proxy = Proxy {
            listener,
            app: self.proxy_config.clone(),
            backend_nodes: self.nodes.clone(),
            nodes: self.nodes.clone(),
        };

        let listener = proxy.build_listener().map_err(ErrorKind::Io)?;

        let pool = self
            .pool
            .get_or_insert_with(|| Pool::<ClientConn>::new(self.proxy_config.pool_size as usize))
            .clone();

        let ast_cache = Arc::new(Mutex::new(ParserAstCache::new()));

        // TODO: using a loadbalancer factory for different load balance strategy.
        // Currently simple_loadbalancer purely provide a list of nodes without any strategy.
        let route_strategy = Arc::new(Mutex::new(self.build_route()?));

        // Build sharding rewriter
        let rewriter = self.build_sharding_rewriter();

        let mut plugin: Option<PluginPhase> = None;
        if let Some(config) = &self.proxy_config.plugin {
            plugin = Some(PluginPhase::new(config.clone()))
        };

        // TODO: 加载配置

        let parser = Arc::new(Parser::new());
        //let metrics_collector = MySQLServerMetricsCollector::new();

        let has_rw = self.proxy_config.read_write_splitting.is_some();
        let mut start_source = StartSource::new(self.shutdown_handle.clone());
        let session_registry = self.sessions.get_or_insert_with(SessionRegistry::default).clone();

        loop {
            let socket = tokio::select! {
                _ = self.shutdown_handle.cancelled() => {
                    debug!("gateway '{}' shutdown requested", self.proxy_config.name);
                    break;
                }
                accepted = proxy.accept(&listener) => {
                    accepted.map_err(ErrorKind::Io)?
                }
            };

            let route_strategy = route_strategy.clone();
            let plugin = plugin.clone();
            let parser = parser.clone();
            let ast_cache = ast_cache.clone();
            let pool = pool.clone();
            let proxy_name = self.proxy_config.name.clone();
            let session_listener = proxy_name.clone();
            let session_registry = session_registry.clone();
            let peer_addr = socket.peer_addr().ok().map(|addr| addr.to_string());
            let frontend_protocol = self.frontend_protocol_name();
            let backend_protocol = self.backend_protocol_name();
            let service = self.service_name();
            let database = optional_database(&self.proxy_config.db);
            let rewriter = rewriter.clone();

            let frontend = MySqlFrontendProtocol::new(
                self.proxy_config.user.clone(),
                self.proxy_config.password.clone(),
                self.proxy_config.db.clone(),
                self.proxy_config.server_version.clone(),
            );

            // TODO: 根据node_type创建实例
            let mut instance = MySqlFrontendConnection::new(MySqlBackendConnector::new());
            debug!("loop start....");
            let join_handle = tokio::spawn(async move {
                let _session_registration = session_registry.register(SessionEntrySnapshot {
                    id: 0,
                    listener: session_listener,
                    peer_addr,
                    frontend_protocol: frontend_protocol.clone(),
                    database,
                });

                let framed = match frontend.handshake(socket).await {
                    Ok(framed) => framed,
                    Err(e) => {
                        error!("handshake error {:?}", e);
                        return;
                    }
                };

                let context = ReqContext {
                    fsm: TransFsm::new(pool.clone()),
                    route_strategy,
                    pool,
                    ast_cache,
                    plugin,
                    metrics_collector: MySQLServerMetricsCollector,
                    concurrency_control_rule_idx: None,
                    framed,
                    name: proxy_name,
                    service,
                    frontend_protocol,
                    backend_protocol,
                    // mysql_parser: Arc::new(()),
                    parser,
                    rewriter,
                    rewrite_outputs: ShardingRewriteOutput {
                        results: vec![],
                        agg_fields: IndexMap::new(),
                    },
                    has_readwritesplitting: has_rw,
                    stmt_cache: StmtCache::new(),
                    stmt_id: AtomicU32::new(0),
                };

                if let Err(e) = instance.run(context).await {
                    error!("instance run error {:?}", e);
                }
            }); // end  tokio::spawn

            start_source.thread_handles.push(join_handle);
        }

        Ok(start_source)
    }

    // stop proxy server
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
    }

    #[test]
    fn derives_legacy_mysql_runtime_fields_from_v2_config() {
        let runtime = GatewayRuntime::from_core_config(&mysql_config()).unwrap();

        assert_eq!(runtime.proxy_config.name, "mysql-listener");
        assert_eq!(runtime.proxy_config.listen_addr, "127.0.0.1:3307");
        assert_eq!(runtime.proxy_config.db, "orders_db");
        assert_eq!(
            runtime.proxy_config.simple_loadbalance.as_ref().unwrap().nodes,
            vec!["orders-primary".to_string()]
        );
        assert_eq!(runtime.nodes.len(), 1);
        assert_eq!(runtime.nodes[0].name, "orders-primary");
        assert_eq!(runtime.nodes[0].host, "127.0.0.1");
        assert_eq!(runtime.nodes[0].port, 3306);
        assert_eq!(runtime.nodes[0].user, "root");
    }

    #[test]
    fn derives_legacy_simple_load_balance_algorithm_from_route_policy() {
        let mut config = mysql_config();
        config.services[0].route_policy = Some("orders-balance".into());
        config.route_policies = vec![gateway_core::RoutePolicyConfig {
            name: "orders-balance".into(),
            kind: "round_robin".into(),
        }];

        let runtime = GatewayRuntime::from_core_config(&config).unwrap();

        assert!(matches!(
            runtime.proxy_config.simple_loadbalance.as_ref().unwrap().balance_type,
            AlgorithmName::RoundRobin
        ));
    }

    #[test]
    fn derives_legacy_read_write_splitting_from_v2_route_policy() {
        let mut config = mysql_config();
        config.services[0].route_policy = Some("orders-read-write".into());
        config.services[0].endpoints.push("orders-replica".into());
        config.endpoints.push(EndpointConfig {
            name: "orders-replica".into(),
            protocol: ProtocolKind::MySql,
            address: "127.0.0.1:3307".into(),
            database: Some("orders_db".into()),
            role: EndpointRole::Read,
            username: "root".into(),
            password: "backend-secret".into(),
            weight: 1,
        });
        config.route_policies = vec![gateway_core::RoutePolicyConfig {
            name: "orders-read-write".into(),
            kind: "read_write_splitting".into(),
        }];

        let runtime = GatewayRuntime::from_core_config(&config).unwrap();
        let read_write_splitting = runtime.proxy_config.read_write_splitting.as_ref().unwrap();
        let statics = read_write_splitting.statics.as_ref().unwrap();

        assert_eq!(statics.default_target, TargetRole::ReadWrite);
        assert!(matches!(
            statics.rules.first(),
            Some(ReadWriteSplittingRule::Generic(rule))
                if matches!(&rule.algorithm_name, AlgorithmName::Random)
        ));
        assert!(runtime.build_route().is_ok());
    }

    #[test]
    fn derives_legacy_endpoint_roles_from_v2_config() {
        let mut config = mysql_config();
        config.services[0].endpoints.push("orders-replica".into());
        config.endpoints.push(EndpointConfig {
            name: "orders-replica".into(),
            protocol: ProtocolKind::MySql,
            address: "127.0.0.1:3307".into(),
            database: Some("orders_db".into()),
            role: EndpointRole::Read,
            username: "root".into(),
            password: "backend-secret".into(),
            weight: 1,
        });

        let runtime = GatewayRuntime::from_core_config(&config).unwrap();

        let primary = runtime.nodes.iter().find(|node| node.name == "orders-primary").unwrap();
        let replica = runtime.nodes.iter().find(|node| node.name == "orders-replica").unwrap();
        assert_eq!(primary.role, TargetRole::ReadWrite);
        assert_eq!(replica.role, TargetRole::Read);
    }

    #[test]
    #[allow(deprecated)]
    fn derives_postgresql_runtime_fields_from_v2_config() {
        let runtime = GatewayRuntime::from_core_config_for_listener(
            &postgresql_config(),
            "postgresql-listener",
        )
        .unwrap();

        assert_eq!(runtime.proxy_config.name, "postgresql-listener");
        assert_eq!(runtime.proxy_config.node_type, "postgresql");
        assert_eq!(runtime.proxy_config.backend_type, "postgresql");
        assert_eq!(runtime.proxy_config.server_version, "14.0");
        assert_eq!(runtime.proxy_config.listen_addr, "127.0.0.1:5433");
        assert_eq!(runtime.proxy_config.db, "analytics_db");
        assert_eq!(runtime.nodes.len(), 1);
        assert_eq!(runtime.nodes[0].node_type, "postgresql");
        assert_eq!(runtime.nodes[0].port, 5432);

        let connection = runtime.build_core_connection("postgresql-listener").unwrap();
        assert_eq!(connection.frontend_protocol(), ProtocolKind::PostgreSql);
        assert_eq!(connection.backend_protocol(), ProtocolKind::PostgreSql);
    }

    #[test]
    #[allow(deprecated)]
    fn listener_protocols_prefer_core_plan_over_legacy_strings() {
        let mut runtime = GatewayRuntime::from_core_config(&mysql_config()).unwrap();
        runtime.proxy_config.node_type = "legacy-front".into();
        runtime.proxy_config.backend_type = "legacy-back".into();

        let listener = runtime.build_listener_config();

        assert_eq!(listener.node_type, "mysql");
        assert_eq!(listener.backend_type, "mysql");
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
    fn build_route_reports_missing_simple_loadbalance() {
        let mut runtime = GatewayRuntime::default();
        runtime.proxy_config.name = "broken".into();

        let error = match runtime.build_route() {
            Ok(_) => panic!("missing simple_loadbalance should be rejected"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("gateway 'broken' requires simple_loadbalance"));
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
