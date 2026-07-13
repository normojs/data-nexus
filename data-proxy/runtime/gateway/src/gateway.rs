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

use std::sync::{atomic::AtomicU32, Arc};

use common::ast_cache::ParserAstCache;
use conn_pool::Pool;
use endpoint::endpoint::Endpoint;
use gateway_core::{EndpointConfig, EndpointRole, GatewayConfig, GatewayError, ProtocolKind};
use indexmap::IndexMap;
use loadbalance::balance::{AlgorithmName, Balance, LoadBalance};
use mysql_parser::parser::Parser;
use mysql_protocol::client::conn::ClientConn;
use parking_lot::Mutex;
use pisa_error::error::{Error, ErrorKind};
use plugin::build_phase::PluginPhase;
use proxy::{
    factory::StartSource,
    listener::Listener,
    proxy::{endpoint_from_unisql_node, Proxy, ProxyConfig, ProxySimpleLoadBalance, UniSQLNode},
};
use strategy::{
    config::{NodeGroup, TargetRole},
    readwritesplitting::ReadWriteEndpoint,
    route::RouteStrategy,
    sharding_rewrite::{ShardingRewrite, ShardingRewriteOutput},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::watch,
    task::JoinHandle,
};
use tracing::{debug, error};

use crate::{
    backend::mysql::MySqlBackendConnector,
    core_engine::{CoreGatewayConnection, CoreGatewayListenerPlan, CoreGatewayRuntimePlan},
    frontend::{
        mysql::{MySqlFrontendConnection, MySqlFrontendProtocol, ReqContext},
        postgresql::{PostgreSqlFrontendProtocol, PostgreSqlStartupAction},
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
    pub gateway_config: Option<GatewayConfig>,
    pub runtime_plan: Option<CoreGatewayRuntimePlan>,
    shutdown_tx: Option<watch::Sender<bool>>,
    connection_handles: Vec<JoinHandle<()>>,
}

#[derive(Clone)]
pub struct GatewayRuntimeShutdownHandle {
    sender: watch::Sender<bool>,
}

impl GatewayRuntimeShutdownHandle {
    pub fn shutdown(&self) {
        let _ = self.sender.send(true);
    }
}

struct LegacyMySqlRuntimeConfig {
    proxy_config: ProxyConfig,
    nodes: Vec<UniSQLNode>,
}

struct RuntimeListenerConfig {
    proxy_config: ProxyConfig,
    nodes: Vec<UniSQLNode>,
}

impl RuntimeListenerConfig {
    fn from_listener_plan(
        listener_plan: &CoreGatewayListenerPlan,
        pisa_version: &str,
    ) -> Result<Self, GatewayError> {
        let auth_user = listener_plan.auth_policy().and_then(|policy| policy.users.first());
        let database = listener_plan.default_database().unwrap_or_default().to_string();
        let endpoint_names = listener_plan
            .endpoints()
            .iter()
            .map(|endpoint| endpoint.name.clone())
            .collect::<Vec<_>>();

        let proxy_config = ProxyConfig {
            name: listener_plan.listener().name.clone(),
            node_type: listener_plan.listener().protocol.clone(),
            listen_addr: listener_plan.listener().listen_addr.clone(),
            user: auth_user.map(|user| user.username.clone()).unwrap_or_default(),
            password: auth_user.map(|user| user.password.clone()).unwrap_or_default(),
            db: database,
            simple_loadbalance: Some(ProxySimpleLoadBalance {
                balance_type: AlgorithmName::Random,
                nodes: endpoint_names,
            }),
            ..ProxyConfig::default()
        };

        let nodes = listener_plan
            .endpoints()
            .iter()
            .map(|endpoint| endpoint_to_legacy_node(endpoint, pisa_version))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { proxy_config, nodes })
    }
}

impl LegacyMySqlRuntimeConfig {
    fn from_listener_plan(
        listener_plan: &CoreGatewayListenerPlan,
        pisa_version: &str,
    ) -> Result<Self, GatewayError> {
        ensure_legacy_mysql_listener(listener_plan)?;
        let config = RuntimeListenerConfig::from_listener_plan(listener_plan, pisa_version)?;

        Ok(Self { proxy_config: config.proxy_config, nodes: config.nodes })
    }
}

impl GatewayRuntime {
    pub fn from_legacy(
        proxy_config: ProxyConfig,
        node_group: Option<NodeGroup>,
        nodes: Vec<UniSQLNode>,
        pisa_version: String,
    ) -> Self {
        Self {
            proxy_config,
            node_group,
            nodes,
            pisa_version,
            gateway_config: None,
            runtime_plan: None,
            shutdown_tx: None,
            connection_handles: Vec::new(),
        }
    }

    pub fn from_gateway_config(
        gateway_config: GatewayConfig,
        listener_name: &str,
        pisa_version: String,
    ) -> Result<Self, GatewayError> {
        let runtime_plan = CoreGatewayRuntimePlan::from_config(&gateway_config)?;
        let listener_plan = runtime_plan.listener(listener_name).ok_or_else(|| {
            GatewayError::Configuration(format!(
                "gateway listener '{}' was not found",
                listener_name
            ))
        })?;

        ensure_supported_runtime_listener(listener_plan)?;

        let listener_config = if listener_plan.listener().protocol == ProtocolKind::MySql
            && listener_plan.service().backend_protocol == ProtocolKind::MySql
        {
            let legacy_mysql_config =
                LegacyMySqlRuntimeConfig::from_listener_plan(listener_plan, &pisa_version)?;
            RuntimeListenerConfig {
                proxy_config: legacy_mysql_config.proxy_config,
                nodes: legacy_mysql_config.nodes,
            }
        } else {
            RuntimeListenerConfig::from_listener_plan(listener_plan, &pisa_version)?
        };

        Ok(Self {
            proxy_config: listener_config.proxy_config,
            node_group: None,
            nodes: listener_config.nodes,
            pisa_version,
            gateway_config: Some(gateway_config),
            runtime_plan: Some(runtime_plan),
            shutdown_tx: None,
            connection_handles: Vec::new(),
        })
    }

    pub fn shutdown_handle(&mut self) -> GatewayRuntimeShutdownHandle {
        let sender = self.shutdown_tx.get_or_insert_with(|| {
            let (sender, _) = watch::channel(false);
            sender
        });

        GatewayRuntimeShutdownHandle { sender: sender.clone() }
    }

    // 构建路由
    fn build_route(&self) -> Result<RouteStrategy, Error> {
        let length = self.nodes.len();
        let (mut rw, mut ro) = (Vec::with_capacity(length), Vec::with_capacity(length));
        for node in &self.nodes {
            let ep = endpoint_from_unisql_node(node).map_err(runtime_invalid_input)?;
            match node.role {
                TargetRole::Read => ro.push(ep),
                TargetRole::ReadWrite => rw.push(ep),
            }
        }

        // 路由策略
        let read_write_splitting = self.proxy_config.read_write_splitting.as_ref();
        let sharding = self.proxy_config.sharding.as_ref();

        let strategy = if let Some(config) = read_write_splitting {
            let rw_endpoint = ReadWriteEndpoint { read: ro, readwrite: rw };
            RouteStrategy::new(config.clone(), &self.node_group, rw_endpoint, sharding.is_some())
                .map_err(|e| Error::new(ErrorKind::Runtime(e.into())))?
        } else {
            //let rw_endpoint = ReadWriteEndpoint { read: ro, readwrite: rw };
            let balance_type = self
                .proxy_config
                .simple_loadbalance
                .as_ref()
                .ok_or_else(|| {
                    runtime_invalid_input(format!(
                        "proxy '{}' requires simple_loadbalance when read_write_splitting is not configured",
                        self.proxy_config.name
                    ))
                })?
                .balance_type
                .clone();
            let mut balance = Balance.build_balance(balance_type);
            rw.append(&mut ro);
            for ep in rw.into_iter() {
                balance.add(ep)
            }

            if let Some(sharding) = sharding {
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

    fn build_sharding_rewriter(&self) -> Result<Option<ShardingRewrite>, Error> {
        let Some(config) = self.proxy_config.sharding.as_ref() else {
            return Ok(None);
        };

        let has_strategy = config.iter().all(|x| {
            x.table_strategy.is_some()
                || x.database_strategy.is_some()
                || x.database_table_strategy.is_some()
        });
        if !has_strategy {
            return Ok(None);
        }

        let mut endpoints: Vec<Endpoint> = vec![];
        for node in &self.nodes {
            let endpoint = endpoint_from_unisql_node(node).map_err(runtime_invalid_input)?;
            endpoints.push(endpoint);
        }

        let has_rw = self.proxy_config.read_write_splitting.is_some();

        Ok(Some(ShardingRewrite::new(config.clone(), endpoints, self.node_group.clone(), has_rw)))
    }

    fn metrics_context(&self) -> GatewayMetricsContext {
        if let Some(runtime_plan) = &self.runtime_plan {
            if let Some(listener_plan) = runtime_plan.listener(&self.proxy_config.name) {
                return GatewayMetricsContext {
                    domain: listener_plan.listener().name.clone(),
                    service: listener_plan.service().name.clone(),
                    frontend_protocol: listener_plan.listener().protocol.clone(),
                    backend_protocol: listener_plan.service().backend_protocol.clone(),
                };
            }
        }

        GatewayMetricsContext::legacy_mysql(self.proxy_config.name.clone())
    }
}

fn endpoint_to_legacy_node(
    endpoint: &EndpointConfig,
    version: &str,
) -> Result<UniSQLNode, GatewayError> {
    let (host, port) = split_endpoint_address(&endpoint.address)?;
    Ok(UniSQLNode {
        version: version.to_string(),
        node_type: endpoint.protocol.clone(),
        name: endpoint.name.clone(),
        db: endpoint.database.clone().unwrap_or_default(),
        user: endpoint.username.clone(),
        password: endpoint.password.clone(),
        host,
        port,
        weight: endpoint.weight as i64,
        role: match &endpoint.role {
            EndpointRole::Read => TargetRole::Read,
            EndpointRole::ReadWrite => TargetRole::ReadWrite,
        },
    })
}

fn ensure_legacy_mysql_listener(
    listener_plan: &CoreGatewayListenerPlan,
) -> Result<(), GatewayError> {
    if listener_plan.listener().protocol != ProtocolKind::MySql {
        return Err(GatewayError::Unsupported(format!(
            "frontend protocol '{}' is not supported by the legacy MySQL runtime path",
            listener_plan.listener().protocol
        )));
    }

    if listener_plan.service().backend_protocol != ProtocolKind::MySql {
        return Err(GatewayError::Unsupported(format!(
            "backend protocol '{}' is not supported by the legacy MySQL runtime path",
            listener_plan.service().backend_protocol
        )));
    }

    Ok(())
}

fn ensure_supported_runtime_listener(
    listener_plan: &CoreGatewayListenerPlan,
) -> Result<(), GatewayError> {
    match (&listener_plan.listener().protocol, &listener_plan.service().backend_protocol) {
        (ProtocolKind::MySql, ProtocolKind::MySql)
        | (ProtocolKind::PostgreSql, ProtocolKind::PostgreSql) => Ok(()),
        (ProtocolKind::MySql, backend) => Err(GatewayError::Unsupported(format!(
            "backend protocol '{}' is not supported by the legacy MySQL runtime path",
            backend
        ))),
        (ProtocolKind::PostgreSql, backend) => Err(GatewayError::Unsupported(format!(
            "backend protocol '{}' is not supported by the PostgreSQL runtime path",
            backend
        ))),
    }
}

fn split_endpoint_address(address: &str) -> Result<(String, u32), GatewayError> {
    let (host, port) = address.rsplit_once(':').ok_or_else(|| {
        GatewayError::Configuration(format!(
            "endpoint address '{}' must be in host:port form",
            address
        ))
    })?;
    if host.trim().is_empty() {
        return Err(GatewayError::Configuration(format!(
            "endpoint address '{}' has empty host",
            address
        )));
    }
    let port = port.parse::<u32>().map_err(|_| {
        GatewayError::Configuration(format!(
            "endpoint address '{}' has invalid port '{}'",
            address, port
        ))
    })?;
    Ok((host.to_string(), port))
}

async fn run_postgresql_core_connection<S>(
    mut stream: S,
    connection: &mut CoreGatewayConnection,
    metrics_context: Option<GatewayMetricsContext>,
) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut frontend = PostgreSqlFrontendProtocol::new();

    loop {
        let startup_frame = read_postgresql_startup_frame(&mut stream).await?;
        match frontend
            .decode_startup(&startup_frame, connection.session_mut())
            .map_err(gateway_error_to_runtime)?
        {
            PostgreSqlStartupAction::Startup(_) => {
                stream
                    .write_all(&frontend.encode_startup_complete(connection.session()))
                    .await
                    .map_err(ErrorKind::Io)?;
                stream.flush().await.map_err(ErrorKind::Io)?;
                break;
            }
            PostgreSqlStartupAction::SslRequest => {
                stream.write_all(&frontend.encode_ssl_denied()).await.map_err(ErrorKind::Io)?;
                stream.flush().await.map_err(ErrorKind::Io)?;
            }
            PostgreSqlStartupAction::CancelRequest { .. } => return Ok(()),
        }
    }

    loop {
        let frame = match read_postgresql_frontend_frame(&mut stream).await {
            Ok(frame) => frame,
            Err(error) if is_unexpected_eof(&error) => return Ok(()),
            Err(error) => return Err(error),
        };

        let terminate = frame.first() == Some(&b'X');
        let collect_metrics = frame.first() == Some(&b'Q');
        let now = std::time::Instant::now();
        let packets = connection.handle_frame(&frame).await.map_err(gateway_error_to_runtime)?;
        if collect_metrics {
            if let Some(metrics_context) = metrics_context.as_ref() {
                let endpoint = connection.last_backend_endpoint_label().unwrap_or_default();
                let collector = MySQLServerMetricsCollector::new();
                collector.set_sql_processed_total(metrics_context, "QUERY", &endpoint);
                collector.set_sql_processed_duration(
                    metrics_context,
                    "QUERY",
                    &endpoint,
                    now.elapsed().as_secs_f64(),
                );
            }
        }
        for packet in packets {
            if !packet.is_empty() {
                stream.write_all(&packet).await.map_err(ErrorKind::Io)?;
            }
        }
        stream.flush().await.map_err(ErrorKind::Io)?;

        if terminate {
            return Ok(());
        }
    }
}

async fn read_postgresql_startup_frame<S>(stream: &mut S) -> Result<Vec<u8>, Error>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0; 4];
    stream.read_exact(&mut header).await.map_err(ErrorKind::Io)?;
    let len = u32::from_be_bytes(header) as usize;
    if len < 8 {
        return Err(runtime_invalid_input(format!(
            "postgresql startup frame has invalid length {}",
            len
        )));
    }

    let mut frame = Vec::with_capacity(len);
    frame.extend_from_slice(&header);
    frame.resize(len, 0);
    stream.read_exact(&mut frame[4..]).await.map_err(ErrorKind::Io)?;
    Ok(frame)
}

async fn read_postgresql_frontend_frame<S>(stream: &mut S) -> Result<Vec<u8>, Error>
where
    S: AsyncRead + Unpin,
{
    let mut message_type = [0; 1];
    stream.read_exact(&mut message_type).await.map_err(ErrorKind::Io)?;

    let mut len_buf = [0; 4];
    stream.read_exact(&mut len_buf).await.map_err(ErrorKind::Io)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len < 4 {
        return Err(runtime_invalid_input(format!(
            "postgresql frontend frame has invalid length {}",
            len
        )));
    }

    let mut frame = Vec::with_capacity(1 + len);
    frame.extend_from_slice(&message_type);
    frame.extend_from_slice(&len_buf);
    frame.resize(1 + len, 0);
    stream.read_exact(&mut frame[5..]).await.map_err(ErrorKind::Io)?;
    Ok(frame)
}

fn gateway_error_to_runtime(error: GatewayError) -> Error {
    runtime_invalid_input(error.to_string())
}

fn is_unexpected_eof(error: &Error) -> bool {
    match error.kind() {
        ErrorKind::Io(io_error) => io_error.kind() == std::io::ErrorKind::UnexpectedEof,
        _ => false,
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
        let protocol = self.listener_protocol()?;
        let listener = Listener {
            name: self.proxy_config.name.clone(),
            protocol: protocol.clone(),
            listen_addr: self.proxy_config.listen_addr.clone(),
            server_version: self.proxy_config.server_version.clone(),
        };

        let mut proxy = Proxy {
            listener,
            app: self.proxy_config.clone(),
            backend_nodes: self.nodes.clone(),
            nodes: self.nodes.clone(),
        };

        let listener = proxy.build_listener().map_err(ErrorKind::Io)?;

        let shutdown_tx = self.shutdown_tx.get_or_insert_with(|| {
            let (sender, _) = watch::channel(false);
            sender
        });
        let mut shutdown_rx = shutdown_tx.subscribe();
        let metrics_context = self.metrics_context();

        if protocol == ProtocolKind::PostgreSql {
            let runtime_plan = self.runtime_plan.clone().ok_or_else(|| {
                runtime_invalid_input("postgresql listener requires a gateway runtime plan")
            })?;
            let listener_name = self.proxy_config.name.clone();
            let metrics_context = metrics_context.clone();

            loop {
                let socket = tokio::select! {
                    changed = shutdown_rx.changed() => {
                        match changed {
                            Ok(_) if *shutdown_rx.borrow() => break,
                            Ok(_) => continue,
                            Err(_) => break,
                        }
                    }
                    accept_result = proxy.accept(&listener) => {
                        accept_result.map_err(ErrorKind::Io)?
                    }
                };

                let runtime_plan = runtime_plan.clone();
                let listener_name = listener_name.clone();
                let metrics_context = metrics_context.clone();
                let join_handle = tokio::spawn(async move {
                    let mut connection = match runtime_plan.build_connection(&listener_name) {
                        Ok(connection) => connection,
                        Err(error) => {
                            error!("postgresql connection build error {:?}", error);
                            return;
                        }
                    };

                    if let Err(error) = run_postgresql_core_connection(
                        socket,
                        &mut connection,
                        Some(metrics_context),
                    )
                    .await
                    {
                        error!("postgresql connection run error {:?}", error);
                    }
                });

                self.connection_handles.push(join_handle);
            }

            for handle in self.connection_handles.drain(..) {
                handle.abort();
            }

            return Ok(StartSource { thread_handles: Vec::new() });
        }

        let pool = Pool::<ClientConn>::new(self.proxy_config.pool_size as usize);

        let ast_cache = Arc::new(Mutex::new(ParserAstCache::new()));

        // TODO: using a loadbalancer factory for different load balance strategy.
        // Currently simple_loadbalancer purely provide a list of nodes without any strategy.
        let route_strategy = Arc::new(Mutex::new(self.build_route()?));

        // Build sharding rewriter
        let rewriter = self.build_sharding_rewriter()?;

        let mut plugin: Option<PluginPhase> = None;
        if let Some(config) = &self.proxy_config.plugin {
            plugin = Some(PluginPhase::new(config.clone()))
        };

        // TODO: 加载配置

        let parser = Arc::new(Parser::new());
        //let metrics_collector = MySQLServerMetricsCollector::new();

        let has_rw = self.proxy_config.read_write_splitting.is_some();

        loop {
            // TODO: need refactor
            let socket = tokio::select! {
                changed = shutdown_rx.changed() => {
                    match changed {
                        Ok(_) if *shutdown_rx.borrow() => break,
                        Ok(_) => continue,
                        Err(_) => break,
                    }
                }
                accept_result = proxy.accept(&listener) => {
                    accept_result.map_err(ErrorKind::Io)?
                }
            };

            let route_strategy = route_strategy.clone();
            let plugin = plugin.clone();
            let parser = parser.clone();
            let ast_cache = ast_cache.clone();
            let pool = pool.clone();
            let proxy_name = self.proxy_config.name.clone();
            let metrics_context = metrics_context.clone();
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
                let framed = match frontend.handshake(socket).await {
                    Ok(framed) => framed,
                    Err(e) => {
                        error!("handshake error {:?}", e);
                        return;
                    }
                };

                let context = ReqContext {
                    fsm: TransFsm::new(),
                    route_strategy,
                    pool,
                    ast_cache,
                    plugin,
                    metrics_collector: MySQLServerMetricsCollector,
                    metrics_context,
                    concurrency_control_rule_idx: None,
                    framed,
                    name: proxy_name,
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

            self.connection_handles.push(join_handle);
        }

        for handle in self.connection_handles.drain(..) {
            handle.abort();
        }

        Ok(StartSource { thread_handles: Vec::new() })
    }

    // stop proxy server
    async fn stop(&mut self) -> Result<(), Error> {
        if let Some(sender) = &self.shutdown_tx {
            let _ = sender.send(true);
        }
        for handle in self.connection_handles.drain(..) {
            handle.abort();
        }
        Ok(())
    }
}

impl GatewayRuntime {
    fn listener_protocol(&self) -> Result<ProtocolKind, Error> {
        if let Some(runtime_plan) = &self.runtime_plan {
            if let Some(listener) = runtime_plan.listener(&self.proxy_config.name) {
                return Ok(listener.listener().protocol.clone());
            }
        }

        Ok(self.proxy_config.node_type.clone())
    }
}

fn runtime_invalid_input(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::Runtime(Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message.into(),
    ))))
}

#[cfg(test)]
mod tests {
    use gateway_core::{
        AuthPolicyConfig, AuthPolicyUserConfig, EndpointConfig, EndpointRole, GatewayConfig,
        ListenerConfig, ProtocolKind, ServiceConfig, SessionState,
    };
    use proxy::factory::Proxy as _;
    use tokio::{
        io::{duplex, AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpListener,
    };

    use super::*;
    use crate::{
        backend::postgresql::PostgreSqlBackendConnector,
        frontend::postgresql::PostgreSqlFrontendProtocol,
    };

    fn gateway_config() -> GatewayConfig {
        GatewayConfig {
            listeners: vec![ListenerConfig {
                name: "mysql-public".into(),
                listen_addr: "127.0.0.1:3307".into(),
                protocol: ProtocolKind::MySql,
                service: "orders".into(),
                auth_policy: Some("local-users".into()),
            }],
            services: vec![ServiceConfig {
                name: "orders".into(),
                frontend_protocols: vec![ProtocolKind::MySql],
                backend_protocol: ProtocolKind::MySql,
                endpoints: vec!["orders-primary".into(), "orders-replica".into()],
                route_policy: None,
                plugin_policies: vec![],
            }],
            endpoints: vec![
                EndpointConfig {
                    name: "orders-primary".into(),
                    protocol: ProtocolKind::MySql,
                    address: "127.0.0.1:3306".into(),
                    database: Some("orders".into()),
                    username: "root".into(),
                    password: "backend-secret".into(),
                    role: EndpointRole::ReadWrite,
                    weight: 2,
                },
                EndpointConfig {
                    name: "orders-replica".into(),
                    protocol: ProtocolKind::MySql,
                    address: "127.0.0.2:3306".into(),
                    database: Some("orders".into()),
                    username: "readonly".into(),
                    password: "replica-secret".into(),
                    role: EndpointRole::Read,
                    weight: 1,
                },
            ],
            auth_policies: vec![AuthPolicyConfig {
                name: "local-users".into(),
                kind: "static".into(),
                users: vec![AuthPolicyUserConfig {
                    username: "app".into(),
                    password: "secret".into(),
                    databases: vec!["orders".into()],
                }],
            }],
            ..GatewayConfig::default()
        }
    }

    fn mixed_protocol_gateway_config() -> GatewayConfig {
        let mut config = gateway_config();
        config.listeners.push(ListenerConfig {
            name: "postgres-public".into(),
            listen_addr: "127.0.0.1:5433".into(),
            protocol: ProtocolKind::PostgreSql,
            service: "orders-pg".into(),
            auth_policy: None,
        });
        config.services.push(ServiceConfig {
            name: "orders-pg".into(),
            frontend_protocols: vec![ProtocolKind::PostgreSql],
            backend_protocol: ProtocolKind::PostgreSql,
            endpoints: vec!["orders-pg-primary".into()],
            route_policy: None,
            plugin_policies: vec![],
        });
        config.endpoints.push(EndpointConfig {
            name: "orders-pg-primary".into(),
            protocol: ProtocolKind::PostgreSql,
            address: "127.0.0.1:5432".into(),
            database: Some("orders".into()),
            username: "postgres".into(),
            password: "backend-secret".into(),
            role: EndpointRole::ReadWrite,
            weight: 1,
        });
        config
    }

    #[test]
    fn builds_legacy_mysql_runtime_from_v2_gateway_config() {
        let runtime =
            GatewayRuntime::from_gateway_config(gateway_config(), "mysql-public", "8.0".into())
                .unwrap();

        assert!(runtime.gateway_config.is_some());
        assert!(runtime.runtime_plan.is_some());
        assert_eq!(runtime.proxy_config.name, "mysql-public");
        assert_eq!(runtime.proxy_config.node_type, ProtocolKind::MySql);
        assert_eq!(runtime.proxy_config.listen_addr, "127.0.0.1:3307");
        assert_eq!(runtime.proxy_config.user, "app");
        assert_eq!(runtime.proxy_config.password, "secret");
        assert_eq!(runtime.proxy_config.db, "orders");

        let loadbalance = runtime.proxy_config.simple_loadbalance.as_ref().unwrap();
        assert_eq!(loadbalance.nodes, vec!["orders-primary", "orders-replica"]);

        assert_eq!(runtime.nodes.len(), 2);
        assert_eq!(runtime.nodes[0].name, "orders-primary");
        assert_eq!(runtime.nodes[0].host, "127.0.0.1");
        assert_eq!(runtime.nodes[0].port, 3306);
        assert_eq!(runtime.nodes[0].role, TargetRole::ReadWrite);
        assert_eq!(runtime.nodes[1].role, TargetRole::Read);
    }

    #[test]
    fn builds_postgresql_runtime_from_v2_gateway_config() {
        let mut config = gateway_config();
        config.listeners[0].protocol = ProtocolKind::PostgreSql;
        config.listeners[0].listen_addr = "127.0.0.1:5433".into();
        config.services[0].frontend_protocols = vec![ProtocolKind::PostgreSql];
        config.services[0].backend_protocol = ProtocolKind::PostgreSql;
        for endpoint in &mut config.endpoints {
            endpoint.protocol = ProtocolKind::PostgreSql;
            endpoint.address = endpoint.address.replace(":3306", ":5432");
        }

        let runtime =
            GatewayRuntime::from_gateway_config(config, "mysql-public", "15.0".into()).unwrap();

        assert!(runtime.gateway_config.is_some());
        assert!(runtime.runtime_plan.is_some());
        assert_eq!(runtime.proxy_config.name, "mysql-public");
        assert_eq!(runtime.proxy_config.node_type, ProtocolKind::PostgreSql);
        assert_eq!(runtime.proxy_config.listen_addr, "127.0.0.1:5433");
        assert_eq!(runtime.proxy_config.user, "app");
        assert_eq!(runtime.proxy_config.db, "orders");
        assert_eq!(runtime.nodes.len(), 2);
        assert_eq!(runtime.nodes[0].node_type, ProtocolKind::PostgreSql);
        assert_eq!(runtime.nodes[0].port, 5432);
    }

    #[test]
    fn builds_mysql_and_postgresql_runtimes_from_same_v2_gateway_config() {
        let config = mixed_protocol_gateway_config();

        let mysql_runtime =
            GatewayRuntime::from_gateway_config(config.clone(), "mysql-public", "8.0".into())
                .unwrap();
        let postgresql_runtime =
            GatewayRuntime::from_gateway_config(config, "postgres-public", "15.0".into()).unwrap();

        assert_eq!(mysql_runtime.proxy_config.name, "mysql-public");
        assert_eq!(mysql_runtime.proxy_config.node_type, ProtocolKind::MySql);
        assert_eq!(mysql_runtime.proxy_config.listen_addr, "127.0.0.1:3307");
        assert_eq!(mysql_runtime.nodes[0].node_type, ProtocolKind::MySql);

        assert_eq!(postgresql_runtime.proxy_config.name, "postgres-public");
        assert_eq!(postgresql_runtime.proxy_config.node_type, ProtocolKind::PostgreSql);
        assert_eq!(postgresql_runtime.proxy_config.listen_addr, "127.0.0.1:5433");
        assert_eq!(postgresql_runtime.nodes[0].node_type, ProtocolKind::PostgreSql);

        assert_eq!(mysql_runtime.runtime_plan.as_ref().unwrap().listeners().len(), 2);
        assert_eq!(postgresql_runtime.runtime_plan.as_ref().unwrap().listeners().len(), 2);
    }

    #[test]
    fn builds_protocol_aware_metrics_context_from_v2_gateway_config() {
        let runtime =
            GatewayRuntime::from_gateway_config(gateway_config(), "mysql-public", "8.0".into())
                .unwrap();

        let context = runtime.metrics_context();

        assert_eq!(context.domain, "mysql-public");
        assert_eq!(context.service, "orders");
        assert_eq!(context.frontend_protocol, ProtocolKind::MySql);
        assert_eq!(context.backend_protocol, ProtocolKind::MySql);
    }

    #[test]
    fn builds_legacy_mysql_runtime_adapter_from_core_listener_plan() {
        let plan = CoreGatewayRuntimePlan::from_config(&gateway_config()).unwrap();
        let listener_plan = plan.listener("mysql-public").unwrap();

        let adapter = LegacyMySqlRuntimeConfig::from_listener_plan(listener_plan, "8.0").unwrap();

        assert_eq!(adapter.proxy_config.name, "mysql-public");
        assert_eq!(adapter.proxy_config.node_type, ProtocolKind::MySql);
        assert_eq!(adapter.proxy_config.listen_addr, "127.0.0.1:3307");
        assert_eq!(adapter.proxy_config.user, "app");
        assert_eq!(adapter.proxy_config.password, "secret");
        assert_eq!(adapter.proxy_config.db, "orders");
        assert_eq!(adapter.nodes.len(), 2);
        assert_eq!(adapter.nodes[0].version, "8.0");
        assert_eq!(adapter.nodes[0].name, "orders-primary");
        assert_eq!(adapter.nodes[0].role, TargetRole::ReadWrite);
        assert_eq!(adapter.nodes[1].name, "orders-replica");
        assert_eq!(adapter.nodes[1].role, TargetRole::Read);
    }

    #[test]
    fn rejects_cross_protocol_runtime_before_start() {
        let mut config = gateway_config();
        config.listeners[0].protocol = ProtocolKind::PostgreSql;
        config.services[0].frontend_protocols = vec![ProtocolKind::PostgreSql];

        let error = match GatewayRuntime::from_gateway_config(config, "mysql-public", "8.0".into())
        {
            Err(error) => error,
            Ok(_) => panic!("expected unsupported protocol error"),
        };

        assert_eq!(
            error,
            GatewayError::Unsupported(
                "backend protocol 'my_sql' is not supported by the PostgreSQL runtime path".into()
            )
        );
    }

    #[test]
    fn rejects_non_mysql_backend_protocols_before_legacy_start() {
        let mut config = gateway_config();
        config.services[0].backend_protocol = ProtocolKind::PostgreSql;
        config.endpoints[0].protocol = ProtocolKind::PostgreSql;
        config.endpoints[1].protocol = ProtocolKind::PostgreSql;

        let error = match GatewayRuntime::from_gateway_config(config, "mysql-public", "8.0".into())
        {
            Err(error) => error,
            Ok(_) => panic!("expected unsupported protocol error"),
        };

        assert_eq!(
            error,
            GatewayError::Unsupported(
                "backend protocol 'postgre_sql' is not supported by the legacy MySQL runtime path"
                    .into()
            )
        );
    }

    #[test]
    fn rejects_endpoint_addresses_without_ports() {
        let mut config = gateway_config();
        config.endpoints[0].address = "127.0.0.1".into();

        let error = match GatewayRuntime::from_gateway_config(config, "mysql-public", "8.0".into())
        {
            Err(error) => error,
            Ok(_) => panic!("expected endpoint address error"),
        };

        assert_eq!(
            error,
            GatewayError::Configuration(
                "endpoint address '127.0.0.1' must be in host:port form".into()
            )
        );
    }

    #[tokio::test]
    async fn stop_sends_shutdown_and_clears_connection_handles() {
        let mut runtime =
            GatewayRuntime::from_legacy(ProxyConfig::default(), None, Vec::new(), "8.0".into());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        runtime.shutdown_tx = Some(shutdown_tx);
        runtime.connection_handles.push(tokio::spawn(async {
            futures::future::pending::<()>().await;
        }));

        runtime.stop().await.unwrap();

        assert!(*shutdown_rx.borrow());
        assert!(runtime.connection_handles.is_empty());
    }

    #[test]
    fn resolves_listener_protocol_from_runtime_plan_before_legacy_string() {
        let mut runtime =
            GatewayRuntime::from_gateway_config(gateway_config(), "mysql-public", "8.0".into())
                .unwrap();
        runtime.proxy_config.node_type = ProtocolKind::PostgreSql;

        assert_eq!(runtime.listener_protocol().unwrap(), ProtocolKind::MySql);
    }

    #[test]
    fn resolves_listener_protocol_from_legacy_node_type() {
        let mut runtime =
            GatewayRuntime::from_legacy(ProxyConfig::default(), None, Vec::new(), "8.0".into());
        runtime.proxy_config.node_type = ProtocolKind::MySql;

        assert_eq!(runtime.listener_protocol().unwrap(), ProtocolKind::MySql);
    }

    #[tokio::test]
    async fn runs_postgresql_core_socket_startup_and_simple_query() {
        let (mut client, server) = duplex(4096);
        let mut connection = CoreGatewayConnection::new(
            Box::new(PostgreSqlFrontendProtocol::new()),
            Arc::new(PostgreSqlBackendConnector::new(Vec::new())),
            SessionState::default(),
        );

        let server_task = tokio::spawn(async move {
            run_postgresql_core_connection(server, &mut connection, None).await.unwrap();
            connection
        });

        client.write_all(&postgresql_startup_frame()).await.unwrap();
        let startup_response = read_until_ready_for_query(&mut client).await;
        assert!(startup_response.starts_with(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0]));
        assert!(startup_response.ends_with(&[b'Z', 0, 0, 0, 5, b'I']));

        client.write_all(&postgresql_query_frame("BEGIN")).await.unwrap();
        let query_response = read_until_ready_for_query(&mut client).await;
        let mut expected = vec![b'C', 0, 0, 0, 9];
        expected.extend_from_slice(b"OK 0\0");
        expected.extend_from_slice(&[b'Z', 0, 0, 0, 5, b'T']);
        assert_eq!(query_response, expected);

        client.write_all(&[b'X', 0, 0, 0, 4]).await.unwrap();
        let connection = server_task.await.unwrap();
        assert_eq!(connection.session().user, Some("app".into()));
        assert_eq!(connection.session().database, Some("orders".into()));
    }

    #[tokio::test]
    async fn collects_postgresql_core_sql_metrics_with_endpoint_label() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let backend = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let startup = read_pg_backend_startup_frame(&mut stream).await;
            assert!(startup.ends_with(b"user\0postgres\0database\0orders\0\0"));
            write_pg_backend_message(&mut stream, b'R', &[0, 0, 0, 0]).await;
            write_pg_backend_message(&mut stream, b'S', b"client_encoding\0UTF8\0").await;
            write_pg_backend_message(&mut stream, b'K', &[0, 0, 0, 42, 0, 0, 0, 7]).await;
            write_pg_backend_message(&mut stream, b'Z', b"I").await;

            let query = read_pg_typed_frontend_frame(&mut stream).await;
            assert_eq!(query, b"Q\0\0\0\rselect 1\0".to_vec());
            write_pg_select_one_response(&mut stream).await;
            write_pg_backend_message(&mut stream, b'Z', b"I").await;
        });

        let (mut client, server) = duplex(4096);
        let mut connection = CoreGatewayConnection::new(
            Box::new(PostgreSqlFrontendProtocol::new()),
            Arc::new(PostgreSqlBackendConnector::new(vec![EndpointConfig {
                name: "orders-pg-primary".into(),
                protocol: ProtocolKind::PostgreSql,
                address,
                database: Some("orders".into()),
                username: "postgres".into(),
                password: "secret".into(),
                role: EndpointRole::ReadWrite,
                weight: 1,
            }])),
            SessionState::default(),
        );
        let metrics_context = GatewayMetricsContext {
            domain: "pg-metrics-listener".into(),
            service: "pg-metrics-service".into(),
            frontend_protocol: ProtocolKind::PostgreSql,
            backend_protocol: ProtocolKind::PostgreSql,
        };

        let server_task = tokio::spawn(async move {
            run_postgresql_core_connection(server, &mut connection, Some(metrics_context))
                .await
                .unwrap();
        });

        client.write_all(&postgresql_startup_frame()).await.unwrap();
        let _startup_response = read_until_ready_for_query(&mut client).await;
        client.write_all(&postgresql_query_frame("select 1")).await.unwrap();
        let _query_response = read_until_ready_for_query(&mut client).await;
        client.write_all(&[b'X', 0, 0, 0, 4]).await.unwrap();

        server_task.await.unwrap();
        backend.await.unwrap();
        let counter = SQL_PROCESSED_TOTAL
            .with_label_values(&[
                "pg-metrics-listener",
                "pg-metrics-service",
                "postgre_sql",
                "postgre_sql",
                "QUERY",
                "orders-pg-primary",
            ])
            .get();
        assert!(counter >= 1);
    }

    #[test]
    fn build_route_rejects_missing_simple_loadbalance_config() {
        let mut proxy_config = ProxyConfig::default();
        proxy_config.name = "legacy-mysql".into();
        proxy_config.node_type = ProtocolKind::MySql;
        proxy_config.simple_loadbalance = None;
        let runtime = GatewayRuntime::from_legacy(
            proxy_config,
            None,
            vec![legacy_node(ProtocolKind::MySql, TargetRole::ReadWrite)],
            "8.0".into(),
        );

        let error = match runtime.build_route() {
            Ok(_) => panic!("expected route config error"),
            Err(error) => error,
        };

        assert!(error
            .to_string()
            .contains("requires simple_loadbalance when read_write_splitting is not configured"));
    }

    #[test]
    fn build_route_accepts_typed_legacy_endpoint_protocol() {
        let mut proxy_config = ProxyConfig::default();
        proxy_config.name = "legacy-mysql".into();
        proxy_config.node_type = ProtocolKind::MySql;
        proxy_config.simple_loadbalance = Some(proxy::proxy::ProxySimpleLoadBalance {
            balance_type: AlgorithmName::Random,
            nodes: vec!["orders-primary".into()],
        });
        let runtime = GatewayRuntime::from_legacy(
            proxy_config,
            None,
            vec![legacy_node(ProtocolKind::MySql, TargetRole::ReadWrite)],
            "8.0".into(),
        );

        assert!(runtime.build_route().is_ok());
    }

    fn legacy_node(node_type: ProtocolKind, role: TargetRole) -> UniSQLNode {
        UniSQLNode {
            version: "8.0".into(),
            node_type,
            name: "orders-primary".into(),
            db: "orders".into(),
            user: "root".into(),
            password: "secret".into(),
            host: "127.0.0.1".into(),
            port: 3306,
            weight: 1,
            role,
        }
    }

    async fn read_pg_backend_startup_frame<S>(stream: &mut S) -> Vec<u8>
    where
        S: AsyncRead + Unpin,
    {
        let mut header = [0; 4];
        stream.read_exact(&mut header).await.unwrap();
        let len = u32::from_be_bytes(header) as usize;
        let mut frame = Vec::with_capacity(len);
        frame.extend_from_slice(&header);
        frame.resize(len, 0);
        stream.read_exact(&mut frame[4..]).await.unwrap();
        frame
    }

    async fn read_pg_typed_frontend_frame<S>(stream: &mut S) -> Vec<u8>
    where
        S: AsyncRead + Unpin,
    {
        let mut header = [0; 5];
        stream.read_exact(&mut header).await.unwrap();
        let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        let mut frame = Vec::with_capacity(1 + len);
        frame.extend_from_slice(&header);
        frame.resize(1 + len, 0);
        stream.read_exact(&mut frame[5..]).await.unwrap();
        frame
    }

    async fn write_pg_backend_message<S>(stream: &mut S, message_type: u8, payload: &[u8])
    where
        S: AsyncWrite + Unpin,
    {
        let mut frame = vec![message_type];
        frame.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
        frame.extend_from_slice(payload);
        stream.write_all(&frame).await.unwrap();
        stream.flush().await.unwrap();
    }

    async fn write_pg_select_one_response<S>(stream: &mut S)
    where
        S: AsyncWrite + Unpin,
    {
        let mut row_description = Vec::new();
        push_i16(&mut row_description, 1);
        row_description.extend_from_slice(b"one\0");
        push_i32(&mut row_description, 0);
        push_i16(&mut row_description, 0);
        push_i32(&mut row_description, 23);
        push_i16(&mut row_description, 4);
        push_i32(&mut row_description, -1);
        push_i16(&mut row_description, 0);
        write_pg_backend_message(stream, b'T', &row_description).await;

        let mut data_row = Vec::new();
        push_i16(&mut data_row, 1);
        push_i32(&mut data_row, 1);
        data_row.extend_from_slice(b"1");
        write_pg_backend_message(stream, b'D', &data_row).await;
        write_pg_backend_message(stream, b'C', b"SELECT 1\0").await;
    }

    fn push_i16(payload: &mut Vec<u8>, value: i16) {
        payload.extend_from_slice(&value.to_be_bytes());
    }

    fn push_i32(payload: &mut Vec<u8>, value: i32) {
        payload.extend_from_slice(&value.to_be_bytes());
    }

    fn postgresql_startup_frame() -> Vec<u8> {
        let mut frame = vec![0, 0, 0, 0, 0, 3, 0, 0];
        frame.extend_from_slice(b"user\0app\0database\0orders\0\0");
        let len = frame.len() as u32;
        frame[..4].copy_from_slice(&len.to_be_bytes());
        frame
    }

    fn postgresql_query_frame(sql: &str) -> Vec<u8> {
        let len = 4 + sql.len() + 1;
        let mut frame = vec![b'Q'];
        frame.extend_from_slice(&(len as u32).to_be_bytes());
        frame.extend_from_slice(sql.as_bytes());
        frame.push(0);
        frame
    }

    async fn read_until_ready_for_query<S>(stream: &mut S) -> Vec<u8>
    where
        S: AsyncRead + Unpin,
    {
        let mut out = Vec::new();
        loop {
            let mut header = [0; 5];
            stream.read_exact(&mut header).await.unwrap();
            let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
            let mut body = vec![0; len - 4];
            stream.read_exact(&mut body).await.unwrap();
            out.extend_from_slice(&header);
            out.extend_from_slice(&body);
            if header[0] == b'Z' {
                return out;
            }
        }
    }
}
