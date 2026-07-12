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
    proxy::{endpoint_from_unisql_node, Proxy, ProxyConfig, UniSQLNode},
};
use strategy::{
    config::{NodeGroup, TargetRole},
    readwritesplitting::ReadWriteEndpoint,
    route::RouteStrategy,
    sharding_rewrite::{ShardingRewrite, ShardingRewriteOutput},
};
use tokio::{sync::watch, task::JoinHandle};
use tracing::{debug, error};

use crate::{
    backend::mysql::MySqlBackendConnector,
    core_engine::CoreGatewayRuntimePlan,
    frontend::mysql::{MySqlFrontendConnection, MySqlFrontendProtocol, ReqContext},
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

        let auth_user = listener_plan.auth_policy().and_then(|policy| policy.users.first());
        let database = listener_plan.default_database().unwrap_or_default().to_string();
        let endpoint_names = listener_plan
            .endpoints()
            .iter()
            .map(|endpoint| endpoint.name.clone())
            .collect::<Vec<_>>();

        let proxy_config = ProxyConfig {
            name: listener_plan.listener().name.clone(),
            node_type: listener_plan.listener().protocol.to_string(),
            listen_addr: listener_plan.listener().listen_addr.clone(),
            user: auth_user.map(|user| user.username.clone()).unwrap_or_default(),
            password: auth_user.map(|user| user.password.clone()).unwrap_or_default(),
            db: database,
            simple_loadbalance: Some(proxy::proxy::ProxySimpleLoadBalance {
                balance_type: AlgorithmName::Random,
                nodes: endpoint_names,
            }),
            ..ProxyConfig::default()
        };

        let nodes = listener_plan
            .endpoints()
            .iter()
            .map(|endpoint| endpoint_to_legacy_node(endpoint, &pisa_version))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            proxy_config,
            node_group: None,
            nodes,
            pisa_version,
            gateway_config: Some(gateway_config),
            runtime_plan: Some(runtime_plan),
            shutdown_tx: None,
            connection_handles: Vec::new(),
        })
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
}

fn endpoint_to_legacy_node(
    endpoint: &EndpointConfig,
    version: &str,
) -> Result<UniSQLNode, GatewayError> {
    let (host, port) = split_endpoint_address(&endpoint.address)?;
    Ok(UniSQLNode {
        version: version.to_string(),
        node_type: endpoint.protocol.to_string(),
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
            protocol,
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

        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);

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
                    fsm: TransFsm::new(pool.clone()),
                    route_strategy,
                    pool,
                    ast_cache,
                    plugin,
                    metrics_collector: MySQLServerMetricsCollector,
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

        self.proxy_config.node_type.parse::<ProtocolKind>().map_err(runtime_invalid_input)
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
        ListenerConfig, ProtocolKind, ServiceConfig,
    };
    use proxy::factory::Proxy as _;

    use super::*;

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

    #[test]
    fn builds_legacy_mysql_runtime_from_v2_gateway_config() {
        let runtime =
            GatewayRuntime::from_gateway_config(gateway_config(), "mysql-public", "8.0".into())
                .unwrap();

        assert!(runtime.gateway_config.is_some());
        assert!(runtime.runtime_plan.is_some());
        assert_eq!(runtime.proxy_config.name, "mysql-public");
        assert_eq!(runtime.proxy_config.node_type, "my_sql");
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
    fn rejects_non_mysql_runtime_protocols_before_legacy_start() {
        let mut config = gateway_config();
        config.listeners[0].protocol = ProtocolKind::PostgreSql;

        let error = match GatewayRuntime::from_gateway_config(config, "mysql-public", "8.0".into())
        {
            Err(error) => error,
            Ok(_) => panic!("expected unsupported protocol error"),
        };

        assert_eq!(
            error,
            GatewayError::Unsupported(
                "frontend protocol 'postgre_sql' is not supported by the legacy MySQL runtime path"
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
        runtime.proxy_config.node_type = "".into();

        assert_eq!(runtime.listener_protocol().unwrap(), ProtocolKind::MySql);
    }

    #[test]
    fn resolves_listener_protocol_from_legacy_node_type() {
        let mut runtime =
            GatewayRuntime::from_legacy(ProxyConfig::default(), None, Vec::new(), "8.0".into());
        runtime.proxy_config.node_type = "mysql".into();

        assert_eq!(runtime.listener_protocol().unwrap(), ProtocolKind::MySql);
    }

    #[test]
    fn build_route_rejects_missing_simple_loadbalance_config() {
        let mut proxy_config = ProxyConfig::default();
        proxy_config.name = "legacy-mysql".into();
        proxy_config.node_type = "mysql".into();
        proxy_config.simple_loadbalance = None;
        let runtime = GatewayRuntime::from_legacy(
            proxy_config,
            None,
            vec![legacy_node("mysql", TargetRole::ReadWrite)],
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
    fn build_route_rejects_invalid_legacy_endpoint_protocol() {
        let mut proxy_config = ProxyConfig::default();
        proxy_config.name = "legacy-mysql".into();
        proxy_config.node_type = "mysql".into();
        proxy_config.simple_loadbalance = Some(proxy::proxy::ProxySimpleLoadBalance {
            balance_type: AlgorithmName::Random,
            nodes: vec!["orders-primary".into()],
        });
        let runtime = GatewayRuntime::from_legacy(
            proxy_config,
            None,
            vec![legacy_node("oracle", TargetRole::ReadWrite)],
            "8.0".into(),
        );

        let error = match runtime.build_route() {
            Ok(_) => panic!("expected endpoint protocol error"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("unsupported protocol kind 'oracle'"));
    }

    fn legacy_node(node_type: &str, role: TargetRole) -> UniSQLNode {
        UniSQLNode {
            version: "8.0".into(),
            node_type: node_type.into(),
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
}
