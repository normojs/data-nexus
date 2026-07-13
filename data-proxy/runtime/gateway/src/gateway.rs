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
use gateway_core::{EndpointConfig, GatewayConfig, GatewayError, GatewayResult, ProtocolKind};
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
    proxy::{Proxy, ProxyConfig, UniSQLNode},
};
use strategy::{
    config::{NodeGroup, TargetRole},
    readwritesplitting::ReadWriteEndpoint,
    route::RouteStrategy,
    sharding_rewrite::{ShardingRewrite, ShardingRewriteOutput},
};
use tracing::{debug, error};

use crate::{
    backend::mysql::MySqlBackendConnector,
    core_engine::{CoreGatewayConnection, CoreGatewayListenerPlan, CoreGatewayRuntimePlan},
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
    pub core_plan: Option<CoreGatewayRuntimePlan>,
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

        Ok(Self { proxy_config, nodes, core_plan: Some(core_plan), ..Default::default() })
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
}

fn runtime_configuration_error(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::Runtime(Box::new(GatewayError::Configuration(message.into()))))
}

#[allow(deprecated)]
fn legacy_proxy_config_from_core_plan(
    plan: &CoreGatewayListenerPlan,
) -> GatewayResult<ProxyConfig> {
    if plan.listener().protocol != ProtocolKind::MySql {
        return Err(GatewayError::Unsupported(format!(
            "{:?} listener '{}' cannot run on the legacy mysql accept loop yet",
            plan.listener().protocol,
            plan.listener().name
        )));
    }
    if plan.service().backend_protocol != ProtocolKind::MySql {
        return Err(GatewayError::Unsupported(format!(
            "{:?} service '{}' cannot run on the legacy mysql accept loop yet",
            plan.service().backend_protocol,
            plan.service().name
        )));
    }

    Ok(ProxyConfig {
        name: plan.listener().name.clone(),
        node_type: protocol_name(&plan.listener().protocol).into(),
        backend_type: protocol_name(&plan.service().backend_protocol).into(),
        listen_addr: plan.listener().listen_addr.clone(),
        db: plan.default_database().unwrap_or_default().into(),
        pool_size: 64,
        server_version: "8.0".into(),
        simple_loadbalance: Some(proxy::proxy::ProxySimpleLoadBalance {
            balance_type: AlgorithmName::Random,
            nodes: plan.endpoints().iter().map(|endpoint| endpoint.name.clone()).collect(),
        }),
        ..ProxyConfig::default()
    })
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
        role: TargetRole::ReadWrite,
    })
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

#[async_trait::async_trait]
impl proxy::factory::Proxy for GatewayRuntime {
    // TODO：优雅退出
    // 1、关闭监听
    // 2、等待处理连接的线程结束
    // thread_handld:ThreadHandld<()>;

    // 3、退出循环

    // async fn start(&mut self, &mut start_source: StartSource) -> Result<StartSource, Error> {
    async fn start(&mut self) -> Result<StartSource, Error> {
        let listener = self.build_listener_config();

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
        let rewriter = self.build_sharding_rewriter();

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
            let socket = proxy.accept(&listener).await.map_err(ErrorKind::Io)?;

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
            let _join_handle = tokio::spawn(async move {
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

            // start_source.thread_handles.push(join_handle);
        }
    }

    // stop proxy server
    async fn stop(&mut self) -> Result<(), Error> {
        // TODO：
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use gateway_core::{
        EndpointConfig, GatewayConfig, ListenerConfig, ProtocolKind, ServiceConfig,
    };

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
                username: "root".into(),
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
}
