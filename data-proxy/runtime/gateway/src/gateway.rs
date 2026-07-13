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
use gateway_core::{GatewayConfig, GatewayError, GatewayResult};
use indexmap::IndexMap;
use loadbalance::balance::{Balance, LoadBalance};
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
    core_engine::{CoreGatewayConnection, CoreGatewayRuntimePlan},
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
        Ok(Self {
            core_plan: Some(CoreGatewayRuntimePlan::from_config(config)?),
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

    pub fn build_core_connection(
        &self,
        listener_name: &str,
    ) -> GatewayResult<CoreGatewayConnection> {
        let plan = self.core_plan.as_ref().ok_or_else(|| {
            GatewayError::Configuration("gateway runtime has no v2 core config".into())
        })?;
        plan.build_connection(listener_name)
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
        let strategy = if self.proxy_config.read_write_splitting.is_some()
            && self.proxy_config.sharding.is_some()
        {
            let rw_endpoint = ReadWriteEndpoint { read: ro, readwrite: rw };
            RouteStrategy::new(
                self.proxy_config.read_write_splitting.as_ref().unwrap().clone(),
                &self.node_group,
                rw_endpoint,
                true,
            )
            .map_err(|e| Error::new(ErrorKind::Runtime(e.into())))?
        } else if self.proxy_config.read_write_splitting.is_some() {
            let rw_endpoint = ReadWriteEndpoint { read: ro, readwrite: rw };
            RouteStrategy::new(
                self.proxy_config.read_write_splitting.as_ref().unwrap().clone(),
                &self.node_group,
                rw_endpoint,
                false,
            )
            .map_err(|e| Error::new(ErrorKind::Runtime(e.into())))?
        } else {
            //let rw_endpoint = ReadWriteEndpoint { read: ro, readwrite: rw };
            let balance_type =
                self.proxy_config.simple_loadbalance.as_ref().unwrap().balance_type.clone();
            let mut balance = Balance.build_balance(balance_type);
            rw.append(&mut ro);
            for ep in rw.into_iter() {
                balance.add(ep)
            }

            if self.proxy_config.sharding.is_some() {
                let has_strategy = &self.proxy_config.sharding.as_ref().unwrap().iter().all(|x| {
                    x.table_strategy.is_some()
                        || x.database_strategy.is_some()
                        || x.database_table_strategy.is_some()
                });
                if *has_strategy {
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
        let config = self.proxy_config.sharding.clone();

        if config.is_none() {
            return None;
        }

        let has_strategy = config.as_ref().unwrap().iter().all(|x| {
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

        Some(ShardingRewrite::new(config.unwrap(), endpoints, self.node_group.clone(), has_rw))
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
        let listener = Listener {
            name: self.proxy_config.name.clone(),
            node_type: self.proxy_config.node_type.clone(),
            backend_type: self.proxy_config.backend_type.clone(),
            listen_addr: self.proxy_config.listen_addr.clone(),
            server_version: self.proxy_config.server_version.clone(),
        };

        let mut proxy = Proxy {
            listener,
            app: self.proxy_config.clone(),
            backend_nodes: self.nodes.clone(),
            nodes: self.nodes.clone(),
        };

        let listener = proxy.build_listener().unwrap();

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
