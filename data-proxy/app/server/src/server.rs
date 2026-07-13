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

use std::{error::Error, fmt};

use config::config::{GatewayConfigDocument, PisaProxyConfig};
use proxy::{
    factory::{PoolSnapshotter, Proxy, ProxyFactory, SessionSnapshotter, ShutdownHandle},
    proxy::ProxyConfig,
};
// use runtime_mysql::mysql;

#[derive(Clone)]
enum GatewayFactoryConfig {
    Legacy { proxy_config: ProxyConfig, pisa_config: PisaProxyConfig },
    Native(GatewayConfigDocument),
}

pub struct GatewayFactory {
    config: GatewayFactoryConfig,
}

pub struct GatewayProxyInstance {
    pub name: String,
    pub proxy: Box<dyn Proxy + Send>,
    pub shutdown_handle: ShutdownHandle,
    pub pool_snapshotter: Option<PoolSnapshotter>,
    pub session_snapshotter: Option<SessionSnapshotter>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayFactoryError {
    message: String,
}

impl GatewayFactoryError {
    fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }
}

impl fmt::Display for GatewayFactoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for GatewayFactoryError {}

impl From<gateway_core::GatewayError> for GatewayFactoryError {
    fn from(error: gateway_core::GatewayError) -> Self {
        Self::new(error.to_string())
    }
}

impl GatewayFactory {
    pub fn new(proxy_config: ProxyConfig, pisa_config: PisaProxyConfig) -> Self {
        Self { config: GatewayFactoryConfig::Legacy { proxy_config, pisa_config } }
    }

    pub fn from_gateway_config(config: GatewayConfigDocument) -> Self {
        Self { config: GatewayFactoryConfig::Native(config) }
    }

    pub fn try_build_proxy(&self) -> Result<Box<dyn Proxy + Send>, GatewayFactoryError> {
        self.try_build_proxies()?
            .into_iter()
            .next()
            .map(|instance| instance.proxy)
            .ok_or_else(|| GatewayFactoryError::new("gateway config has no listeners"))
    }

    pub fn try_build_proxy_for_listener(
        &self,
        listener_name: &str,
    ) -> Result<GatewayProxyInstance, GatewayFactoryError> {
        match &self.config {
            GatewayFactoryConfig::Legacy { proxy_config, .. } => {
                if proxy_config.name != listener_name {
                    return Err(GatewayFactoryError::new(format!(
                        "listener '{}' is not defined",
                        listener_name
                    )));
                }

                self.try_build_proxies()?
                    .into_iter()
                    .next()
                    .ok_or_else(|| GatewayFactoryError::new("gateway config has no listeners"))
            }
            GatewayFactoryConfig::Native(config) => {
                let listener = config
                    .gateway
                    .listeners
                    .iter()
                    .find(|listener| listener.name == listener_name)
                    .ok_or_else(|| {
                        GatewayFactoryError::new(format!(
                            "listener '{}' is not defined",
                            listener_name
                        ))
                    })?;

                Self::build_native_proxy_instance(config, &listener.name)
            }
        }
    }

    pub fn try_build_proxies(&self) -> Result<Vec<GatewayProxyInstance>, GatewayFactoryError> {
        match &self.config {
            GatewayFactoryConfig::Legacy { proxy_config, pisa_config } => {
                let mut runtime = runtime_gateway::gateway::GatewayRuntime {
                    proxy_config: proxy_config.clone(),
                    node_group: pisa_config.node_group.clone(),
                    nodes: pisa_config.get_nodes().to_vec(),
                    pisa_version: pisa_config.get_version().to_string(),
                    core_plan: None,
                    ..Default::default()
                };
                let shutdown_handle = runtime.shutdown_handle();
                let pool_snapshotter = Some(runtime.pool_snapshotter());
                let session_snapshotter = Some(runtime.session_snapshotter());

                Ok(vec![GatewayProxyInstance {
                    name: proxy_config.name.clone(),
                    proxy: Box::new(runtime),
                    shutdown_handle,
                    pool_snapshotter,
                    session_snapshotter,
                }])
            }
            GatewayFactoryConfig::Native(config) => {
                if config.gateway.listeners.is_empty() {
                    return Err(GatewayFactoryError::new("gateway config has no listeners"));
                }

                config
                    .gateway
                    .listeners
                    .iter()
                    .map(|listener| Self::build_native_proxy_instance(config, &listener.name))
                    .collect()
            }
        }
    }

    fn build_native_proxy_instance(
        config: &GatewayConfigDocument,
        listener_name: &str,
    ) -> Result<GatewayProxyInstance, GatewayFactoryError> {
        let mut gateway_runtime =
            runtime_gateway::gateway::GatewayRuntime::from_core_config_for_listener(
                &config.gateway,
                listener_name,
            )?;
        gateway_runtime.pisa_version = config.version.clone().unwrap_or_else(|| "2".into());

        let shutdown_handle = gateway_runtime.shutdown_handle();
        let pool_snapshotter = Some(gateway_runtime.pool_snapshotter());
        let session_snapshotter = Some(gateway_runtime.session_snapshotter());

        Ok(GatewayProxyInstance {
            name: listener_name.to_owned(),
            proxy: Box::new(gateway_runtime),
            shutdown_handle,
            pool_snapshotter,
            session_snapshotter,
        })
    }
}

impl ProxyFactory for GatewayFactory {
    fn build_proxy(&self) -> Box<dyn Proxy + Send> {
        return self.try_build_proxy().unwrap_or_else(|error| {
            panic!("failed to build gateway proxy: {}", error);
        });

        // 以下废弃
        // match kind {
        //
        //     ProxyKind::ShardingSphereProxy => {
        //         Box::new(runtime_shardingsphereproxy::shardingsphereproxy::ShardingSphereProxy {
        //             proxy_config: config,
        //             shardingsphereproxy_nodes: self.pisa_config.get_shardingsphere_proxy().to_vec(),
        //             // shardingsphereproxy_nodes: self.pisa_config.clone().get_shardingsphere_proxy(),
        //             // shardingsphereproxy_nodes: self.pisa_config.get_shardingsphere_proxy(),
        //             // pisa_version: self.pisa_config.clone().get_version(),
        //             // pisa_version: self.pisa_config.get_version(),
        //             pisa_version: self.pisa_config.get_version().to_string(),
        //             // shardingsphereproxy_nodes: self.pisa_config.shardingsphere_proxy.as_ref().unwrap().node.as_ref().unwrap().to_vec(),
        //             // pisa_version: self.pisa_config.version.as_ref().unwrap().to_string(),
        //         })
        //     },
        //
        // }
    }
}
/// 启动代理服务器
pub async fn start_gateway_server(mut s: Box<dyn proxy::factory::Proxy + Send>) {
    match s.start().await {
        Ok(start_source) => {
            for handle in start_source.thread_handles {
                if let Err(error) = handle.await {
                    eprintln!("gateway connection task stopped with error: {}", error);
                }
            }
        }
        Err(error) => {
            eprintln!("gateway server stopped with error: {}", error);
        }
    }
}

#[cfg(test)]
mod tests {
    use config::config::GatewayConfigDocument;

    use super::*;

    fn gateway_config() -> GatewayConfigDocument {
        GatewayConfigDocument::from_toml(include_str!("../../../examples/gateway-config.toml"))
            .unwrap()
    }

    #[test]
    fn builds_one_proxy_per_v2_listener() {
        let factory = GatewayFactory::from_gateway_config(gateway_config());

        let proxies = factory.try_build_proxies().unwrap();

        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].name, "orders-mysql");
        assert!(!proxies[0].shutdown_handle.is_shutdown_requested());

        let pool_snapshot = proxies[0].pool_snapshotter.as_ref().unwrap()();
        assert_eq!(pool_snapshot.capacity, 64);
        assert_eq!(pool_snapshot.endpoints.len(), 2);
        assert_eq!(pool_snapshot.endpoints[0].endpoint, "127.0.0.1:3306");
        assert_eq!(pool_snapshot.endpoints[1].endpoint, "127.0.0.1:3307");

        let session_snapshot = proxies[0].session_snapshotter.as_ref().unwrap()();
        assert!(session_snapshot.sessions.is_empty());
    }

    #[test]
    fn rejects_v2_config_without_listeners() {
        let factory = GatewayFactory::from_gateway_config(GatewayConfigDocument::default());

        let error = match factory.try_build_proxies() {
            Ok(_) => panic!("empty gateway config should be rejected"),
            Err(error) => error,
        };

        assert_eq!(error, GatewayFactoryError::new("gateway config has no listeners"));
    }
}
