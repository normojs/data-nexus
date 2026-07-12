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

use config::config::PisaProxyConfig;
use gateway_core::GatewayConfig;
use proxy::{
    factory::{Proxy, ProxyFactory},
    proxy::ProxyConfig,
};
// use runtime_mysql::mysql;

pub struct GatewayFactory {
    source: GatewayFactorySource,
}

enum GatewayFactorySource {
    Legacy { proxy_config: ProxyConfig, pisa_config: PisaProxyConfig },
    NativeGateway { gateway_config: GatewayConfig, listener_name: String, version: String },
}

impl GatewayFactory {
    pub fn new(proxy_config: ProxyConfig, pisa_config: PisaProxyConfig) -> Self {
        Self { source: GatewayFactorySource::Legacy { proxy_config, pisa_config } }
    }

    pub fn from_gateway_config(
        gateway_config: GatewayConfig,
        listener_name: String,
        version: String,
    ) -> Self {
        Self {
            source: GatewayFactorySource::NativeGateway { gateway_config, listener_name, version },
        }
    }
}

impl ProxyFactory for GatewayFactory {
    fn build_proxy(&self) -> Box<dyn Proxy + Send> {
        match &self.source {
            GatewayFactorySource::Legacy { proxy_config, pisa_config } => {
                let gateway_runtime = runtime_gateway::gateway::GatewayRuntime::from_legacy(
                    proxy_config.clone(),
                    pisa_config.node_group.clone(),
                    pisa_config.get_nodes().to_vec(),
                    pisa_config.get_version().to_string(),
                );
                Box::new(gateway_runtime)
            }
            GatewayFactorySource::NativeGateway { gateway_config, listener_name, version } => {
                let gateway_runtime =
                    runtime_gateway::gateway::GatewayRuntime::from_gateway_config(
                        gateway_config.clone(),
                        listener_name,
                        version.clone(),
                    )
                    .unwrap_or_else(|error| {
                        panic!(
                            "failed to build gateway runtime for listener '{}': {}",
                            listener_name, error
                        )
                    });
                Box::new(gateway_runtime)
            }
        }

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
    // let xx = s.start().await.unwrap();
    s.start().await.unwrap();
}
