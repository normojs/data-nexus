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

#![warn(unused_must_use)]
#![allow(dead_code)]

mod node;

use std::{
    collections::HashMap,
    hash::Hash,
    str::FromStr,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use ::server::server::{start_gateway_server, GatewayFactory};
use tokio::{
    runtime::{Builder, Runtime},
    task::JoinHandle,
};
use tracing::{
    error, info,
    log::{debug, kv::Source},
    warn, Level,
};

extern crate tokio;

use config::config::{PisaProxyConfig, PisaProxyConfigBuilder};
use http::http::{new_http_server, HttpFactory, HttpServerKind, PisaHttpServerFactory};
use pisa_metrics::metrics::MetricsManager;
use proxy::{
    factory::{ProxyFactory, ProxyKind},
    proxy::ProxyConfig,
};
use runtime_gateway::supervisor::GatewayRuntimeSupervisor;

use crate::node::NodeInstance;

fn main() {
    // --config examples/example-config.toml
    // info!("uni-proxy info");
    // warn!("uni-proxy warn");
    // error!("uni-proxy error");
    // print!("xxxxx");
    // return;
    let config: PisaProxyConfig = PisaProxyConfigBuilder::new().collect_from_cmd().build();
    tracing_subscriber::fmt()
        .with_max_level(Level::from_str(config.get_admin().log_level.as_str()).ok())
        .init();
    info!("uni-proxy start: {}", config.version.as_ref().unwrap());

    // TODO: 获取数据库中的配置
    // TODO：动态修改配置

    // TODO:
    // 1、初始化
    // 2、启动
    // 3、停止
    // 4、重启
    if config.has_gateway_config() {
        let version = config.get_version().to_string();
        let gateway_config = config.gateway.clone();
        let http_config = config.clone();

        build_runtime().block_on(async move {
            let gateway_supervisor = Arc::new(tokio::sync::Mutex::new(
                GatewayRuntimeSupervisor::new(gateway_config, version).unwrap(),
            ));
            gateway_supervisor.lock().await.start_all().unwrap();

            let http_server = PisaHttpServerFactory::new(http_config, MetricsManager::new())
                .with_gateway_supervisor(gateway_supervisor)
                .build_http_server(HttpServerKind::Axum);

            if let Err(e) = tokio::spawn(new_http_server(http_server)).await {
                error!("{:?}", e)
            }
        });
    } else {
        match config.proxy.clone() {
            Some(_) => {
                // TODO: 使用map
                // let mut serverMaps :HashMap<String, JoinHandle<()>> = HashMap::with_capacity(config.get_proxy().len() + 1);
                let mut servers = Vec::with_capacity(config.get_proxy().len() + 1);

                build_runtime().block_on(async move {
                    let http_server =
                        PisaHttpServerFactory::new(config.clone(), MetricsManager::new())
                            .build_http_server(HttpServerKind::Axum);

                    for proxy_config in config.get_proxy() {
                        let cfg = proxy_config;

                        let factory = GatewayFactory::new(cfg.to_owned(), config.clone());
                        servers.push(NodeInstance::new(
                            cfg.name.clone(),
                            tokio::spawn(start_gateway_server(factory.build_proxy())),
                        ));
                    } // end for

                    // new_http_server(http_server).await;
                    // serverMaps.insert("httpserver-001".to_string(), );
                    servers.push(NodeInstance::new(
                        "httpserver-001".to_string(),
                        tokio::spawn(new_http_server(http_server)),
                    ));

                    for serverInstance in &servers {
                        debug!("server instance name is: {}", serverInstance.name);
                        if serverInstance.name.starts_with("proxy") {
                            // closeNode
                        }
                    }
                    for serverInstance in servers {
                        if let Err(e) = serverInstance.joinHandle.await {
                            error!("{:?}", e)
                        }
                    }
                }); // end build_runtime
            } // end Some()
            None => {
                build_runtime().block_on(async move {
                    // if let Err(e) = tokio::spawn(new_http_server(http_server)).await {
                    //     error!("{:?}", e)
                    // }
                });
            }
        }
    }
}

// TODO: 新增的方法
// TODO： 启动节点
// fn start_node(mut servers: &Vec<NodeInstance>,cfg: &ProxyConfig, config: PisaProxyConfig){
//     // 根据配置启动
//     let factory = GatewayFactory::new(cfg.to_owned(), config);
//     servers.push(
//         NodeInstance::new(
//             cfg.name.clone(), tokio::spawn(start_gateway_server(factory.build_proxy()))
//         )
//     );
// }

// fn close_node(duration: Duration, mut server: &JoinHandle<()>) {
//     println!("Elapsed time:");
//     thread::sleep(duration); // 暂停当前线程指定时间
//     server.abort();
// }

fn restart_node(name: String) {
    //     TODO: restart node
}

/// build runtime, build Tokio runtime
pub fn build_runtime() -> Runtime {
    let num_cpus = num_cpus::get();

    match num_cpus {
        0 | 1 => {
            info!("data-nexus running on current thread");
            Builder::new_current_thread()
                .thread_name("data-nexus")
                .enable_all()
                .build()
                .expect("failed to build runtime")
        }
        num_cpus => {
            info!("data-nexus running on multi thread");
            Builder::new_multi_thread()
                .thread_name("data-nexus")
                .worker_threads(num_cpus)
                .max_blocking_threads(num_cpus)
                .enable_all()
                .build()
                .expect("failed to build runtime")
        }
    }
}
