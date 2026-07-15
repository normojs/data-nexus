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

use std::str::FromStr;

use ::server::server::{start_gateway_server, GatewayFactory};
use tokio::runtime::{Builder, Runtime};
use tracing::{error, info, log::debug, Level};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

extern crate tokio;

use config::config::PisaProxyConfigBuilder;
use http::http::{
    new_http_server, AdminRuntimeState, GatewayConfigSource, HttpFactory, HttpServerKind,
    PisaHttpServerFactory,
};
use pisa_metrics::metrics::MetricsManager;

use crate::node::NodeInstance;

/// Initialize structured logging.
///
/// - `RUST_LOG` / `DATA_NEXUS_LOG` env filters (default: admin.log_level)
/// - `DATA_NEXUS_LOG_FORMAT=json` for JSON logs (spans included)
/// - spans from runtime (`gateway.handle_frame`, `gateway.command`) attach fields
fn init_tracing(admin_log_level: &str) {
    let default_level = Level::from_str(admin_log_level).unwrap_or(Level::INFO);
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_from_env("DATA_NEXUS_LOG"))
        .unwrap_or_else(|_| EnvFilter::new(default_level.as_str()));

    let json = std::env::var("DATA_NEXUS_LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);

    let registry = tracing_subscriber::registry().with(filter);
    if json {
        registry.with(fmt::layer().json().with_span_list(true).with_current_span(true)).init();
    } else {
        registry.with(fmt::layer().with_target(true)).init();
    }
}

fn main() {
    let config_builder = PisaProxyConfigBuilder::new().collect_from_cmd();
    let gateway_config_source =
        config_builder.gateway_config_path().map(|path| GatewayConfigSource::file(path.to_owned()));
    let config = match config_builder.build_gateway() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{}", error);
            std::process::exit(-1);
        }
    };
    init_tracing(config.admin.log_level.as_str());
    info!("data-nexus gateway start: {}", config.version.as_deref().unwrap_or("unknown"));

    // TODO: 获取数据库中的配置
    // TODO：动态修改配置

    // TODO:
    // 1、初始化
    // 2、启动
    // 3、停止
    // 4、重启
    let factory = GatewayFactory::from_gateway_config(config.clone());
    let proxy_instances = match factory.try_build_proxies() {
        Ok(instances) => instances,
        Err(error) => {
            error!("failed to build gateway proxy: {}", error);
            std::process::exit(-1);
        }
    };
    let runtime_state =
        AdminRuntimeState::new_with_runtime_controls(proxy_instances.iter().map(|instance| {
            (
                instance.name.clone(),
                instance.shutdown_handle.clone(),
                instance.pool_snapshotter.clone(),
                instance.pool_refresher.clone(),
                instance.session_snapshotter.clone(),
            )
        }));
    let http_factory = match gateway_config_source {
        Some(source) => PisaHttpServerFactory::new_gateway_with_runtime_state_and_config_source(
            config,
            MetricsManager::new(),
            runtime_state,
            source,
        ),
        None => PisaHttpServerFactory::new_gateway_with_runtime_state(
            config,
            MetricsManager::new(),
            runtime_state,
        ),
    };
    let http_server = http_factory.build_http_server(HttpServerKind::Axum);

    let mut servers = Vec::with_capacity(proxy_instances.len() + 1);

    build_runtime().block_on(async move {
        for instance in proxy_instances {
            servers.push(NodeInstance::new(
                instance.name,
                tokio::spawn(start_gateway_server(instance.proxy)),
                Some(instance.shutdown_handle),
            ));
        }

        servers.push(NodeInstance::new(
            "httpserver-001".to_string(),
            tokio::spawn(new_http_server(http_server)),
            None,
        ));

        for server_instance in &servers {
            debug!("server instance name is: {}", server_instance.name);
        }
        for server_instance in servers {
            if let Err(e) = server_instance.join_handle.await {
                error!("{:?}", e)
            }
        }
    });
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

fn restart_node(_name: String) {
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
