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

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::{
    body::Body,
    extract::State,
    http::{header, StatusCode},
    response::Response,
    routing::{get, post},
    Router,
};
use config::config::PisaProxyConfig;
use pisa_error::error::*;
use pisa_metrics::metrics::MetricsManager;
use tracing::{error, info};
use ver::version::get_version;

#[async_trait::async_trait]
pub trait HttpServer {
    async fn start(&mut self) -> Result<(), Error>;
}

pub trait HttpFactory {
    fn build_http_server(&self, kind: HttpServerKind) -> Box<dyn HttpServer + Send>;
}

#[derive(Debug)]
pub enum HttpServerKind {
    Axum,
}

#[derive(Debug)]
pub struct PisaHttpServerFactory {
    pisa_config: PisaProxyConfig,
    metrics_manager: MetricsManager,
}
impl PisaHttpServerFactory {
    pub fn new(pcfg: PisaProxyConfig, mgr: MetricsManager) -> PisaHttpServerFactory {
        PisaHttpServerFactory { pisa_config: pcfg, metrics_manager: mgr }
    }
}

impl HttpFactory for PisaHttpServerFactory {
    fn build_http_server(&self, kind: HttpServerKind) -> Box<dyn HttpServer + Send> {
        match kind {
            HttpServerKind::Axum => {
                let xx = AxumServer {
                    pisa_config: self.pisa_config.clone(),
                    metrics_manager: self.metrics_manager.clone(),
                };
                return Box::new(xx);
            }
            _ => {
                error!("参数错误，无法启动：{:?}", kind);
                panic!("参数错误，无法启动");
            }
        }
    }
}

pub async fn new_http_server(mut s: Box<dyn HttpServer + Send>) {
    s.start().await.unwrap();
}

#[derive(Clone, Debug)]
pub struct AxumServer {
    pisa_config: PisaProxyConfig,
    metrics_manager: MetricsManager,
}

impl AxumServer {
    fn routes(&self) -> Router<(), Body> {
        let state = self.clone();

        Router::new()
            .route("/", get(Self::version))
            .route("/version", get(Self::version))
            .route("/healthz", get(Self::healthz))
            .route("/metrics", get(Self::metrics))
            // TODO：添加配置管理
            // .route("/config", get(Self::get_config))
            // .route("/config", post(Self::post_config))
            .with_state(state)
    }

    async fn healthz(_state: State<Self>) -> StatusCode {
        // TODO: add checking logic
        StatusCode::OK
    }

    async fn version(State(_state): State<Self>) -> String {
        get_version()
    }

    async fn metrics(State(state): State<Self>) -> Response<Body> {
        let buf = state.metrics_manager.gather();

        Response::builder()
            .header(header::CONTENT_TYPE, "text/plain; version=0.0.4")
            .body(Body::from(buf))
            .unwrap()
    }

    async fn get_config(&mut self, _state: State<Self>) -> Response<Body> {
        let cfg = self.pisa_config.clone();
        let json_string = serde_json::to_string(&cfg).unwrap();
        Response::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json_string))
            .unwrap()
    }

    // 设置config
    async fn post_config(&mut self, _state: State<Self>, cfg: Body) -> Response<Body> {
        // let cfg = cfg.parse::<PisaProxyConfig>().unwrap();
        // self.pisa_config = cfg;
        info!("config changed: {:?}", cfg);
        Response::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("success"))
            .unwrap()
    }
}

#[async_trait::async_trait]
impl HttpServer for AxumServer {
    async fn start(&mut self) -> Result<(), Error> {
        // If `host` converting to `Ipv4Addr` faild, then panic directly.
        let addr: Ipv4Addr = self.pisa_config.get_admin().host.parse().unwrap();
        let port = self.pisa_config.get_admin().port;
        let socket_addr = SocketAddr::new(IpAddr::V4(addr), port);
        info!("http api url: {}:{}", addr, port);
        axum::Server::bind(&socket_addr)
            .serve(self.routes().into_make_service())
            .await
            .map_err(|e| ErrorKind::Runtime(e.into()))?;
        Ok(())
    }
}
