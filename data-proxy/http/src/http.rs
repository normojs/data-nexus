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
    routing::get,
    Router,
};
use config::config::{GatewayConfigDocument, PisaProxyConfig};
use pisa_error::error::*;
use pisa_metrics::metrics::MetricsManager;
use serde::Serialize;
use tracing::info;
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
    gateway_config: Option<GatewayConfigDocument>,
    metrics_manager: MetricsManager,
}
impl PisaHttpServerFactory {
    pub fn new(pcfg: PisaProxyConfig, mgr: MetricsManager) -> PisaHttpServerFactory {
        PisaHttpServerFactory { pisa_config: pcfg, gateway_config: None, metrics_manager: mgr }
    }

    pub fn new_gateway(
        gateway_config: GatewayConfigDocument,
        mgr: MetricsManager,
    ) -> PisaHttpServerFactory {
        let pisa_config = PisaProxyConfig {
            admin: gateway_config.admin.clone(),
            version: gateway_config.version.clone(),
            ..PisaProxyConfig::default()
        };
        PisaHttpServerFactory {
            pisa_config,
            gateway_config: Some(gateway_config),
            metrics_manager: mgr,
        }
    }
}

impl HttpFactory for PisaHttpServerFactory {
    fn build_http_server(&self, kind: HttpServerKind) -> Box<dyn HttpServer + Send> {
        match kind {
            HttpServerKind::Axum => {
                let xx = AxumServer {
                    pisa_config: self.pisa_config.clone(),
                    gateway_config: self.gateway_config.clone(),
                    metrics_manager: self.metrics_manager.clone(),
                };
                return Box::new(xx);
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
    gateway_config: Option<GatewayConfigDocument>,
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
            .route("/config", get(Self::admin_config))
            .route("/admin/config", get(Self::admin_config))
            .route("/admin/listeners", get(Self::admin_listeners))
            .route("/admin/services", get(Self::admin_services))
            .route("/admin/endpoints", get(Self::admin_endpoints))
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

    async fn admin_config(State(state): State<Self>) -> Response<Body> {
        match &state.gateway_config {
            Some(config) => json_response(config),
            None => json_response(&state.pisa_config),
        }
    }

    async fn admin_listeners(State(state): State<Self>) -> Response<Body> {
        match &state.gateway_config {
            Some(config) => json_response(&config.gateway.listeners),
            None => gateway_config_not_available(),
        }
    }

    async fn admin_services(State(state): State<Self>) -> Response<Body> {
        match &state.gateway_config {
            Some(config) => json_response(&config.gateway.services),
            None => gateway_config_not_available(),
        }
    }

    async fn admin_endpoints(State(state): State<Self>) -> Response<Body> {
        match &state.gateway_config {
            Some(config) => json_response(&config.gateway.endpoints),
            None => gateway_config_not_available(),
        }
    }
}

fn json_response<T: Serialize>(value: &T) -> Response<Body> {
    match serde_json::to_vec(value) {
        Ok(body) => Response::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap_or_else(|error| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from(error.to_string()))
                    .expect("static internal server error response is valid")
            }),
        Err(error) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from(error.to_string()))
            .expect("static internal server error response is valid"),
    }
}

fn gateway_config_not_available() -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::from("gateway config is not available"))
        .expect("static not found response is valid")
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

#[cfg(test)]
mod tests {
    use axum::http::Request;
    use hyper::body::to_bytes;
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;

    fn gateway_config() -> GatewayConfigDocument {
        GatewayConfigDocument::from_toml(include_str!("../../examples/gateway-config.toml"))
            .unwrap()
    }

    fn gateway_server() -> AxumServer {
        let gateway_config = gateway_config();
        AxumServer {
            pisa_config: PisaProxyConfig {
                admin: gateway_config.admin.clone(),
                version: gateway_config.version.clone(),
                ..PisaProxyConfig::default()
            },
            gateway_config: Some(gateway_config),
            metrics_manager: MetricsManager::new(),
        }
    }

    async fn get_json(path: &str) -> (StatusCode, Value) {
        let response = gateway_server()
            .routes()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body()).await.unwrap();
        let value = serde_json::from_slice(&body).unwrap();
        (status, value)
    }

    #[tokio::test]
    async fn admin_config_returns_native_gateway_config() {
        let (status, value) = get_json("/admin/config").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["listeners"][0]["name"], "orders-mysql");
        assert_eq!(value["services"][0]["name"], "orders");
        assert_eq!(value["endpoints"][0]["name"], "orders-primary");
    }

    #[tokio::test]
    async fn legacy_config_route_returns_native_gateway_config() {
        let (status, value) = get_json("/config").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["version"], "2");
    }

    #[tokio::test]
    async fn admin_topology_routes_return_gateway_sections() {
        let (status, listeners) = get_json("/admin/listeners").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(listeners.as_array().unwrap().len(), 1);
        assert_eq!(listeners[0]["protocol"], "my_sql");

        let (status, services) = get_json("/admin/services").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(services.as_array().unwrap().len(), 1);
        assert_eq!(services[0]["backend_protocol"], "my_sql");

        let (status, endpoints) = get_json("/admin/endpoints").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(endpoints.as_array().unwrap().len(), 2);
        assert_eq!(endpoints[1]["address"], "127.0.0.1:3307");
    }

    #[tokio::test]
    async fn topology_routes_report_missing_gateway_config_for_legacy_state() {
        let response = AxumServer {
            pisa_config: PisaProxyConfig::default(),
            gateway_config: None,
            metrics_manager: MetricsManager::new(),
        }
        .routes()
        .oneshot(Request::builder().uri("/admin/listeners").body(Body::empty()).unwrap())
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
