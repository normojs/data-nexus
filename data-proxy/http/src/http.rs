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

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, RwLock},
};

use axum::{
    body::Body,
    extract::State,
    http::{header, StatusCode},
    response::Response,
    routing::get,
    Json, Router,
};
use config::config::PisaProxyConfig;
use gateway_core::GatewayConfigDiff;
use pisa_error::error::*;
use pisa_metrics::metrics::MetricsManager;
use runtime_gateway::supervisor::GatewayRuntimeSupervisor;
use serde::Serialize;
use tracing::info;
use ver::version::get_version;

type SharedPisaConfig = Arc<RwLock<PisaProxyConfig>>;
type SharedGatewaySupervisor = Arc<tokio::sync::Mutex<GatewayRuntimeSupervisor>>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdminListenerView {
    pub name: String,
    pub listen_addr: String,
    pub protocol: String,
    pub service: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdminServiceView {
    pub name: String,
    pub frontend_protocols: Vec<String>,
    pub backend_protocol: String,
    pub endpoints: Vec<String>,
    pub route_policy: Option<String>,
    pub plugin_policies: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdminEndpointView {
    pub name: String,
    pub protocol: String,
    pub address: String,
    pub database: Option<String>,
    pub username: String,
    pub password_configured: bool,
    pub role: String,
    pub weight: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdminPoolView {
    pub service: String,
    pub endpoint: String,
    pub protocol: String,
    pub address: String,
    pub role: String,
    pub weight: i64,
    pub configured: bool,
    pub idle_connections: Option<usize>,
    pub active_connections: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdminSessionView {
    pub id: String,
    pub listener: String,
    pub service: String,
    pub frontend_protocol: String,
    pub backend_protocol: String,
    pub user: Option<String>,
    pub database: Option<String>,
    pub transaction_state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdminReloadResponse {
    pub applied: bool,
    pub diff: GatewayConfigDiff,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdminErrorResponse {
    pub error: String,
}

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

pub struct PisaHttpServerFactory {
    pisa_config: SharedPisaConfig,
    metrics_manager: MetricsManager,
    gateway_supervisor: Option<SharedGatewaySupervisor>,
}
impl PisaHttpServerFactory {
    pub fn new(pcfg: PisaProxyConfig, mgr: MetricsManager) -> PisaHttpServerFactory {
        PisaHttpServerFactory {
            pisa_config: Arc::new(RwLock::new(pcfg)),
            metrics_manager: mgr,
            gateway_supervisor: None,
        }
    }

    pub fn with_gateway_supervisor(mut self, gateway_supervisor: SharedGatewaySupervisor) -> Self {
        self.gateway_supervisor = Some(gateway_supervisor);
        self
    }
}

impl HttpFactory for PisaHttpServerFactory {
    fn build_http_server(&self, kind: HttpServerKind) -> Box<dyn HttpServer + Send> {
        match kind {
            HttpServerKind::Axum => {
                let mut xx = AxumServer::new(
                    self.pisa_config.read().unwrap().clone(),
                    self.metrics_manager.clone(),
                );
                xx.gateway_supervisor = self.gateway_supervisor.clone();
                return Box::new(xx);
            }
        }
    }
}

pub async fn new_http_server(mut s: Box<dyn HttpServer + Send>) {
    s.start().await.unwrap();
}

#[derive(Clone)]
pub struct AxumServer {
    pisa_config: SharedPisaConfig,
    metrics_manager: MetricsManager,
    gateway_supervisor: Option<SharedGatewaySupervisor>,
}

impl AxumServer {
    fn new(pisa_config: PisaProxyConfig, metrics_manager: MetricsManager) -> Self {
        Self {
            pisa_config: Arc::new(RwLock::new(pisa_config)),
            metrics_manager,
            gateway_supervisor: None,
        }
    }

    fn config_snapshot(&self) -> PisaProxyConfig {
        self.pisa_config.read().unwrap().clone()
    }

    fn replace_config(&self, next: PisaProxyConfig) {
        *self.pisa_config.write().unwrap() = next;
    }

    fn routes(&self) -> Router<(), Body> {
        let state = self.clone();

        Router::new()
            .route("/", get(Self::version))
            .route("/version", get(Self::version))
            .route("/healthz", get(Self::healthz))
            .route("/metrics", get(Self::metrics))
            .route("/admin/listeners", get(Self::admin_listeners))
            .route("/admin/services", get(Self::admin_services))
            .route("/admin/endpoints", get(Self::admin_endpoints))
            .route("/admin/pools", get(Self::admin_pools))
            .route("/admin/sessions", get(Self::admin_sessions))
            .route("/admin/config", get(Self::get_config).post(Self::post_config))
            .route("/admin/reload", axum::routing::post(Self::reload_config))
            // TODO：添加配置管理
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

    async fn admin_listeners(State(state): State<Self>) -> Json<Vec<AdminListenerView>> {
        Json(state.listener_views())
    }

    async fn admin_services(State(state): State<Self>) -> Json<Vec<AdminServiceView>> {
        Json(state.service_views())
    }

    async fn admin_endpoints(State(state): State<Self>) -> Json<Vec<AdminEndpointView>> {
        Json(state.endpoint_views())
    }

    async fn admin_pools(State(state): State<Self>) -> Json<Vec<AdminPoolView>> {
        Json(state.pool_views())
    }

    async fn admin_sessions(State(state): State<Self>) -> Json<Vec<AdminSessionView>> {
        Json(state.session_views())
    }

    fn listener_views(&self) -> Vec<AdminListenerView> {
        let pisa_config = self.config_snapshot();
        if pisa_config.has_gateway_config() {
            return pisa_config
                .gateway
                .listeners
                .iter()
                .map(|listener| AdminListenerView {
                    name: listener.name.clone(),
                    listen_addr: listener.listen_addr.clone(),
                    protocol: listener.protocol.to_string(),
                    service: listener.service.clone(),
                })
                .collect();
        }

        pisa_config
            .proxy
            .as_ref()
            .and_then(|proxy| proxy.config.as_ref())
            .map(|proxies| {
                proxies
                    .iter()
                    .map(|proxy| AdminListenerView {
                        name: proxy.name.clone(),
                        listen_addr: proxy.listen_addr.clone(),
                        protocol: proxy.node_type.to_string(),
                        service: proxy.name.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn service_views(&self) -> Vec<AdminServiceView> {
        let pisa_config = self.config_snapshot();
        if pisa_config.has_gateway_config() {
            return pisa_config
                .gateway
                .services
                .iter()
                .map(|service| AdminServiceView {
                    name: service.name.clone(),
                    frontend_protocols: service
                        .frontend_protocols
                        .iter()
                        .map(ToString::to_string)
                        .collect(),
                    backend_protocol: service.backend_protocol.to_string(),
                    endpoints: service.endpoints.clone(),
                    route_policy: service.route_policy.clone(),
                    plugin_policies: service.plugin_policies.clone(),
                })
                .collect();
        }

        pisa_config
            .proxy
            .as_ref()
            .and_then(|proxy| proxy.config.as_ref())
            .map(|proxies| {
                proxies
                    .iter()
                    .map(|proxy| AdminServiceView {
                        name: proxy.name.clone(),
                        frontend_protocols: vec![proxy.node_type.to_string()],
                        backend_protocol: proxy.node_type.to_string(),
                        endpoints: proxy
                            .simple_loadbalance
                            .as_ref()
                            .map(|loadbalance| loadbalance.nodes.clone())
                            .unwrap_or_default(),
                        route_policy: None,
                        plugin_policies: vec![],
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn endpoint_views(&self) -> Vec<AdminEndpointView> {
        let pisa_config = self.config_snapshot();
        if pisa_config.has_gateway_config() {
            return pisa_config
                .gateway
                .endpoints
                .iter()
                .map(|endpoint| AdminEndpointView {
                    name: endpoint.name.clone(),
                    protocol: endpoint.protocol.to_string(),
                    address: endpoint.address.clone(),
                    database: endpoint.database.clone(),
                    username: endpoint.username.clone(),
                    password_configured: !endpoint.password.is_empty(),
                    role: format!("{:?}", endpoint.role),
                    weight: i64::from(endpoint.weight),
                })
                .collect();
        }

        let mut endpoints = pisa_config
            .nodes
            .as_ref()
            .and_then(|nodes| nodes.node.as_ref())
            .map(|nodes| {
                nodes
                    .iter()
                    .map(|node| AdminEndpointView {
                        name: node.name.clone(),
                        protocol: node.node_type.to_string(),
                        address: format!("{}:{}", node.host, node.port),
                        database: Some(node.db.clone()).filter(|database| !database.is_empty()),
                        username: node.user.clone(),
                        password_configured: !node.password.is_empty(),
                        role: format!("{:?}", node.role),
                        weight: node.weight,
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        if endpoints.is_empty() {
            endpoints = pisa_config
                .proxy
                .as_ref()
                .and_then(|proxy| proxy.config.as_ref())
                .map(|proxies| {
                    proxies
                        .iter()
                        .filter_map(|proxy| {
                            proxy.cloud.as_ref().map(|cloud| AdminEndpointView {
                                name: format!("{}-cloud", proxy.name),
                                protocol: cloud.node_type.to_string(),
                                address: cloud.host.clone(),
                                database: Some(cloud.db.clone())
                                    .filter(|database| !database.is_empty()),
                                username: cloud.user.clone(),
                                password_configured: !cloud.password.is_empty(),
                                role: "ReadWrite".into(),
                                weight: 1,
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
        }

        endpoints
    }

    fn pool_views(&self) -> Vec<AdminPoolView> {
        let pisa_config = self.config_snapshot();
        if pisa_config.has_gateway_config() {
            return pisa_config
                .gateway
                .services
                .iter()
                .flat_map(|service| {
                    service.endpoints.iter().filter_map(|endpoint_name| {
                        pisa_config
                            .gateway
                            .endpoints
                            .iter()
                            .find(|endpoint| endpoint.name == *endpoint_name)
                            .map(|endpoint| AdminPoolView {
                                service: service.name.clone(),
                                endpoint: endpoint.name.clone(),
                                protocol: endpoint.protocol.to_string(),
                                address: endpoint.address.clone(),
                                role: format!("{:?}", endpoint.role),
                                weight: i64::from(endpoint.weight),
                                configured: true,
                                idle_connections: None,
                                active_connections: None,
                            })
                    })
                })
                .collect();
        }

        pisa_config
            .nodes
            .as_ref()
            .and_then(|nodes| nodes.node.as_ref())
            .map(|nodes| {
                nodes
                    .iter()
                    .map(|node| AdminPoolView {
                        service: self.proxy_service_for_node(&pisa_config, &node.name),
                        endpoint: node.name.clone(),
                        protocol: node.node_type.to_string(),
                        address: format!("{}:{}", node.host, node.port),
                        role: format!("{:?}", node.role),
                        weight: node.weight,
                        configured: true,
                        idle_connections: None,
                        active_connections: None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn session_views(&self) -> Vec<AdminSessionView> {
        Vec::new()
    }

    fn reload_preview(
        &self,
        next: &PisaProxyConfig,
    ) -> Result<AdminReloadResponse, AdminErrorResponse> {
        let current = self.config_snapshot();
        if !current.has_gateway_config() || !next.has_gateway_config() {
            return Err(AdminErrorResponse {
                error: "admin reload requires current and submitted v2 gateway config".into(),
            });
        }

        if let Err(error) = next.gateway.validate() {
            return Err(AdminErrorResponse { error: error.to_string() });
        }

        Ok(AdminReloadResponse { applied: false, diff: current.gateway.diff(&next.gateway) })
    }

    async fn reload_apply(
        &self,
        next: PisaProxyConfig,
    ) -> Result<AdminReloadResponse, AdminErrorResponse> {
        let Some(supervisor) = &self.gateway_supervisor else {
            return self.reload_preview(&next);
        };

        if !next.has_gateway_config() {
            return Err(AdminErrorResponse {
                error: "admin reload requires submitted v2 gateway config".into(),
            });
        }

        if let Err(error) = next.gateway.validate() {
            return Err(AdminErrorResponse { error: error.to_string() });
        }

        let current = self.config_snapshot();
        let diff = current.gateway.diff(&next.gateway);
        supervisor
            .lock()
            .await
            .apply_config(next.gateway.clone())
            .await
            .map_err(|error| AdminErrorResponse { error: error.to_string() })?;

        self.replace_config(next);
        Ok(AdminReloadResponse { applied: true, diff })
    }

    fn proxy_service_for_node(&self, pisa_config: &PisaProxyConfig, node_name: &str) -> String {
        pisa_config
            .proxy
            .as_ref()
            .and_then(|proxy| proxy.config.as_ref())
            .and_then(|proxies| {
                proxies.iter().find(|proxy| {
                    proxy
                        .simple_loadbalance
                        .as_ref()
                        .map(|loadbalance| loadbalance.nodes.iter().any(|name| name == node_name))
                        .unwrap_or(false)
                })
            })
            .map(|proxy| proxy.name.clone())
            .unwrap_or_default()
    }

    async fn get_config(State(state): State<Self>) -> Response<Body> {
        let cfg = state.config_snapshot();
        let json_string = serde_json::to_string(&cfg).unwrap();
        Response::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json_string))
            .unwrap()
    }

    // 设置config
    async fn post_config(State(_state): State<Self>, cfg: String) -> Response<Body> {
        // let cfg = cfg.parse::<PisaProxyConfig>().unwrap();
        // self.pisa_config = cfg;
        info!("config changed: {} bytes", cfg.len());
        Response::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("success"))
            .unwrap()
    }

    async fn reload_config(
        State(state): State<Self>,
        Json(next): Json<PisaProxyConfig>,
    ) -> Response<Body> {
        match state.reload_apply(next).await {
            Ok(response) => json_response(StatusCode::OK, &response),
            Err(response) => json_response(StatusCode::BAD_REQUEST, &response),
        }
    }
}

fn json_response<T: Serialize>(status: StatusCode, body: &T) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(body).unwrap()))
        .unwrap()
}

#[async_trait::async_trait]
impl HttpServer for AxumServer {
    async fn start(&mut self) -> Result<(), Error> {
        // If `host` converting to `Ipv4Addr` faild, then panic directly.
        let config = self.config_snapshot();
        let addr: Ipv4Addr = config.get_admin().host.parse().unwrap();
        let port = config.get_admin().port;
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
    use config::config::PisaProxyConfig;
    use gateway_core::{
        EndpointConfig, EndpointRole, GatewayConfig, ListenerConfig, ProtocolKind, ServiceConfig,
    };

    use super::*;

    fn build_gateway_config() -> PisaProxyConfig {
        PisaProxyConfig {
            admin: Default::default(),
            gateway: GatewayConfig {
                listeners: vec![
                    ListenerConfig {
                        name: "orders-mysql".into(),
                        listen_addr: "0.0.0.0:3306".into(),
                        protocol: ProtocolKind::MySql,
                        service: "orders".into(),
                        auth_policy: Some("orders-auth".into()),
                    },
                    ListenerConfig {
                        name: "orders-postgresql".into(),
                        listen_addr: "0.0.0.0:5432".into(),
                        protocol: ProtocolKind::PostgreSql,
                        service: "orders-pg".into(),
                        auth_policy: Some("orders-pg-auth".into()),
                    },
                ],
                services: vec![
                    ServiceConfig {
                        name: "orders".into(),
                        frontend_protocols: vec![ProtocolKind::MySql],
                        backend_protocol: ProtocolKind::MySql,
                        endpoints: vec!["orders-primary".into()],
                        route_policy: Some("simple-route".into()),
                        plugin_policies: vec!["audit".into()],
                    },
                    ServiceConfig {
                        name: "orders-pg".into(),
                        frontend_protocols: vec![ProtocolKind::PostgreSql],
                        backend_protocol: ProtocolKind::PostgreSql,
                        endpoints: vec!["orders-pg-primary".into()],
                        route_policy: None,
                        plugin_policies: vec![],
                    },
                ],
                endpoints: vec![
                    EndpointConfig {
                        name: "orders-primary".into(),
                        protocol: ProtocolKind::MySql,
                        address: "127.0.0.1:3306".into(),
                        database: Some("orders".into()),
                        username: "root".into(),
                        password: "secret".into(),
                        role: EndpointRole::ReadWrite,
                        weight: 1,
                    },
                    EndpointConfig {
                        name: "orders-pg-primary".into(),
                        protocol: ProtocolKind::PostgreSql,
                        address: "127.0.0.1:5432".into(),
                        database: Some("orders".into()),
                        username: "postgres".into(),
                        password: "pg-secret".into(),
                        role: EndpointRole::ReadWrite,
                        weight: 1,
                    },
                ],
                route_policies: vec![],
                auth_policies: vec![],
                plugin_policies: vec![],
            },
            proxy: None,
            node_group: None,
            nodes: None,
            shardingsphere_proxy: None,
            version: Some("v-test".into()),
        }
    }

    #[test]
    fn builds_admin_views_from_gateway_config() {
        let state = AxumServer::new(build_gateway_config(), MetricsManager::new());

        assert_eq!(state.listener_views().len(), 2);

        let services = state.service_views();
        assert_eq!(services.len(), 2);
        assert_eq!(services[0].frontend_protocols, vec!["my_sql"]);
        assert_eq!(services[1].backend_protocol, "postgre_sql");

        let endpoints = state.endpoint_views();
        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints[0].name, "orders-primary");
        assert!(endpoints.iter().all(|endpoint| endpoint.password_configured));
        assert_eq!(endpoints[0].role, "ReadWrite");

        let pools = state.pool_views();
        assert_eq!(pools.len(), 2);
        assert_eq!(pools[0].service, "orders");
        assert_eq!(pools[0].endpoint, "orders-primary");
        assert_eq!(pools[0].idle_connections, None);
        assert!(pools.iter().all(|pool| pool.configured));

        assert!(state.session_views().is_empty());
    }

    #[test]
    fn previews_admin_reload_diff_for_gateway_config() {
        let state = AxumServer::new(build_gateway_config(), MetricsManager::new());
        let mut next = state.config_snapshot();
        next.gateway.listeners[0].listen_addr = "0.0.0.0:3307".into();
        next.gateway.endpoints[0].address = "127.0.0.1:3307".into();
        next.gateway.route_policies.push(gateway_core::RoutePolicyConfig {
            name: "simple-route".into(),
            kind: "read-write-splitting".into(),
        });
        next.gateway.auth_policies = vec![
            gateway_core::AuthPolicyConfig {
                name: "orders-auth".into(),
                kind: "static".into(),
                users: vec![],
            },
            gateway_core::AuthPolicyConfig {
                name: "orders-pg-auth".into(),
                kind: "static".into(),
                users: vec![],
            },
        ];
        next.gateway.plugin_policies =
            vec![gateway_core::PluginPolicyConfig { name: "audit".into(), kind: "audit".into() }];

        let preview = state.reload_preview(&next).unwrap();

        assert!(!preview.applied);
        assert_eq!(preview.diff.listeners.updated, vec!["orders-mysql"]);
        assert_eq!(preview.diff.endpoints.updated, vec!["orders-primary"]);
        assert_eq!(preview.diff.route_policies.added, vec!["simple-route"]);
        assert_eq!(preview.diff.listener_restarts, vec!["orders-mysql"]);
        assert_eq!(preview.diff.endpoint_pool_refreshes, vec!["orders"]);
    }
}
