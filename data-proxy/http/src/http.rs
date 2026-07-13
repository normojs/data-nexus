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
    collections::{BTreeMap, HashMap},
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, RwLock},
};

use axum::{
    body::Body,
    extract::{Json, Path, State},
    http::{header, StatusCode},
    response::Response,
    routing::{get, post, put},
    Router,
};
use config::config::{GatewayConfigDocument, GatewayConfigLoadError, PisaProxyConfig};
use gateway_core::{ListenerConfig, RoutePolicyConfig};
use pisa_error::error::*;
use pisa_metrics::metrics::MetricsManager;
use proxy::factory::{
    PoolSnapshot, PoolSnapshotter, SessionEntrySnapshot, SessionSnapshotter, ShutdownHandle,
};
use serde::Serialize;
use server::server::{start_gateway_server, GatewayFactory};
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
    gateway_config: Option<SharedGatewayConfig>,
    gateway_config_source: Option<GatewayConfigSource>,
    runtime_state: Option<AdminRuntimeState>,
    metrics_manager: MetricsManager,
}
impl PisaHttpServerFactory {
    pub fn new(pcfg: PisaProxyConfig, mgr: MetricsManager) -> PisaHttpServerFactory {
        PisaHttpServerFactory {
            pisa_config: pcfg,
            gateway_config: None,
            gateway_config_source: None,
            runtime_state: None,
            metrics_manager: mgr,
        }
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
            gateway_config: Some(shared_gateway_config(gateway_config)),
            gateway_config_source: None,
            runtime_state: None,
            metrics_manager: mgr,
        }
    }

    pub fn new_gateway_with_runtime_state(
        gateway_config: GatewayConfigDocument,
        mgr: MetricsManager,
        runtime_state: AdminRuntimeState,
    ) -> PisaHttpServerFactory {
        let mut factory = Self::new_gateway(gateway_config, mgr);
        factory.runtime_state = Some(runtime_state);
        factory
    }

    pub fn new_gateway_with_runtime_state_and_config_source(
        gateway_config: GatewayConfigDocument,
        mgr: MetricsManager,
        runtime_state: AdminRuntimeState,
        gateway_config_source: GatewayConfigSource,
    ) -> PisaHttpServerFactory {
        let mut factory = Self::new_gateway_with_runtime_state(gateway_config, mgr, runtime_state);
        factory.gateway_config_source = Some(gateway_config_source);
        factory
    }
}

impl HttpFactory for PisaHttpServerFactory {
    fn build_http_server(&self, kind: HttpServerKind) -> Box<dyn HttpServer + Send> {
        match kind {
            HttpServerKind::Axum => {
                let xx = AxumServer {
                    pisa_config: self.pisa_config.clone(),
                    gateway_config: self.gateway_config.clone(),
                    gateway_config_source: self.gateway_config_source.clone(),
                    runtime_state: self.runtime_state.clone(),
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
pub enum GatewayConfigSource {
    File { path: String },
}

impl GatewayConfigSource {
    pub fn file(path: impl Into<String>) -> Self {
        Self::File { path: path.into() }
    }

    fn description(&self) -> String {
        match self {
            Self::File { path } => path.clone(),
        }
    }

    fn load(&self) -> Result<GatewayConfigDocument, GatewayConfigLoadError> {
        match self {
            Self::File { path } => {
                let config_str =
                    std::fs::read_to_string(path).map_err(GatewayConfigLoadError::Io)?;
                GatewayConfigDocument::from_toml(&config_str)
            }
        }
    }
}

type SharedGatewayConfig = Arc<RwLock<GatewayConfigDocument>>;

fn shared_gateway_config(config: GatewayConfigDocument) -> SharedGatewayConfig {
    Arc::new(RwLock::new(config))
}

#[derive(Clone, Default)]
pub struct AdminRuntimeState {
    inner: Arc<RwLock<AdminRuntimeStateInner>>,
}

#[derive(Default)]
struct AdminRuntimeStateInner {
    listener_shutdown_handles: HashMap<String, ShutdownHandle>,
    listener_pool_snapshotters: HashMap<String, PoolSnapshotter>,
    listener_session_snapshotters: HashMap<String, SessionSnapshotter>,
}

impl fmt::Debug for AdminRuntimeState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = match self.inner.read() {
            Ok(inner) => inner,
            Err(_) => {
                return formatter
                    .debug_struct("AdminRuntimeState")
                    .field("poisoned", &true)
                    .finish()
            }
        };

        formatter
            .debug_struct("AdminRuntimeState")
            .field("listener_shutdown_handles", &inner.listener_shutdown_handles)
            .field("listener_pool_snapshotter_count", &inner.listener_pool_snapshotters.len())
            .field("listener_session_snapshotter_count", &inner.listener_session_snapshotters.len())
            .finish()
    }
}

impl AdminRuntimeState {
    pub fn new(
        listener_shutdown_handles: impl IntoIterator<Item = (String, ShutdownHandle)>,
    ) -> Self {
        Self::new_with_pool_snapshotters(
            listener_shutdown_handles
                .into_iter()
                .map(|(name, shutdown_handle)| (name, shutdown_handle, None)),
        )
    }

    pub fn new_with_pool_snapshotters(
        listener_runtimes: impl IntoIterator<Item = (String, ShutdownHandle, Option<PoolSnapshotter>)>,
    ) -> Self {
        Self::new_with_runtime_snapshotters(listener_runtimes.into_iter().map(
            |(name, shutdown_handle, pool_snapshotter)| {
                (name, shutdown_handle, pool_snapshotter, None)
            },
        ))
    }

    pub fn new_with_runtime_snapshotters(
        listener_runtimes: impl IntoIterator<
            Item = (String, ShutdownHandle, Option<PoolSnapshotter>, Option<SessionSnapshotter>),
        >,
    ) -> Self {
        let mut inner = AdminRuntimeStateInner::default();

        for (name, shutdown_handle, pool_snapshotter, session_snapshotter) in listener_runtimes {
            inner.listener_shutdown_handles.insert(name.clone(), shutdown_handle);
            if let Some(pool_snapshotter) = pool_snapshotter {
                inner.listener_pool_snapshotters.insert(name.clone(), pool_snapshotter);
            }
            if let Some(session_snapshotter) = session_snapshotter {
                inner.listener_session_snapshotters.insert(name, session_snapshotter);
            }
        }

        Self { inner: Arc::new(RwLock::new(inner)) }
    }

    fn register_listener(
        &self,
        name: String,
        shutdown_handle: ShutdownHandle,
        pool_snapshotter: Option<PoolSnapshotter>,
        session_snapshotter: Option<SessionSnapshotter>,
    ) -> Result<(), String> {
        let mut inner =
            self.inner.write().map_err(|_| "admin runtime state lock is poisoned".to_string())?;

        if inner.listener_shutdown_handles.contains_key(&name) {
            return Err(format!("listener runtime '{}' is already registered", name));
        }

        inner.listener_shutdown_handles.insert(name.clone(), shutdown_handle);
        if let Some(pool_snapshotter) = pool_snapshotter {
            inner.listener_pool_snapshotters.insert(name.clone(), pool_snapshotter);
        }
        if let Some(session_snapshotter) = session_snapshotter {
            inner.listener_session_snapshotters.insert(name, session_snapshotter);
        }

        Ok(())
    }

    fn stop_listener(&self, name: &str) -> Option<ListenerRuntimeStatus> {
        let shutdown_handle = self.inner.read().ok()?.listener_shutdown_handles.get(name)?.clone();
        shutdown_handle.shutdown();
        Some(ListenerRuntimeStatus {
            name: name.to_owned(),
            shutdown_requested: shutdown_handle.is_shutdown_requested(),
        })
    }

    fn pool_statuses(&self) -> Vec<ListenerPoolRuntimeStatus> {
        let snapshotters = self
            .inner
            .read()
            .map(|inner| {
                inner
                    .listener_pool_snapshotters
                    .iter()
                    .map(|(name, snapshotter)| (name.clone(), snapshotter.clone()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let mut statuses = snapshotters
            .iter()
            .map(|(name, snapshotter)| ListenerPoolRuntimeStatus {
                name: name.clone(),
                snapshot: snapshotter(),
            })
            .collect::<Vec<_>>();
        statuses.sort_by(|left, right| left.name.cmp(&right.name));
        statuses
    }

    fn session_statuses(&self) -> Vec<SessionEntrySnapshot> {
        let snapshotters = self
            .inner
            .read()
            .map(|inner| inner.listener_session_snapshotters.values().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        let mut sessions =
            snapshotters.iter().flat_map(|snapshotter| snapshotter().sessions).collect::<Vec<_>>();
        sessions.sort_by(|left, right| {
            left.listener.cmp(&right.listener).then_with(|| left.id.cmp(&right.id))
        });
        sessions
    }
}

#[derive(Debug, Serialize)]
struct ListenerRuntimeStatus {
    name: String,
    shutdown_requested: bool,
}

#[derive(Debug, Serialize)]
struct ListenerPoolRuntimeStatus {
    name: String,
    #[serde(flatten)]
    snapshot: PoolSnapshot,
}

#[derive(Debug, Serialize)]
struct GatewayReloadResponse {
    status: &'static str,
    source: String,
    applied: bool,
    changed: bool,
    diff: GatewayConfigDiff,
}

#[derive(Debug, Serialize)]
struct AdminAddListenerResponse {
    status: &'static str,
    name: String,
    listen_addr: String,
}

#[derive(Debug, Serialize)]
struct AdminReplaceRoutePolicyResponse {
    status: &'static str,
    name: String,
    kind: String,
}

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
struct GatewayConfigDiff {
    admin_changed: bool,
    version_changed: bool,
    listeners: NamedSectionDiff,
    services: NamedSectionDiff,
    endpoints: NamedSectionDiff,
    route_policies: NamedSectionDiff,
    auth_policies: NamedSectionDiff,
    plugin_policies: NamedSectionDiff,
}

impl GatewayConfigDiff {
    fn between(current: &GatewayConfigDocument, next: &GatewayConfigDocument) -> Self {
        Self {
            admin_changed: serde_json::to_value(&current.admin).ok()
                != serde_json::to_value(&next.admin).ok(),
            version_changed: current.version != next.version,
            listeners: diff_named_section(
                &current.gateway.listeners,
                &next.gateway.listeners,
                |item| item.name.as_str(),
            ),
            services: diff_named_section(
                &current.gateway.services,
                &next.gateway.services,
                |item| item.name.as_str(),
            ),
            endpoints: diff_named_section(
                &current.gateway.endpoints,
                &next.gateway.endpoints,
                |item| item.name.as_str(),
            ),
            route_policies: diff_named_section(
                &current.gateway.route_policies,
                &next.gateway.route_policies,
                |item| item.name.as_str(),
            ),
            auth_policies: diff_named_section(
                &current.gateway.auth_policies,
                &next.gateway.auth_policies,
                |item| item.name.as_str(),
            ),
            plugin_policies: diff_named_section(
                &current.gateway.plugin_policies,
                &next.gateway.plugin_policies,
                |item| item.name.as_str(),
            ),
        }
    }

    fn has_changes(&self) -> bool {
        self.admin_changed
            || self.version_changed
            || self.listeners.has_changes()
            || self.services.has_changes()
            || self.endpoints.has_changes()
            || self.route_policies.has_changes()
            || self.auth_policies.has_changes()
            || self.plugin_policies.has_changes()
    }
}

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
struct NamedSectionDiff {
    added: Vec<String>,
    removed: Vec<String>,
    changed: Vec<String>,
}

impl NamedSectionDiff {
    fn has_changes(&self) -> bool {
        !self.added.is_empty() || !self.removed.is_empty() || !self.changed.is_empty()
    }
}

fn diff_named_section<T>(current: &[T], next: &[T], name: impl Fn(&T) -> &str) -> NamedSectionDiff
where
    T: PartialEq,
{
    let current = current.iter().map(|item| (name(item), item)).collect::<BTreeMap<_, _>>();
    let next = next.iter().map(|item| (name(item), item)).collect::<BTreeMap<_, _>>();

    let added = next
        .keys()
        .filter(|name| !current.contains_key(*name))
        .map(|name| (*name).to_owned())
        .collect();
    let removed = current
        .keys()
        .filter(|name| !next.contains_key(*name))
        .map(|name| (*name).to_owned())
        .collect();
    let changed = current
        .iter()
        .filter_map(|(name, current_item)| match next.get(name) {
            Some(next_item) if current_item != next_item => Some((*name).to_owned()),
            _ => None,
        })
        .collect();

    NamedSectionDiff { added, removed, changed }
}

#[derive(Debug, Serialize)]
struct AdminErrorResponse {
    error: &'static str,
    message: String,
}

#[derive(Clone, Debug)]
pub struct AxumServer {
    pisa_config: PisaProxyConfig,
    gateway_config: Option<SharedGatewayConfig>,
    gateway_config_source: Option<GatewayConfigSource>,
    runtime_state: Option<AdminRuntimeState>,
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
            .route("/admin/listeners", get(Self::admin_listeners).post(Self::admin_add_listener))
            .route("/admin/listeners/:name/stop", post(Self::admin_stop_listener))
            .route("/admin/route-policies/:name", put(Self::admin_replace_route_policy))
            .route("/admin/services", get(Self::admin_services))
            .route("/admin/endpoints", get(Self::admin_endpoints))
            .route("/admin/pools", get(Self::admin_pools))
            .route("/admin/sessions", get(Self::admin_sessions))
            .route("/admin/reload", post(Self::admin_reload))
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
            Some(config) => match gateway_config_snapshot(config) {
                Ok(config) => json_response(&config),
                Err(response) => response,
            },
            None => json_response(&state.pisa_config),
        }
    }

    async fn admin_listeners(State(state): State<Self>) -> Response<Body> {
        match &state.gateway_config {
            Some(config) => match gateway_config_snapshot(config) {
                Ok(config) => json_response(&config.gateway.listeners),
                Err(response) => response,
            },
            None => gateway_config_not_available(),
        }
    }

    async fn admin_services(State(state): State<Self>) -> Response<Body> {
        match &state.gateway_config {
            Some(config) => match gateway_config_snapshot(config) {
                Ok(config) => json_response(&config.gateway.services),
                Err(response) => response,
            },
            None => gateway_config_not_available(),
        }
    }

    async fn admin_endpoints(State(state): State<Self>) -> Response<Body> {
        match &state.gateway_config {
            Some(config) => match gateway_config_snapshot(config) {
                Ok(config) => json_response(&config.gateway.endpoints),
                Err(response) => response,
            },
            None => gateway_config_not_available(),
        }
    }

    async fn admin_add_listener(
        State(state): State<Self>,
        Json(listener): Json<ListenerConfig>,
    ) -> Response<Body> {
        let gateway_config = match &state.gateway_config {
            Some(gateway_config) => gateway_config.clone(),
            None => return gateway_config_not_available(),
        };
        let runtime_state = match &state.runtime_state {
            Some(runtime_state) => runtime_state.clone(),
            None => return admin_runtime_unavailable("admin runtime state is not available"),
        };
        let listener_name = listener.name.clone();
        let listen_addr = listener.listen_addr.clone();

        let listener_runtime = {
            let mut current_config = match gateway_config.write() {
                Ok(current_config) => current_config,
                Err(_) => {
                    return admin_json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "gateway listener add failed",
                        "gateway config lock is poisoned".to_string(),
                    )
                }
            };
            let mut next_config = current_config.clone();
            next_config.gateway.listeners.push(listener);

            if let Err(error) = next_config.gateway.validate() {
                return admin_json_error(
                    StatusCode::BAD_REQUEST,
                    "gateway listener add failed",
                    format!("invalid gateway configuration: {}", error),
                );
            }

            let listener_runtime = match GatewayFactory::from_gateway_config(next_config.clone())
                .try_build_proxy_for_listener(&listener_name)
            {
                Ok(listener_runtime) => listener_runtime,
                Err(error) => {
                    return admin_json_error(
                        StatusCode::BAD_REQUEST,
                        "gateway listener add failed",
                        format!("failed to build listener runtime: {}", error),
                    )
                }
            };

            if let Err(error) = runtime_state.register_listener(
                listener_runtime.name.clone(),
                listener_runtime.shutdown_handle.clone(),
                listener_runtime.pool_snapshotter.clone(),
                listener_runtime.session_snapshotter.clone(),
            ) {
                return admin_json_error(
                    StatusCode::BAD_REQUEST,
                    "gateway listener add failed",
                    error,
                );
            }

            *current_config = next_config;
            listener_runtime
        };

        tokio::spawn(start_gateway_server(listener_runtime.proxy));

        json_response(&AdminAddListenerResponse {
            status: "started",
            name: listener_name,
            listen_addr,
        })
    }

    async fn admin_replace_route_policy(
        Path(name): Path<String>,
        State(state): State<Self>,
        Json(route_policy): Json<RoutePolicyConfig>,
    ) -> Response<Body> {
        let gateway_config = match &state.gateway_config {
            Some(gateway_config) => gateway_config.clone(),
            None => return gateway_config_not_available(),
        };

        if route_policy.name != name {
            return admin_json_error(
                StatusCode::BAD_REQUEST,
                "gateway route policy replace failed",
                format!(
                    "route policy name '{}' does not match path parameter '{}'",
                    route_policy.name, name
                ),
            );
        }

        let updated_kind = route_policy.kind.clone();
        let route_policy_name = route_policy.name.clone();

        let response = {
            let mut current_config = match gateway_config.write() {
                Ok(current_config) => current_config,
                Err(_) => {
                    return admin_json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "gateway route policy replace failed",
                        "gateway config lock is poisoned".to_string(),
                    )
                }
            };
            let route_policy_idx = match current_config
                .gateway
                .route_policies
                .iter()
                .position(|policy| policy.name == name)
            {
                Some(index) => index,
                None => {
                    return admin_json_error(
                        StatusCode::NOT_FOUND,
                        "gateway route policy replace failed",
                        format!("route policy '{}' is not defined", name),
                    )
                }
            };

            let mut next_config = current_config.clone();
            next_config.gateway.route_policies[route_policy_idx] = route_policy;

            if let Err(error) = next_config.gateway.validate() {
                return admin_json_error(
                    StatusCode::BAD_REQUEST,
                    "gateway route policy replace failed",
                    format!("invalid gateway configuration: {}", error),
                );
            }

            *current_config = next_config;
            AdminReplaceRoutePolicyResponse {
                status: "updated",
                name: route_policy_name,
                kind: updated_kind,
            }
        };

        json_response(&response)
    }

    async fn admin_pools(State(state): State<Self>) -> Response<Body> {
        match &state.runtime_state {
            Some(runtime_state) => json_response(&runtime_state.pool_statuses()),
            None => admin_runtime_not_found("admin runtime state is not available"),
        }
    }

    async fn admin_sessions(State(state): State<Self>) -> Response<Body> {
        match &state.runtime_state {
            Some(runtime_state) => json_response(&runtime_state.session_statuses()),
            None => admin_runtime_not_found("admin runtime state is not available"),
        }
    }

    async fn admin_reload(State(state): State<Self>) -> Response<Body> {
        let current_config = match &state.gateway_config {
            Some(config) => match gateway_config_snapshot(config) {
                Ok(config) => config,
                Err(response) => return response,
            },
            None => return gateway_config_not_available(),
        };
        let config_source = match &state.gateway_config_source {
            Some(config_source) => config_source,
            None => return admin_runtime_not_found("gateway config source is not available"),
        };

        let next_config = match config_source.load() {
            Ok(config) => config,
            Err(error) => return gateway_config_load_error(error),
        };
        let diff = GatewayConfigDiff::between(&current_config, &next_config);
        let changed = diff.has_changes();

        json_response(&GatewayReloadResponse {
            status: "validated",
            source: config_source.description(),
            applied: false,
            changed,
            diff,
        })
    }

    async fn admin_stop_listener(
        Path(name): Path<String>,
        State(state): State<Self>,
    ) -> Response<Body> {
        match &state.runtime_state {
            Some(runtime_state) => match runtime_state.stop_listener(&name) {
                Some(status) => json_response(&status),
                None => admin_runtime_not_found("listener runtime control is not available"),
            },
            None => admin_runtime_not_found("admin runtime state is not available"),
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

fn gateway_config_snapshot(
    config: &SharedGatewayConfig,
) -> Result<GatewayConfigDocument, Response<Body>> {
    config.read().map(|config| config.clone()).map_err(|_| {
        admin_json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "gateway config unavailable",
            "gateway config lock is poisoned".to_string(),
        )
    })
}

fn gateway_config_not_available() -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::from("gateway config is not available"))
        .expect("static not found response is valid")
}

fn admin_runtime_unavailable(message: &'static str) -> Response<Body> {
    admin_json_error(StatusCode::SERVICE_UNAVAILABLE, "admin runtime unavailable", message)
}

fn admin_runtime_not_found(message: &'static str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::from(message))
        .expect("static not found response is valid")
}

fn admin_json_error(
    status: StatusCode,
    error: &'static str,
    message: impl Into<String>,
) -> Response<Body> {
    let value = AdminErrorResponse { error, message: message.into() };

    match serde_json::to_vec(&value) {
        Ok(body) => Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .expect("static admin error response is valid"),
        Err(error) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from(error.to_string()))
            .expect("static internal server error response is valid"),
    }
}

fn gateway_config_load_error(error: GatewayConfigLoadError) -> Response<Body> {
    let status = match &error {
        GatewayConfigLoadError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
        GatewayConfigLoadError::Parse(_) | GatewayConfigLoadError::Validation(_) => {
            StatusCode::BAD_REQUEST
        }
        GatewayConfigLoadError::Unsupported(_) => StatusCode::NOT_IMPLEMENTED,
    };
    admin_json_error(status, "gateway config reload failed", error.to_string())
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
    use std::{fs, sync::Arc};

    use axum::http::{Method, Request};
    use hyper::body::to_bytes;
    use proxy::factory::{PoolEndpointSnapshot, SessionEntrySnapshot, SessionSnapshot};
    use serde_json::{json, Value};
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
            gateway_config: Some(shared_gateway_config(gateway_config)),
            gateway_config_source: None,
            runtime_state: None,
            metrics_manager: MetricsManager::new(),
        }
    }

    fn gateway_server_with_runtime_state(runtime_state: AdminRuntimeState) -> AxumServer {
        let mut server = gateway_server();
        server.runtime_state = Some(runtime_state);
        server
    }

    fn gateway_server_with_config_source(path: String) -> AxumServer {
        let mut server = gateway_server();
        server.gateway_config_source = Some(GatewayConfigSource::file(path));
        server
    }

    fn write_temp_gateway_config(contents: &str) -> String {
        let path = std::env::temp_dir().join(format!(
            "data-nexus-reload-test-{}-{}.toml",
            std::process::id(),
            unique_test_id()
        ));
        fs::write(&path, contents).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn unique_test_id() -> u128 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    }

    async fn get_json_from(server: AxumServer, path: &str) -> (StatusCode, Value) {
        let response = server
            .routes()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body()).await.unwrap();
        let value = serde_json::from_slice(&body).unwrap();
        (status, value)
    }

    async fn get_json(path: &str) -> (StatusCode, Value) {
        get_json_from(gateway_server(), path).await
    }

    async fn post_json(server: AxumServer, path: &str) -> (StatusCode, Value) {
        let response = server
            .routes()
            .oneshot(Request::builder().method(Method::POST).uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body()).await.unwrap();
        let value = serde_json::from_slice(&body).unwrap();
        (status, value)
    }

    async fn json_body_request(
        server: AxumServer,
        method: Method,
        path: &str,
        value: Value,
    ) -> (StatusCode, Value) {
        let body = serde_json::to_vec(&value).unwrap();
        let response = server
            .routes()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body()).await.unwrap();
        let value = serde_json::from_slice(&body).unwrap();
        (status, value)
    }

    async fn post_json_body(server: AxumServer, path: &str, value: Value) -> (StatusCode, Value) {
        json_body_request(server, Method::POST, path, value).await
    }

    async fn put_json_body(server: AxumServer, path: &str, value: Value) -> (StatusCode, Value) {
        json_body_request(server, Method::PUT, path, value).await
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
    async fn admin_stop_listener_requests_listener_shutdown() {
        let shutdown_handle = ShutdownHandle::new();
        let server = gateway_server_with_runtime_state(AdminRuntimeState::new(vec![(
            "orders-mysql".to_string(),
            shutdown_handle.clone(),
        )]));

        let (status, value) = post_json(server, "/admin/listeners/orders-mysql/stop").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["name"], "orders-mysql");
        assert_eq!(value["shutdown_requested"], true);
        assert!(shutdown_handle.is_shutdown_requested());
    }

    #[tokio::test]
    async fn admin_add_listener_updates_config_and_runtime_registry() {
        let server = gateway_server_with_runtime_state(AdminRuntimeState::default());

        let (status, value) = post_json_body(
            server.clone(),
            "/admin/listeners",
            json!({
                "name": "orders-mysql-extra",
                "listen_addr": "127.0.0.1:0",
                "protocol": "my_sql",
                "service": "orders",
                "auth_policy": null
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["status"], "started");
        assert_eq!(value["name"], "orders-mysql-extra");
        assert_eq!(value["listen_addr"], "127.0.0.1:0");

        let (status, listeners) = get_json_from(server.clone(), "/admin/listeners").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(listeners.as_array().unwrap().len(), 2);
        assert_eq!(listeners[1]["name"], "orders-mysql-extra");

        let (status, pools) = get_json_from(server, "/admin/pools").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(pools[0]["name"], "orders-mysql-extra");
        assert_eq!(pools[0]["capacity"], 64);
    }

    #[tokio::test]
    async fn admin_add_listener_rejects_duplicate_listener_name() {
        let server = gateway_server_with_runtime_state(AdminRuntimeState::default());

        let (status, value) = post_json_body(
            server,
            "/admin/listeners",
            json!({
                "name": "orders-mysql",
                "listen_addr": "127.0.0.1:0",
                "protocol": "my_sql",
                "service": "orders",
                "auth_policy": null
            }),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(value["error"], "gateway listener add failed");
        assert!(value["message"].as_str().unwrap().contains("duplicate listener"));
    }

    #[tokio::test]
    async fn admin_replace_route_policy_updates_shared_config() {
        let server = gateway_server();

        let (status, value) = put_json_body(
            server.clone(),
            "/admin/route-policies/orders-balance",
            json!({
                "name": "orders-balance",
                "kind": "round_robin"
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["status"], "updated");
        assert_eq!(value["name"], "orders-balance");
        assert_eq!(value["kind"], "round_robin");

        let (status, config) = get_json_from(server, "/admin/config").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(config["route_policies"][0]["name"], "orders-balance");
        assert_eq!(config["route_policies"][0]["kind"], "round_robin");
    }

    #[tokio::test]
    async fn admin_replace_route_policy_rejects_missing_policy() {
        let server = gateway_server();

        let (status, value) = put_json_body(
            server,
            "/admin/route-policies/missing",
            json!({
                "name": "missing",
                "kind": "round_robin"
            }),
        )
        .await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(value["error"], "gateway route policy replace failed");
        assert!(value["message"].as_str().unwrap().contains("not defined"));
    }

    #[tokio::test]
    async fn admin_pools_returns_runtime_pool_snapshots() {
        let shutdown_handle = ShutdownHandle::new();
        let pool_snapshotter: PoolSnapshotter = Arc::new(|| PoolSnapshot {
            capacity: 64,
            endpoints: vec![PoolEndpointSnapshot {
                endpoint: "127.0.0.1:3306".to_string(),
                configured: true,
                factory_registered: true,
                idle_connections: 1,
                capacity: 64,
            }],
        });
        let server =
            gateway_server_with_runtime_state(AdminRuntimeState::new_with_pool_snapshotters(vec![
                ("orders-mysql".to_string(), shutdown_handle, Some(pool_snapshotter)),
            ]));

        let (status, value) = get_json_from(server, "/admin/pools").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(value[0]["name"], "orders-mysql");
        assert_eq!(value[0]["capacity"], 64);
        assert_eq!(value[0]["endpoints"][0]["endpoint"], "127.0.0.1:3306");
        assert_eq!(value[0]["endpoints"][0]["idle_connections"], 1);
    }

    #[tokio::test]
    async fn admin_sessions_returns_runtime_session_snapshots() {
        let shutdown_handle = ShutdownHandle::new();
        let session_snapshotter: SessionSnapshotter = Arc::new(|| SessionSnapshot {
            sessions: vec![SessionEntrySnapshot {
                id: 7,
                listener: "orders-mysql".to_string(),
                peer_addr: Some("127.0.0.1:52144".to_string()),
                frontend_protocol: "mysql".to_string(),
                database: Some("orders".to_string()),
            }],
        });
        let server = gateway_server_with_runtime_state(
            AdminRuntimeState::new_with_runtime_snapshotters(vec![(
                "orders-mysql".to_string(),
                shutdown_handle,
                None,
                Some(session_snapshotter),
            )]),
        );

        let (status, value) = get_json_from(server, "/admin/sessions").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(value[0]["id"], 7);
        assert_eq!(value[0]["listener"], "orders-mysql");
        assert_eq!(value[0]["peer_addr"], "127.0.0.1:52144");
        assert_eq!(value[0]["frontend_protocol"], "mysql");
        assert_eq!(value[0]["database"], "orders");
    }

    #[tokio::test]
    async fn admin_reload_validates_current_config_and_reports_no_changes() {
        let path = write_temp_gateway_config(include_str!("../../examples/gateway-config.toml"));
        let server = gateway_server_with_config_source(path.clone());

        let (status, value) = post_json(server, "/admin/reload").await;
        let _ = fs::remove_file(path);

        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["status"], "validated");
        assert_eq!(value["applied"], false);
        assert_eq!(value["changed"], false);
        assert_eq!(value["diff"]["endpoints"]["changed"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn admin_reload_reports_config_diff_without_applying_runtime_changes() {
        let changed_config = include_str!("../../examples/gateway-config.toml")
            .replace("address = \"127.0.0.1:3307\"", "address = \"127.0.0.1:3317\"");
        let path = write_temp_gateway_config(&changed_config);
        let server = gateway_server_with_config_source(path.clone());

        let (status, value) = post_json(server, "/admin/reload").await;
        let _ = fs::remove_file(path);

        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["status"], "validated");
        assert_eq!(value["applied"], false);
        assert_eq!(value["changed"], true);
        assert_eq!(value["diff"]["endpoints"]["changed"][0], "orders-replica");
    }

    #[tokio::test]
    async fn topology_routes_report_missing_gateway_config_for_legacy_state() {
        let response = AxumServer {
            pisa_config: PisaProxyConfig::default(),
            gateway_config: None,
            gateway_config_source: None,
            runtime_state: None,
            metrics_manager: MetricsManager::new(),
        }
        .routes()
        .oneshot(Request::builder().uri("/admin/listeners").body(Body::empty()).unwrap())
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn admin_stop_listener_reports_missing_runtime_control() {
        let shutdown_handle = ShutdownHandle::new();
        let server = gateway_server_with_runtime_state(AdminRuntimeState::new(vec![(
            "orders-mysql".to_string(),
            shutdown_handle,
        )]));

        let response = server
            .routes()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/admin/listeners/missing/stop")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
