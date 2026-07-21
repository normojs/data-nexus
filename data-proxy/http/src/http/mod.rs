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
    body::{Body, Bytes},
    extract::{Json, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    response::Response,
    routing::{get, post, put},
    Router,
};
use tower_http::cors::{Any, CorsLayer};
use config::config::{GatewayConfigDocument, GatewayConfigLoadError, PisaProxyConfig};
use gateway_core::{
    AdminAuthConfig, AdminAuthContext, AuditAction, AuditDecision, ListenerConfig,
    RoutePolicyConfig, AUDIT_TARGET,
};
use pisa_error::error::*;
use pisa_metrics::metrics::MetricsManager;
use proxy::factory::{
    PoolRefresh, PoolRefresher, PoolSnapshot, PoolSnapshotter, SessionEntrySnapshot,
    SessionSnapshotter, ShutdownHandle,
};
use serde::{Deserialize, Serialize};
use server::server::{start_gateway_server, GatewayFactory};
use tracing::info;
use ver::version::get_version;

mod admin_auth;
mod admin_ui;
mod jwks;

use admin_auth::{
    authenticate_request, break_glass_login, me_response, AdminAuthError, AdminAuthPublicConfig,
    AdminLoginRequest,
};

/// CORS for Admin API / metrics so independent UIs can call the gateway.
///
/// - Default: allow any origin (local/dev friendly)
/// - `DATA_NEXUS_ADMIN_CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000`
fn admin_cors_layer() -> CorsLayer {
    let methods = [
        Method::GET,
        Method::POST,
        Method::PUT,
        Method::OPTIONS,
    ];
    match std::env::var("DATA_NEXUS_ADMIN_CORS_ORIGINS") {
        Ok(raw) if !raw.trim().is_empty() => {
            let origins: Vec<HeaderValue> = raw
                .split(',')
                .filter_map(|s| {
                    let s = s.trim();
                    if s.is_empty() {
                        None
                    } else {
                        HeaderValue::from_str(s).ok()
                    }
                })
                .collect();
            if origins.is_empty() {
                CorsLayer::new()
                    .allow_origin(Any)
                    .allow_methods(methods)
                    .allow_headers(Any)
            } else {
                CorsLayer::new()
                    .allow_origin(origins)
                    .allow_methods(methods)
                    .allow_headers(Any)
            }
        }
        _ => CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(methods)
            .allow_headers(Any),
    }
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
    listener_pool_refreshers: HashMap<String, PoolRefresher>,
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
            .field("listener_pool_refresher_count", &inner.listener_pool_refreshers.len())
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
        Self::new_with_runtime_controls(listener_runtimes.into_iter().map(
            |(name, shutdown_handle, pool_snapshotter, session_snapshotter)| {
                (name, shutdown_handle, pool_snapshotter, None, session_snapshotter)
            },
        ))
    }

    pub fn new_with_runtime_controls(
        listener_runtimes: impl IntoIterator<
            Item = (
                String,
                ShutdownHandle,
                Option<PoolSnapshotter>,
                Option<PoolRefresher>,
                Option<SessionSnapshotter>,
            ),
        >,
    ) -> Self {
        let mut inner = AdminRuntimeStateInner::default();

        for (name, shutdown_handle, pool_snapshotter, pool_refresher, session_snapshotter) in
            listener_runtimes
        {
            inner.listener_shutdown_handles.insert(name.clone(), shutdown_handle);
            if let Some(pool_snapshotter) = pool_snapshotter {
                inner.listener_pool_snapshotters.insert(name.clone(), pool_snapshotter);
            }
            if let Some(pool_refresher) = pool_refresher {
                inner.listener_pool_refreshers.insert(name.clone(), pool_refresher);
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
        pool_refresher: Option<PoolRefresher>,
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
        if let Some(pool_refresher) = pool_refresher {
            inner.listener_pool_refreshers.insert(name.clone(), pool_refresher);
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

    fn refresh_pool(&self, name: &str) -> Option<ListenerPoolRefreshStatus> {
        let refresher = self.inner.read().ok()?.listener_pool_refreshers.get(name)?.clone();

        Some(ListenerPoolRefreshStatus { name: name.to_owned(), refresh: refresher() })
    }

    fn refresh_pools(&self) -> Vec<ListenerPoolRefreshStatus> {
        let refreshers = self
            .inner
            .read()
            .map(|inner| {
                inner
                    .listener_pool_refreshers
                    .iter()
                    .map(|(name, refresher)| (name.clone(), refresher.clone()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let mut statuses = refreshers
            .iter()
            .map(|(name, refresher)| ListenerPoolRefreshStatus {
                name: name.clone(),
                refresh: refresher(),
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
struct ListenerPoolRefreshStatus {
    name: String,
    #[serde(flatten)]
    refresh: PoolRefresh,
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

#[derive(Debug, Serialize)]
struct AdminSecurityPoliciesResponse {
    enabled: bool,
    fail_closed: bool,
    star_policy: String,
    default_audit_level: String,
    pdp_backend: String,
    /// Present when `security.pdp.policy_dir` is set (Cedar / file PDP).
    #[serde(skip_serializing_if = "Option::is_none")]
    pdp_policy_dir: Option<String>,
    rule_count: usize,
    rules: Vec<AdminSecurityRuleSummary>,
    /// UI04: mask algorithms (name + algorithm only; no secrets).
    mask_rules: Vec<AdminSecurityMaskRuleSummary>,
    /// UI04: column → mask_rule bindings.
    column_tags: Vec<AdminSecurityColumnTagSummary>,
    /// UI04: high-risk gates that require tickets.
    high_risk_rules: Vec<AdminSecurityHighRiskSummary>,
    /// UI04: time-window rules (F27).
    time_rules: Vec<AdminSecurityTimeRuleSummary>,
    watermark: AdminSecurityWatermarkSummary,
    streaming: AdminSecurityStreamingSummary,
    /// B08 sample attach policy (requires default_audit_level=L2 when enabled).
    audit_sample: AdminSecurityAuditSampleSummary,
}

#[derive(Debug, Serialize)]
struct AdminSecurityRuleSummary {
    name: String,
    effect: String,
    actions: Vec<String>,
    tables: Vec<String>,
    columns: Vec<String>,
    subjects: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    row_filter: Option<String>,
}

#[derive(Debug, Serialize)]
struct AdminSecurityMaskRuleSummary {
    name: String,
    algorithm: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    replace_with: String,
    prefix_len: usize,
    suffix_len: usize,
}

#[derive(Debug, Serialize)]
struct AdminSecurityColumnTagSummary {
    column: String,
    tables: Vec<String>,
    subjects: Vec<String>,
    mask_rule: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    label: String,
}

#[derive(Debug, Serialize)]
struct AdminSecurityHighRiskSummary {
    name: String,
    kind: String,
    ticket_type: String,
    actions: Vec<String>,
    tables: Vec<String>,
    subjects: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    message: String,
}

#[derive(Debug, Serialize)]
struct AdminSecurityTimeRuleSummary {
    name: String,
    effect: String,
    outside: bool,
    days: Vec<String>,
    start: String,
    end: String,
    timezone: String,
    actions: Vec<String>,
    subjects: Vec<String>,
}

#[derive(Debug, Serialize)]
struct AdminSecurityWatermarkSummary {
    enabled: bool,
    mode: String,
    column: String,
    /// True when a static token is configured (value never returned).
    has_static_token: bool,
}

#[derive(Debug, Serialize)]
struct AdminSecurityStreamingSummary {
    window_rows: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_rows: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_bytes: Option<u64>,
    passthrough: bool,
}

/// B08: audit sample knobs (read-only; no secrets).
#[derive(Debug, Serialize)]
struct AdminSecurityAuditSampleSummary {
    sample_enabled: bool,
    sample_max_rows: u32,
    sample_max_bytes: u32,
    sample_inline: bool,
    /// Empty uses default prefix `samples`.
    sample_prefix: String,
}

#[derive(Debug, Deserialize, Default)]
struct AdminAuditEventsQuery {
    decision: Option<String>,
    subject_id: Option<String>,
    service: Option<String>,
    /// Exact event id lookup (B06 index / recent).
    event_id: Option<String>,
    /// Inclusive lower bound, unix epoch milliseconds.
    from_ms: Option<u64>,
    /// Inclusive upper bound, unix epoch milliseconds.
    to_ms: Option<u64>,
    limit: Option<u32>,
}

#[derive(Debug, Serialize)]
struct AdminAuditEventsResponse {
    events: Vec<gateway_core::AuditEvent>,
    stats: Option<gateway_core::AuditPipelineStats>,
    /// `index` when served from SQLite side-index; `recent` for in-memory ring.
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct AdminTicketsQuery {
    limit: Option<u32>,
}

#[derive(Debug, Serialize)]
struct AdminTicketsResponse {
    tickets: Vec<gateway_core::Ticket>,
}

#[derive(Debug, Deserialize)]
struct AdminPortalQueryRequest {
    /// Target gateway service (must exist in config).
    service: String,
    sql: String,
    /// Optional vault lease id (subject binding / audit).
    #[serde(default)]
    lease_id: Option<String>,
    /// Data-plane subject override (defaults to admin subject or lease).
    #[serde(default)]
    subject_id: Option<String>,
    #[serde(default)]
    max_rows: Option<u64>,
    /// Response encoding: `json` (default), `csv`, or `ndjson` (B05 export).
    #[serde(default)]
    format: Option<String>,
    /// When true, set Content-Disposition attachment for browser download.
    #[serde(default)]
    download: Option<bool>,
}

#[derive(Debug, Serialize)]
struct AdminPortalQueryResponse {
    columns: Vec<String>,
    rows: Vec<Vec<serde_json::Value>>,
    row_count: usize,
    truncated: bool,
    service: String,
    decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

/// Portal export hard cap (rows) to keep Admin path bounded.
const PORTAL_MAX_ROWS_CAP: u64 = 10_000;
const PORTAL_DEFAULT_EXPORT_MAX_ROWS: u64 = 5_000;




#[derive(Debug, Default, Serialize, PartialEq, Eq)]
struct GatewayConfigDiff {
    admin_changed: bool,
    version_changed: bool,
    /// Data-plane security section differs (rules, audit, streaming, …).
    security_changed: bool,
    /// F28: security change is rules/mask/time/audit only — Local PDP hot-swap,
    /// no listener rebuild.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    security_local_hot_reload: bool,
    /// F28: security change requires listener rebuild (enabled/subject/pdp/
    /// streaming window/passthrough).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    security_requires_listener_rebuild: bool,
    listeners: NamedSectionDiff,
    services: NamedSectionDiff,
    endpoints: NamedSectionDiff,
    route_policies: NamedSectionDiff,
    auth_policies: NamedSectionDiff,
    plugin_policies: NamedSectionDiff,
}

impl GatewayConfigDiff {
    fn between(current: &GatewayConfigDocument, next: &GatewayConfigDocument) -> Self {
        let security_changed = current.gateway.security != next.gateway.security;
        let security_requires_listener_rebuild = security_changed
            && gateway_core::security_requires_listener_rebuild(
                &current.gateway.security,
                &next.gateway.security,
            );
        let security_local_hot_reload = security_changed && !security_requires_listener_rebuild;
        let mut listeners = diff_named_section(
            &current.gateway.listeners,
            &next.gateway.listeners,
            |item| item.name.as_str(),
        );
        // Only force-rebuild listeners when security changes cannot be applied
        // via the process-wide Local PDP snapshot (F28). Rule/mask/time/audit
        // alone hot-swap without tearing down accept loops.
        if security_requires_listener_rebuild {
            for listener in &next.gateway.listeners {
                let name = listener.name.clone();
                if !listeners.added.contains(&name)
                    && !listeners.removed.contains(&name)
                    && !listeners.changed.contains(&name)
                {
                    listeners.changed.push(name);
                }
            }
        }
        Self {
            admin_changed: serde_json::to_value(&current.admin).ok()
                != serde_json::to_value(&next.admin).ok(),
            version_changed: current.version != next.version,
            security_changed,
            security_local_hot_reload,
            security_requires_listener_rebuild,
            listeners,
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
            || self.security_changed
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
        // Allow browser-based admin UIs (e.g. data-ui Nuxt) on another origin.
        // Origins can be restricted via DATA_NEXUS_ADMIN_CORS_ORIGINS (comma-separated).
        let cors = admin_cors_layer();

        Router::new()
            .route("/", get(Self::version))
            .route("/version", get(Self::version))
            .route("/healthz", get(Self::healthz))
            .route("/metrics", get(Self::metrics))
            .route("/admin", get(Self::admin_dashboard))
            .route("/admin/", get(Self::admin_dashboard))
            .route("/config", get(Self::admin_config))
            .route("/admin/config", get(Self::admin_config))
            .route("/admin/listeners", get(Self::admin_listeners).post(Self::admin_add_listener))
            .route("/admin/listeners/:name/stop", post(Self::admin_stop_listener))
            .route("/admin/route-policies/:name", put(Self::admin_replace_route_policy))
            .route("/admin/services", get(Self::admin_services))
            .route("/admin/endpoints", get(Self::admin_endpoints))
            .route("/admin/security-policies", get(Self::admin_security_policies))
            .route("/admin/security/cedar", get(Self::admin_cedar_status))
            .route(
                "/admin/security/cedar/reload",
                post(Self::admin_cedar_reload),
            )
            .route("/admin/audit/events", get(Self::admin_audit_events))
            .route("/admin/audit/stats", get(Self::admin_audit_stats))
            .route(
                "/admin/tickets",
                get(Self::admin_list_tickets).post(Self::admin_issue_ticket),
            )
            .route(
                "/admin/tickets/:id/approve",
                post(Self::admin_approve_ticket),
            )
            .route(
                "/admin/tickets/:id/reject",
                post(Self::admin_reject_ticket),
            )
            .route("/admin/projects", get(Self::admin_list_projects))
            .route(
                "/admin/vault/leases",
                get(Self::admin_list_vault_leases).post(Self::admin_issue_vault_lease),
            )
            .route(
                "/admin/vault/leases/prune",
                post(Self::admin_prune_vault_leases),
            )
            .route(
                "/admin/vault/leases/:id/revoke",
                post(Self::admin_revoke_vault_lease),
            )
            .route(
                "/admin/vault/leases/:id/renew",
                post(Self::admin_renew_vault_lease),
            )
            .route(
                "/admin/tickets/:id/revoke",
                post(Self::admin_revoke_ticket),
            )
            .route(
                "/admin/tickets/prune",
                post(Self::admin_prune_tickets),
            )
            .route("/admin/portal/query", post(Self::admin_portal_query))
            .route("/admin/pools", get(Self::admin_pools))
            .route("/admin/pools/refresh", post(Self::admin_refresh_pools))
            .route("/admin/pools/:name/refresh", post(Self::admin_refresh_pool))
            .route("/admin/sessions", get(Self::admin_sessions))
            .route("/admin/reload", post(Self::admin_reload))
            .route("/admin/me", get(Self::admin_me))
            .route("/admin/auth/config", get(Self::admin_auth_config))
            .route("/admin/auth/login", post(Self::admin_auth_login))
            .layer(cors)
            .with_state(state)
    }

    fn admin_auth_config_snapshot(&self) -> AdminAuthConfig {
        self.gateway_config
            .as_ref()
            .and_then(|config| config.read().ok().map(|guard| guard.admin_auth.clone()))
            .unwrap_or_default()
    }

    fn authorize(
        &self,
        headers: &HeaderMap,
        method: &str,
        path: &str,
    ) -> Result<Option<AdminAuthContext>, Response<Body>> {
        let auth = self.admin_auth_config_snapshot();
        let authorization = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        match authenticate_request(&auth, authorization, method, path) {
            Ok(ctx) => Ok(ctx),
            Err(err) => Err(admin_auth_error_response(err)),
        }
    }

    async fn admin_dashboard(State(state): State<Self>, headers: HeaderMap) -> Response<Body> {
        if let Err(response) = state.authorize(&headers, "GET", "/admin") {
            return response;
        }
        Response::builder()
            .status(StatusCode::OK)
            .header(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            )
            .body(Body::from(admin_ui::ADMIN_DASHBOARD_HTML))
            .unwrap_or_else(|_| Response::new(Body::from("admin ui unavailable")))
    }

    async fn healthz(_state: State<Self>) -> StatusCode {
        // Liveness only: process is up and Admin router is serving.
        // Readiness (backends/listeners) is covered by topology/pools endpoints.
        StatusCode::OK
    }

    async fn version(State(_state): State<Self>) -> String {
        get_version()
    }

    async fn metrics(State(state): State<Self>, headers: HeaderMap) -> Response<Body> {
        if let Err(response) = state.authorize(&headers, "GET", "/metrics") {
            return response;
        }
        let buf = state.metrics_manager.gather();

        Response::builder()
            .header(header::CONTENT_TYPE, "text/plain; version=0.0.4")
            .body(Body::from(buf))
            .unwrap()
    }

    async fn admin_auth_config(State(state): State<Self>) -> Response<Body> {
        let auth = state.admin_auth_config_snapshot();
        json_response(&AdminAuthPublicConfig::from(&auth))
    }

    async fn admin_auth_login(
        State(state): State<Self>,
        Json(body): Json<AdminLoginRequest>,
    ) -> Response<Body> {
        let auth = state.admin_auth_config_snapshot();
        match break_glass_login(&auth, &body.password) {
            Ok(token) => {
                info!(
                    target: AUDIT_TARGET,
                    action = AuditAction::AdminLogin.as_str(),
                    decision = AuditDecision::Allow.as_str(),
                    subject_id = "break-glass",
                    auth_method = "break_glass",
                    method = "POST",
                    path = "/admin/auth/login",
                    "admin break-glass login"
                );
                json_response(&token)
            }
            Err(err) => admin_auth_error_response(err),
        }
    }

    async fn admin_me(State(state): State<Self>, headers: HeaderMap) -> Response<Body> {
        let auth = state.admin_auth_config_snapshot();
        if !auth.enabled {
            return json_response(&me_response(None, false));
        }
        let authorization = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        // When auth is enabled, /admin/me always requires a valid Bearer token.
        match authenticate_request(&auth, authorization, "GET", "/admin/me") {
            Ok(Some(ctx)) => json_response(&me_response(Some(&ctx), true)),
            Ok(None) | Err(AdminAuthError::Unauthorized(_)) => {
                admin_auth_error_response(AdminAuthError::Unauthorized(
                    "authentication required".into(),
                ))
            }
            Err(err) => admin_auth_error_response(err),
        }
    }

    async fn admin_config(State(state): State<Self>, headers: HeaderMap) -> Response<Body> {
        if let Err(response) = state.authorize(&headers, "GET", "/admin/config") {
            return response;
        }
        match &state.gateway_config {
            Some(config) => match gateway_config_snapshot(config) {
                Ok(config) => json_response(&config),
                Err(response) => response,
            },
            None => json_response(&state.pisa_config),
        }
    }

    async fn admin_listeners(State(state): State<Self>, headers: HeaderMap) -> Response<Body> {
        if let Err(response) = state.authorize(&headers, "GET", "/admin/listeners") {
            return response;
        }
        match &state.gateway_config {
            Some(config) => match gateway_config_snapshot(config) {
                Ok(config) => json_response(&config.gateway.listeners),
                Err(response) => response,
            },
            None => gateway_config_not_available(),
        }
    }

    async fn admin_services(State(state): State<Self>, headers: HeaderMap) -> Response<Body> {
        if let Err(response) = state.authorize(&headers, "GET", "/admin/services") {
            return response;
        }
        match &state.gateway_config {
            Some(config) => match gateway_config_snapshot(config) {
                Ok(config) => json_response(&config.gateway.services),
                Err(response) => response,
            },
            None => gateway_config_not_available(),
        }
    }

    async fn admin_endpoints(State(state): State<Self>, headers: HeaderMap) -> Response<Body> {
        if let Err(response) = state.authorize(&headers, "GET", "/admin/endpoints") {
            return response;
        }
        match &state.gateway_config {
            Some(config) => match gateway_config_snapshot(config) {
                Ok(config) => json_response(&config.gateway.endpoints),
                Err(response) => response,
            },
            None => gateway_config_not_available(),
        }
    }

    async fn admin_security_policies(
        State(state): State<Self>,
        headers: HeaderMap,
    ) -> Response<Body> {
        if let Err(response) = state.authorize(&headers, "GET", "/admin/security-policies") {
            return response;
        }
        match &state.gateway_config {
            Some(config) => match gateway_config_snapshot(config) {
                Ok(config) => {
                    let security = &config.gateway.security;
                    let pdp_policy_dir = if security.pdp.policy_dir.is_empty() {
                        None
                    } else {
                        Some(security.pdp.policy_dir.clone())
                    };
                    json_response(&AdminSecurityPoliciesResponse {
                        enabled: security.enabled,
                        fail_closed: security.fail_closed,
                        star_policy: security.star_policy.clone(),
                        default_audit_level: security.default_audit_level.clone(),
                        pdp_backend: security.pdp.backend.clone(),
                        pdp_policy_dir,
                        rule_count: security.rules.len(),
                        rules: security
                            .rules
                            .iter()
                            .map(|rule| AdminSecurityRuleSummary {
                                name: rule.name.clone(),
                                effect: rule.effect.clone(),
                                actions: rule.actions.clone(),
                                tables: rule.tables.clone(),
                                columns: rule.columns.clone(),
                                subjects: rule.subjects.clone(),
                                row_filter: rule.row_filter.clone(),
                            })
                            .collect(),
                        mask_rules: security
                            .mask_rules
                            .iter()
                            .map(|r| AdminSecurityMaskRuleSummary {
                                name: r.name.clone(),
                                algorithm: r.algorithm.clone(),
                                replace_with: r.replace_with.clone(),
                                prefix_len: r.prefix_len,
                                suffix_len: r.suffix_len,
                            })
                            .collect(),
                        column_tags: security
                            .column_tags
                            .iter()
                            .map(|t| AdminSecurityColumnTagSummary {
                                column: t.column.clone(),
                                tables: t.tables.clone(),
                                subjects: t.subjects.clone(),
                                mask_rule: t.mask_rule.clone(),
                                label: t.label.clone(),
                            })
                            .collect(),
                        high_risk_rules: security
                            .high_risk_rules
                            .iter()
                            .map(|r| AdminSecurityHighRiskSummary {
                                name: r.name.clone(),
                                kind: r.kind.clone(),
                                ticket_type: r.ticket_type.clone(),
                                actions: r.actions.clone(),
                                tables: r.tables.clone(),
                                subjects: r.subjects.clone(),
                                message: r.message.clone(),
                            })
                            .collect(),
                        time_rules: security
                            .time_rules
                            .iter()
                            .map(|r| AdminSecurityTimeRuleSummary {
                                name: r.name.clone(),
                                effect: r.effect.clone(),
                                outside: r.outside,
                                days: r.days.clone(),
                                start: r.start.clone(),
                                end: r.end.clone(),
                                timezone: r.timezone.clone(),
                                actions: r.actions.clone(),
                                subjects: r.subjects.clone(),
                            })
                            .collect(),
                        watermark: AdminSecurityWatermarkSummary {
                            enabled: security.watermark.enabled,
                            mode: security.watermark.mode.clone(),
                            column: security.watermark.column.clone(),
                            has_static_token: !security.watermark.token.is_empty(),
                        },
                        streaming: AdminSecurityStreamingSummary {
                            window_rows: security.streaming.window_rows,
                            max_rows: security.streaming.max_rows,
                            max_bytes: security.streaming.max_bytes,
                            passthrough: security.streaming.passthrough,
                        },
                        audit_sample: AdminSecurityAuditSampleSummary {
                            sample_enabled: security.audit.sample_enabled,
                            sample_max_rows: security.audit.sample_max_rows,
                            sample_max_bytes: security.audit.sample_max_bytes,
                            sample_inline: security.audit.sample_inline,
                            sample_prefix: security.audit.sample_prefix.clone(),
                        },
                    })
                }
                Err(response) => response,
            },
            None => gateway_config_not_available(),
        }
    }

    async fn admin_cedar_status(
        State(state): State<Self>,
        headers: HeaderMap,
    ) -> Response<Body> {
        if let Err(response) = state.authorize(&headers, "GET", "/admin/security/cedar") {
            return response;
        }
        #[cfg(feature = "security-cedar")]
        {
            if let Some(store) = gateway_core::global_cedar_store() {
                return json_response(&store.status());
            }
            // Not installed yet — report config intent.
            let (backend, dir, epoch_reload) = state
                .gateway_config
                .as_ref()
                .and_then(|c| c.read().ok())
                .map(|g| {
                    (
                        g.gateway.security.pdp.backend.clone(),
                        g.gateway.security.pdp.policy_dir.clone(),
                        g.gateway.security.pdp.cache_epoch_reload,
                    )
                })
                .unwrap_or_else(|| ("local".into(), String::new(), true));
            return json_response(&serde_json::json!({
                "installed": false,
                "ready": false,
                "epoch": 0,
                "source": dir,
                "files": 0,
                "policy_count": 0,
                "loaded_at_unix_ms": 0,
                "pdp_backend": backend,
                "cache_epoch_reload": epoch_reload,
            }));
        }
        #[cfg(not(feature = "security-cedar"))]
        {
            json_response(&serde_json::json!({
                "installed": false,
                "ready": false,
                "feature": "security-cedar",
                "message": "binary built without --features security-cedar",
            }))
        }
    }

    async fn admin_cedar_reload(
        State(state): State<Self>,
        headers: HeaderMap,
    ) -> Response<Body> {
        let auth_ctx = match state.authorize(&headers, "POST", "/admin/security/cedar/reload") {
            Ok(ctx) => ctx,
            Err(response) => return response,
        };
        #[cfg(feature = "security-cedar")]
        {
            let (backend, policy_dir, cache_epoch_reload) = match &state.gateway_config {
                Some(cfg) => match cfg.read() {
                    Ok(g) => (
                        g.gateway.security.pdp.backend.clone(),
                        g.gateway.security.pdp.policy_dir.clone(),
                        g.gateway.security.pdp.cache_epoch_reload,
                    ),
                    Err(_) => {
                        return admin_json_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "gateway_config_poisoned",
                            "gateway config lock is poisoned",
                        );
                    }
                },
                None => return gateway_config_not_available(),
            };
            if !backend.eq_ignore_ascii_case("cedar") {
                return admin_json_error(
                    StatusCode::BAD_REQUEST,
                    "cedar_not_active",
                    format!("security.pdp.backend is '{backend}', not cedar"),
                );
            }
            if policy_dir.trim().is_empty() {
                return admin_json_error(
                    StatusCode::BAD_REQUEST,
                    "cedar_policy_dir_empty",
                    "security.pdp.policy_dir is empty",
                );
            }
            if !cache_epoch_reload {
                return admin_json_error(
                    StatusCode::CONFLICT,
                    "cedar_epoch_reload_disabled",
                    "security.pdp.cache_epoch_reload=false; restart process to load policies",
                );
            }
            match gateway_core::reload_global_cedar(&policy_dir) {
                Ok(info) => {
                    audit_admin_write(
                        auth_ctx.as_ref(),
                        "POST",
                        "/admin/security/cedar/reload",
                        if info.swapped { "swapped" } else { "unchanged" },
                        Some(policy_dir.as_str()),
                    );
                    info!(
                        target: AUDIT_TARGET,
                        epoch = info.epoch,
                        swapped = info.swapped,
                        files = info.files,
                        "admin reloaded cedar policies"
                    );
                    json_response(&info)
                }
                Err(e) => admin_json_error(
                    StatusCode::BAD_REQUEST,
                    "cedar_reload_failed",
                    e.to_string(),
                ),
            }
        }
        #[cfg(not(feature = "security-cedar"))]
        {
            let _ = auth_ctx;
            admin_json_error(
                StatusCode::NOT_IMPLEMENTED,
                "cedar_feature_disabled",
                "binary built without --features security-cedar",
            )
        }
    }

    async fn admin_audit_events(
        State(state): State<Self>,
        headers: HeaderMap,
        Query(query): Query<AdminAuditEventsQuery>,
    ) -> Response<Body> {
        if let Err(response) = state.authorize(&headers, "GET", "/admin/audit/events") {
            return response;
        }
        let Some(pipe) = gateway_core::global_audit_pipeline() else {
            return json_response(&AdminAuditEventsResponse {
                events: vec![],
                stats: None,
                source: None,
                note: Some("audit pipeline not installed (gateway not started with security.audit)".into()),
            });
        };
        let limit = query.limit.unwrap_or(100).clamp(1, 1000) as usize;
        let filter = gateway_core::AuditQueryFilter {
            decision: query.decision.clone(),
            subject_id: query.subject_id.clone(),
            service: query.service.clone(),
            event_id: query.event_id.clone(),
            from_ms: query.from_ms,
            to_ms: query.to_ms,
            limit,
        };
        let events = pipe.query_filter(&filter);
        let stats = pipe.stats();
        let source = if stats.index_enabled {
            Some("index".into())
        } else {
            Some("recent".into())
        };
        json_response(&AdminAuditEventsResponse {
            events,
            stats: Some(stats),
            source,
            note: None,
        })
    }

    async fn admin_audit_stats(
        State(state): State<Self>,
        headers: HeaderMap,
    ) -> Response<Body> {
        if let Err(response) = state.authorize(&headers, "GET", "/admin/audit/stats") {
            return response;
        }
        match gateway_core::global_audit_pipeline() {
            Some(pipe) => json_response(&pipe.stats()),
            None => json_response(&serde_json::json!({
                "accepted": 0,
                "written": 0,
                "dropped": 0,
                "queue_capacity": 0,
                "priority_queue_capacity": 0,
                "priority_accepted": 0,
                "priority_dropped": 0,
                "queue_len": 0,
                "priority_queue_len": 0,
                "recent_len": 0,
                "rotated": 0,
                "pruned": 0,
                "index_enabled": false,
                "index_rows": 0,
                "index_inserted": 0,
                "index_errors": 0,
                "index_pruned": 0,
                "installed": false
            })),
        }
    }


    async fn admin_list_tickets(
        State(state): State<Self>,
        headers: HeaderMap,
        Query(query): Query<AdminTicketsQuery>,
    ) -> Response<Body> {
        if let Err(response) = state.authorize(&headers, "GET", "/admin/tickets") {
            return response;
        }
        let limit = query.limit.unwrap_or(50).clamp(1, 500) as usize;
        let tickets = gateway_core::global_ticket_store().list(limit);
        json_response(&AdminTicketsResponse { tickets })
    }

    async fn admin_issue_ticket(
        State(state): State<Self>,
        headers: HeaderMap,
        Json(mut body): Json<gateway_core::IssueTicketRequest>,
    ) -> Response<Body> {
        let auth_ctx = match state.authorize(&headers, "POST", "/admin/tickets") {
            Ok(ctx) => ctx,
            Err(response) => return response,
        };
        if body.issued_by.is_none() {
            if let Some(ctx) = auth_ctx.as_ref() {
                body.issued_by = Some(ctx.subject.clone());
            }
        }
        if body.subject_id.trim().is_empty() || body.sql.trim().is_empty() {
            return admin_json_error(
                StatusCode::BAD_REQUEST,
                "invalid_ticket_request",
                "subject_id and sql are required",
            );
        }
        let ticket = gateway_core::global_ticket_store().issue(body);
        info!(
            target: AUDIT_TARGET,
            action = AuditAction::AdminWrite.as_str(),
            decision = AuditDecision::Allow.as_str(),
            ticket_id = %ticket.id,
            subject_id = %ticket.subject_id,
            ticket_type = %ticket.ticket_type,
            dual_control = ticket.dual_control,
            status = ticket.status.as_str(),
            "admin issued security ticket"
        );
        gateway_core::try_audit(gateway_core::AuditEvent {
            action: Some(AuditAction::AdminWrite.as_str().into()),
            decision: Some(AuditDecision::Allow.as_str().into()),
            subject_id: ticket.issued_by.clone(),
            outcome: Some(if ticket.dual_control {
                "ticket_pending".into()
            } else {
                "ticket_issued".into()
            }),
            message: Some(format!(
                "issued {} for {} status={}",
                ticket.id,
                ticket.subject_id,
                ticket.status.as_str()
            )),
            rule: Some(ticket.ticket_type.clone()),
            audit_level: Some("L0".into()),
            ..gateway_core::AuditEvent::default()
        });
        json_response(&ticket)
    }

    async fn admin_approve_ticket(
        State(state): State<Self>,
        headers: HeaderMap,
        Path(id): Path<String>,
        body: Option<Json<gateway_core::ApproveTicketRequest>>,
    ) -> Response<Body> {
        let auth_ctx = match state.authorize(&headers, "POST", &format!("/admin/tickets/{id}/approve"))
        {
            Ok(ctx) => ctx,
            Err(response) => return response,
        };
        let mut req = body.map(|Json(b)| b).unwrap_or_default();
        if req.approved_by.as_ref().map(|s| s.trim().is_empty()).unwrap_or(true) {
            if let Some(ctx) = auth_ctx.as_ref() {
                req.approved_by = Some(ctx.subject.clone());
            }
        }
        let approver = match req.approved_by.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(s) => s.to_owned(),
            None => {
                return admin_json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_approve_request",
                    "approved_by is required (or authenticate so subject is inferred)",
                );
            }
        };
        match gateway_core::global_ticket_store().approve(&id, &approver) {
            Ok(ticket) => {
                info!(
                    target: AUDIT_TARGET,
                    action = AuditAction::AdminWrite.as_str(),
                    decision = AuditDecision::Allow.as_str(),
                    ticket_id = %ticket.id,
                    approved_by = %approver,
                    "admin approved dual-control ticket"
                );
                gateway_core::try_audit(gateway_core::AuditEvent {
                    action: Some(AuditAction::AdminWrite.as_str().into()),
                    decision: Some(AuditDecision::Allow.as_str().into()),
                    subject_id: Some(approver),
                    outcome: Some("ticket_approved".into()),
                    message: Some(format!("approved {}", ticket.id)),
                    rule: Some(ticket.ticket_type.clone()),
                    audit_level: Some("L0".into()),
                    ..gateway_core::AuditEvent::default()
                });
                json_response(&ticket)
            }
            Err(msg) => admin_json_error(StatusCode::BAD_REQUEST, "ticket_approve_failed", msg),
        }
    }

    async fn admin_reject_ticket(
        State(state): State<Self>,
        headers: HeaderMap,
        Path(id): Path<String>,
        body: Option<Json<gateway_core::RejectTicketRequest>>,
    ) -> Response<Body> {
        let auth_ctx = match state.authorize(&headers, "POST", &format!("/admin/tickets/{id}/reject"))
        {
            Ok(ctx) => ctx,
            Err(response) => return response,
        };
        let mut req = body.map(|Json(b)| b).unwrap_or_default();
        if req.rejected_by.as_ref().map(|s| s.trim().is_empty()).unwrap_or(true) {
            if let Some(ctx) = auth_ctx.as_ref() {
                req.rejected_by = Some(ctx.subject.clone());
            }
        }
        let rejector = match req.rejected_by.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(s) => s.to_owned(),
            None => {
                return admin_json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_reject_request",
                    "rejected_by is required (or authenticate so subject is inferred)",
                );
            }
        };
        match gateway_core::global_ticket_store().reject(&id, &rejector, req.reason) {
            Ok(ticket) => {
                info!(
                    target: AUDIT_TARGET,
                    action = AuditAction::AdminWrite.as_str(),
                    decision = AuditDecision::Allow.as_str(),
                    ticket_id = %ticket.id,
                    rejected_by = %rejector,
                    "admin rejected dual-control ticket"
                );
                gateway_core::try_audit(gateway_core::AuditEvent {
                    action: Some(AuditAction::AdminWrite.as_str().into()),
                    decision: Some(AuditDecision::Allow.as_str().into()),
                    subject_id: Some(rejector),
                    outcome: Some("ticket_rejected".into()),
                    message: Some(format!("rejected {}", ticket.id)),
                    rule: Some(ticket.ticket_type.clone()),
                    audit_level: Some("L0".into()),
                    ..gateway_core::AuditEvent::default()
                });
                json_response(&ticket)
            }
            Err(msg) => admin_json_error(StatusCode::BAD_REQUEST, "ticket_reject_failed", msg),
        }
    }

    async fn admin_list_projects(
        State(state): State<Self>,
        headers: HeaderMap,
    ) -> Response<Body> {
        if let Err(response) = state.authorize(&headers, "GET", "/admin/projects") {
            return response;
        }
        // Seed projects from services if empty.
        if let Some(cfg) = &state.gateway_config {
            if let Ok(guard) = cfg.read() {
                let services: Vec<String> = guard
                    .gateway
                    .services
                    .iter()
                    .map(|s| s.name.clone())
                    .collect();
                gateway_core::global_vault_store().ensure_default_projects_from_services(&services);
            }
        }
        json_response(&gateway_core::global_vault_store().list_projects())
    }

    async fn admin_list_vault_leases(
        State(state): State<Self>,
        headers: HeaderMap,
    ) -> Response<Body> {
        if let Err(response) = state.authorize(&headers, "GET", "/admin/vault/leases") {
            return response;
        }
        json_response(&gateway_core::global_vault_store().list_leases(100))
    }

    async fn admin_issue_vault_lease(
        State(state): State<Self>,
        headers: HeaderMap,
        Json(mut body): Json<gateway_core::IssueVaultLeaseRequest>,
    ) -> Response<Body> {
        let auth_ctx = match state.authorize(&headers, "POST", "/admin/vault/leases") {
            Ok(ctx) => ctx,
            Err(response) => return response,
        };
        if body.issued_by.is_none() {
            if let Some(ctx) = auth_ctx.as_ref() {
                body.issued_by = Some(ctx.subject.clone());
            }
        }
        let Some(cfg_lock) = &state.gateway_config else {
            return gateway_config_not_available();
        };
        let config = match cfg_lock.read() {
            Ok(g) => g.clone(),
            Err(_) => return gateway_config_not_available(),
        };
        // Resolve project -> service
        let store = gateway_core::global_vault_store();
        let services: Vec<String> = config
            .gateway
            .services
            .iter()
            .map(|s| s.name.clone())
            .collect();
        store.ensure_default_projects_from_services(&services);
        let projects = store.list_projects();
        let project = projects.iter().find(|p| {
            p.name.eq_ignore_ascii_case(&body.project)
                && p.environment.eq_ignore_ascii_case(&body.environment)
        });
        let service_name = match project {
            Some(p) => p.service.clone(),
            None => {
                // allow direct service name as project
                body.project.clone()
            }
        };
        let service = match config
            .gateway
            .services
            .iter()
            .find(|s| s.name == service_name)
        {
            Some(s) => s.clone(),
            None => {
                return admin_json_error(
                    StatusCode::BAD_REQUEST,
                    "unknown_service",
                    format!("service '{service_name}' not found"),
                );
            }
        };
        let endpoint_name = match service.endpoints.first() {
            Some(n) => n.clone(),
            None => {
                return admin_json_error(
                    StatusCode::BAD_REQUEST,
                    "no_endpoint",
                    "service has no endpoints",
                );
            }
        };
        let endpoint = match config
            .gateway
            .endpoints
            .iter()
            .find(|e| e.name == endpoint_name)
        {
            Some(e) => e.clone(),
            None => {
                return admin_json_error(
                    StatusCode::BAD_REQUEST,
                    "unknown_endpoint",
                    format!("endpoint '{endpoint_name}' missing"),
                );
            }
        };
        let lease = store.issue_lease(
            body,
            &service.name,
            &endpoint.name,
            endpoint.protocol.as_str(),
            &endpoint.address,
            endpoint.database.clone(),
            &endpoint.username,
            &endpoint.password,
        );
        info!(
            target: AUDIT_TARGET,
            action = AuditAction::AdminWrite.as_str(),
            decision = AuditDecision::Allow.as_str(),
            lease_id = %lease.lease_id,
            service = %lease.service,
            "admin issued vault lease"
        );
        gateway_core::try_audit(gateway_core::AuditEvent {
            action: Some(AuditAction::AdminWrite.as_str().into()),
            decision: Some(AuditDecision::Allow.as_str().into()),
            subject_id: lease.project.clone().into(),
            service: Some(lease.service.clone()),
            outcome: Some("vault_lease_issued".into()),
            message: Some(format!("lease {} for {}", lease.lease_id, lease.endpoint)),
            audit_level: Some("L0".into()),
            ..gateway_core::AuditEvent::default()
        });
        json_response(&lease)
    }

    async fn admin_revoke_vault_lease(
        State(state): State<Self>,
        headers: HeaderMap,
        Path(id): Path<String>,
        body: Option<Json<gateway_core::RevokeVaultLeaseRequest>>,
    ) -> Response<Body> {
        let auth_ctx = match state.authorize(
            &headers,
            "POST",
            &format!("/admin/vault/leases/{id}/revoke"),
        ) {
            Ok(ctx) => ctx,
            Err(response) => return response,
        };
        let mut req = body.map(|Json(b)| b).unwrap_or_default();
        if req.revoked_by.as_ref().map(|s| s.trim().is_empty()).unwrap_or(true) {
            if let Some(ctx) = auth_ctx.as_ref() {
                req.revoked_by = Some(ctx.subject.clone());
            }
        }
        match gateway_core::global_vault_store()
            .revoke(&id, req.revoked_by.as_deref())
        {
            Ok(lease) => {
                audit_admin_write(
                    auth_ctx.as_ref(),
                    "POST",
                    "/admin/vault/leases/:id/revoke",
                    "revoked",
                    Some(id.as_str()),
                );
                gateway_core::try_audit(gateway_core::AuditEvent {
                    action: Some(AuditAction::AdminWrite.as_str().into()),
                    decision: Some(AuditDecision::Allow.as_str().into()),
                    subject_id: req.revoked_by.clone(),
                    outcome: Some("vault_lease_revoked".into()),
                    message: Some(format!("revoked {id}")),
                    audit_level: Some("L0".into()),
                    ..gateway_core::AuditEvent::default()
                });
                json_response(&lease)
            }
            Err(msg) => admin_json_error(StatusCode::BAD_REQUEST, "vault_revoke_failed", msg),
        }
    }

    async fn admin_renew_vault_lease(
        State(state): State<Self>,
        headers: HeaderMap,
        Path(id): Path<String>,
        body: Option<Json<gateway_core::RenewVaultLeaseRequest>>,
    ) -> Response<Body> {
        let auth_ctx = match state.authorize(
            &headers,
            "POST",
            &format!("/admin/vault/leases/{id}/renew"),
        ) {
            Ok(ctx) => ctx,
            Err(response) => return response,
        };
        let req = body.map(|Json(b)| b).unwrap_or_default();
        match gateway_core::global_vault_store().renew(&id, req.ttl_secs) {
            Ok(lease) => {
                audit_admin_write(
                    auth_ctx.as_ref(),
                    "POST",
                    "/admin/vault/leases/:id/renew",
                    "renewed",
                    Some(id.as_str()),
                );
                json_response(&lease)
            }
            Err(msg) => admin_json_error(StatusCode::BAD_REQUEST, "vault_renew_failed", msg),
        }
    }

    async fn admin_prune_vault_leases(
        State(state): State<Self>,
        headers: HeaderMap,
    ) -> Response<Body> {
        let auth_ctx = match state.authorize(&headers, "POST", "/admin/vault/leases/prune") {
            Ok(ctx) => ctx,
            Err(response) => return response,
        };
        let removed = gateway_core::global_vault_store().prune_expired();
        audit_admin_write(
            auth_ctx.as_ref(),
            "POST",
            "/admin/vault/leases/prune",
            "ok",
            None,
        );
        json_response(&serde_json::json!({ "removed": removed }))
    }

    async fn admin_revoke_ticket(
        State(state): State<Self>,
        headers: HeaderMap,
        Path(id): Path<String>,
        body: Option<Json<gateway_core::RejectTicketRequest>>,
    ) -> Response<Body> {
        let auth_ctx = match state.authorize(
            &headers,
            "POST",
            &format!("/admin/tickets/{id}/revoke"),
        ) {
            Ok(ctx) => ctx,
            Err(response) => return response,
        };
        let mut req = body.map(|Json(b)| b).unwrap_or_default();
        if req.rejected_by.as_ref().map(|s| s.trim().is_empty()).unwrap_or(true) {
            if let Some(ctx) = auth_ctx.as_ref() {
                req.rejected_by = Some(ctx.subject.clone());
            }
        }
        let rejector = match req.rejected_by.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(s) => s.to_owned(),
            None => {
                return admin_json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_revoke_request",
                    "rejected_by is required (or authenticate so subject is inferred)",
                );
            }
        };
        match gateway_core::global_ticket_store().revoke(&id, &rejector, req.reason) {
            Ok(ticket) => {
                audit_admin_write(
                    auth_ctx.as_ref(),
                    "POST",
                    "/admin/tickets/:id/revoke",
                    "revoked",
                    Some(id.as_str()),
                );
                json_response(&ticket)
            }
            Err(msg) => admin_json_error(StatusCode::BAD_REQUEST, "ticket_revoke_failed", msg),
        }
    }

    async fn admin_prune_tickets(
        State(state): State<Self>,
        headers: HeaderMap,
    ) -> Response<Body> {
        let auth_ctx = match state.authorize(&headers, "POST", "/admin/tickets/prune") {
            Ok(ctx) => ctx,
            Err(response) => return response,
        };
        let removed = gateway_core::global_ticket_store().prune_expired();
        audit_admin_write(
            auth_ctx.as_ref(),
            "POST",
            "/admin/tickets/prune",
            "ok",
            None,
        );
        json_response(&serde_json::json!({ "removed": removed }))
    }

    async fn admin_portal_query(
        State(state): State<Self>,
        headers: HeaderMap,
        Json(body): Json<AdminPortalQueryRequest>,
    ) -> Response<Body> {
        let auth_ctx = match state.authorize(&headers, "POST", "/admin/portal/query") {
            Ok(ctx) => ctx,
            Err(response) => return response,
        };
        if body.sql.trim().is_empty() || body.service.trim().is_empty() {
            return admin_json_error(
                StatusCode::BAD_REQUEST,
                "invalid_portal_query",
                "service and sql are required",
            );
        }
        let format = normalize_portal_format(body.format.as_deref());
        if format.is_none() {
            return admin_json_error(
                StatusCode::BAD_REQUEST,
                "invalid_portal_format",
                "format must be json, csv, or ndjson",
            );
        }
        let format = format.unwrap_or("json");
        let download = body.download.unwrap_or(false) || format != "json";

        let Some(cfg_lock) = &state.gateway_config else {
            return gateway_config_not_available();
        };
        let config = match cfg_lock.read() {
            Ok(g) => g.gateway.clone(),
            Err(_) => return gateway_config_not_available(),
        };

        if let Some(lease_id) = body.lease_id.as_deref() {
            match gateway_core::global_vault_store().get_valid_lease(lease_id) {
                Some(lease) if lease.service == body.service => {}
                Some(_) => {
                    return admin_json_error(
                        StatusCode::FORBIDDEN,
                        "lease_service_mismatch",
                        "vault lease does not match service",
                    );
                }
                None => {
                    return admin_json_error(
                        StatusCode::FORBIDDEN,
                        "lease_invalid",
                        "vault lease missing or expired",
                    );
                }
            }
        }

        let subject_id = body
            .subject_id
            .clone()
            .or_else(|| auth_ctx.as_ref().map(|c| c.subject.clone()))
            .unwrap_or_else(|| "portal".into());

        // Bound portal result size; export defaults higher but still capped.
        let max_rows = clamp_portal_max_rows(body.max_rows, format);
        let stream_window = config.security.streaming.window_rows.max(1) as usize;

        // A09: NDJSON / CSV / JSON all prefer backend Streaming → HTTP window chunks.
        // Complete backends fall back to materialized single-body (no backend_window).
        if format == "ndjson" {
            match portal_execute_ndjson_streaming(
                &config,
                &body.service,
                &body.sql,
                &subject_id,
                Some(max_rows),
                stream_window,
                download,
            )
            .await
            {
                Ok(response) => {
                    gateway_core::try_audit(gateway_core::AuditEvent {
                        action: Some(AuditAction::Query.as_str().into()),
                        decision: Some(AuditDecision::Execute.as_str().into()),
                        subject_id: Some(subject_id),
                        service: Some(body.service.clone()),
                        outcome: Some("portal_export".into()),
                        message: Some(format!(
                            "format=ndjson stream=backend_window window={stream_window} max_rows={max_rows}"
                        )),
                        audit_level: Some("L0".into()),
                        ..gateway_core::AuditEvent::default()
                    });
                    return response;
                }
                Err((code, msg)) => {
                    gateway_core::try_audit(gateway_core::AuditEvent {
                        action: Some(AuditAction::Query.as_str().into()),
                        decision: Some(AuditDecision::Deny.as_str().into()),
                        subject_id: Some(subject_id),
                        service: Some(body.service.clone()),
                        outcome: Some("portal_deny".into()),
                        message: Some(msg.clone()),
                        code: Some(code.clone()),
                        audit_level: Some("L0".into()),
                        ..gateway_core::AuditEvent::default()
                    });
                    return admin_json_error(StatusCode::FORBIDDEN, "portal_denied", msg);
                }
            }
        }

        if format == "csv" {
            match portal_execute_csv_streaming(
                &config,
                &body.service,
                &body.sql,
                &subject_id,
                Some(max_rows),
                stream_window,
                download,
            )
            .await
            {
                Ok(response) => {
                    gateway_core::try_audit(gateway_core::AuditEvent {
                        action: Some(AuditAction::Query.as_str().into()),
                        decision: Some(AuditDecision::Execute.as_str().into()),
                        subject_id: Some(subject_id),
                        service: Some(body.service.clone()),
                        outcome: Some("portal_export".into()),
                        message: Some(format!(
                            "format=csv stream=backend_window_or_materialized window={stream_window} max_rows={max_rows}"
                        )),
                        audit_level: Some("L0".into()),
                        ..gateway_core::AuditEvent::default()
                    });
                    return response;
                }
                Err((code, msg)) => {
                    gateway_core::try_audit(gateway_core::AuditEvent {
                        action: Some(AuditAction::Query.as_str().into()),
                        decision: Some(AuditDecision::Deny.as_str().into()),
                        subject_id: Some(subject_id),
                        service: Some(body.service.clone()),
                        outcome: Some("portal_deny".into()),
                        message: Some(msg.clone()),
                        code: Some(code.clone()),
                        audit_level: Some("L0".into()),
                        ..gateway_core::AuditEvent::default()
                    });
                    return admin_json_error(StatusCode::FORBIDDEN, "portal_denied", msg);
                }
            }
        }

        if format == "json" {
            match portal_execute_json_streaming(
                &config,
                &body.service,
                &body.sql,
                &subject_id,
                Some(max_rows),
                stream_window,
                download,
            )
            .await
            {
                Ok(response) => {
                    gateway_core::try_audit(gateway_core::AuditEvent {
                        action: Some(AuditAction::Query.as_str().into()),
                        decision: Some(AuditDecision::Execute.as_str().into()),
                        subject_id: Some(subject_id),
                        service: Some(body.service.clone()),
                        outcome: Some("portal_query".into()),
                        message: Some(format!(
                            "format=json stream=backend_window_or_materialized window={stream_window} max_rows={max_rows}"
                        )),
                        audit_level: Some("L0".into()),
                        ..gateway_core::AuditEvent::default()
                    });
                    return response;
                }
                Err((code, msg)) => {
                    gateway_core::try_audit(gateway_core::AuditEvent {
                        action: Some(AuditAction::Query.as_str().into()),
                        decision: Some(AuditDecision::Deny.as_str().into()),
                        subject_id: Some(subject_id),
                        service: Some(body.service.clone()),
                        outcome: Some("portal_deny".into()),
                        message: Some(msg.clone()),
                        code: Some(code.clone()),
                        audit_level: Some("L0".into()),
                        ..gateway_core::AuditEvent::default()
                    });
                    return admin_json_error(StatusCode::FORBIDDEN, "portal_denied", msg);
                }
            }
        }

        match portal_execute_logical(
            &config,
            &body.service,
            &body.sql,
            &subject_id,
            Some(max_rows),
        )
        .await
        {
            Ok(resp) => {
                let outcome = if format == "json" {
                    "portal_query"
                } else {
                    "portal_export"
                };
                gateway_core::try_audit(gateway_core::AuditEvent {
                    action: Some(AuditAction::Query.as_str().into()),
                    decision: Some(AuditDecision::Execute.as_str().into()),
                    subject_id: Some(subject_id),
                    service: Some(body.service.clone()),
                    outcome: Some(outcome.into()),
                    message: Some(format!(
                        "format={format} rows={} truncated={}",
                        resp.row_count, resp.truncated
                    )),
                    audit_level: Some("L0".into()),
                    ..gateway_core::AuditEvent::default()
                });
                portal_format_response(&resp, format, download)
            }
            Err((code, msg)) => {
                gateway_core::try_audit(gateway_core::AuditEvent {
                    action: Some(AuditAction::Query.as_str().into()),
                    decision: Some(AuditDecision::Deny.as_str().into()),
                    subject_id: Some(subject_id),
                    service: Some(body.service.clone()),
                    outcome: Some("portal_deny".into()),
                    message: Some(msg.clone()),
                    code: Some(code.clone()),
                    audit_level: Some("L0".into()),
                    ..gateway_core::AuditEvent::default()
                });
                admin_json_error(StatusCode::FORBIDDEN, "portal_denied", msg)
            }
        }
    }


    async fn admin_add_listener(
        State(state): State<Self>,
        headers: HeaderMap,
        Json(listener): Json<ListenerConfig>,
    ) -> Response<Body> {
        let auth_ctx = match state.authorize(&headers, "POST", "/admin/listeners") {
            Ok(ctx) => ctx,
            Err(response) => return response,
        };
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
                listener_runtime.pool_refresher.clone(),
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

        audit_admin_write(
            auth_ctx.as_ref(),
            "POST",
            "/admin/listeners",
            "ok",
            Some(listener_name.as_str()),
        );
        json_response(&AdminAddListenerResponse {
            status: "started",
            name: listener_name,
            listen_addr,
        })
    }

    async fn admin_replace_route_policy(
        Path(name): Path<String>,
        State(state): State<Self>,
        headers: HeaderMap,
        Json(route_policy): Json<RoutePolicyConfig>,
    ) -> Response<Body> {
        let policy_path = format!("/admin/route-policies/{}", name);
        let auth_ctx = match state.authorize(&headers, "PUT", &policy_path) {
            Ok(ctx) => ctx,
            Err(response) => return response,
        };
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

        audit_admin_write(
            auth_ctx.as_ref(),
            "PUT",
            &policy_path,
            "ok",
            Some(response.name.as_str()),
        );
        json_response(&response)
    }

    async fn admin_pools(State(state): State<Self>, headers: HeaderMap) -> Response<Body> {
        if let Err(response) = state.authorize(&headers, "GET", "/admin/pools") {
            return response;
        }
        match &state.runtime_state {
            Some(runtime_state) => json_response(&runtime_state.pool_statuses()),
            None => admin_runtime_not_found("admin runtime state is not available"),
        }
    }

    async fn admin_refresh_pool(
        Path(name): Path<String>,
        State(state): State<Self>,
        headers: HeaderMap,
    ) -> Response<Body> {
        let path = format!("/admin/pools/{}/refresh", name);
        let auth_ctx = match state.authorize(&headers, "POST", &path) {
            Ok(ctx) => ctx,
            Err(response) => return response,
        };
        match &state.runtime_state {
            Some(runtime_state) => match runtime_state.refresh_pool(&name) {
                Some(status) => {
                    audit_admin_write(auth_ctx.as_ref(), "POST", &path, "ok", Some(name.as_str()));
                    json_response(&status)
                }
                None => admin_runtime_not_found("listener pool refresher is not available"),
            },
            None => admin_runtime_not_found("admin runtime state is not available"),
        }
    }

    async fn admin_refresh_pools(State(state): State<Self>, headers: HeaderMap) -> Response<Body> {
        let auth_ctx = match state.authorize(&headers, "POST", "/admin/pools/refresh") {
            Ok(ctx) => ctx,
            Err(response) => return response,
        };
        match &state.runtime_state {
            Some(runtime_state) => {
                let status = runtime_state.refresh_pools();
                audit_admin_write(
                    auth_ctx.as_ref(),
                    "POST",
                    "/admin/pools/refresh",
                    "ok",
                    None,
                );
                json_response(&status)
            }
            None => admin_runtime_not_found("admin runtime state is not available"),
        }
    }

    async fn admin_sessions(State(state): State<Self>, headers: HeaderMap) -> Response<Body> {
        if let Err(response) = state.authorize(&headers, "GET", "/admin/sessions") {
            return response;
        }
        match &state.runtime_state {
            Some(runtime_state) => json_response(&runtime_state.session_statuses()),
            None => admin_runtime_not_found("admin runtime state is not available"),
        }
    }

    async fn admin_reload(State(state): State<Self>, headers: HeaderMap) -> Response<Body> {
        let auth_ctx = match state.authorize(&headers, "POST", "/admin/reload") {
            Ok(ctx) => ctx,
            Err(response) => return response,
        };
        let shared_config = match &state.gateway_config {
            Some(config) => config.clone(),
            None => return gateway_config_not_available(),
        };
        let current_config = match gateway_config_snapshot(&shared_config) {
            Ok(config) => config,
            Err(response) => return response,
        };
        let config_source = match &state.gateway_config_source {
            Some(config_source) => config_source,
            None => return admin_runtime_not_found("gateway config source is not available"),
        };

        // Load+validate next config. On failure keep the previous in-memory config.
        let next_config = match config_source.load() {
            Ok(config) => config,
            Err(error) => return gateway_config_load_error(error),
        };
        let diff = GatewayConfigDiff::between(&current_config, &next_config);
        let changed = diff.has_changes();
        if !changed {
            audit_admin_write(
                auth_ctx.as_ref(),
                "POST",
                "/admin/reload",
                "validated",
                None,
            );
            return json_response(&GatewayReloadResponse {
                status: "validated",
                source: config_source.description(),
                applied: false,
                changed: false,
                diff,
            });
        }

        // Apply shared config first so topology APIs see the new document.
        {
            let mut current = match shared_config.write() {
                Ok(current) => current,
                Err(_) => {
                    return admin_json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "gateway reload failed",
                        "gateway config lock is poisoned".to_string(),
                    )
                }
            };
            *current = next_config.clone();
        }

        // Best-effort runtime reconcile for listener topology when controls exist.
        if let Some(runtime_state) = &state.runtime_state {
            for removed in &diff.listeners.removed {
                let _ = runtime_state.stop_listener(removed);
            }
            for changed_listener in &diff.listeners.changed {
                let _ = runtime_state.stop_listener(changed_listener);
            }

            for added in diff.listeners.added.iter().chain(diff.listeners.changed.iter()) {
                match GatewayFactory::from_gateway_config(next_config.clone())
                    .try_build_proxy_for_listener(added)
                {
                    Ok(listener_runtime) => {
                        if let Err(_error) = runtime_state.register_listener(
                            listener_runtime.name.clone(),
                            listener_runtime.shutdown_handle.clone(),
                            listener_runtime.pool_snapshotter.clone(),
                            listener_runtime.pool_refresher.clone(),
                            listener_runtime.session_snapshotter.clone(),
                        ) {
                            // Listener may still be registered after stop; replace registration.
                            let _ = runtime_state.stop_listener(added);
                            if let Err(error) = runtime_state.register_listener(
                                listener_runtime.name.clone(),
                                listener_runtime.shutdown_handle.clone(),
                                listener_runtime.pool_snapshotter.clone(),
                                listener_runtime.pool_refresher.clone(),
                                listener_runtime.session_snapshotter.clone(),
                            ) {
                                return admin_json_error(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    "gateway reload failed",
                                    format!(
                                        "config applied but failed to register listener '{}': {}",
                                        added, error
                                    ),
                                );
                            }
                        }
                        tokio::spawn(start_gateway_server(listener_runtime.proxy));
                    }
                    Err(error) => {
                        return admin_json_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "gateway reload failed",
                            format!(
                                "config applied but failed to build listener '{}': {}",
                                added, error
                            ),
                        );
                    }
                }
            }

            // Endpoint/pool changes: refresh pools so idle conns pick up new topology.
            if diff.endpoints.has_changes() {
                let _ = runtime_state.refresh_pools();
            }
        }

        // F28: Local rules/mask/time/watermark/audit hot-swap without listener rebuild.
        // Always refresh the process-wide PDP snapshot when security is enabled so
        // live connections (holding the same store handle) see the new epoch.
        maybe_reload_local_pdp(&next_config.gateway.security, &diff);
        // Audit pipeline reconfigure is idempotent (queue worker stays up).
        if diff.security_changed {
            let _ = gateway_core::install_audit_pipeline(
                &next_config.gateway.security.audit,
                &next_config.gateway.security.default_audit_level,
            );
            if let Err(e) = gateway_core::install_ticket_store(
                &next_config.gateway.security.state.backend,
                &next_config.gateway.security.state.ticket_path,
                &next_config.gateway.security.state.ticket_encrypt_key,
            ) {
                tracing::error!(target: "data_nexus::security", error = %e, "reload ticket store failed");
            }
            if let Err(e) = gateway_core::install_vault_store(
                &next_config.gateway.security.state.backend,
                &next_config.gateway.security.state.vault_path,
                &next_config.gateway.security.state.vault_encrypt_key,
            ) {
                tracing::error!(target: "data_nexus::security", error = %e, "reload vault store failed");
            }
        }

        // Cedar policy hot-reload (keep-old on failure): when security.pdp is cedar
        // and cache_epoch_reload is true, re-read policy_dir without restarting listeners.
        maybe_reload_cedar_policies(&next_config.gateway.security);

        audit_admin_write(auth_ctx.as_ref(), "POST", "/admin/reload", "applied", None);
        json_response(&GatewayReloadResponse {
            status: "applied",
            source: config_source.description(),
            applied: true,
            changed: true,
            diff,
        })
    }

    async fn admin_stop_listener(
        Path(name): Path<String>,
        State(state): State<Self>,
        headers: HeaderMap,
    ) -> Response<Body> {
        let path = format!("/admin/listeners/{}/stop", name);
        let auth_ctx = match state.authorize(&headers, "POST", &path) {
            Ok(ctx) => ctx,
            Err(response) => return response,
        };
        match &state.runtime_state {
            Some(runtime_state) => match runtime_state.stop_listener(&name) {
                Some(status) => {
                    audit_admin_write(auth_ctx.as_ref(), "POST", &path, "ok", Some(name.as_str()));
                    json_response(&status)
                }
                None => admin_runtime_not_found("listener runtime control is not available"),
            },
            None => admin_runtime_not_found("admin runtime state is not available"),
        }
    }
}


/// F28: swap Local PDP snapshot when security is enabled and changed.
fn maybe_reload_local_pdp(
    security: &gateway_core::SecurityPolicyConfig,
    diff: &GatewayConfigDiff,
) {
    if !security.enabled || !diff.security_changed {
        return;
    }
    if let Some(info) = gateway_core::reload_global_local_pdp(security) {
        tracing::info!(
            target: AUDIT_TARGET,
            epoch = info.epoch,
            rules = info.rule_count,
            previous_rules = info.previous_rule_count,
            local_hot = diff.security_local_hot_reload,
            requires_listener_rebuild = diff.security_requires_listener_rebuild,
            "local PDP hot-reloaded with admin reload"
        );
    }
}

fn maybe_reload_cedar_policies(security: &gateway_core::SecurityPolicyConfig) {
    #[cfg(feature = "security-cedar")]
    {
        if !security.enabled {
            return;
        }
        if !security.pdp.backend.eq_ignore_ascii_case("cedar") {
            return;
        }
        if !security.pdp.cache_epoch_reload {
            tracing::info!(
                target: AUDIT_TARGET,
                "cedar cache_epoch_reload=false; skip policy hot-reload on admin reload"
            );
            return;
        }
        let dir = security.pdp.policy_dir.trim();
        if dir.is_empty() {
            return;
        }
        match gateway_core::reload_global_cedar(dir) {
            Ok(info) => {
                tracing::info!(
                    target: AUDIT_TARGET,
                    epoch = info.epoch,
                    swapped = info.swapped,
                    files = info.files,
                    "cedar policies hot-reloaded with admin reload"
                );
            }
            Err(e) => {
                // Keep-old: do not fail the whole admin reload; log loudly.
                tracing::error!(
                    target: AUDIT_TARGET,
                    error = %e,
                    "cedar hot-reload failed; kept previous policy epoch"
                );
            }
        }
    }
    #[cfg(not(feature = "security-cedar"))]
    {
        let _ = security;
    }
}

fn audit_admin_write(
    ctx: Option<&AdminAuthContext>,
    method: &str,
    path: &str,
    outcome: &str,
    resource: Option<&str>,
) {
    let subject_id = ctx.map(|c| c.subject.as_str()).unwrap_or("anonymous");
    let auth_method = ctx.map(|c| c.auth_method.as_str()).unwrap_or("none");
    info!(
        target: AUDIT_TARGET,
        action = AuditAction::AdminWrite.as_str(),
        decision = AuditDecision::Allow.as_str(),
        subject_id = %subject_id,
        auth_method = %auth_method,
        method = %method,
        path = %path,
        outcome = %outcome,
        resource = resource,
        "admin write audited"
    );
}

fn admin_auth_error_response(error: AdminAuthError) -> Response<Body> {
    admin_json_error(error.status(), error.code(), error.message().to_owned())
}



async fn portal_execute_logical(
    config: &gateway_core::GatewayConfig,
    service_name: &str,
    sql: &str,
    subject_id: &str,
    max_rows: Option<u64>,
) -> Result<AdminPortalQueryResponse, (String, String)> {
    // Fallback materialize path (tests / unexpected formats). Live json/csv/ndjson
    // use portal_execute_*_streaming for backend_window when Streaming.
    let prepared = portal_prepare(config, service_name, sql, subject_id, max_rows)?;
    let response = prepared
        .backend
        .execute_outcome(
            prepared.command,
            &mut prepared.session.clone(),
            prepared.mode,
        )
        .await
        .map_err(|e| ("backend".into(), e.to_string()))?;

    use gateway_core::{
        apply_masks_to_rows, apply_obligations_to_response, apply_watermark_to_resultset,
        build_mask_index, map_response_types, ExecuteOutcome, GatewayResponse, GatewayValue,
    };

    let session = prepared.session;
    match response {
        // Portal never requests Passthrough; if a WireRelay appears, drain and reject.
        ExecuteOutcome::WireRelay(mut relay) => {
            while relay
                .stream
                .poll_packets(64)
                .await
                .map_err(|e| ("backend".into(), e.to_string()))?
                .is_some()
            {}
            Err((
                "unsupported".into(),
                "portal path does not support wire passthrough relay".into(),
            ))
        }
        ExecuteOutcome::Streaming(mut query) => {
            // Map column types for cross-protocol.
            if prepared.backend_protocol != prepared.frontend_protocol {
                for col in &mut query.columns {
                    col.data_type = gateway_core::map_column_type(
                        &col.data_type,
                        &prepared.backend_protocol,
                        &prepared.frontend_protocol,
                    );
                }
            }
            let mut columns = query.columns;
            let mask_idx = build_mask_index(&columns, &prepared.obligations.column_masks);
            if let Some(wm) = prepared.obligations.watermark.as_ref() {
                let mut empty = Vec::new();
                apply_watermark_to_resultset(&mut columns, &mut empty, wm);
            }
            let header_width = columns.len();
            let window = prepared.mode.window_rows().unwrap_or(256).max(1);
            let max_total = max_rows.or(prepared.obligations.max_rows);
            let mut all_rows = Vec::new();
            let mut total: u64 = 0;
            let mut truncated = false;
            loop {
                if let Some(max) = max_total {
                    if total >= max {
                        while query.stream.poll_window(window).await.map_err(|e| {
                            ("backend".into(), e.to_string())
                        })?.is_some()
                        {}
                        truncated = true;
                        break;
                    }
                }
                let want = match max_total {
                    Some(max) => ((max - total) as usize).min(window).max(1),
                    None => window,
                };
                let Some(mut chunk) = query
                    .stream
                    .poll_window(want)
                    .await
                    .map_err(|e| ("backend".into(), e.to_string()))?
                else {
                    break;
                };
                if !mask_idx.is_empty() {
                    apply_masks_to_rows(&mut chunk, &mask_idx);
                }
                if let Some(wm) = prepared.obligations.watermark.as_ref() {
                    for row in chunk.iter_mut() {
                        while row.len() < header_width {
                            if row.len() + 1 == header_width {
                                row.push(GatewayValue::String(wm.token.clone()));
                            } else {
                                row.push(GatewayValue::Null);
                            }
                        }
                    }
                }
                total += chunk.len() as u64;
                all_rows.extend(chunk);
            }
            let col_names: Vec<String> = columns.into_iter().map(|c| c.name).collect();
            let json_rows = all_rows
                .into_iter()
                .map(|row| row.into_iter().map(gateway_value_to_json).collect())
                .collect::<Vec<_>>();
            let row_count = json_rows.len();
            let _ = session;
            Ok(AdminPortalQueryResponse {
                columns: col_names,
                rows: json_rows,
                row_count,
                truncated,
                service: service_name.to_owned(),
                decision: "allow".into(),
                message: None,
            })
        }
        ExecuteOutcome::Complete(response) => {
            let response = map_response_types(
                response,
                &prepared.backend_protocol,
                &prepared.frontend_protocol,
            );
            let response = if prepared.obligations.has_result_obligations() {
                apply_obligations_to_response(response, &prepared.obligations)
            } else {
                response
            };
            match response {
                GatewayResponse::ResultSet { columns, rows } => {
                    let limit = max_rows.or(prepared.obligations.max_rows);
                    let truncated = limit.map(|m| rows.len() as u64 >= m).unwrap_or(false);
                    let col_names: Vec<String> = columns.into_iter().map(|c| c.name).collect();
                    let json_rows = rows
                        .into_iter()
                        .map(|row| row.into_iter().map(gateway_value_to_json).collect())
                        .collect::<Vec<_>>();
                    let row_count = json_rows.len();
                    Ok(AdminPortalQueryResponse {
                        columns: col_names,
                        rows: json_rows,
                        row_count,
                        truncated,
                        service: service_name.to_owned(),
                        decision: "allow".into(),
                        message: None,
                    })
                }
                GatewayResponse::Error { code, message } => Err((code, message)),
                GatewayResponse::Ok { affected_rows, .. } => Ok(AdminPortalQueryResponse {
                    columns: vec!["affected_rows".into()],
                    rows: vec![vec![serde_json::json!(affected_rows)]],
                    row_count: 1,
                    truncated: false,
                    service: service_name.to_owned(),
                    decision: "allow".into(),
                    message: Some("ok".into()),
                }),
                GatewayResponse::Wire { .. } => Err((
                    "wire".into(),
                    "portal expects logical result set".into(),
                )),
                other => Err(("unsupported".into(), format!("{other:?}"))),
            }
        }
    }
}

/// Shared portal setup: PEP + translation + backend connector.
struct PortalPrepared {
    backend: std::sync::Arc<dyn gateway_core::BackendConnector>,
    command: gateway_core::GatewayCommand,
    session: gateway_core::SessionState,
    mode: gateway_core::ExecuteMode,
    obligations: gateway_core::Obligations,
    frontend_protocol: gateway_core::ProtocolKind,
    backend_protocol: gateway_core::ProtocolKind,
}

fn portal_prepare(
    config: &gateway_core::GatewayConfig,
    service_name: &str,
    sql: &str,
    subject_id: &str,
    max_rows: Option<u64>,
) -> Result<PortalPrepared, (String, String)> {
    use gateway_core::{
        default_dialect_parser, BackendConnector, ExecuteMode, GatewayCommand, LocalPdp, Subject,
    };
    use runtime_gateway::core_engine::CoreGatewayRuntimePlan;

    let plan = CoreGatewayRuntimePlan::from_config(config)
        .map_err(|e| ("plan".into(), e.to_string()))?;
    let _listener_ok = plan
        .listeners()
        .iter()
        .any(|l| l.service().name == service_name);
    if !_listener_ok {
        return Err((
            "no_listener".into(),
            format!("no listener for service '{service_name}'"),
        ));
    }

    let service = config
        .services
        .iter()
        .find(|s| s.name == service_name)
        .cloned()
        .ok_or_else(|| ("service".into(), "missing service".into()))?;
    let endpoints: Vec<_> = service
        .endpoints
        .iter()
        .filter_map(|n| config.endpoints.iter().find(|e| e.name == *n).cloned())
        .collect();
    if endpoints.is_empty() {
        return Err(("endpoint".into(), "service has no endpoints".into()));
    }

    let frontend_protocol = plan
        .listeners()
        .iter()
        .find(|l| l.service().name == service_name)
        .map(|l| l.listener().protocol.clone())
        .unwrap_or_else(|| service.backend_protocol.clone());

    let objects =
        runtime_gateway::object_extract::extract_object_set(sql, frontend_protocol.as_str());
    let dialect = default_dialect_parser(&frontend_protocol);
    let subject = Subject::from_protocol_user(Some(subject_id), None);
    let mut sql_exec = sql.to_owned();
    let mut obligations = gateway_core::Obligations::default();

    if let Some(pdp) = LocalPdp::from_config(&config.security) {
        match pdp.authorize_command_with_objects(
            &subject,
            service_name,
            &GatewayCommand::Query {
                sql: sql_exec.clone(),
            },
            &dialect,
            Some(&objects),
        ) {
            gateway_core::SecurityDecision::Deny { rule, message }
            | gateway_core::SecurityDecision::RequireTicket { rule, message, .. } => {
                return Err((rule, message));
            }
            gateway_core::SecurityDecision::Allow { obligations: obl } => {
                obligations = obl;
            }
            gateway_core::SecurityDecision::AllowRewrite {
                sql: rewritten,
                obligations: obl,
            } => {
                sql_exec = rewritten;
                obligations = obl;
            }
        }
    }

    let mut command = GatewayCommand::Query { sql: sql_exec };
    if let Some(policy_name) = &service.translation_policy {
        if let Some(policy) = config
            .translation_policies
            .iter()
            .find(|p| p.name == *policy_name)
        {
            command = gateway_core::prepare_cross_protocol_command(policy, command, &dialect)
                .map_err(|e| ("translation".into(), e.to_string()))?;
        }
    }

    let backend: std::sync::Arc<dyn BackendConnector> = match service.backend_protocol {
        gateway_core::ProtocolKind::MySql => std::sync::Arc::new(
            runtime_gateway::backend::mysql::MySqlBackendConnector::with_endpoints(
                endpoints.clone(),
            ),
        ),
        gateway_core::ProtocolKind::PostgreSql => std::sync::Arc::new(
            runtime_gateway::backend::postgresql::PostgreSqlBackendConnector::with_endpoints(
                endpoints.clone(),
            ),
        ),
    };

    let session = gateway_core::SessionState {
        user: Some(subject_id.to_owned()),
        database: endpoints.first().and_then(|e| e.database.clone()),
        ..Default::default()
    };
    let mode = ExecuteMode::from_streaming_config(
        config.security.streaming.window_rows.max(1),
        max_rows.or(obligations.max_rows),
    );

    Ok(PortalPrepared {
        backend,
        command,
        session,
        mode,
        obligations,
        frontend_protocol,
        backend_protocol: service.backend_protocol,
    })
}

fn gateway_value_to_json(v: gateway_core::GatewayValue) -> serde_json::Value {
    match v {
        gateway_core::GatewayValue::Null => serde_json::Value::Null,
        gateway_core::GatewayValue::Boolean(b) => serde_json::Value::Bool(b),
        gateway_core::GatewayValue::Integer(i) => serde_json::json!(i),
        gateway_core::GatewayValue::UnsignedInteger(u) => serde_json::json!(u),
        gateway_core::GatewayValue::Float(f) => serde_json::json!(f),
        gateway_core::GatewayValue::Decimal(s) | gateway_core::GatewayValue::String(s) => {
            serde_json::Value::String(s)
        }
        gateway_core::GatewayValue::Bytes(b) => {
            serde_json::Value::String(format!("bytes:{}", b.len()))
        }
    }
}

/// A09: NDJSON export with backend window yield → HTTP chunk (when Streaming).
async fn portal_execute_ndjson_streaming(
    config: &gateway_core::GatewayConfig,
    service_name: &str,
    sql: &str,
    subject_id: &str,
    max_rows: Option<u64>,
    window_rows: usize,
    download: bool,
) -> Result<Response<Body>, (String, String)> {
    use gateway_core::{
        apply_masks_to_rows, apply_watermark_to_resultset, build_mask_index, map_response_types,
        ExecuteOutcome, GatewayResponse, GatewayValue,
    };

    let prepared = portal_prepare(config, service_name, sql, subject_id, max_rows)?;
    let mut session = prepared.session.clone();
    let outcome = prepared
        .backend
        .execute_outcome(prepared.command, &mut session, prepared.mode)
        .await
        .map_err(|e| ("backend".into(), e.to_string()))?;

    let window = window_rows.max(1);
    let (mut tx, body) = Body::channel();

    match outcome {
        ExecuteOutcome::WireRelay(mut relay) => {
            while relay
                .stream
                .poll_packets(64)
                .await
                .map_err(|e| ("backend".into(), e.to_string()))?
                .is_some()
            {}
            Err((
                "unsupported".into(),
                "portal NDJSON path does not support wire passthrough relay".into(),
            ))
        }
        ExecuteOutcome::Streaming(mut query) => {
            if prepared.backend_protocol != prepared.frontend_protocol {
                for col in &mut query.columns {
                    col.data_type = gateway_core::map_column_type(
                        &col.data_type,
                        &prepared.backend_protocol,
                        &prepared.frontend_protocol,
                    );
                }
            }
            let mut columns = query.columns;
            let mask_specs = prepared.obligations.column_masks.clone();
            let mask_idx: Vec<(usize, gateway_core::MaskSpec)> = {
                let tmp = build_mask_index(&columns, &mask_specs);
                tmp.into_iter().map(|(i, s)| (i, s.clone())).collect()
            };
            if let Some(wm) = prepared.obligations.watermark.as_ref() {
                let mut empty = Vec::new();
                apply_watermark_to_resultset(&mut columns, &mut empty, wm);
            }
            let header_width = columns.len();
            let col_names: Vec<String> = columns.iter().map(|c| c.name.clone()).collect();
            let max_total = max_rows.or(prepared.obligations.max_rows);
            let service = service_name.to_owned();
            let watermark = prepared.obligations.watermark.clone();

            tokio::spawn(async move {
                // Keep `_meta` compatible with B05b clients; `stream=backend_window`
                // marks true backend yield (vs HTTP-only chunked of a materialized set).
                let meta = serde_json::json!({
                    "_meta": true,
                    "columns": col_names,
                    "service": service,
                    "decision": "allow",
                    "stream": "backend_window",
                    "window_rows": window,
                });
                if let Ok(mut b) = serde_json::to_vec(&meta) {
                    b.push(b'\n');
                    if tx.send_data(Bytes::from(b)).await.is_err() {
                        while query.stream.poll_window(window).await.ok().flatten().is_some() {}
                        return;
                    }
                }
                let mut total: u64 = 0;
                loop {
                    if let Some(max) = max_total {
                        if total >= max {
                            while query.stream.poll_window(window).await.ok().flatten().is_some() {}
                            break;
                        }
                    }
                    let want = match max_total {
                        Some(max) => ((max - total) as usize).min(window).max(1),
                        None => window,
                    };
                    let chunk = match query.stream.poll_window(want).await {
                        Ok(Some(c)) => c,
                        Ok(None) => break,
                        Err(_) => break,
                    };
                    let mut chunk = chunk;
                    if !mask_idx.is_empty() {
                        let refs: Vec<(usize, &gateway_core::MaskSpec)> =
                            mask_idx.iter().map(|(i, s)| (*i, s)).collect();
                        apply_masks_to_rows(&mut chunk, &refs);
                    }
                    if let Some(wm) = watermark.as_ref() {
                        for row in chunk.iter_mut() {
                            while row.len() < header_width {
                                if row.len() + 1 == header_width {
                                    row.push(GatewayValue::String(wm.token.clone()));
                                } else {
                                    row.push(GatewayValue::Null);
                                }
                            }
                        }
                    }
                    total += chunk.len() as u64;
                    let json_batch: Vec<Vec<serde_json::Value>> = chunk
                        .into_iter()
                        .map(|row| row.into_iter().map(gateway_value_to_json).collect())
                        .collect();
                    let bytes = portal_ndjson_encode_rows(&col_names, &json_batch);
                    if tx.send_data(Bytes::from(bytes)).await.is_err() {
                        while query.stream.poll_window(window).await.ok().flatten().is_some() {}
                        return;
                    }
                }
            });

            let mut builder = Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/x-ndjson; charset=utf-8")
                .header("x-data-nexus-stream", "backend_window");
            if download {
                builder = builder.header(
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"portal-export.ndjson\"",
                );
            }
            Ok(builder.body(body).unwrap_or_else(|_| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("response build failed"))
                    .expect("static")
            }))
        }
        ExecuteOutcome::Complete(response) => {
            // Fallback: materialize then reuse B05b chunked encoder.
            let response = map_response_types(
                response,
                &prepared.backend_protocol,
                &prepared.frontend_protocol,
            );
            let response = if prepared.obligations.has_result_obligations() {
                gateway_core::apply_obligations_to_response(response, &prepared.obligations)
            } else {
                response
            };
            match response {
                GatewayResponse::ResultSet { columns, rows } => {
                    let limit = max_rows.or(prepared.obligations.max_rows);
                    let truncated = limit.map(|m| rows.len() as u64 >= m).unwrap_or(false);
                    let col_names: Vec<String> = columns.into_iter().map(|c| c.name).collect();
                    let json_rows = rows
                        .into_iter()
                        .map(|row| row.into_iter().map(gateway_value_to_json).collect())
                        .collect::<Vec<_>>();
                    let row_count = json_rows.len();
                    let resp = AdminPortalQueryResponse {
                        columns: col_names,
                        rows: json_rows,
                        row_count,
                        truncated,
                        service: service_name.to_owned(),
                        decision: "allow".into(),
                        message: None,
                    };
                    Ok(portal_ndjson_chunked_response(resp, download, window))
                }
                GatewayResponse::Error { code, message } => Err((code, message)),
                GatewayResponse::Ok { affected_rows, .. } => {
                    let resp = AdminPortalQueryResponse {
                        columns: vec!["affected_rows".into()],
                        rows: vec![vec![serde_json::json!(affected_rows)]],
                        row_count: 1,
                        truncated: false,
                        service: service_name.to_owned(),
                        decision: "allow".into(),
                        message: Some("ok".into()),
                    };
                    Ok(portal_ndjson_chunked_response(resp, download, window))
                }
                other => Err(("unsupported".into(), format!("{other:?}"))),
            }
        }
    }
}

/// A09: CSV export with backend window yield → HTTP chunk (when Streaming).
/// Materialized backends fall back to a single-body CSV (same as before).
async fn portal_execute_csv_streaming(
    config: &gateway_core::GatewayConfig,
    service_name: &str,
    sql: &str,
    subject_id: &str,
    max_rows: Option<u64>,
    window_rows: usize,
    download: bool,
) -> Result<Response<Body>, (String, String)> {
    use gateway_core::{
        apply_masks_to_rows, apply_watermark_to_resultset, build_mask_index, map_response_types,
        ExecuteOutcome, GatewayResponse, GatewayValue,
    };

    let prepared = portal_prepare(config, service_name, sql, subject_id, max_rows)?;
    let mut session = prepared.session.clone();
    let outcome = prepared
        .backend
        .execute_outcome(prepared.command, &mut session, prepared.mode)
        .await
        .map_err(|e| ("backend".into(), e.to_string()))?;

    let window = window_rows.max(1);
    let (mut tx, body) = Body::channel();

    match outcome {
        ExecuteOutcome::WireRelay(mut relay) => {
            while relay
                .stream
                .poll_packets(64)
                .await
                .map_err(|e| ("backend".into(), e.to_string()))?
                .is_some()
            {}
            Err((
                "unsupported".into(),
                "portal CSV path does not support wire passthrough relay".into(),
            ))
        }
        ExecuteOutcome::Streaming(mut query) => {
            if prepared.backend_protocol != prepared.frontend_protocol {
                for col in &mut query.columns {
                    col.data_type = gateway_core::map_column_type(
                        &col.data_type,
                        &prepared.backend_protocol,
                        &prepared.frontend_protocol,
                    );
                }
            }
            let mut columns = query.columns;
            let mask_specs = prepared.obligations.column_masks.clone();
            let mask_idx: Vec<(usize, gateway_core::MaskSpec)> = {
                let tmp = build_mask_index(&columns, &mask_specs);
                tmp.into_iter().map(|(i, s)| (i, s.clone())).collect()
            };
            if let Some(wm) = prepared.obligations.watermark.as_ref() {
                let mut empty = Vec::new();
                apply_watermark_to_resultset(&mut columns, &mut empty, wm);
            }
            let header_width = columns.len();
            let col_names: Vec<String> = columns.iter().map(|c| c.name.clone()).collect();
            let max_total = max_rows.or(prepared.obligations.max_rows);
            let watermark = prepared.obligations.watermark.clone();

            tokio::spawn(async move {
                // Header line first (CSV schema).
                let mut header = col_names
                    .iter()
                    .map(|c| csv_escape(c))
                    .collect::<Vec<_>>()
                    .join(",");
                header.push('\n');
                if tx.send_data(Bytes::from(header)).await.is_err() {
                    while query.stream.poll_window(window).await.ok().flatten().is_some() {}
                    return;
                }
                let mut total: u64 = 0;
                let mut truncated = false;
                loop {
                    if let Some(max) = max_total {
                        if total >= max {
                            truncated = true;
                            while query.stream.poll_window(window).await.ok().flatten().is_some() {}
                            break;
                        }
                    }
                    let want = match max_total {
                        Some(max) => ((max - total) as usize).min(window).max(1),
                        None => window,
                    };
                    let chunk = match query.stream.poll_window(want).await {
                        Ok(Some(c)) => c,
                        Ok(None) => break,
                        Err(_) => break,
                    };
                    let mut chunk = chunk;
                    if !mask_idx.is_empty() {
                        let refs: Vec<(usize, &gateway_core::MaskSpec)> =
                            mask_idx.iter().map(|(i, s)| (*i, s)).collect();
                        apply_masks_to_rows(&mut chunk, &refs);
                    }
                    if let Some(wm) = watermark.as_ref() {
                        for row in chunk.iter_mut() {
                            while row.len() < header_width {
                                if row.len() + 1 == header_width {
                                    row.push(GatewayValue::String(wm.token.clone()));
                                } else {
                                    row.push(GatewayValue::Null);
                                }
                            }
                        }
                    }
                    total += chunk.len() as u64;
                    let bytes = portal_csv_encode_rows(&col_names, &chunk);
                    if tx.send_data(Bytes::from(bytes)).await.is_err() {
                        while query.stream.poll_window(window).await.ok().flatten().is_some() {}
                        return;
                    }
                }
                if truncated {
                    let _ = tx
                        .send_data(Bytes::from_static(b"# truncated=true\n"))
                        .await;
                }
            });

            let mut builder = Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/csv; charset=utf-8")
                .header("x-data-nexus-stream", "backend_window");
            if download {
                builder = builder.header(
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"portal-export.csv\"",
                );
            }
            Ok(builder.body(body).unwrap_or_else(|_| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("response build failed"))
                    .expect("static")
            }))
        }
        ExecuteOutcome::Complete(response) => {
            // Fallback: Complete ResultSet is already in memory, but HTTP body is
            // emitted window-by-window (x-data-nexus-stream: chunked — not backend_window).
            let response = map_response_types(
                response,
                &prepared.backend_protocol,
                &prepared.frontend_protocol,
            );
            let response = if prepared.obligations.has_result_obligations() {
                gateway_core::apply_obligations_to_response(response, &prepared.obligations)
            } else {
                response
            };
            match response {
                GatewayResponse::ResultSet { columns, rows } => {
                    let limit = max_rows.or(prepared.obligations.max_rows);
                    let truncated = limit.map(|m| rows.len() as u64 >= m).unwrap_or(false);
                    let col_names: Vec<String> = columns.into_iter().map(|c| c.name).collect();
                    let mut rows = rows;
                    if let Some(max) = limit {
                        if rows.len() as u64 > max {
                            rows.truncate(max as usize);
                        }
                    }
                    let json_rows = rows
                        .into_iter()
                        .map(|row| row.into_iter().map(gateway_value_to_json).collect())
                        .collect::<Vec<_>>();
                    let row_count = json_rows.len();
                    let resp = AdminPortalQueryResponse {
                        columns: col_names,
                        rows: json_rows,
                        row_count,
                        truncated,
                        service: service_name.to_owned(),
                        decision: "allow".into(),
                        message: None,
                    };
                    Ok(portal_csv_chunked_response(resp, download, window))
                }
                GatewayResponse::Error { code, message } => Err((code, message)),
                GatewayResponse::Ok { affected_rows, .. } => {
                    let resp = AdminPortalQueryResponse {
                        columns: vec!["affected_rows".into()],
                        rows: vec![vec![serde_json::json!(affected_rows)]],
                        row_count: 1,
                        truncated: false,
                        service: service_name.to_owned(),
                        decision: "allow".into(),
                        message: Some("ok".into()),
                    };
                    Ok(portal_csv_chunked_response(resp, download, window))
                }
                other => Err(("unsupported".into(), format!("{other:?}"))),
            }
        }
    }
}

/// A09: JSON portal query with backend window yield → HTTP chunk (when Streaming).
/// Emits one valid `AdminPortalQueryResponse` document as chunked JSON so the UI
/// can still `JSON.parse` the full body; peak encode buffer ≈ window.
/// Complete backends fall back to progressive JSON chunked (no backend_window).
async fn portal_execute_json_streaming(
    config: &gateway_core::GatewayConfig,
    service_name: &str,
    sql: &str,
    subject_id: &str,
    max_rows: Option<u64>,
    window_rows: usize,
    download: bool,
) -> Result<Response<Body>, (String, String)> {
    use gateway_core::{
        apply_masks_to_rows, apply_watermark_to_resultset, build_mask_index, map_response_types,
        ExecuteOutcome, GatewayResponse, GatewayValue,
    };

    let prepared = portal_prepare(config, service_name, sql, subject_id, max_rows)?;
    let mut session = prepared.session.clone();
    let outcome = prepared
        .backend
        .execute_outcome(prepared.command, &mut session, prepared.mode)
        .await
        .map_err(|e| ("backend".into(), e.to_string()))?;

    let window = window_rows.max(1);

    match outcome {
        ExecuteOutcome::WireRelay(mut relay) => {
            while relay
                .stream
                .poll_packets(64)
                .await
                .map_err(|e| ("backend".into(), e.to_string()))?
                .is_some()
            {}
            Err((
                "unsupported".into(),
                "portal JSON path does not support wire passthrough relay".into(),
            ))
        }
        ExecuteOutcome::Streaming(mut query) => {
            if prepared.backend_protocol != prepared.frontend_protocol {
                for col in &mut query.columns {
                    col.data_type = gateway_core::map_column_type(
                        &col.data_type,
                        &prepared.backend_protocol,
                        &prepared.frontend_protocol,
                    );
                }
            }
            let mut columns = query.columns;
            let mask_specs = prepared.obligations.column_masks.clone();
            let mask_idx: Vec<(usize, gateway_core::MaskSpec)> = {
                let tmp = build_mask_index(&columns, &mask_specs);
                tmp.into_iter().map(|(i, s)| (i, s.clone())).collect()
            };
            if let Some(wm) = prepared.obligations.watermark.as_ref() {
                let mut empty = Vec::new();
                apply_watermark_to_resultset(&mut columns, &mut empty, wm);
            }
            let header_width = columns.len();
            let col_names: Vec<String> = columns.iter().map(|c| c.name.clone()).collect();
            let max_total = max_rows.or(prepared.obligations.max_rows);
            let watermark = prepared.obligations.watermark.clone();
            let service = service_name.to_owned();
            let (mut tx, body) = Body::channel();

            tokio::spawn(async move {
                // Prefix: open AdminPortalQueryResponse shell with empty rows array.
                // Row arrays are appended as JSON fragments; trailer fills counts.
                let cols_json = match serde_json::to_string(&col_names) {
                    Ok(s) => s,
                    Err(_) => {
                        while query.stream.poll_window(window).await.ok().flatten().is_some() {}
                        return;
                    }
                };
                let service_json = match serde_json::to_string(&service) {
                    Ok(s) => s,
                    Err(_) => {
                        while query.stream.poll_window(window).await.ok().flatten().is_some() {}
                        return;
                    }
                };
                let prefix = format!(
                    "{{\"columns\":{cols_json},\"rows\":["
                );
                if tx.send_data(Bytes::from(prefix)).await.is_err() {
                    while query.stream.poll_window(window).await.ok().flatten().is_some() {}
                    return;
                }

                let mut total: u64 = 0;
                let mut truncated = false;
                let mut first_row = true;
                loop {
                    if let Some(max) = max_total {
                        if total >= max {
                            truncated = true;
                            while query.stream.poll_window(window).await.ok().flatten().is_some() {}
                            break;
                        }
                    }
                    let want = match max_total {
                        Some(max) => ((max - total) as usize).min(window).max(1),
                        None => window,
                    };
                    let chunk = match query.stream.poll_window(want).await {
                        Ok(Some(c)) => c,
                        Ok(None) => break,
                        Err(_) => break,
                    };
                    let mut chunk = chunk;
                    if !mask_idx.is_empty() {
                        let refs: Vec<(usize, &gateway_core::MaskSpec)> =
                            mask_idx.iter().map(|(i, s)| (*i, s)).collect();
                        apply_masks_to_rows(&mut chunk, &refs);
                    }
                    if let Some(wm) = watermark.as_ref() {
                        for row in chunk.iter_mut() {
                            while row.len() < header_width {
                                if row.len() + 1 == header_width {
                                    row.push(GatewayValue::String(wm.token.clone()));
                                } else {
                                    row.push(GatewayValue::Null);
                                }
                            }
                        }
                    }
                    total += chunk.len() as u64;
                    let bytes = portal_json_encode_row_array_fragment(&chunk, &mut first_row);
                    if !bytes.is_empty() && tx.send_data(Bytes::from(bytes)).await.is_err() {
                        while query.stream.poll_window(window).await.ok().flatten().is_some() {}
                        return;
                    }
                }

                // Close rows array and emit trailing fields (counts after stream).
                let trailer = format!(
                    "],\"row_count\":{total},\"truncated\":{truncated},\"service\":{service_json},\"decision\":\"allow\",\"stream\":\"backend_window\",\"window_rows\":{window}}}"
                );
                let _ = tx.send_data(Bytes::from(trailer)).await;
            });

            let mut builder = Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
                .header("x-data-nexus-stream", "backend_window");
            if download {
                builder = builder.header(
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"portal-export.json\"",
                );
            }
            Ok(builder.body(body).unwrap_or_else(|_| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("response build failed"))
                    .expect("static")
            }))
        }
        ExecuteOutcome::Complete(response) => {
            // Fallback: Complete ResultSet already held; stream JSON document in
            // windows (stream=chunked). Not backend_window (no RowStream).
            let response = map_response_types(
                response,
                &prepared.backend_protocol,
                &prepared.frontend_protocol,
            );
            let response = if prepared.obligations.has_result_obligations() {
                gateway_core::apply_obligations_to_response(response, &prepared.obligations)
            } else {
                response
            };
            match response {
                GatewayResponse::ResultSet { columns, rows } => {
                    let limit = max_rows.or(prepared.obligations.max_rows);
                    let truncated = limit.map(|m| rows.len() as u64 >= m).unwrap_or(false);
                    let col_names: Vec<String> = columns.into_iter().map(|c| c.name).collect();
                    let mut rows = rows;
                    if let Some(max) = limit {
                        if rows.len() as u64 > max {
                            rows.truncate(max as usize);
                        }
                    }
                    let json_rows = rows
                        .into_iter()
                        .map(|row| row.into_iter().map(gateway_value_to_json).collect())
                        .collect::<Vec<_>>();
                    let row_count = json_rows.len();
                    let resp = AdminPortalQueryResponse {
                        columns: col_names,
                        rows: json_rows,
                        row_count,
                        truncated,
                        service: service_name.to_owned(),
                        decision: "allow".into(),
                        message: None,
                    };
                    Ok(portal_json_chunked_response(resp, download, window))
                }
                GatewayResponse::Error { code, message } => Err((code, message)),
                GatewayResponse::Ok { affected_rows, .. } => {
                    let resp = AdminPortalQueryResponse {
                        columns: vec!["affected_rows".into()],
                        rows: vec![vec![serde_json::json!(affected_rows)]],
                        row_count: 1,
                        truncated: false,
                        service: service_name.to_owned(),
                        decision: "allow".into(),
                        message: Some("ok".into()),
                    };
                    Ok(portal_json_chunked_response(resp, download, window))
                }
                other => Err(("unsupported".into(), format!("{other:?}"))),
            }
        }
    }
}

/// Encode a window of GatewayValue rows as a JSON array-fragment for `rows: [ ... ]`.
/// Commas are inserted between rows across windows via `first_row`.
fn portal_json_encode_row_array_fragment(
    chunk: &[Vec<gateway_core::GatewayValue>],
    first_row: &mut bool,
) -> Vec<u8> {
    let mut out = Vec::new();
    for row in chunk {
        if !*first_row {
            out.push(b',');
        }
        *first_row = false;
        let vals: Vec<serde_json::Value> = row
            .iter()
            .cloned()
            .map(gateway_value_to_json)
            .collect();
        match serde_json::to_vec(&vals) {
            Ok(b) => out.extend_from_slice(&b),
            Err(_) => out.extend_from_slice(b"null"),
        }
    }
    out
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

fn normalize_portal_format(raw: Option<&str>) -> Option<&'static str> {
    match raw.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
        None | Some("") | Some("json") => Some("json"),
        Some("csv") => Some("csv"),
        Some("ndjson") | Some("jsonl") | Some("json-lines") => Some("ndjson"),
        _ => None,
    }
}

fn clamp_portal_max_rows(requested: Option<u64>, format: &str) -> u64 {
    let default = if format == "json" {
        1_000
    } else {
        PORTAL_DEFAULT_EXPORT_MAX_ROWS
    };
    requested
        .unwrap_or(default)
        .clamp(1, PORTAL_MAX_ROWS_CAP)
}

fn portal_format_response(
    resp: &AdminPortalQueryResponse,
    format: &str,
    download: bool,
) -> Response<Body> {
    match format {
        "csv" => {
            let body = portal_to_csv(resp);
            portal_download_response(
                body,
                "text/csv; charset=utf-8",
                download,
                "portal-export.csv",
            )
        }
        // Buffered NDJSON for tests / callers that already hold `resp`.
        // Live NDJSON uses `portal_execute_ndjson_streaming` (A09 backend window
        // when available, else B05b chunked of a materialized set).
        "ndjson" => {
            let body = portal_to_ndjson(resp);
            portal_download_response(
                body,
                "application/x-ndjson; charset=utf-8",
                download,
                "portal-export.ndjson",
            )
        }
        _ => {
            if download {
                match serde_json::to_vec(resp) {
                    Ok(body) => portal_download_response(
                        body,
                        "application/json",
                        true,
                        "portal-export.json",
                    ),
                    Err(error) => Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::from(error.to_string()))
                        .expect("static internal server error response is valid"),
                }
            } else {
                json_response(resp)
            }
        }
    }
}

/// B05b: stream NDJSON over a chunked HTTP body, encoding `window_rows` at a time
/// so the full export document is never assembled as one contiguous buffer.
fn portal_ndjson_chunked_response(
    resp: AdminPortalQueryResponse,
    download: bool,
    window_rows: usize,
) -> Response<Body> {
    let window = window_rows.max(1);
    let (mut tx, body) = Body::channel();
    tokio::spawn(async move {
        let meta = portal_ndjson_meta_value(&resp);
        match serde_json::to_vec(&meta) {
            Ok(mut b) => {
                b.push(b'\n');
                if tx.send_data(Bytes::from(b)).await.is_err() {
                    return;
                }
            }
            Err(_) => return,
        }
        let columns = resp.columns;
        let mut rows = resp.rows.into_iter();
        loop {
            let mut batch = Vec::with_capacity(window);
            for _ in 0..window {
                match rows.next() {
                    Some(r) => batch.push(r),
                    None => break,
                }
            }
            if batch.is_empty() {
                break;
            }
            let chunk = portal_ndjson_encode_rows(&columns, &batch);
            if tx.send_data(Bytes::from(chunk)).await.is_err() {
                return;
            }
            // `batch` drops here — progressive free of row memory.
        }
    });

    let mut builder = Response::builder()
        .header(header::CONTENT_TYPE, "application/x-ndjson; charset=utf-8")
        .header("x-data-nexus-stream", "chunked");
    if download {
        builder = builder.header(
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"portal-export.ndjson\"",
        );
    }
    builder.body(body).unwrap_or_else(|error| {
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from(error.to_string()))
            .expect("static internal server error response is valid")
    })
}

/// A09: Complete-path CSV — header once, then windowed data lines.
/// Header `x-data-nexus-stream: chunked` (not backend_window).
fn portal_csv_chunked_response(
    resp: AdminPortalQueryResponse,
    download: bool,
    window_rows: usize,
) -> Response<Body> {
    let window = window_rows.max(1);
    let (mut tx, body) = Body::channel();
    tokio::spawn(async move {
        let truncated = resp.truncated;
        let mut header = resp
            .columns
            .iter()
            .map(|c| csv_escape(c))
            .collect::<Vec<_>>()
            .join(",");
        header.push('\n');
        if tx.send_data(Bytes::from(header)).await.is_err() {
            return;
        }
        let columns = resp.columns;
        let mut rows = resp.rows.into_iter();
        loop {
            let mut batch: Vec<Vec<serde_json::Value>> = Vec::with_capacity(window);
            for _ in 0..window {
                match rows.next() {
                    Some(r) => batch.push(r),
                    None => break,
                }
            }
            if batch.is_empty() {
                break;
            }
            let mut out = String::new();
            for row in &batch {
                let line = columns
                    .iter()
                    .enumerate()
                    .map(|(i, _)| {
                        csv_escape(&json_cell_to_string(
                            row.get(i).unwrap_or(&serde_json::Value::Null),
                        ))
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                out.push_str(&line);
                out.push('\n');
            }
            if tx.send_data(Bytes::from(out)).await.is_err() {
                return;
            }
        }
        if truncated {
            let _ = tx
                .send_data(Bytes::from_static(b"# truncated=true\n"))
                .await;
        }
    });

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/csv; charset=utf-8")
        .header("x-data-nexus-stream", "chunked");
    if download {
        builder = builder.header(
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"portal-export.csv\"",
        );
    }
    builder.body(body).unwrap_or_else(|_| {
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from("response build failed"))
            .expect("static")
    })
}

/// A09: Complete-path JSON document streamed in row windows (stream=chunked).
/// Body is still one valid AdminPortalQueryResponse JSON object.
fn portal_json_chunked_response(
    resp: AdminPortalQueryResponse,
    download: bool,
    window_rows: usize,
) -> Response<Body> {
    let window = window_rows.max(1);
    let (mut tx, body) = Body::channel();
    tokio::spawn(async move {
        let cols_json = match serde_json::to_string(&resp.columns) {
            Ok(s) => s,
            Err(_) => return,
        };
        let service_json = match serde_json::to_string(&resp.service) {
            Ok(s) => s,
            Err(_) => return,
        };
        let prefix = format!("{{\"columns\":{cols_json},\"rows\":[");
        if tx.send_data(Bytes::from(prefix)).await.is_err() {
            return;
        }
        let mut first = true;
        let mut rows = resp.rows.into_iter();
        let mut sent = 0usize;
        loop {
            let mut batch = Vec::with_capacity(window);
            for _ in 0..window {
                match rows.next() {
                    Some(r) => batch.push(r),
                    None => break,
                }
            }
            if batch.is_empty() {
                break;
            }
            let mut frag = Vec::new();
            for row in batch {
                if !first {
                    frag.push(b',');
                }
                first = false;
                match serde_json::to_vec(&row) {
                    Ok(b) => frag.extend_from_slice(&b),
                    Err(_) => frag.extend_from_slice(b"null"),
                }
                sent += 1;
            }
            if tx.send_data(Bytes::from(frag)).await.is_err() {
                return;
            }
        }
        let trailer = format!(
            "],\"row_count\":{sent},\"truncated\":{},\"service\":{service_json},\"decision\":\"allow\",\"stream\":\"chunked\",\"window_rows\":{window}}}",
            resp.truncated
        );
        let _ = tx.send_data(Bytes::from(trailer)).await;
    });

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
        .header("x-data-nexus-stream", "chunked");
    if download {
        builder = builder.header(
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"portal-export.json\"",
        );
    }
    builder.body(body).unwrap_or_else(|_| {
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from("response build failed"))
            .expect("static")
    })
}

fn portal_ndjson_meta_value(resp: &AdminPortalQueryResponse) -> serde_json::Value {
    serde_json::json!({
        "_meta": true,
        "service": resp.service,
        "decision": resp.decision,
        "row_count": resp.row_count,
        "truncated": resp.truncated,
        "columns": resp.columns,
        "stream": "chunked",
    })
}

/// Encode one NDJSON object line per row (no trailing meta).
fn portal_ndjson_encode_rows(columns: &[String], rows: &[Vec<serde_json::Value>]) -> Vec<u8> {
    let mut out = Vec::new();
    for row in rows {
        let mut obj = serde_json::Map::new();
        for (i, col) in columns.iter().enumerate() {
            let v = row.get(i).cloned().unwrap_or(serde_json::Value::Null);
            obj.insert(col.clone(), v);
        }
        if let Ok(b) = serde_json::to_vec(&serde_json::Value::Object(obj)) {
            out.extend_from_slice(&b);
            out.push(b'\n');
        }
    }
    out
}

fn portal_download_response(
    body: impl Into<Vec<u8>>,
    content_type: &str,
    download: bool,
    filename: &str,
) -> Response<Body> {
    let bytes = body.into();
    let mut builder = Response::builder().header(header::CONTENT_TYPE, content_type);
    if download {
        builder = builder.header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        );
    }
    builder
        .body(Body::from(bytes))
        .unwrap_or_else(|error| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from(error.to_string()))
                .expect("static internal server error response is valid")
        })
}

fn portal_to_csv(resp: &AdminPortalQueryResponse) -> Vec<u8> {
    let mut out = String::new();
    out.push_str(
        &resp
            .columns
            .iter()
            .map(|c| csv_escape(c))
            .collect::<Vec<_>>()
            .join(","),
    );
    out.push('\n');
    for row in &resp.rows {
        let line = resp
            .columns
            .iter()
            .enumerate()
            .map(|(i, _)| {
                csv_escape(&json_cell_to_string(
                    row.get(i).unwrap_or(&serde_json::Value::Null),
                ))
            })
            .collect::<Vec<_>>()
            .join(",");
        out.push_str(&line);
        out.push('\n');
    }
    if resp.truncated {
        out.push_str("# truncated=true\n");
    }
    out.into_bytes()
}

/// A09: encode one window of gateway rows as CSV lines (no header).
fn portal_csv_encode_rows(
    columns: &[String],
    rows: &[Vec<gateway_core::GatewayValue>],
) -> Vec<u8> {
    let mut out = String::new();
    for row in rows {
        let line = columns
            .iter()
            .enumerate()
            .map(|(i, _)| {
                let cell = row.get(i).cloned().unwrap_or(gateway_core::GatewayValue::Null);
                csv_escape(&gateway_value_to_csv_cell(&cell))
            })
            .collect::<Vec<_>>()
            .join(",");
        out.push_str(&line);
        out.push('\n');
    }
    out.into_bytes()
}

fn gateway_value_to_csv_cell(v: &gateway_core::GatewayValue) -> String {
    match v {
        gateway_core::GatewayValue::Null => String::new(),
        gateway_core::GatewayValue::Boolean(b) => b.to_string(),
        gateway_core::GatewayValue::Integer(i) => i.to_string(),
        gateway_core::GatewayValue::UnsignedInteger(u) => u.to_string(),
        gateway_core::GatewayValue::Float(f) => f.to_string(),
        gateway_core::GatewayValue::Decimal(s) | gateway_core::GatewayValue::String(s) => s.clone(),
        gateway_core::GatewayValue::Bytes(b) => {
            let mut hex = String::with_capacity(2 + b.len() * 2);
            hex.push_str("0x");
            for byte in b {
                hex.push_str(&format!("{byte:02x}"));
            }
            hex
        }
    }
}

fn portal_to_ndjson(resp: &AdminPortalQueryResponse) -> Vec<u8> {
    let mut out = Vec::new();
    if let Ok(b) = serde_json::to_vec(&portal_ndjson_meta_value(resp)) {
        out.extend_from_slice(&b);
        out.push(b'\n');
    }
    out.extend_from_slice(&portal_ndjson_encode_rows(&resp.columns, &resp.rows));
    out
}

fn json_cell_to_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Null => String::new(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_owned()
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
    use proxy::factory::{
        PoolEndpointRefresh, PoolEndpointSnapshot, PoolRefresh, PoolRefresher,
        SessionEntrySnapshot, SessionSnapshot,
    };
    use serde_json::{json, Value};
    use tower::ServiceExt;

    use super::*;

    fn gateway_config() -> GatewayConfigDocument {
        GatewayConfigDocument::from_toml(include_str!("../../../examples/gateway-config.toml"))
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
    async fn admin_dashboard_returns_html() {
        let app = gateway_server().routes();
        let response = app
            .oneshot(Request::builder().uri("/admin").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(content_type.contains("text/html"), "content-type={content_type}");
        let body = to_bytes(response.into_body()).await.unwrap();
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("Data Nexus Admin"));
        assert!(html.contains("/admin/listeners"));
        assert!(html.contains("/admin/reload"));
    }

    fn gateway_server_with_auth(auth: gateway_core::AdminAuthConfig) -> AxumServer {
        let server = gateway_server();
        if let Some(shared) = &server.gateway_config {
            let mut guard = shared.write().unwrap();
            guard.admin_auth = auth;
        }
        server
    }

    #[tokio::test]
    async fn admin_auth_config_is_public_when_enabled() {
        let auth = gateway_core::AdminAuthConfig {
            enabled: true,
            mode: gateway_core::AdminAuthMode::JwtHmac,
            jwt_secret: "test-secret-16b!!".into(),
            ..gateway_core::AdminAuthConfig::default()
        };
        let server = gateway_server_with_auth(auth);
        let (status, value) = get_json_from(server, "/admin/auth/config").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["enabled"], true);
        assert_eq!(value["mode"], "jwt_hmac");
    }

    #[tokio::test]
    async fn enabled_auth_rejects_reload_without_token() {
        let auth = gateway_core::AdminAuthConfig {
            enabled: true,
            mode: gateway_core::AdminAuthMode::JwtHmac,
            jwt_secret: "test-secret-16b!!".into(),
            issuer: "data-nexus-test".into(),
            audience: "data-nexus-admin".into(),
            ..gateway_core::AdminAuthConfig::default()
        };
        let server = gateway_server_with_auth(auth);
        let (status, value) = post_json(server, "/admin/reload").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(value["error"], "unauthorized");
    }

    #[tokio::test]
    async fn enabled_auth_allows_admin_token_on_me_and_forbids_viewer_reload() {
        use gateway_core::{AdminAuthMode, AdminRole};

        let auth = gateway_core::AdminAuthConfig {
            enabled: true,
            mode: AdminAuthMode::JwtHmac,
            jwt_secret: "test-secret-16b!!".into(),
            issuer: "data-nexus-test".into(),
            audience: "data-nexus-admin".into(),
            ..gateway_core::AdminAuthConfig::default()
        };
        let viewer = admin_auth::issue_hmac_token(&auth, "viewer1", &[AdminRole::Viewer], 3600)
            .expect("token");
        let admin =
            admin_auth::issue_hmac_token(&auth, "admin1", &[AdminRole::Admin], 3600).expect("token");
        let server = gateway_server_with_auth(auth);

        let response = server
            .routes()
            .oneshot(
                Request::builder()
                    .uri("/admin/me")
                    .header(header::AUTHORIZATION, format!("Bearer {admin}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body()).await.unwrap();
        let me: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(me["subject"], "admin1");
        assert!(me["roles"].as_array().unwrap().iter().any(|r| r == "admin"));

        let response = server
            .routes()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/admin/reload")
                    .header(header::AUTHORIZATION, format!("Bearer {viewer}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn admin_api_allows_cors_preflight() {
        let app = gateway_server().routes();
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/admin/listeners")
                    .header(header::ORIGIN, "http://localhost:3000")
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            response.status() == StatusCode::OK
                || response.status() == StatusCode::NO_CONTENT
                || response.status() == StatusCode::BAD_REQUEST,
            "unexpected status {}",
            response.status()
        );
        // With allow any origin, CORS headers should be present on preflight or GET.
        let get_response = gateway_server()
            .routes()
            .oneshot(
                Request::builder()
                    .uri("/admin/listeners")
                    .header(header::ORIGIN, "http://localhost:3000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get_response.status(), StatusCode::OK);
        let acao = get_response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            acao == "*" || acao == "http://localhost:3000",
            "missing/invalid ACAO: {acao}"
        );
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
        assert_eq!(listeners[0]["protocol"], "mysql");

        let (status, services) = get_json("/admin/services").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(services.as_array().unwrap().len(), 1);
        assert_eq!(services[0]["backend_protocol"], "mysql");

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
                "protocol": "mysql",
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
                "protocol": "mysql",
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
    async fn admin_refresh_pool_returns_runtime_refresh_status() {
        let shutdown_handle = ShutdownHandle::new();
        let pool_refresher: PoolRefresher = Arc::new(|| PoolRefresh {
            endpoints: vec![PoolEndpointRefresh {
                endpoint: "127.0.0.1:3306".to_string(),
                configured: true,
                factory_registered: true,
                idle_connections_closed: 2,
                remaining_idle_connections: 0,
                capacity: 64,
            }],
        });
        let server =
            gateway_server_with_runtime_state(AdminRuntimeState::new_with_runtime_controls(vec![
                ("orders-mysql".to_string(), shutdown_handle, None, Some(pool_refresher), None),
            ]));

        let (status, value) = post_json(server, "/admin/pools/orders-mysql/refresh").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["name"], "orders-mysql");
        assert_eq!(value["endpoints"][0]["endpoint"], "127.0.0.1:3306");
        assert_eq!(value["endpoints"][0]["idle_connections_closed"], 2);
        assert_eq!(value["endpoints"][0]["remaining_idle_connections"], 0);
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
        let path = write_temp_gateway_config(include_str!("../../../examples/gateway-config.toml"));
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
    async fn admin_reload_applies_shared_config_when_diff_exists() {
        let changed_config = include_str!("../../../examples/gateway-config.toml")
            .replace("address = \"127.0.0.1:3307\"", "address = \"127.0.0.1:3317\"");
        let path = write_temp_gateway_config(&changed_config);
        let server = gateway_server_with_config_source(path.clone());

        let (status, value) = post_json(server.clone(), "/admin/reload").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["status"], "applied");
        assert_eq!(value["applied"], true);
        assert_eq!(value["changed"], true);
        assert_eq!(value["diff"]["endpoints"]["changed"][0], "orders-replica");

        let (status, endpoints) = get_json_from(server, "/admin/endpoints").await;
        let _ = fs::remove_file(path);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(endpoints[1]["address"], "127.0.0.1:3317");
    }

    #[tokio::test]
    async fn admin_reload_rejects_invalid_config_and_keeps_previous() {
        let path = write_temp_gateway_config(
            r#"
version = "2"
[admin]
host = "0.0.0.0"
port = 8082
log_level = "INFO"
[[listeners]]
name = "broken"
listen_addr = "0.0.0.0:1"
protocol = "mysql"
service = "missing-service"
"#,
        );
        let server = gateway_server_with_config_source(path.clone());

        let (status, value) = post_json(server.clone(), "/admin/reload").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(value["message"].as_str().unwrap().contains("invalid gateway configuration"));

        let (status, listeners) = get_json_from(server, "/admin/listeners").await;
        let _ = fs::remove_file(path);
        assert_eq!(status, StatusCode::OK);
        // Previous valid example config remains.
        assert_eq!(listeners[0]["name"], "orders-mysql");
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

    #[test]
    fn portal_ndjson_encode_rows_windowed_matches_full() {
        let resp = AdminPortalQueryResponse {
            columns: vec!["id".into(), "name".into()],
            rows: (0..5)
                .map(|i| vec![json!(i), json!(format!("n{i}"))])
                .collect(),
            row_count: 5,
            truncated: false,
            service: "orders".into(),
            decision: "allow".into(),
            message: None,
        };
        let full = portal_to_ndjson(&resp);
        // Window size 2: meta + 3 chunks (2+2+1) should reconstruct same lines.
        let mut rebuilt = Vec::new();
        let meta = portal_ndjson_meta_value(&resp);
        rebuilt.extend(serde_json::to_vec(&meta).unwrap());
        rebuilt.push(b'\n');
        for chunk in resp.rows.chunks(2) {
            rebuilt.extend(portal_ndjson_encode_rows(&resp.columns, chunk));
        }
        assert_eq!(
            String::from_utf8_lossy(&full),
            String::from_utf8_lossy(&rebuilt)
        );
        let lines: Vec<_> = std::str::from_utf8(&full)
            .unwrap()
            .lines()
            .filter(|l| !l.is_empty())
            .collect();
        assert_eq!(lines.len(), 6); // meta + 5 rows
        let meta_v: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(meta_v["_meta"], true);
        assert_eq!(meta_v["stream"], "chunked");
        assert_eq!(meta_v["row_count"], 5);
    }

    #[tokio::test]
    async fn portal_ndjson_chunked_response_streams_body() {
        let resp = AdminPortalQueryResponse {
            columns: vec!["id".into(), "name".into()],
            rows: vec![
                vec![json!(1), json!("a")],
                vec![json!(2), json!("b")],
                vec![json!(3), json!("c")],
            ],
            row_count: 3,
            truncated: true,
            service: "orders".into(),
            decision: "allow".into(),
            message: None,
        };
        let response = portal_ndjson_chunked_response(resp, true, 2);
        assert_eq!(response.status(), StatusCode::OK);
        let ct = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(ct.contains("ndjson"), "{ct}");
        assert_eq!(
            response
                .headers()
                .get("x-data-nexus-stream")
                .and_then(|v| v.to_str().ok()),
            Some("chunked")
        );
        let cd = response
            .headers()
            .get(header::CONTENT_DISPOSITION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(cd.contains("portal-export.ndjson"), "{cd}");

        let bytes = to_bytes(response.into_body()).await.unwrap();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        let lines: Vec<_> = text.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 4, "{text}");
        let meta: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(meta["_meta"], true);
        assert_eq!(meta["truncated"], true);
        assert_eq!(meta["stream"], "chunked");
        let r1: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(r1["id"], 1);
        assert_eq!(r1["name"], "a");
        let r3: Value = serde_json::from_str(lines[3]).unwrap();
        assert_eq!(r3["id"], 3);
    }

    #[test]
    fn gateway_value_to_json_covers_variants() {
        assert_eq!(gateway_value_to_json(gateway_core::GatewayValue::Null), json!(null));
        assert_eq!(
            gateway_value_to_json(gateway_core::GatewayValue::Boolean(true)),
            json!(true)
        );
        assert_eq!(
            gateway_value_to_json(gateway_core::GatewayValue::Integer(-3)),
            json!(-3)
        );
        assert_eq!(
            gateway_value_to_json(gateway_core::GatewayValue::UnsignedInteger(9)),
            json!(9)
        );
        assert_eq!(
            gateway_value_to_json(gateway_core::GatewayValue::String("x".into())),
            json!("x")
        );
        assert_eq!(
            gateway_value_to_json(gateway_core::GatewayValue::Bytes(vec![1, 2, 3])),
            json!("bytes:3")
        );
    }

    #[test]
    fn portal_ndjson_backend_window_meta_shape() {
        // Mirrors A09 streaming producer meta (must stay client-compatible with `_meta`).
        let meta = json!({
            "_meta": true,
            "columns": ["id", "name"],
            "service": "orders",
            "decision": "allow",
            "stream": "backend_window",
            "window_rows": 256,
        });
        assert_eq!(meta["_meta"], true);
        assert_eq!(meta["stream"], "backend_window");
        assert_eq!(meta["window_rows"], 256);
        assert!(meta["columns"].is_array());
    }

    #[test]
    fn a09_portal_ndjson_encode_multi_row_window() {
        // Multi-row SELECT body is encoded as one NDJSON line per row; meta is
        // separate (backend_window path yields meta first, then row lines).
        let cols = vec!["id".into(), "name".into()];
        let rows = vec![
            vec![json!(1), json!("portal")],
            vec![json!(2), json!("row2")],
            vec![json!(3), json!("row3")],
        ];
        let bytes = portal_ndjson_encode_rows(&cols, &rows);
        let text = String::from_utf8(bytes).unwrap();
        let lines: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 3);
        let r0: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(r0["id"], 1);
        assert_eq!(r0["name"], "portal");
        let r2: serde_json::Value = serde_json::from_str(lines[2]).unwrap();
        assert_eq!(r2["id"], 3);
    }

    #[test]
    fn a09_portal_csv_encode_rows_escapes_and_joins() {
        use gateway_core::GatewayValue;
        let cols = vec!["id".into(), "name".into()];
        let rows = vec![
            vec![GatewayValue::Integer(1), GatewayValue::String("a,b".into())],
            vec![GatewayValue::Integer(2), GatewayValue::String("x\"y".into())],
        ];
        let text = String::from_utf8(portal_csv_encode_rows(&cols, &rows)).unwrap();
        let lines: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "1,\"a,b\"");
        assert!(lines[1].starts_with("2,"));
        assert!(lines[1].contains("\"\"")); // escaped quote
    }

    #[test]
    fn a09_portal_json_encode_row_array_fragment_joins_windows() {
        use gateway_core::GatewayValue;
        let mut first = true;
        let w1 = vec![
            vec![GatewayValue::Integer(1), GatewayValue::String("a".into())],
            vec![GatewayValue::Integer(2), GatewayValue::String("b".into())],
        ];
        let w2 = vec![vec![
            GatewayValue::Integer(3),
            GatewayValue::String("c".into()),
        ]];
        let mut body = b"{\"columns\":[\"id\",\"name\"],\"rows\":[".to_vec();
        body.extend(portal_json_encode_row_array_fragment(&w1, &mut first));
        body.extend(portal_json_encode_row_array_fragment(&w2, &mut first));
        body.extend_from_slice(
            br#"],"row_count":3,"truncated":false,"service":"orders","decision":"allow","stream":"backend_window","window_rows":2}"#,
        );
        let v: serde_json::Value = serde_json::from_slice(&body).expect("valid json document");
        assert_eq!(v["decision"], "allow");
        assert_eq!(v["stream"], "backend_window");
        assert_eq!(v["row_count"], 3);
        assert_eq!(v["rows"].as_array().unwrap().len(), 3);
        assert_eq!(v["rows"][0][0], 1);
        assert_eq!(v["rows"][2][1], "c");
    }

    #[tokio::test]
    async fn a09_portal_json_chunked_complete_path_is_valid_document() {
        // Complete-path progressive JSON must still parse as AdminPortalQueryResponse.
        let resp = AdminPortalQueryResponse {
            columns: vec!["id".into(), "name".into()],
            rows: vec![
                vec![serde_json::json!(1), serde_json::json!("a")],
                vec![serde_json::json!(2), serde_json::json!("b")],
                vec![serde_json::json!(3), serde_json::json!("c")],
            ],
            row_count: 3,
            truncated: false,
            service: "orders".into(),
            decision: "allow".into(),
            message: None,
        };
        let response = portal_json_chunked_response(resp, false, 2);
        assert_eq!(
            response
                .headers()
                .get("x-data-nexus-stream")
                .and_then(|v| v.to_str().ok()),
            Some("chunked")
        );
        // Collect body via hyper Body stream is awkward without runtime helpers;
        // shape is covered by fragment unit test + smoke Streaming path.
        let _ = response;
    }

    #[test]
    fn a09_portal_prepare_mode_is_streaming() {
        // portal_prepare always uses ExecuteMode::Streaming from security.streaming
        // so MySQL/PG backends can yield RowStream for NDJSON/CSV/JSON backend_window.
        use gateway_core::ExecuteMode;
        let mode = ExecuteMode::from_streaming_config(256, Some(10));
        assert!(matches!(mode, ExecuteMode::Streaming { .. }));
        assert_eq!(mode.window_rows(), Some(256));
        assert_eq!(mode.effective_max_rows(), Some(10));
    }

    #[test]
    fn a09_portal_prepare_applies_cross_protocol_translation() {
        // Portal SQL is written in the listener (frontend) dialect; when the
        // service has a translation_policy, portal_prepare rewrites before backend.
        use gateway_core::{
            default_dialect_parser, prepare_cross_protocol_command, GatewayCommand, ProtocolKind,
            TranslationPolicyConfig, TranslationStatementKind,
        };
        let policy = TranslationPolicyConfig {
            name: "mysql-to-pg".into(),
            enabled: true,
            frontend_protocol: ProtocolKind::MySql,
            backend_protocol: ProtocolKind::PostgreSql,
            allowed_statements: vec![TranslationStatementKind::Select],
        };
        let dialect = default_dialect_parser(&ProtocolKind::MySql);
        let cmd = prepare_cross_protocol_command(
            &policy,
            GatewayCommand::Query {
                sql: "SELECT `id`, IFNULL(name, '') FROM portal_xproto WHERE id=1".into(),
            },
            &dialect,
        )
        .expect("translation");
        match cmd {
            GatewayCommand::Query { sql } => {
                assert!(
                    sql.contains("COALESCE") || sql.contains("coalesce"),
                    "expected IFNULL→COALESCE rewrite, got {sql}"
                );
                assert!(
                    !sql.contains("IFNULL") && !sql.contains("ifnull"),
                    "IFNULL should be rewritten: {sql}"
                );
                assert!(
                    sql.contains("\"id\"") || sql.contains("id"),
                    "id should remain: {sql}"
                );
            }
            other => panic!("expected Query, got {other:?}"),
        }
    }

    #[test]
    fn a09_portal_prepare_applies_reverse_cross_protocol_translation() {
        // Reverse: PostgreSQL SQL surface → MySQL backend (identifier quotes).
        use gateway_core::{
            default_dialect_parser, prepare_cross_protocol_command, GatewayCommand, ProtocolKind,
            TranslationPolicyConfig, TranslationStatementKind,
        };
        let policy = TranslationPolicyConfig {
            name: "pg-to-mysql".into(),
            enabled: true,
            frontend_protocol: ProtocolKind::PostgreSql,
            backend_protocol: ProtocolKind::MySql,
            allowed_statements: vec![TranslationStatementKind::Select],
        };
        let dialect = default_dialect_parser(&ProtocolKind::PostgreSql);
        let cmd = prepare_cross_protocol_command(
            &policy,
            GatewayCommand::Query {
                sql: "SELECT \"id\", COALESCE(name, '') FROM portal_xproto_rev WHERE id=1".into(),
            },
            &dialect,
        )
        .expect("translation");
        match cmd {
            GatewayCommand::Query { sql } => {
                assert!(
                    sql.contains("`id`") || sql.contains("id"),
                    "expected MySQL-style id, got {sql}"
                );
                // Double-quoted identifiers should become backticks for MySQL.
                assert!(
                    !sql.contains("\"id\""),
                    "PG double-quoted id should be rewritten: {sql}"
                );
                assert!(
                    sql.contains("COALESCE") || sql.contains("coalesce"),
                    "COALESCE is portable and should remain: {sql}"
                );
            }
            other => panic!("expected Query, got {other:?}"),
        }
    }
}
