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

use std::{sync::Arc, time::Instant};

use endpoint::endpoint::Endpoint;
use gateway_core::{
    map_response_types, prepare_cross_protocol_command, BackendConnector, CommandSummary,
    DialectParser, EndpointConfig, EndpointRef, EndpointRole, FrontendProtocolAdapter,
    GatewayCommand, GatewayConfig, GatewayError, GatewayResponse, GatewayResult, ListenerConfig,
    PluginContext, PluginDecision, ProtocolKind, RoutePlan, ServiceConfig, SessionState,
    TransactionState, TranslationPolicyConfig,
};
use loadbalance::balance::{AlgorithmName, Balance, BalanceType, LoadBalance};
use parking_lot::Mutex;
use plugin::build_phase::PluginPhase;
use tracing::{info, info_span, Instrument};

use crate::{
    backend::{mysql::MySqlBackendConnector, postgresql::PostgreSqlBackendConnector},
    dialect::runtime_dialect_parser,
    frontend::{mysql::MySqlFrontendProtocol, postgresql::PostgreSqlFrontendProtocol},
    server::metrics::MySQLServerMetricsCollector,
};

/// Protocol-neutral execution path for one frontend connection.
///
/// Wire-specific code still owns socket framing and handshake. Once a frontend
/// frame is available, this bridge keeps the request path on gateway_core
/// contracts: decode command, route, plugin evaluate, execute, then encode.
pub struct CoreGatewayConnection {
    frontend: Box<dyn FrontendProtocolAdapter>,
    backend: Arc<dyn BackendConnector>,
    session: SessionState,
    listener_name: String,
    service_name: String,
    route_policy: Option<CoreRoutePolicy>,
    plugins: Option<PluginPhase>,
    /// Present only for cross-protocol services with an enabled policy.
    translation_policy: Option<TranslationPolicyConfig>,
    /// Frontend dialect used for translation checks (SQL arrives as client dialect).
    frontend_dialect: Arc<dyn DialectParser>,
    /// Data-plane Local PDP when `security.enabled` (S1+).
    security: Option<gateway_core::LocalPdp>,
    metrics: MySQLServerMetricsCollector,
}

impl CoreGatewayConnection {
    pub fn new(
        frontend: Box<dyn FrontendProtocolAdapter>,
        backend: Arc<dyn BackendConnector>,
        session: SessionState,
    ) -> Self {
        let frontend_protocol = frontend.protocol();
        Self {
            frontend,
            backend,
            session,
            listener_name: String::new(),
            service_name: String::new(),
            route_policy: None,
            plugins: None,
            translation_policy: None,
            frontend_dialect: Arc::from(runtime_dialect_parser(&frontend_protocol)),
            security: None,
            metrics: MySQLServerMetricsCollector,
        }
    }

    fn with_route_policy(
        frontend: Box<dyn FrontendProtocolAdapter>,
        backend: Arc<dyn BackendConnector>,
        session: SessionState,
        listener_name: String,
        service_name: String,
        route_policy: CoreRoutePolicy,
        translation_policy: Option<TranslationPolicyConfig>,
        security: Option<gateway_core::LocalPdp>,
    ) -> Self {
        let frontend_protocol = frontend.protocol();
        Self {
            frontend,
            backend,
            session,
            listener_name,
            service_name,
            route_policy: Some(route_policy),
            plugins: None,
            translation_policy,
            frontend_dialect: Arc::from(runtime_dialect_parser(&frontend_protocol)),
            security,
            metrics: MySQLServerMetricsCollector,
        }
    }

    pub fn with_plugins(mut self, plugins: PluginPhase) -> Self {
        self.plugins = Some(plugins);
        self
    }

    pub fn with_security(mut self, security: Option<gateway_core::LocalPdp>) -> Self {
        self.security = security;
        self
    }

    pub fn frontend_protocol(&self) -> ProtocolKind {
        self.frontend.protocol()
    }

    pub fn backend_protocol(&self) -> ProtocolKind {
        self.backend.protocol()
    }

    pub fn session(&self) -> &SessionState {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut SessionState {
        &mut self.session
    }

    pub async fn handle_frame(&mut self, frame: &[u8]) -> GatewayResult<Vec<Vec<u8>>> {
        let frame_span = info_span!(
            "gateway.handle_frame",
            listener = %self.listener_name,
            service = %self.service_name,
            frontend_protocol = %protocol_metric_name(&self.frontend.protocol()),
            backend_protocol = %protocol_metric_name(&self.backend.protocol()),
        );
        async {
            self.handle_frame_inner(frame).await
        }
        .instrument(frame_span)
        .await
    }

    async fn handle_frame_inner(&mut self, frame: &[u8]) -> GatewayResult<Vec<Vec<u8>>> {
        let commands = self.frontend.decode(frame, &mut self.session)?;
        let mut packets = Vec::with_capacity(commands.len());

        for mut command in commands {
            let command_type = command_metric_type(&command);
            let started_at = Instant::now();
            let command_span = info_span!(
                "gateway.command",
                command_type = %command_type,
                endpoint = tracing::field::Empty,
                outcome = tracing::field::Empty,
            );

            let route_plan = if let Some(route_policy) = &self.route_policy {
                let plan = route_policy.plan_command(&command, &self.session)?;
                apply_route_plan(&plan, &mut self.session)?;
                Some(plan)
            } else {
                None
            };

            let endpoint_label = route_endpoint_label(route_plan.as_ref(), &self.session);
            command_span.record("endpoint", tracing::field::display(&endpoint_label));
            let label_owned = [
                self.listener_name.clone(),
                self.service_name.clone(),
                protocol_metric_name(&self.frontend.protocol()).to_owned(),
                protocol_metric_name(&self.backend.protocol()).to_owned(),
                command_type.to_owned(),
                endpoint_label,
            ];
            let labels = [
                label_owned[0].as_str(),
                label_owned[1].as_str(),
                label_owned[2].as_str(),
                label_owned[3].as_str(),
                label_owned[4].as_str(),
                label_owned[5].as_str(),
            ];
            self.metrics.set_sql_under_processing_inc(&labels);

            let mut concurrency_rule_idx = None;
            if let Some(plugins) = self.plugins.as_mut() {
                let ctx = PluginContext {
                    service: self.service_name.clone(),
                    client_protocol: self.frontend.protocol(),
                    user: self.session.user.clone(),
                    database: self.session.database.clone(),
                    command: CommandSummary::from_command(&command),
                    route_plan: route_plan.clone(),
                };
                match plugins.evaluate(&ctx).map_err(|error| {
                    GatewayError::Configuration(format!("plugin evaluate failed: {}", error))
                }) {
                    Ok(PluginDecision::Continue { concurrency_rule_idx: idx }) => {
                        concurrency_rule_idx = idx;
                    }
                    Ok(PluginDecision::Reject { code, message }) => {
                        info!(
                            target: gateway_core::AUDIT_TARGET,
                            action = gateway_core::AuditAction::Query.as_str(),
                            listener = %self.listener_name,
                            service = %self.service_name,
                            frontend_protocol = %protocol_metric_name(&self.frontend.protocol()),
                            backend_protocol = %protocol_metric_name(&self.backend.protocol()),
                            command_type = %command_type,
                            endpoint = %label_owned[5],
                            db_user = ?self.session.user,
                            database = ?self.session.database,
                            decision = gateway_core::AuditDecision::Reject.as_str(),
                            code = %code,
                            message = %message,
                            "gateway command rejected by plugin"
                        );
                        let response = GatewayResponse::Error { code, message };
                        packets.extend(self.frontend.encode(response, &mut self.session)?);
                        record_otel_command(
                            &self.listener_name,
                            &self.service_name,
                            labels[2],
                            labels[3],
                            command_type,
                            labels[5],
                            "plugin_reject",
                            started_at,
                        );
                        finish_command_metrics(&self.metrics, &labels, started_at);
                        continue;
                    }
                    Ok(PluginDecision::Rewrite { sql }) => {
                        if let Some(rewritten) =
                            CommandSummary::from_command(&command).rewritten_sql(sql)
                        {
                            command = rewritten;
                        }
                    }
                    Err(error) => {
                        finish_command_metrics(&self.metrics, &labels, started_at);
                        return Err(error);
                    }
                }
            }

            // Cross-protocol: validate subset, rewrite SQL, reject prepared stmts.
            if let Some(policy) = &self.translation_policy {
                match prepare_cross_protocol_command(
                    policy,
                    command,
                    self.frontend_dialect.as_ref(),
                ) {
                    Ok(translated) => command = translated,
                    Err(error) => {
                        let response = GatewayResponse::Error {
                            code: "translation_error".into(),
                            message: error.to_string(),
                        };
                        info!(
                            target: gateway_core::AUDIT_TARGET,
                            action = gateway_core::AuditAction::Query.as_str(),
                            listener = %self.listener_name,
                            service = %self.service_name,
                            frontend_protocol = %protocol_metric_name(&self.frontend.protocol()),
                            backend_protocol = %protocol_metric_name(&self.backend.protocol()),
                            command_type = %command_type,
                            endpoint = %label_owned[5],
                            db_user = ?self.session.user,
                            database = ?self.session.database,
                            decision = gateway_core::AuditDecision::TranslationReject.as_str(),
                            message = %error,
                            "gateway command rejected by translation policy"
                        );
                        command_span.record("outcome", "translation_reject");
                        packets.extend(self.frontend.encode(response, &mut self.session)?);
                        record_otel_command(
                            &self.listener_name,
                            &self.service_name,
                            labels[2],
                            labels[3],
                            command_type,
                            labels[5],
                            "translation_reject",
                            started_at,
                        );
                        finish_command_metrics(&self.metrics, &labels, started_at);
                        continue;
                    }
                }
            }

            // S1/S2/S3: data-plane Local PDP (table/statement/column/mask/row) before backend execute.
            let mut command = command;
            let mut pending_obligations = gateway_core::Obligations::default();
            if let Some(pdp) = &self.security {
                let subject = gateway_core::Subject::from_protocol_user(
                    self.session.user.as_deref(),
                    self.session.database.as_deref(),
                );
                let objects = match &command {
                    GatewayCommand::Query { sql } | GatewayCommand::Prepare { sql } => {
                        let set = crate::object_extract::extract_object_set(
                            sql,
                            self.frontend.protocol().as_str(),
                        );
                        if set.parse_failed {
                            tracing::warn!(
                                target: "data_nexus::security",
                                listener = %self.listener_name,
                                service = %self.service_name,
                                subject_id = %subject.subject_id,
                                heuristic = set.heuristic,
                                "security object extraction failed or partial"
                            );
                        }
                        Some(set)
                    }
                    _ => None,
                };
                match pdp.authorize_command_with_objects(
                    &subject,
                    &self.service_name,
                    &command,
                    self.frontend_dialect.as_ref(),
                    objects.as_ref(),
                ) {
                    gateway_core::SecurityDecision::Allow { obligations } => {
                        pending_obligations = obligations;
                    }
                    gateway_core::SecurityDecision::AllowRewrite { sql, obligations } => {
                        info!(
                            target: gateway_core::AUDIT_TARGET,
                            action = gateway_core::AuditAction::Query.as_str(),
                            listener = %self.listener_name,
                            service = %self.service_name,
                            subject_id = %subject.subject_id,
                            decision = gateway_core::AuditDecision::Allow.as_str(),
                            row_filter = obligations.row_filter.as_deref().unwrap_or(""),
                            mask_count = obligations.column_masks.len(),
                            "security policy rewrote SQL / attached obligations"
                        );
                        pending_obligations = obligations;
                        match &mut command {
                            GatewayCommand::Query { sql: original }
                            | GatewayCommand::Prepare { sql: original } => {
                                *original = sql;
                            }
                            _ => {}
                        }
                    }
                    gateway_core::SecurityDecision::Deny { rule, message } => {
                        info!(
                            target: gateway_core::AUDIT_TARGET,
                            action = gateway_core::AuditAction::Query.as_str(),
                            listener = %self.listener_name,
                            service = %self.service_name,
                            frontend_protocol = %protocol_metric_name(&self.frontend.protocol()),
                            backend_protocol = %protocol_metric_name(&self.backend.protocol()),
                            command_type = %command_type,
                            endpoint = %label_owned[5],
                            subject_id = %subject.subject_id,
                            db_user = ?self.session.user,
                            database = ?self.session.database,
                            decision = gateway_core::AuditDecision::Deny.as_str(),
                            rule = %rule,
                            message = %message,
                            "gateway command denied by security policy"
                        );
                        let response = GatewayResponse::Error {
                            code: "security_deny".into(),
                            message,
                        };
                        command_span.record("outcome", "security_deny");
                        packets.extend(self.frontend.encode(response, &mut self.session)?);
                        record_otel_command(
                            &self.listener_name,
                            &self.service_name,
                            labels[2],
                            labels[3],
                            command_type,
                            labels[5],
                            "security_deny",
                            started_at,
                        );
                        finish_command_metrics(&self.metrics, &labels, started_at);
                        if let (Some(plugins), Some(idx)) =
                            (self.plugins.as_mut(), concurrency_rule_idx)
                        {
                            plugins.release_concurrency(idx);
                        }
                        continue;
                    }
                }
            }

            let response = match self
                .backend
                .execute(command, &mut self.session)
                .instrument(command_span.clone())
                .await
            {
                Ok(response) => {
                    let response = map_response_types(
                        response,
                        &self.backend.protocol(),
                        &self.frontend.protocol(),
                    );
                    if pending_obligations.has_result_obligations() {
                        info!(
                            target: gateway_core::AUDIT_TARGET,
                            action = gateway_core::AuditAction::Query.as_str(),
                            listener = %self.listener_name,
                            service = %self.service_name,
                            mask_count = pending_obligations.column_masks.len(),
                            max_rows = ?pending_obligations.max_rows,
                            "security applied result obligations"
                        );
                        gateway_core::apply_obligations_to_response(response, &pending_obligations)
                    } else {
                        response
                    }
                }
                Err(error) => GatewayResponse::Error {
                    code: "gateway_error".into(),
                    message: error.to_string(),
                },
            };

            let outcome = match &response {
                GatewayResponse::Error { code, .. } => format!("error:{code}"),
                GatewayResponse::ResultSet { .. } => "resultset".to_owned(),
                GatewayResponse::Ok { .. } => "ok".to_owned(),
                GatewayResponse::Pong => "pong".to_owned(),
                GatewayResponse::Bye => "bye".to_owned(),
                GatewayResponse::Prepared { .. } => "prepared".to_owned(),
            };
            command_span.record("outcome", tracing::field::display(&outcome));
            info!(
                target: gateway_core::AUDIT_TARGET,
                action = gateway_core::AuditAction::Query.as_str(),
                listener = %self.listener_name,
                service = %self.service_name,
                frontend_protocol = %protocol_metric_name(&self.frontend.protocol()),
                backend_protocol = %protocol_metric_name(&self.backend.protocol()),
                command_type = %command_type,
                endpoint = %label_owned[5],
                db_user = ?self.session.user,
                database = ?self.session.database,
                decision = gateway_core::AuditDecision::Execute.as_str(),
                outcome = %outcome,
                latency_ms = started_at.elapsed().as_millis() as u64,
                "gateway command audited"
            );

            if let (Some(plugins), Some(idx)) = (self.plugins.as_mut(), concurrency_rule_idx) {
                plugins.release_concurrency(idx);
            }

            packets.extend(self.frontend.encode(response, &mut self.session)?);
            record_otel_command(
                &self.listener_name,
                &self.service_name,
                labels[2],
                labels[3],
                command_type,
                labels[5],
                &outcome,
                started_at,
            );
            finish_command_metrics(&self.metrics, &labels, started_at);
        }

        Ok(packets)
    }
}

fn finish_command_metrics(
    metrics: &MySQLServerMetricsCollector,
    labels: &[&str],
    started_at: Instant,
) {
    metrics.set_sql_under_processing_dec(labels);
    metrics.set_sql_processed_total(labels);
    metrics.set_sql_processed_duration(labels, started_at.elapsed().as_secs_f64());
}

fn record_otel_command(
    listener: &str,
    service: &str,
    frontend_protocol: &str,
    backend_protocol: &str,
    command_type: &str,
    endpoint: &str,
    outcome: &str,
    started_at: Instant,
) {
    crate::otel_metrics::record_command(
        listener,
        service,
        frontend_protocol,
        backend_protocol,
        command_type,
        endpoint,
        outcome,
        started_at.elapsed(),
    );
}

fn protocol_metric_name(protocol: &ProtocolKind) -> &'static str {
    match protocol {
        ProtocolKind::MySql => "mysql",
        ProtocolKind::PostgreSql => "postgresql",
    }
}

fn command_metric_type(command: &GatewayCommand) -> &'static str {
    match command {
        GatewayCommand::Query { .. } => "QUERY",
        GatewayCommand::Prepare { .. } => "PREPARE",
        GatewayCommand::Execute { .. } => "EXECUTE",
        GatewayCommand::CloseStatement { .. } => "CLOSE",
        GatewayCommand::UseDatabase { .. } => "USE",
        GatewayCommand::Begin => "BEGIN",
        GatewayCommand::Commit => "COMMIT",
        GatewayCommand::Rollback => "ROLLBACK",
        GatewayCommand::Ping => "PING",
        GatewayCommand::Quit => "QUIT",
    }
}

fn route_endpoint_label(route_plan: Option<&RoutePlan>, session: &SessionState) -> String {
    if let Some(endpoint) = route_plan.and_then(RoutePlan::as_single_endpoint) {
        return endpoint.address.clone();
    }
    session.backend_endpoint.clone().unwrap_or_default()
}

pub async fn handle_gateway_frame(
    frontend: &mut dyn FrontendProtocolAdapter,
    backend: &dyn BackendConnector,
    session: &mut SessionState,
    frame: &[u8],
) -> GatewayResult<Vec<Vec<u8>>> {
    let commands = frontend.decode(frame, session)?;
    let mut packets = Vec::with_capacity(commands.len());

    for command in commands {
        let response = match backend.execute(command, session).await {
            Ok(response) => response,
            Err(error) => {
                GatewayResponse::Error { code: "gateway_error".into(), message: error.to_string() }
            }
        };

        packets.extend(frontend.encode(response, session)?);
    }

    Ok(packets)
}

/// Resolved v2 gateway topology ready to create protocol-neutral connections.
#[derive(Debug, Clone)]
pub struct CoreGatewayRuntimePlan {
    listeners: Vec<CoreGatewayListenerPlan>,
}

impl PartialEq for CoreGatewayRuntimePlan {
    fn eq(&self, other: &Self) -> bool {
        self.listeners == other.listeners
    }
}

impl Eq for CoreGatewayRuntimePlan {}

impl CoreGatewayRuntimePlan {
    pub fn from_config(config: &GatewayConfig) -> GatewayResult<Self> {
        config.validate()?;

        let listeners = config
            .listeners
            .iter()
            .map(|listener| CoreGatewayListenerPlan::from_config(config, listener))
            .collect::<GatewayResult<Vec<_>>>()?;

        Ok(Self { listeners })
    }

    pub fn listeners(&self) -> &[CoreGatewayListenerPlan] {
        &self.listeners
    }

    pub fn listener(&self, name: &str) -> Option<&CoreGatewayListenerPlan> {
        self.listeners.iter().find(|listener| listener.listener.name == name)
    }

    pub fn build_connection(&self, listener_name: &str) -> GatewayResult<CoreGatewayConnection> {
        let listener = self.listener(listener_name).ok_or_else(|| {
            GatewayError::Configuration(format!("runtime plan has no listener '{}'", listener_name))
        })?;
        listener.build_connection()
    }
}

/// A listener with its selected service and backend endpoints.
#[derive(Debug, Clone)]
pub struct CoreGatewayListenerPlan {
    listener: ListenerConfig,
    service: ServiceConfig,
    endpoints: Vec<EndpointConfig>,
    route_policy_kind: Option<String>,
    route_policy: CoreRoutePolicy,
    plugin_config: Option<plugin::config::Plugin>,
    /// Frontend static auth credential (username, password), if configured.
    auth_user: Option<(String, String)>,
    /// Enabled cross-protocol translation policy, if any.
    translation_policy: Option<TranslationPolicyConfig>,
    /// Shared data-plane security PDP (from `GatewayConfig.security`).
    security: Option<gateway_core::LocalPdp>,
}

impl PartialEq for CoreGatewayListenerPlan {
    fn eq(&self, other: &Self) -> bool {
        self.listener == other.listener
            && self.service == other.service
            && self.endpoints == other.endpoints
            && self.route_policy_kind == other.route_policy_kind
    }
}

impl Eq for CoreGatewayListenerPlan {}

impl CoreGatewayListenerPlan {
    fn from_config(config: &GatewayConfig, listener: &ListenerConfig) -> GatewayResult<Self> {
        let service =
            config.services.iter().find(|service| service.name == listener.service).ok_or_else(
                || {
                    GatewayError::Configuration(format!(
                        "listener '{}' references missing service '{}'",
                        listener.name, listener.service
                    ))
                },
            )?;

        let endpoints = service
            .endpoints
            .iter()
            .map(|endpoint_name| {
                config
                    .endpoints
                    .iter()
                    .find(|endpoint| endpoint.name == *endpoint_name)
                    .cloned()
                    .ok_or_else(|| {
                        GatewayError::Configuration(format!(
                            "service '{}' references missing endpoint '{}'",
                            service.name, endpoint_name
                        ))
                    })
            })
            .collect::<GatewayResult<Vec<_>>>()?;

        let route_policy_kind = match &service.route_policy {
            Some(route_policy_name) => {
                let route_policy = config
                    .route_policies
                    .iter()
                    .find(|route_policy| route_policy.name == *route_policy_name)
                    .ok_or_else(|| {
                        GatewayError::Configuration(format!(
                            "service '{}' references missing route policy '{}'",
                            service.name, route_policy_name
                        ))
                    })?;
                Some(route_policy.kind.clone())
            }
            None => None,
        };
        // Route SQL classification uses frontend dialect (commands arrive as client SQL).
        let route_policy = CoreRoutePolicy::build(
            route_policy_kind.as_deref(),
            endpoints.clone(),
            &listener.protocol,
        )?;
        let plugin_config = build_plugin_config(config, &service.plugin_policies)?;
        let auth_user = resolve_auth_user(config, listener.auth_policy.as_deref())?;
        let translation_policy =
            resolve_translation_policy(config, listener, service)?;
        let security = gateway_core::LocalPdp::from_config(&config.security);

        Ok(Self {
            listener: listener.clone(),
            service: service.clone(),
            endpoints,
            route_policy_kind,
            route_policy,
            plugin_config,
            auth_user,
            translation_policy,
            security,
        })
    }

    pub fn listener(&self) -> &ListenerConfig {
        &self.listener
    }

    pub fn service(&self) -> &ServiceConfig {
        &self.service
    }

    pub fn endpoints(&self) -> &[EndpointConfig] {
        &self.endpoints
    }

    pub fn route_policy_kind(&self) -> Option<&str> {
        self.route_policy_kind.as_deref()
    }

    pub fn default_database(&self) -> Option<&str> {
        self.endpoints.iter().find_map(|endpoint| endpoint.database.as_deref())
    }

    pub fn auth_user(&self) -> Option<&(String, String)> {
        self.auth_user.as_ref()
    }

    pub fn build_connection(&self) -> GatewayResult<CoreGatewayConnection> {
        let endpoint = self.route_policy.select_initial_endpoint()?;
        let database = endpoint.database.clone();
        let frontend = build_frontend_protocol(&self.listener, database.clone())?;
        let backend = build_backend_connector(&self.service, &self.endpoints)?;
        let session = SessionState {
            database,
            backend_endpoint: Some(endpoint.name),
            ..SessionState::default()
        };

        let mut connection = CoreGatewayConnection::with_route_policy(
            frontend,
            backend,
            session,
            self.listener.name.clone(),
            self.service.name.clone(),
            self.route_policy.clone(),
            self.translation_policy.clone(),
            self.security.clone(),
        );
        if let Some(plugin_config) = &self.plugin_config {
            connection = connection.with_plugins(PluginPhase::new(plugin_config.clone()));
        }
        Ok(connection)
    }

    pub fn select_endpoint(&self) -> GatewayResult<EndpointConfig> {
        self.route_policy.select_initial_endpoint()
    }

    pub fn has_plugins(&self) -> bool {
        self.plugin_config.is_some()
    }
}

fn resolve_translation_policy(
    config: &GatewayConfig,
    listener: &ListenerConfig,
    service: &ServiceConfig,
) -> GatewayResult<Option<TranslationPolicyConfig>> {
    if listener.protocol == service.backend_protocol {
        return Ok(None);
    }
    let policy_name = service.translation_policy.as_deref().ok_or_else(|| {
        GatewayError::Configuration(format!(
            "listener '{}' protocol '{}' does not match service '{}' backend protocol '{}' (set service.translation_policy)",
            listener.name,
            listener.protocol,
            service.name,
            service.backend_protocol
        ))
    })?;
    let policy = config
        .translation_policies
        .iter()
        .find(|policy| policy.name == policy_name)
        .cloned()
        .ok_or_else(|| {
            GatewayError::Configuration(format!(
                "service '{}' references missing translation policy '{}'",
                service.name, policy_name
            ))
        })?;
    if !policy.enabled {
        return Err(GatewayError::Configuration(format!(
            "translation policy '{}' is disabled",
            policy.name
        )));
    }
    Ok(Some(policy))
}

fn resolve_auth_user(
    config: &GatewayConfig,
    auth_policy_name: Option<&str>,
) -> GatewayResult<Option<(String, String)>> {
    let Some(name) = auth_policy_name else {
        return Ok(None);
    };
    let policy = config.auth_policies.iter().find(|policy| policy.name == name).ok_or_else(|| {
        GatewayError::Configuration(format!("listener references missing auth policy '{}'", name))
    })?;
    let kind = policy.kind.to_ascii_lowercase();
    if kind != "static" {
        return Err(GatewayError::Configuration(format!(
            "unsupported auth policy kind '{}' for policy '{}'",
            policy.kind, policy.name
        )));
    }
    Ok(policy.primary_static_user())
}

fn build_plugin_config(
    config: &GatewayConfig,
    policy_names: &[String],
) -> GatewayResult<Option<plugin::config::Plugin>> {
    if policy_names.is_empty() {
        return Ok(None);
    }

    let mut concurrency_control = Vec::new();
    let mut circuit_break = Vec::new();

    for name in policy_names {
        let policy = config.plugin_policies.iter().find(|policy| policy.name == *name).ok_or_else(
            || {
                GatewayError::Configuration(format!(
                    "service references missing plugin policy '{}'",
                    name
                ))
            },
        )?;

        let kind = normalize_policy_kind(&policy.kind);
        match kind.as_str() {
            "circuitbreak" | "audit" => {
                if policy.regex.is_empty() {
                    // Policy declared without rules: no-op, skip.
                    continue;
                }
                circuit_break.push(plugin::config::CircuitBreak {
                    regex: policy.regex.clone(),
                    case_insensitive: policy.case_insensitive,
                });
            }
            "concurrencycontrol" => {
                if policy.regex.is_empty() {
                    continue;
                }
                concurrency_control.push(plugin::config::ConcurrencyControl {
                    regex: policy.regex.clone(),
                    max_concurrency: policy.max_concurrency.unwrap_or(1),
                    duration: std::time::Duration::from_secs(policy.duration_secs.unwrap_or(60)),
                });
            }
            other => {
                return Err(GatewayError::Configuration(format!(
                    "unsupported plugin policy kind '{}' for policy '{}'",
                    other, policy.name
                )));
            }
        }
    }

    if concurrency_control.is_empty() && circuit_break.is_empty() {
        return Ok(None);
    }

    Ok(Some(plugin::config::Plugin {
        concurrency_control: (!concurrency_control.is_empty()).then_some(concurrency_control),
        circuit_break: (!circuit_break.is_empty()).then_some(circuit_break),
    }))
}

#[derive(Clone)]
struct CoreRoutePolicy {
    endpoints: Vec<EndpointConfig>,
    kind: CoreRoutePolicyKind,
    dialect: Arc<dyn DialectParser>,
}

impl std::fmt::Debug for CoreRoutePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoreRoutePolicy")
            .field("endpoints", &self.endpoints)
            .field("kind", &self.kind)
            .field("dialect", &self.dialect.dialect())
            .finish()
    }
}

#[derive(Debug, Clone)]
enum CoreRoutePolicyKind {
    First,
    Simple {
        balancer: Arc<Mutex<BalanceType>>,
    },
    ReadWrite {
        read_balancer: Arc<Mutex<BalanceType>>,
        readwrite_balancer: Arc<Mutex<BalanceType>>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteTargetRole {
    Read,
    ReadWrite,
}

impl CoreRoutePolicy {
    fn build(
        route_policy_kind: Option<&str>,
        endpoints: Vec<EndpointConfig>,
        backend_protocol: &ProtocolKind,
    ) -> GatewayResult<Self> {
        let kind = if is_read_write_splitting_policy(route_policy_kind) {
            CoreRoutePolicyKind::build_read_write(&endpoints)?
        } else if let Some(algorithm) = route_policy_kind.and_then(simple_load_balance_algorithm) {
            CoreRoutePolicyKind::Simple { balancer: build_balancer(algorithm, &endpoints) }
        } else {
            CoreRoutePolicyKind::First
        };

        Ok(Self {
            endpoints,
            kind,
            dialect: Arc::from(runtime_dialect_parser(backend_protocol)),
        })
    }

    fn select_initial_endpoint(&self) -> GatewayResult<EndpointConfig> {
        match self.plan_for_role(RouteTargetRole::ReadWrite)? {
            RoutePlan::Single { endpoint } => self.endpoint_by_name(&endpoint.name),
            RoutePlan::Reject { reason } => Err(GatewayError::Configuration(reason)),
            other => Err(GatewayError::Unsupported(format!(
                "initial endpoint selection only supports Single route plans, got {:?}",
                other
            ))),
        }
    }

    /// Build a protocol-neutral route plan for one command.
    fn plan_command(
        &self,
        command: &GatewayCommand,
        session: &SessionState,
    ) -> GatewayResult<RoutePlan> {
        // Sticky endpoint for simple policies once chosen.
        if matches!(self.kind, CoreRoutePolicyKind::First | CoreRoutePolicyKind::Simple { .. }) {
            if let Some(name) = session.backend_endpoint.as_deref() {
                let endpoint = self.endpoint_by_name(name)?;
                return Ok(endpoint_to_route_plan(&endpoint));
            }
        }

        // Transactions stick to the already chosen endpoint when present.
        if session.transaction_state == TransactionState::Active {
            if let Some(name) = session.backend_endpoint.as_deref() {
                let endpoint = self.endpoint_by_name(name)?;
                return Ok(endpoint_to_route_plan(&endpoint));
            }
        }

        self.plan_for_role(command_target_role(command, session, self.dialect.as_ref()))
    }

    fn plan_for_role(&self, target_role: RouteTargetRole) -> GatewayResult<RoutePlan> {
        let endpoint = match &self.kind {
            CoreRoutePolicyKind::First => self.first_endpoint()?,
            CoreRoutePolicyKind::Simple { balancer } => self.select_from_balancer(balancer)?,
            CoreRoutePolicyKind::ReadWrite { read_balancer, readwrite_balancer } => {
                let balancer = match target_role {
                    RouteTargetRole::Read => read_balancer,
                    RouteTargetRole::ReadWrite => readwrite_balancer,
                };
                self.select_from_balancer(balancer)?
            }
        };
        Ok(endpoint_to_route_plan(&endpoint))
    }

    fn first_endpoint(&self) -> GatewayResult<EndpointConfig> {
        self.endpoints
            .first()
            .cloned()
            .ok_or_else(|| GatewayError::Configuration("service has no endpoints".into()))
    }

    fn endpoint_by_name(&self, name: &str) -> GatewayResult<EndpointConfig> {
        self.endpoints
            .iter()
            .find(|endpoint| endpoint.name == name)
            .cloned()
            .ok_or_else(|| {
                GatewayError::Configuration(format!(
                    "route policy references missing endpoint '{}'",
                    name
                ))
            })
    }

    fn select_from_balancer(
        &self,
        balancer: &Arc<Mutex<BalanceType>>,
    ) -> GatewayResult<EndpointConfig> {
        let selected = balancer.lock().next();
        if let Some(selected) = selected {
            return self.endpoint_by_name(&selected.name);
        }

        self.first_endpoint()
    }
}

fn endpoint_to_route_plan(endpoint: &EndpointConfig) -> RoutePlan {
    RoutePlan::Single {
        endpoint: EndpointRef::new(endpoint.name.clone(), endpoint.address.clone()),
    }
}

fn apply_route_plan(plan: &RoutePlan, session: &mut SessionState) -> GatewayResult<()> {
    match plan {
        RoutePlan::Single { endpoint } => {
            session.backend_endpoint = Some(endpoint.name.clone());
            Ok(())
        }
        RoutePlan::Reject { reason } => Err(GatewayError::Configuration(reason.clone())),
        RoutePlan::Broadcast { .. } | RoutePlan::Sharded { .. } => Err(GatewayError::Unsupported(
            "broadcast/sharded route plans are not executed by core runtime yet".into(),
        )),
    }
}

impl CoreRoutePolicyKind {
    fn build_read_write(endpoints: &[EndpointConfig]) -> GatewayResult<Self> {
        let read_endpoints = endpoints
            .iter()
            .filter(|endpoint| endpoint.role == EndpointRole::Read)
            .cloned()
            .collect::<Vec<_>>();
        let readwrite_endpoints = endpoints
            .iter()
            .filter(|endpoint| endpoint.role == EndpointRole::ReadWrite)
            .cloned()
            .collect::<Vec<_>>();

        if readwrite_endpoints.is_empty() {
            return Err(GatewayError::Configuration(
                "read_write_splitting route policy requires at least one readwrite endpoint".into(),
            ));
        }

        let read_targets =
            if read_endpoints.is_empty() { &readwrite_endpoints } else { &read_endpoints };

        Ok(CoreRoutePolicyKind::ReadWrite {
            read_balancer: build_balancer(AlgorithmName::Random, read_targets),
            readwrite_balancer: build_balancer(AlgorithmName::Random, &readwrite_endpoints),
        })
    }
}

fn build_balancer(
    algorithm: AlgorithmName,
    endpoints: &[EndpointConfig],
) -> Arc<Mutex<BalanceType>> {
    let mut builder = Balance {};
    let mut balancer = builder.build_balance(algorithm);
    for endpoint in endpoints {
        balancer.add(load_balance_endpoint(endpoint));
    }
    Arc::new(Mutex::new(balancer))
}

fn is_read_write_splitting_policy(route_policy_kind: Option<&str>) -> bool {
    matches!(route_policy_kind.map(normalize_policy_kind).as_deref(), Some("readwritesplitting"))
}

fn normalize_policy_kind(kind: &str) -> String {
    kind.chars()
        .filter(|char| *char != '_' && *char != '-')
        .flat_map(|char| char.to_lowercase())
        .collect()
}

fn simple_load_balance_algorithm(kind: &str) -> Option<AlgorithmName> {
    match kind.to_ascii_lowercase().as_str() {
        "simple_load_balance" | "random" => Some(AlgorithmName::Random),
        "round_robin" | "round-robin" | "roundrobin" => Some(AlgorithmName::RoundRobin),
        _ => None,
    }
}

fn command_target_role(
    command: &GatewayCommand,
    session: &SessionState,
    dialect: &dyn DialectParser,
) -> RouteTargetRole {
    if session.transaction_state == TransactionState::Active {
        return RouteTargetRole::ReadWrite;
    }

    match command {
        GatewayCommand::Query { sql } if dialect.is_read_only(sql) => RouteTargetRole::Read,
        _ => RouteTargetRole::ReadWrite,
    }
}

fn load_balance_endpoint(endpoint: &EndpointConfig) -> Endpoint {
    Endpoint {
        node_type: endpoint_protocol_name(&endpoint.protocol).to_owned(),
        weight: endpoint.weight as i64,
        name: endpoint.name.clone(),
        db: endpoint.database.clone().unwrap_or_default(),
        user: endpoint.username.clone(),
        password: endpoint.password.clone(),
        addr: endpoint.address.clone(),
    }
}

fn endpoint_protocol_name(protocol: &ProtocolKind) -> &'static str {
    match protocol {
        ProtocolKind::MySql => "mysql",
        ProtocolKind::PostgreSql => "postgresql",
    }
}

fn build_frontend_protocol(
    listener: &ListenerConfig,
    database: Option<String>,
) -> GatewayResult<Box<dyn FrontendProtocolAdapter>> {
    match &listener.protocol {
        ProtocolKind::MySql => Ok(Box::new(MySqlFrontendProtocol::new(
            String::new(),
            String::new(),
            database.unwrap_or_default(),
            "8.0".into(),
        ))),
        ProtocolKind::PostgreSql => Ok(Box::new(PostgreSqlFrontendProtocol::new("14.0".into()))),
    }
}

fn build_backend_connector(
    service: &ServiceConfig,
    endpoints: &[EndpointConfig],
) -> GatewayResult<Arc<dyn BackendConnector>> {
    match &service.backend_protocol {
        ProtocolKind::MySql => {
            Ok(Arc::new(MySqlBackendConnector::with_endpoints(endpoints.to_vec())))
        }
        ProtocolKind::PostgreSql => {
            Ok(Arc::new(PostgreSqlBackendConnector::with_endpoints(endpoints.to_vec())))
        }
    }
}

#[cfg(test)]
mod tests {
    use gateway_core::{Column as GatewayColumn, GatewayCommand, GatewayValue};
    use mysql_protocol::{
        mysql_const::{COM_INIT_DB, COM_PING, COM_QUERY, COM_QUIT},
        server::codec::ok_packet,
    };
    use postgresql_protocol::encode_query_message;

    use super::*;

    #[derive(Clone)]
    struct StaticBackendConnector {
        protocol: ProtocolKind,
        expected_command: GatewayCommand,
        response: GatewayResponse,
    }

    #[async_trait::async_trait]
    impl BackendConnector for StaticBackendConnector {
        fn protocol(&self) -> ProtocolKind {
            self.protocol.clone()
        }

        async fn execute(
            &self,
            command: GatewayCommand,
            _session: &mut SessionState,
        ) -> GatewayResult<GatewayResponse> {
            assert_eq!(command, self.expected_command);
            Ok(self.response.clone())
        }
    }

    fn mysql_connection() -> CoreGatewayConnection {
        CoreGatewayConnection::new(
            Box::new(MySqlFrontendProtocol::new(
                "app".into(),
                "secret".into(),
                "test".into(),
                "8.0".into(),
            )),
            Arc::new(MySqlBackendConnector::new()),
            SessionState::default(),
        )
    }

    #[tokio::test]
    async fn plugin_reject_returns_protocol_error_without_backend_execute() {
        use plugin::{
            build_phase::PluginPhase,
            config::{CircuitBreak, Plugin},
        };

        let plugins = PluginPhase::new(Plugin {
            concurrency_control: None,
            circuit_break: Some(vec![CircuitBreak {
                regex: vec![r"(?i)drop\s+table".into()],
                case_insensitive: true,
            }]),
        });
        let mut connection = CoreGatewayConnection::new(
            Box::new(MySqlFrontendProtocol::new(
                "app".into(),
                "secret".into(),
                "test".into(),
                "8.0".into(),
            )),
            Arc::new(StaticBackendConnector {
                protocol: ProtocolKind::MySql,
                expected_command: GatewayCommand::Query { sql: "should not run".into() },
                response: GatewayResponse::Pong,
            }),
            SessionState::default(),
        )
        .with_plugins(plugins);

        let mut frame = vec![COM_QUERY];
        frame.extend_from_slice(b"drop table users");
        let packets = connection.handle_frame(&frame).await.unwrap();
        assert!(!packets.is_empty());
        assert_eq!(packets[0].first(), Some(&0xff));
    }

    #[tokio::test]
    async fn security_deny_returns_protocol_error_without_backend_execute() {
        use gateway_core::{LocalPdp, SecurityPolicyConfig, SecurityRuleConfig};

        let mut security = SecurityPolicyConfig::default();
        security.enabled = true;
        security.rules.push(SecurityRuleConfig {
            name: "deny-secret".into(),
            effect: "deny".into(),
            actions: vec!["select".into()],
            tables: vec!["secret_*".into()],
            columns: vec![],
            subjects: vec![],
            row_filter: None,
        });
        let pdp = LocalPdp::from_config(&security).expect("enabled pdp");

        let mut connection = CoreGatewayConnection::new(
            Box::new(MySqlFrontendProtocol::new(
                "app".into(),
                "secret".into(),
                "test".into(),
                "8.0".into(),
            )),
            Arc::new(StaticBackendConnector {
                protocol: ProtocolKind::MySql,
                expected_command: GatewayCommand::Query { sql: "should not run".into() },
                response: GatewayResponse::Pong,
            }),
            SessionState {
                user: Some("app".into()),
                database: Some("orders".into()),
                ..SessionState::default()
            },
        )
        .with_security(Some(pdp));

        let mut frame = vec![COM_QUERY];
        frame.extend_from_slice(b"SELECT * FROM secret_tokens");
        let packets = connection.handle_frame(&frame).await.unwrap();
        assert!(!packets.is_empty());
        assert_eq!(packets[0].first(), Some(&0xff));
    }

    #[test]
    fn security_enabled_plan_attaches_pdp() {
        let mut config = mysql_config();
        config.security.enabled = true;
        config.security.rules.push(gateway_core::SecurityRuleConfig {
            name: "deny-ddl".into(),
            effect: "deny".into(),
            actions: vec!["ddl".into()],
            tables: vec![],
            columns: vec![],
            subjects: vec![],
            row_filter: None,
        });
        let plan = CoreGatewayRuntimePlan::from_config(&config).unwrap();
        let connection = plan.build_connection("mysql-listener").unwrap();
        assert!(connection.security.is_some());
    }

    fn postgresql_connection(response: GatewayResponse) -> CoreGatewayConnection {
        CoreGatewayConnection::new(
            Box::new(PostgreSqlFrontendProtocol::new("14.0".into())),
            Arc::new(StaticBackendConnector {
                protocol: ProtocolKind::PostgreSql,
                expected_command: GatewayCommand::Query { sql: "select 1".into() },
                response,
            }),
            SessionState::default(),
        )
    }

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
                translation_policy: None,
            }],
            endpoints: vec![EndpointConfig {
                name: "orders-primary".into(),
                protocol: ProtocolKind::MySql,
                address: "127.0.0.1:3306".into(),
                database: Some("orders_db".into()),
                role: EndpointRole::ReadWrite,
                username: "root".into(),
                password: "backend-secret".into(),
                weight: 1,
            }],
            ..GatewayConfig::default()
        }
    }

    fn round_robin_config() -> GatewayConfig {
        let mut config = mysql_config();
        config.services[0].route_policy = Some("orders-balance".into());
        config.services[0].endpoints.push("orders-replica".into());
        config.endpoints.push(EndpointConfig {
            name: "orders-replica".into(),
            protocol: ProtocolKind::MySql,
            address: "127.0.0.1:3307".into(),
            database: Some("orders_replica_db".into()),
            role: EndpointRole::ReadWrite,
            username: "root".into(),
            password: "backend-secret".into(),
            weight: 1,
        });
        config.route_policies = vec![gateway_core::RoutePolicyConfig {
            name: "orders-balance".into(),
            kind: "round_robin".into(),
        }];
        config
    }

    fn read_write_config() -> GatewayConfig {
        let mut config = mysql_config();
        config.services[0].route_policy = Some("orders-read-write".into());
        config.services[0].endpoints.push("orders-replica".into());
        config.endpoints.push(EndpointConfig {
            name: "orders-replica".into(),
            protocol: ProtocolKind::MySql,
            address: "127.0.0.1:3307".into(),
            database: Some("orders_db".into()),
            role: EndpointRole::Read,
            username: "root".into(),
            password: "backend-secret".into(),
            weight: 1,
        });
        config.route_policies = vec![gateway_core::RoutePolicyConfig {
            name: "orders-read-write".into(),
            kind: "read_write_splitting".into(),
        }];
        config
    }

    fn postgresql_config() -> GatewayConfig {
        let mut config = mysql_config();
        config.listeners[0].name = "postgresql-listener".into();
        config.listeners[0].listen_addr = "127.0.0.1:5433".into();
        config.listeners[0].protocol = ProtocolKind::PostgreSql;
        config.services[0].backend_protocol = ProtocolKind::PostgreSql;
        config.endpoints[0].protocol = ProtocolKind::PostgreSql;
        config.endpoints[0].address = "127.0.0.1:5432".into();
        config.endpoints[0].username = "postgres".into();
        config
    }

    #[tokio::test]
    async fn handles_mysql_ping_through_core_traits() {
        let mut connection = mysql_connection();

        let packets = connection.handle_frame(&[COM_PING]).await;

        assert_eq!(connection.frontend_protocol(), ProtocolKind::MySql);
        assert_eq!(connection.backend_protocol(), ProtocolKind::MySql);
        assert_eq!(packets, Ok(vec![ok_packet()[4..].to_vec()]));
    }

    #[tokio::test]
    async fn handles_mysql_use_database_and_updates_session() {
        let mut connection = mysql_connection();
        let mut frame = vec![COM_INIT_DB];
        frame.extend_from_slice(b"analytics");

        let packets = connection.handle_frame(&frame).await;

        assert_eq!(packets, Ok(vec![ok_packet()[4..].to_vec()]));
        assert_eq!(connection.session().database, Some("analytics".into()));
    }

    #[tokio::test]
    async fn handles_mysql_transaction_commands_through_core_traits() {
        let mut connection = mysql_connection();
        let mut begin = vec![COM_QUERY];
        begin.extend_from_slice(b"begin");

        let packets = connection.handle_frame(&begin).await;

        assert_eq!(packets, Ok(vec![ok_packet()[4..].to_vec()]));
        assert_eq!(connection.session().transaction_state, gateway_core::TransactionState::Active);
    }

    #[tokio::test]
    async fn handles_mysql_quit_through_core_traits() {
        let mut connection = mysql_connection();

        let packets = connection.handle_frame(&[COM_QUIT]).await;

        assert_eq!(packets, Ok(vec![ok_packet()[4..].to_vec()]));
    }

    #[tokio::test]
    async fn encodes_backend_error_for_mysql_query_without_endpoint() {
        let mut connection = mysql_connection();
        let mut frame = vec![COM_QUERY];
        frame.extend_from_slice(b"select 1");

        let packets = connection.handle_frame(&frame).await.unwrap();

        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].first(), Some(&0xff));
        assert!(String::from_utf8_lossy(&packets[0])
            .contains("mysql backend connector has no configured endpoints"));
    }

    #[tokio::test]
    async fn handles_postgresql_simple_query_through_core_traits() {
        let mut connection = postgresql_connection(GatewayResponse::ResultSet {
            columns: vec![GatewayColumn { name: "one".into(), data_type: "int".into() }],
            rows: vec![vec![GatewayValue::Integer(1)]],
        });

        let packets = connection.handle_frame(&encode_query_message("select 1")).await.unwrap();

        assert_eq!(connection.frontend_protocol(), ProtocolKind::PostgreSql);
        assert_eq!(connection.backend_protocol(), ProtocolKind::PostgreSql);
        assert_eq!(packets.len(), 4);
        assert_eq!(packets[0].first(), Some(&b'T'));
        assert_eq!(packets[1].first(), Some(&b'D'));
        assert_eq!(packets[2].first(), Some(&b'C'));
        assert_eq!(packets[3].first(), Some(&b'Z'));
    }

    #[tokio::test]
    async fn encodes_backend_error_for_postgresql_query_without_endpoint() {
        let mut connection = CoreGatewayConnection::new(
            Box::new(PostgreSqlFrontendProtocol::new("14.0".into())),
            Arc::new(PostgreSqlBackendConnector::new()),
            SessionState::default(),
        );

        let packets = connection.handle_frame(&encode_query_message("select 1")).await.unwrap();

        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].first(), Some(&b'E'));
        assert!(String::from_utf8_lossy(&packets[0])
            .contains("postgresql backend connector has no configured endpoints"));
        assert_eq!(packets[1].first(), Some(&b'Z'));
    }

    #[test]
    fn resolves_v2_config_into_runtime_plan() {
        let config = mysql_config();

        let plan = CoreGatewayRuntimePlan::from_config(&config).unwrap();

        assert_eq!(plan.listeners().len(), 1);
        let listener = plan.listener("mysql-listener").unwrap();
        assert_eq!(listener.listener().name, "mysql-listener");
        assert_eq!(listener.service().name, "orders");
        assert_eq!(listener.endpoints()[0].name, "orders-primary");
        assert_eq!(listener.endpoints()[0].username, "root");
        assert_eq!(listener.route_policy_kind(), None);
        assert_eq!(listener.default_database(), Some("orders_db"));
    }

    #[test]
    fn builds_mysql_core_connection_from_runtime_plan() {
        let config = mysql_config();
        let plan = CoreGatewayRuntimePlan::from_config(&config).unwrap();

        let connection = plan.build_connection("mysql-listener").unwrap();

        assert_eq!(connection.frontend_protocol(), ProtocolKind::MySql);
        assert_eq!(connection.backend_protocol(), ProtocolKind::MySql);
        assert_eq!(connection.session().database, Some("orders_db".into()));
        assert_eq!(connection.session().backend_endpoint, Some("orders-primary".into()));
    }

    #[test]
    fn builds_postgresql_core_connection_from_runtime_plan() {
        let config = postgresql_config();
        let plan = CoreGatewayRuntimePlan::from_config(&config).unwrap();

        let connection = plan.build_connection("postgresql-listener").unwrap();

        assert_eq!(connection.frontend_protocol(), ProtocolKind::PostgreSql);
        assert_eq!(connection.backend_protocol(), ProtocolKind::PostgreSql);
        assert_eq!(connection.session().database, Some("orders_db".into()));
        assert_eq!(connection.session().backend_endpoint, Some("orders-primary".into()));
    }

    #[test]
    fn rejects_cross_protocol_listener_and_backend_in_v2_config() {
        // Same-protocol only until M3 translation_policy is introduced.
        let mut config = mysql_config();
        config.services[0].backend_protocol = ProtocolKind::PostgreSql;
        config.endpoints[0].protocol = ProtocolKind::PostgreSql;

        let err = CoreGatewayRuntimePlan::from_config(&config).unwrap_err();
        assert!(
            err.to_string().contains("translation_policy")
                || err.to_string().contains("does not match"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn route_policy_selects_backend_endpoint_for_mysql_sessions() {
        let config = round_robin_config();
        let plan = CoreGatewayRuntimePlan::from_config(&config).unwrap();

        let first = plan.build_connection("mysql-listener").unwrap();
        let second = plan.build_connection("mysql-listener").unwrap();

        assert_eq!(first.session().backend_endpoint, Some("orders-primary".into()));
        assert_eq!(first.session().database, Some("orders_db".into()));
        assert_eq!(second.session().backend_endpoint, Some("orders-replica".into()));
        assert_eq!(second.session().database, Some("orders_replica_db".into()));
    }

    #[test]
    fn route_policy_selects_backend_endpoint_for_postgresql_sessions() {
        let mut config = round_robin_config();
        config.listeners[0].name = "postgresql-listener".into();
        config.listeners[0].listen_addr = "127.0.0.1:5433".into();
        config.listeners[0].protocol = ProtocolKind::PostgreSql;
        config.services[0].backend_protocol = ProtocolKind::PostgreSql;
        for endpoint in &mut config.endpoints {
            endpoint.protocol = ProtocolKind::PostgreSql;
        }
        config.endpoints[0].address = "127.0.0.1:5432".into();
        config.endpoints[1].address = "127.0.0.1:5434".into();
        let plan = CoreGatewayRuntimePlan::from_config(&config).unwrap();

        let first = plan.build_connection("postgresql-listener").unwrap();
        let second = plan.build_connection("postgresql-listener").unwrap();

        assert_eq!(first.session().backend_endpoint, Some("orders-primary".into()));
        assert_eq!(second.session().backend_endpoint, Some("orders-replica".into()));
    }

    #[test]
    fn read_write_route_policy_routes_mysql_gateway_commands_by_role() {
        let config = read_write_config();
        let plan = CoreGatewayRuntimePlan::from_config(&config).unwrap();
        let listener = plan.listener("mysql-listener").unwrap();
        let mut session = SessionState {
            database: Some("orders_db".into()),
            backend_endpoint: Some("orders-primary".into()),
            ..SessionState::default()
        };

        let plan = listener.route_policy.plan_command(


            &GatewayCommand::Query { sql: "select * from orders".into() },


            &session,


        ).unwrap();


        apply_route_plan(&plan, &mut session).unwrap();
        assert_eq!(session.backend_endpoint, Some("orders-replica".into()));

        let plan = listener.route_policy.plan_command(


            &GatewayCommand::Query { sql: "insert into orders values (1)".into() },


            &session,


        ).unwrap();


        apply_route_plan(&plan, &mut session).unwrap();
        assert_eq!(session.backend_endpoint, Some("orders-primary".into()));
    }

    #[test]
    fn read_write_route_policy_routes_postgresql_gateway_commands_by_role() {
        let mut config = read_write_config();
        config.listeners[0].name = "postgresql-listener".into();
        config.listeners[0].listen_addr = "127.0.0.1:5433".into();
        config.listeners[0].protocol = ProtocolKind::PostgreSql;
        config.services[0].backend_protocol = ProtocolKind::PostgreSql;
        for endpoint in &mut config.endpoints {
            endpoint.protocol = ProtocolKind::PostgreSql;
        }
        config.endpoints[0].address = "127.0.0.1:5432".into();
        config.endpoints[1].address = "127.0.0.1:5434".into();
        let plan = CoreGatewayRuntimePlan::from_config(&config).unwrap();
        let listener = plan.listener("postgresql-listener").unwrap();
        let mut session = SessionState {
            database: Some("orders_db".into()),
            backend_endpoint: Some("orders-primary".into()),
            ..SessionState::default()
        };

        let plan = listener.route_policy.plan_command(


            &GatewayCommand::Query { sql: "select * from orders".into() },


            &session,


        ).unwrap();


        apply_route_plan(&plan, &mut session).unwrap();

        assert_eq!(session.backend_endpoint, Some("orders-replica".into()));
    }

    #[test]
    fn read_write_route_policy_keeps_transactions_on_readwrite_endpoint() {
        let config = read_write_config();
        let plan = CoreGatewayRuntimePlan::from_config(&config).unwrap();
        let listener = plan.listener("mysql-listener").unwrap();
        let mut session = SessionState {
            database: Some("orders_db".into()),
            backend_endpoint: Some("orders-primary".into()),
            transaction_state: TransactionState::Active,
            ..SessionState::default()
        };

        let plan = listener.route_policy.plan_command(


            &GatewayCommand::Query { sql: "select * from orders".into() },


            &session,


        ).unwrap();


        apply_route_plan(&plan, &mut session).unwrap();

        assert_eq!(session.backend_endpoint, Some("orders-primary".into()));
    }

    #[test]
    fn read_write_route_policy_falls_back_to_readwrite_when_no_read_endpoint_exists() {
        let mut config = read_write_config();
        config.endpoints.retain(|endpoint| endpoint.role == EndpointRole::ReadWrite);
        config.services[0].endpoints = vec!["orders-primary".into()];
        let plan = CoreGatewayRuntimePlan::from_config(&config).unwrap();
        let listener = plan.listener("mysql-listener").unwrap();
        let mut session = SessionState {
            database: Some("orders_db".into()),
            backend_endpoint: Some("orders-primary".into()),
            ..SessionState::default()
        };

        let plan = listener.route_policy.plan_command(


            &GatewayCommand::Query { sql: "select * from orders".into() },


            &session,


        ).unwrap();


        apply_route_plan(&plan, &mut session).unwrap();

        assert_eq!(session.backend_endpoint, Some("orders-primary".into()));
    }

    #[test]
    fn plan_command_returns_single_route_plan() {
        let config = mysql_config();
        let plan = CoreGatewayRuntimePlan::from_config(&config).unwrap();
        let listener = plan.listener("mysql-listener").unwrap();
        let session = SessionState::default();

        let route_plan = listener
            .route_policy
            .plan_command(&GatewayCommand::Query { sql: "select 1".into() }, &session)
            .unwrap();

        assert_eq!(route_plan, RoutePlan::single("orders-primary", "127.0.0.1:3306"));
    }

    #[test]
    fn apply_single_plan_updates_session_endpoint() {
        let mut session = SessionState::default();
        apply_route_plan(&RoutePlan::single("orders-primary", "127.0.0.1:3306"), &mut session)
            .unwrap();
        assert_eq!(session.backend_endpoint, Some("orders-primary".into()));
    }

    #[test]
    fn apply_reject_plan_returns_configuration_error() {
        let mut session = SessionState::default();
        let err = apply_route_plan(&RoutePlan::reject("no healthy endpoint"), &mut session)
            .unwrap_err();
        assert!(matches!(
            err,
            GatewayError::Configuration(message) if message.contains("no healthy")
        ));
    }

    #[test]
    fn loads_circuit_break_plugin_from_v2_plugin_policies() {
        let mut config = mysql_config();
        config.services[0].plugin_policies = vec!["deny-drop".into()];
        config.plugin_policies = vec![gateway_core::PluginPolicyConfig {
            name: "deny-drop".into(),
            kind: "circuit_break".into(),
            regex: vec![r"(?i)drop\s+table".into()],
            case_insensitive: true,
            max_concurrency: None,
            duration_secs: None,
        }];

        let plan = CoreGatewayRuntimePlan::from_config(&config).unwrap();
        let listener = plan.listener("mysql-listener").unwrap();
        assert!(listener.has_plugins());

        let connection = plan.build_connection("mysql-listener").unwrap();
        // plugins field is private; building connection with policies is enough for load path.
        let _ = connection;
    }

    #[test]
    fn ignores_plugin_policy_without_regex_rules() {
        let mut config = mysql_config();
        config.services[0].plugin_policies = vec!["empty-audit".into()];
        config.plugin_policies = vec![gateway_core::PluginPolicyConfig {
            name: "empty-audit".into(),
            kind: "audit".into(),
            regex: vec![],
            case_insensitive: false,
            max_concurrency: None,
            duration_secs: None,
        }];

        let plan = CoreGatewayRuntimePlan::from_config(&config).unwrap();
        assert!(!plan.listener("mysql-listener").unwrap().has_plugins());
    }

    fn cross_protocol_mysql_to_pg_config() -> GatewayConfig {
        let mut config = mysql_config();
        config.services[0].backend_protocol = ProtocolKind::PostgreSql;
        config.services[0].translation_policy = Some("mysql-to-pg".into());
        config.endpoints[0].protocol = ProtocolKind::PostgreSql;
        config.endpoints[0].address = "127.0.0.1:5432".into();
        config.endpoints[0].username = "postgres".into();
        config.translation_policies = vec![TranslationPolicyConfig {
            name: "mysql-to-pg".into(),
            enabled: true,
            frontend_protocol: ProtocolKind::MySql,
            backend_protocol: ProtocolKind::PostgreSql,
            allowed_statements: gateway_core::default_allowed_statements(),
        }];
        config
    }

    #[test]
    fn builds_cross_protocol_connection_when_translation_enabled() {
        let plan =
            CoreGatewayRuntimePlan::from_config(&cross_protocol_mysql_to_pg_config()).unwrap();
        let connection = plan.build_connection("mysql-listener").unwrap();
        assert_eq!(connection.frontend_protocol(), ProtocolKind::MySql);
        assert_eq!(connection.backend_protocol(), ProtocolKind::PostgreSql);
        assert!(connection.translation_policy.is_some());
    }

    #[tokio::test]
    async fn cross_protocol_rewrites_sql_and_maps_result_types() {
        let mut connection = CoreGatewayConnection::new(
            Box::new(MySqlFrontendProtocol::new(
                "app".into(),
                "secret".into(),
                "test".into(),
                "8.0".into(),
            )),
            Arc::new(StaticBackendConnector {
                protocol: ProtocolKind::PostgreSql,
                expected_command: GatewayCommand::Query {
                    sql: "SELECT \"id\" FROM t LIMIT 2 OFFSET 1".into(),
                },
                response: GatewayResponse::ResultSet {
                    columns: vec![GatewayColumn {
                        name: "id".into(),
                        data_type: "int4".into(),
                    }],
                    rows: vec![vec![GatewayValue::Integer(7)]],
                },
            }),
            SessionState::default(),
        );
        connection.translation_policy = Some(TranslationPolicyConfig {
            name: "mysql-to-pg".into(),
            enabled: true,
            frontend_protocol: ProtocolKind::MySql,
            backend_protocol: ProtocolKind::PostgreSql,
            allowed_statements: gateway_core::default_allowed_statements(),
        });

        let mut frame = vec![COM_QUERY];
        frame.extend_from_slice(b"SELECT `id` FROM t LIMIT 1, 2");
        let packets = connection.handle_frame(&frame).await.unwrap();
        assert!(!packets.is_empty());
        // MySQL resultset: column-count packet is first (lenenc integer).
        assert_ne!(packets[0].first(), Some(&0xff));
    }

    #[tokio::test]
    async fn cross_protocol_rejects_unsupported_sql() {
        let mut connection = CoreGatewayConnection::new(
            Box::new(MySqlFrontendProtocol::new(
                "app".into(),
                "secret".into(),
                "test".into(),
                "8.0".into(),
            )),
            Arc::new(StaticBackendConnector {
                protocol: ProtocolKind::PostgreSql,
                expected_command: GatewayCommand::Query {
                    sql: "should not run".into(),
                },
                response: GatewayResponse::Pong,
            }),
            SessionState::default(),
        );
        connection.translation_policy = Some(TranslationPolicyConfig {
            name: "mysql-to-pg".into(),
            enabled: true,
            frontend_protocol: ProtocolKind::MySql,
            backend_protocol: ProtocolKind::PostgreSql,
            allowed_statements: gateway_core::default_allowed_statements(),
        });

        let mut frame = vec![COM_QUERY];
        frame.extend_from_slice(b"DROP TABLE users");
        let packets = connection.handle_frame(&frame).await.unwrap();
        assert_eq!(packets[0].first(), Some(&0xff));
    }
}
