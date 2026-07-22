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
        write_resultset_windowed, write_resultset_windowed_with_obligations,
        write_streaming_query_with_obligations_sample, write_wire_relay, CollectingWriter, map_response_types,
        prepare_cross_protocol_command, BackendConnector, CommandSummary, DialectParser,
        EndpointConfig, EndpointRef, EndpointRole, ExecuteMode, ExecuteOutcome,
        FrontendProtocolAdapter, GatewayCommand, GatewayConfig, GatewayError, GatewayResponse,
        GatewayResult, ListenerConfig, Obligations, PluginContext, PluginDecision, ProtocolKind,
        ResponseWriter, RoutePlan, ServiceConfig, SessionState, StreamingSampleOpts, TransactionState,
        TranslationPolicyConfig,
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
    /// F32: deployment default audit level (L0/L1/L2) for event tagging.
    default_audit_level: String,
    /// B08: opt-in result sample attach for L2 events.
    audit_sample_enabled: bool,
    audit_sample_max_rows: u32,
    audit_sample_max_bytes: u32,
    /// Result read mode from security.streaming (A1).
    stream_mode: ExecuteMode,
    /// When true and same-protocol + no obligations, prefer wire passthrough (A3).
    passthrough_enabled: bool,
    metrics: MySQLServerMetricsCollector,
    /// Result-path obligations deferred to encode so mask can run per window (A06/A07).
    pending_encode_obligations: Option<Obligations>,
    /// A10: held backend row stream for true multi-Execute portal resume.
    /// When set, the next Execute for the same portal reuses this stream instead of
    /// re-running SQL (logical skip). Dropped on Close / Sync / portal name change.
    held_portal_stream: Option<gateway_core::StreamingQuery>,
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
            default_audit_level: "L0".into(),
            audit_sample_enabled: false,
            audit_sample_max_rows: 5,
            audit_sample_max_bytes: 4096,
            stream_mode: ExecuteMode::Materialized,
            passthrough_enabled: false,
            metrics: MySQLServerMetricsCollector,
            pending_encode_obligations: None,
            held_portal_stream: None,
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
        stream_mode: ExecuteMode,
        passthrough_enabled: bool,
        default_audit_level: String,
        audit_sample_enabled: bool,
        audit_sample_max_rows: u32,
        audit_sample_max_bytes: u32,
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
            default_audit_level,
            audit_sample_enabled,
            audit_sample_max_rows,
            audit_sample_max_bytes,
            stream_mode,
            passthrough_enabled,
            metrics: MySQLServerMetricsCollector,
            pending_encode_obligations: None,
            held_portal_stream: None,
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

    pub fn with_stream_mode(mut self, stream_mode: ExecuteMode) -> Self {
        self.stream_mode = stream_mode;
        self
    }

    /// B08: build L2 result sample from a materialized ResultSet (post-obligation if possible).
    /// Streaming / wire paths intentionally return None (no full materialization for samples).
    fn build_audit_sample(
        &self,
        response: &GatewayResponse,
        pending: &gateway_core::Obligations,
    ) -> Option<(String, u32, u32, bool)> {
        if !self.audit_sample_enabled {
            return None;
        }
        if !self.default_audit_level.eq_ignore_ascii_case("L2") {
            return None;
        }
        let GatewayResponse::ResultSet { columns, rows } = response else {
            return None;
        };
        let col_names: Vec<String> = columns.iter().map(|c| c.name.clone()).collect();
        // If result obligations exist, sample from a masked copy (do not mutate response).
        let masked;
        let rows_ref: &Vec<Vec<gateway_core::GatewayValue>> = if pending.has_result_obligations() {
            let mut tmp = GatewayResponse::ResultSet {
                columns: columns.clone(),
                rows: rows.clone(),
            };
            tmp = gateway_core::apply_obligations_to_response(tmp, pending);
            if let GatewayResponse::ResultSet { rows: r, .. } = tmp {
                masked = r;
                &masked
            } else {
                rows
            }
        } else {
            rows
        };
        gateway_core::build_result_sample(
            &col_names,
            rows_ref,
            self.audit_sample_max_rows.max(1) as usize,
            self.audit_sample_max_bytes.max(1) as usize,
        )
    }

    /// A07: encode a response through a progressive writer (socket or collector).
    async fn encode_response_to_writer(
        &mut self,
        response: GatewayResponse,
        writer: &mut dyn ResponseWriter,
    ) -> GatewayResult<()> {
        let deferred_obl = self.pending_encode_obligations.take();
        let result = match response {
            GatewayResponse::ResultSet { columns, rows } => {
                // A4: cross-protocol always window-encodes after type mapping so
                // frontend dialect packets are produced without one giant encode.
                // A2: same-protocol Streaming also window-encodes.
                // A06/A07: result obligations force windowed encode with per-window mask.
                let cross = self.translation_policy.is_some();
                let has_obl = deferred_obl
                    .as_ref()
                    .map(|o| o.has_result_obligations())
                    .unwrap_or(false);
                let window = self
                    .stream_mode
                    .window_rows()
                    .or(if cross || has_obl { Some(256) } else { None })
                    .unwrap_or(usize::MAX)
                    .max(1);
                let use_windowed = cross
                    || has_obl
                    || matches!(self.stream_mode, ExecuteMode::Streaming { .. });
                if use_windowed {
                    let stats = write_resultset_windowed_with_obligations(
                        self.frontend.as_mut(),
                        &self.session,
                        columns,
                        rows,
                        window,
                        deferred_obl.as_ref(),
                        writer,
                    )
                    .await?;
                    // O01: windowed Complete path (labels: listener/service/protocols/type/endpoint).
                    let ep = self
                        .session
                        .backend_endpoint
                        .as_deref()
                        .unwrap_or("n/a");
                    let labels = [
                        self.listener_name.as_str(),
                        self.service_name.as_str(),
                        protocol_metric_name(&self.frontend.protocol()),
                        protocol_metric_name(&self.backend.protocol()),
                        "QUERY",
                        ep,
                    ];
                    self.metrics.record_secure_encode_peak(
                        &labels,
                        stats.masked_rows,
                        stats.windows,
                        stats.encoded_bytes,
                        stats.peak_window_rows,
                    );
                    Ok(())
                } else {
                    let response = if let Some(obl) = deferred_obl.as_ref() {
                        gateway_core::apply_obligations_to_response(
                            GatewayResponse::ResultSet { columns, rows },
                            obl,
                        )
                    } else {
                        GatewayResponse::ResultSet { columns, rows }
                    };
                    let packets = self.frontend.encode(response, &self.session)?;
                    writer.write_packets(packets).await
                }
            }
            GatewayResponse::Wire { packets } => writer.write_packets(packets).await,
            other => {
                let other = if let Some(obl) = deferred_obl.as_ref() {
                    gateway_core::apply_obligations_to_response(other, obl)
                } else {
                    other
                };
                let packets = self.frontend.encode(other, &self.session)?;
                writer.write_packets(packets).await
            }
        };
        // A10: binary result flag applies to one response only (COM_STMT_EXECUTE).
        self.session.prefer_binary_result = false;
        result
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
        let mut writer = CollectingWriter::new();
        self.handle_frame_to_writer(frame, &mut writer).await?;
        Ok(writer.into_packets())
    }

    /// A07: process one frontend frame, writing response packets progressively.
    ///
    /// Large ResultSets with Streaming / obligations are encoded window-by-window
    /// into `writer` (socket back-pressure) instead of buffering all packets first.
    pub async fn handle_frame_to_writer(
        &mut self,
        frame: &[u8],
        writer: &mut dyn ResponseWriter,
    ) -> GatewayResult<()> {
        let frame_span = info_span!(
            "gateway.handle_frame",
            listener = %self.listener_name,
            service = %self.service_name,
            frontend_protocol = %protocol_metric_name(&self.frontend.protocol()),
            backend_protocol = %protocol_metric_name(&self.backend.protocol()),
        );
        async {
            self.handle_frame_inner(frame, writer).await
        }
        .instrument(frame_span)
        .await
    }

    async fn handle_frame_inner(
        &mut self,
        frame: &[u8],
        writer: &mut dyn ResponseWriter,
    ) -> GatewayResult<()> {
        // Drop any deferred obligations from a previous command that failed mid-path.
        self.pending_encode_obligations = None;
        let commands = self.frontend.decode(frame, &mut self.session)?;

        for mut command in commands {
            let command_type = command_metric_type(&command);
            let started_at = Instant::now();
            let command_span = info_span!(
                "gateway.command",
                command_type = %command_type,
                endpoint = tracing::field::Empty,
                outcome = tracing::field::Empty,
                security_decision = tracing::field::Empty,
                security_rule_class = tracing::field::Empty,
                execute_path = tracing::field::Empty,
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
                        self.encode_response_to_writer(response, writer).await?;
                        record_otel_command(
                            &self.listener_name,
                            &self.service_name,
                            labels[2],
                            labels[3],
                            command_type,
                            labels[5],
                            "plugin_reject",
                            started_at,
                            &crate::otel_metrics::CommandOtelAttrs::none(),
                        );
                        finish_command_metrics(&self.metrics, &labels, started_at, "n/a", 0);
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
                        finish_command_metrics(&self.metrics, &labels, started_at, "n/a", 0);
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
                        self.encode_response_to_writer(response, writer).await?;
                        record_otel_command(
                            &self.listener_name,
                            &self.service_name,
                            labels[2],
                            labels[3],
                            command_type,
                            labels[5],
                            "translation_reject",
                            started_at,
                            &crate::otel_metrics::CommandOtelAttrs::none(),
                        );
                        finish_command_metrics(&self.metrics, &labels, started_at, "n/a", 0);
                        continue;
                    }
                }
            }

            // S1/S2/S3: data-plane Local PDP (table/statement/column/mask/row) before backend execute.
            let mut command = command;
            // F32: capture SQL (+ tables) for audit payload before rewrite/execute.
            let (audit_sql, audit_tables) = match &command {
                GatewayCommand::Query { sql }
                | GatewayCommand::QueryParams { sql, .. }
                | GatewayCommand::Prepare { sql }
                | GatewayCommand::DescribeSql { sql } => {
                    let set = crate::object_extract::extract_object_set(
                        sql,
                        self.frontend.protocol().as_str(),
                    );
                    let tables = set
                        .objects
                        .iter()
                        .map(|o| o.table.clone())
                        .collect::<Vec<_>>();
                    (Some(sql.clone()), tables)
                }
                _ => (None, Vec::new()),
            };
            let mut pending_obligations = gateway_core::Obligations::default();
            if let Some(pdp) = &self.security {
                let subject = gateway_core::Subject::from_protocol_user(
                    self.session.user.as_deref(),
                    self.session.database.as_deref(),
                );
                let objects = match &command {
                    GatewayCommand::Query { sql }
                    | GatewayCommand::QueryParams { sql, .. }
                    | GatewayCommand::Prepare { sql }
                    | GatewayCommand::DescribeSql { sql } => {
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
                            | GatewayCommand::QueryParams { sql: original, .. }
                            | GatewayCommand::Prepare { sql: original } => {
                                *original = sql;
                            }
                            _ => {}
                        }
                    }
                    gateway_core::SecurityDecision::RequireTicket {
                        rule,
                        ticket_type,
                        message,
                    } => {
                        info!(
                            target: gateway_core::AUDIT_TARGET,
                            action = gateway_core::AuditAction::Query.as_str(),
                            listener = %self.listener_name,
                            service = %self.service_name,
                            subject_id = %subject.subject_id,
                            decision = gateway_core::AuditDecision::RequireApproval.as_str(),
                            rule = %rule,
                            ticket_type = %ticket_type,
                            message = %message,
                            "gateway command requires approval ticket"
                        );
                        gateway_core::try_audit(gateway_core::AuditEvent {
                            action: Some(gateway_core::AuditAction::Query.as_str().into()),
                            decision: Some(
                                gateway_core::AuditDecision::RequireApproval.as_str().into(),
                            ),
                            subject_id: Some(subject.subject_id.clone()),
                            db_user: self.session.user.clone(),
                            listener: Some(self.listener_name.clone()),
                            service: Some(self.service_name.clone()),
                            frontend_protocol: Some(
                                protocol_metric_name(&self.frontend.protocol()).to_owned(),
                            ),
                            backend_protocol: Some(
                                protocol_metric_name(&self.backend.protocol()).to_owned(),
                            ),
                            command_type: Some(command_type.to_owned()),
                            endpoint: Some(label_owned[5].clone()),
                            database: self.session.database.clone(),
                            outcome: Some("require_ticket".into()),
                            code: Some("security_require_ticket".into()),
                            message: Some(message.clone()),
                            rule: Some(rule.clone()),
                            audit_level: Some(self.default_audit_level.clone()),
                            sql_fingerprint: audit_sql.as_deref().map(gateway_core::sql_fingerprint),
                            sql_text: audit_sql.clone(),
                            tables: audit_tables.clone(),
                            ..gateway_core::AuditEvent::default()
                        });
                        let response = GatewayResponse::Error {
                            code: "security_require_ticket".into(),
                            message,
                        };
                        command_span.record("outcome", "security_require_ticket");
                        let rule_class = crate::otel_metrics::classify_security_rule(&rule);
                        command_span.record("security_decision", "require_ticket");
                        command_span.record("security_rule_class", rule_class);
                        self.encode_response_to_writer(response, writer).await?;
                        record_otel_command(
                            &self.listener_name,
                            &self.service_name,
                            labels[2],
                            labels[3],
                            command_type,
                            labels[5],
                            "security_require_ticket",
                            started_at,
                            &crate::otel_metrics::CommandOtelAttrs::security(
                                "require_ticket",
                                rule_class,
                            ),
                        );
                        finish_command_metrics(&self.metrics, &labels, started_at, "n/a", 0);
                        if let (Some(plugins), Some(idx)) =
                            (self.plugins.as_mut(), concurrency_rule_idx)
                        {
                            plugins.release_concurrency(idx);
                        }
                        continue;
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
                        gateway_core::try_audit(gateway_core::AuditEvent {
                            action: Some(gateway_core::AuditAction::Query.as_str().into()),
                            decision: Some(gateway_core::AuditDecision::Deny.as_str().into()),
                            subject_id: Some(subject.subject_id.clone()),
                            db_user: self.session.user.clone(),
                            listener: Some(self.listener_name.clone()),
                            service: Some(self.service_name.clone()),
                            frontend_protocol: Some(
                                protocol_metric_name(&self.frontend.protocol()).to_owned(),
                            ),
                            backend_protocol: Some(
                                protocol_metric_name(&self.backend.protocol()).to_owned(),
                            ),
                            command_type: Some(command_type.to_owned()),
                            endpoint: Some(label_owned[5].clone()),
                            database: self.session.database.clone(),
                            outcome: Some("security_deny".into()),
                            code: Some("security_deny".into()),
                            message: Some(message.clone()),
                            rule: Some(rule.clone()),
                            audit_level: Some(self.default_audit_level.clone()),
                            sql_fingerprint: audit_sql.as_deref().map(gateway_core::sql_fingerprint),
                            sql_text: audit_sql.clone(),
                            tables: audit_tables.clone(),
                            ..gateway_core::AuditEvent::default()
                        });
                        let response = GatewayResponse::Error {
                            code: "security_deny".into(),
                            message,
                        };
                        command_span.record("outcome", "security_deny");
                        let rule_class = crate::otel_metrics::classify_security_rule(&rule);
                        command_span.record("security_decision", "deny");
                        command_span.record("security_rule_class", rule_class);
                        self.encode_response_to_writer(response, writer).await?;
                        record_otel_command(
                            &self.listener_name,
                            &self.service_name,
                            labels[2],
                            labels[3],
                            command_type,
                            labels[5],
                            "security_deny",
                            started_at,
                            &crate::otel_metrics::CommandOtelAttrs::security("deny", rule_class),
                        );
                        finish_command_metrics(&self.metrics, &labels, started_at, "n/a", 0);
                        if let (Some(plugins), Some(idx)) =
                            (self.plugins.as_mut(), concurrency_rule_idx)
                        {
                            plugins.release_concurrency(idx);
                        }
                        continue;
                    }
                }
            }

            let same_protocol = self.frontend.protocol() == self.backend.protocol();
            // A06: result obligations force Streaming so backend applies max_rows/window
            // and we never take the wire Passthrough path with masks.
            let has_result_obl = pending_obligations.has_result_obligations();
            let want_passthrough = self.passthrough_enabled
                && same_protocol
                && !has_result_obl
                && matches!(command, GatewayCommand::Query { .. })
                && self.translation_policy.is_none();
            // QueryParams uses bound prepare path (not TCP wire passthrough).
            // A4: cross-protocol never uses wire passthrough; force Streaming so
            // backend max_rows/window apply and encode path is windowed.
            // A06: Materialized is never the production default for row-returning
            // work — promote_row_stream at the backend is the last line of defense;
            // here we also avoid selecting Materialized when stream_mode is already Streaming.
            let exec_mode = if want_passthrough {
                ExecuteMode::Passthrough
            } else if self.translation_policy.is_some() || has_result_obl {
                match self.stream_mode {
                    ExecuteMode::Streaming { .. } => self.stream_mode,
                    _ => ExecuteMode::from_streaming_config(256, pending_obligations.max_rows),
                }
            } else {
                // Merge PDP max_rows into streaming mode when configured.
                match self.stream_mode {
                    ExecuteMode::Streaming {
                        window_rows,
                        max_rows,
                    } => ExecuteMode::Streaming {
                        window_rows,
                        max_rows: match (max_rows, pending_obligations.max_rows) {
                            (Some(a), Some(b)) => Some(a.min(b)),
                            (None, Some(b)) => Some(b),
                            (Some(a), None) => Some(a),
                            (None, None) => None,
                        },
                    },
                    // Materialized stream_mode on Query* → promote so peak ≈ window.
                    ExecuteMode::Materialized
                        if matches!(
                            command,
                            GatewayCommand::Query { .. }
                                | GatewayCommand::QueryParams { .. }
                                | GatewayCommand::Execute { .. }
                        ) =>
                    {
                        ExecuteMode::from_streaming_config(256, pending_obligations.max_rows)
                    }
                    other => other,
                }
            };

            let response = match {
                // A10 true hold: resume held stream without re-running backend SQL.
                if self.session.pg_drop_portal_hold {
                    self.held_portal_stream = None;
                    self.session.pg_drop_portal_hold = false;
                }
                if self.held_portal_stream.is_some()
                    && self.session.pg_portal_name.is_some()
                    && self.session.pg_execute_max_rows.is_some()
                    && self.session.pg_extended_query
                    && matches!(
                        command,
                        GatewayCommand::Query { .. }
                            | GatewayCommand::QueryParams { .. }
                            | GatewayCommand::Execute { .. }
                    )
                {
                    let held = self.held_portal_stream.take().expect("checked is_some");
                    Ok(ExecuteOutcome::Streaming(held))
                } else {
                    if self.held_portal_stream.is_some() {
                        // Different command / portal — drop held stream (best-effort).
                        self.held_portal_stream = None;
                    }
                    self.backend
                        .execute_outcome(command, &mut self.session, exec_mode)
                        .instrument(command_span.clone())
                        .await
                }
            } {
                Ok(ExecuteOutcome::WireRelay(relay)) => {
                    // A08: progressive wire frames → socket (no logical ResultSet).
                    // Only selected when passthrough is allowed (no result obligations).
                    let wire_bytes = write_wire_relay(relay, writer).await?;
                    let execute_path = "passthrough";
                    command_span.record("outcome", "passthrough");
                    command_span.record("security_decision", "allow");
                    command_span.record("security_rule_class", "none");
                    command_span.record("execute_path", execute_path);
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
                        outcome = "passthrough",
                        latency_ms = started_at.elapsed().as_millis() as u64,
                        "gateway command audited"
                    );
                    gateway_core::try_audit(gateway_core::AuditEvent {
                        action: Some(gateway_core::AuditAction::Query.as_str().into()),
                        decision: Some(gateway_core::AuditDecision::Execute.as_str().into()),
                        subject_id: self.session.user.clone(),
                        db_user: self.session.user.clone(),
                        listener: Some(self.listener_name.clone()),
                        service: Some(self.service_name.clone()),
                        frontend_protocol: Some(
                            protocol_metric_name(&self.frontend.protocol()).to_owned(),
                        ),
                        backend_protocol: Some(
                            protocol_metric_name(&self.backend.protocol()).to_owned(),
                        ),
                        command_type: Some(command_type.to_owned()),
                        endpoint: Some(label_owned[5].clone()),
                        database: self.session.database.clone(),
                        outcome: Some("passthrough".into()),
                        latency_ms: Some(started_at.elapsed().as_millis() as u64),
                        audit_level: Some(self.default_audit_level.clone()),
                        sql_fingerprint: audit_sql.as_deref().map(gateway_core::sql_fingerprint),
                        sql_text: audit_sql.clone(),
                        tables: audit_tables.clone(),
                        ..gateway_core::AuditEvent::default()
                    });
                    if let (Some(plugins), Some(idx)) =
                        (self.plugins.as_mut(), concurrency_rule_idx)
                    {
                        plugins.release_concurrency(idx);
                    }
                    record_otel_command(
                        &self.listener_name,
                        &self.service_name,
                        labels[2],
                        labels[3],
                        command_type,
                        labels[5],
                        "passthrough",
                        started_at,
                        &crate::otel_metrics::CommandOtelAttrs::security("allow", "none")
                            .with_execute_path(execute_path)
                            .with_wire_bytes(wire_bytes),
                    );
                    finish_command_metrics(
                        &self.metrics,
                        &labels,
                        started_at,
                        execute_path,
                        wire_bytes,
                    );
                    continue;
                }
                Ok(ExecuteOutcome::Streaming(mut query)) => {
                    // A06: progressive rows — type-map column metadata, then encode
                    // window-by-window with optional obligations (no full ResultSet).
                    // (Hold resume reuses columns already mapped on first Execute.)
                    if self.translation_policy.is_some() {
                        let backend = self.backend.protocol();
                        let frontend = self.frontend.protocol();
                        if backend != frontend {
                            for col in &mut query.columns {
                                col.data_type = gateway_core::map_column_type(
                                    &col.data_type,
                                    &backend,
                                    &frontend,
                                );
                            }
                        }
                    }
                    if pending_obligations.has_result_obligations() {
                        info!(
                            target: gateway_core::AUDIT_TARGET,
                            action = gateway_core::AuditAction::Query.as_str(),
                            listener = %self.listener_name,
                            service = %self.service_name,
                            mask_count = pending_obligations.column_masks.len(),
                            max_rows = ?pending_obligations.max_rows,
                            "security streaming path with result obligations"
                        );
                    }
                    let window = exec_mode.window_rows().unwrap_or(256).max(1);
                    // A10: encode path uses obligations.max_rows for truncation. Fold
                    // client Execute max_rows so PortalSuspended can fire when the
                    // page ends with more backend rows remaining.
                    let mut encode_obl = pending_obligations.clone();
                    if let Some(page) = self.session.pg_execute_max_rows {
                        let page = page as u64;
                        encode_obl.max_rows = Some(match encode_obl.max_rows {
                            Some(m) => m.min(page),
                            None => page,
                        });
                    }
                    // Hold resume: only the client page size applies (no cumulative skip).
                    // Detect resume by empty skip + held stream was just consumed above —
                    // we set skip_rows=0 when hold_remainder is active.
                    let obl = if encode_obl.has_result_obligations() {
                        Some(&encode_obl)
                    } else {
                        None
                    };
                    let sample_opts = if self.audit_sample_enabled
                        && self.default_audit_level.eq_ignore_ascii_case("L2")
                    {
                        StreamingSampleOpts {
                            enabled: true,
                            max_rows: self.audit_sample_max_rows.max(1) as usize,
                            max_bytes: self.audit_sample_max_bytes.max(1) as usize,
                        }
                    } else {
                        StreamingSampleOpts::default()
                    };
                    // Hold remainder for PG client-paged Execute (PortalSuspended path).
                    let want_hold = self.session.pg_execute_max_rows.is_some()
                        && self.session.pg_portal_name.is_some()
                        && self.session.pg_extended_query;
                    // When resuming a held stream, disable logical skip (already at offset).
                    if want_hold {
                        self.session.pg_portal_skip_rows = 0;
                    }
                    let (encode_stats, held) = write_streaming_query_with_obligations_sample(
                        self.frontend.as_mut(),
                        &self.session,
                        query,
                        window,
                        obl,
                        writer,
                        sample_opts,
                        want_hold,
                    )
                    .await?;
                    // A10: portal paging state after this page.
                    if encode_stats.hold_remainder {
                        self.held_portal_stream = held;
                        self.session.pg_portal_skip_rows = 0;
                    } else if encode_stats.truncated
                        && self.session.pg_execute_max_rows.is_some()
                        && self.session.pg_portal_name.is_some()
                    {
                        // Fallback logical skip (no hold / drain path).
                        self.held_portal_stream = None;
                        self.session.pg_portal_skip_rows = self
                            .session
                            .pg_portal_skip_rows
                            .saturating_add(encode_stats.total_rows);
                    } else if self.session.pg_portal_name.is_some() {
                        // Finished portal (no more rows or unlimited fetch).
                        self.held_portal_stream = None;
                        self.session.pg_portal_skip_rows = 0;
                        self.session.pg_portal_name = None;
                    }
                    // A10: clear one-shot Execute page flags after encode.
                    self.session.prefer_binary_result = false;
                    self.session.pg_execute_max_rows = None;
                    self.session.result_truncated = false;
                    // O01/A06: mask / window / encode-byte / peak-window counters on Secure streaming path.
                    self.metrics.record_secure_encode_peak(
                        &labels,
                        encode_stats.masked_rows,
                        encode_stats.windows,
                        encode_stats.encoded_bytes,
                        encode_stats.peak_window_rows,
                    );
                    let execute_path = if self.translation_policy.is_some() {
                        "xproto_stream"
                    } else {
                        "streaming"
                    };
                    let sec_decision = if pending_obligations.has_result_obligations() {
                        "allow_obligations"
                    } else {
                        "allow"
                    };
                    command_span.record("outcome", "resultset");
                    command_span.record("security_decision", sec_decision);
                    command_span.record("security_rule_class", "none");
                    command_span.record("execute_path", execute_path);
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
                        outcome = "resultset",
                        latency_ms = started_at.elapsed().as_millis() as u64,
                        "gateway command audited"
                    );
                    gateway_core::try_audit(gateway_core::AuditEvent {
                        action: Some(gateway_core::AuditAction::Query.as_str().into()),
                        decision: Some(gateway_core::AuditDecision::Execute.as_str().into()),
                        subject_id: self.session.user.clone(),
                        db_user: self.session.user.clone(),
                        listener: Some(self.listener_name.clone()),
                        service: Some(self.service_name.clone()),
                        frontend_protocol: Some(
                            protocol_metric_name(&self.frontend.protocol()).to_owned(),
                        ),
                        backend_protocol: Some(
                            protocol_metric_name(&self.backend.protocol()).to_owned(),
                        ),
                        command_type: Some(command_type.to_owned()),
                        endpoint: Some(label_owned[5].clone()),
                        database: self.session.database.clone(),
                        outcome: Some("resultset".into()),
                        latency_ms: Some(started_at.elapsed().as_millis() as u64),
                        audit_level: Some(self.default_audit_level.clone()),
                        sql_fingerprint: audit_sql.as_deref().map(gateway_core::sql_fingerprint),
                        sql_text: audit_sql.clone(),
                        tables: audit_tables.clone(),
                        sample_body: encode_stats.sample_body.clone(),
                        sample_row_count: encode_stats.sample_row_count,
                        sample_bytes: encode_stats.sample_bytes,
                        sample_truncated: encode_stats.sample_truncated,
                        ..gateway_core::AuditEvent::default()
                    });
                    if let (Some(plugins), Some(idx)) =
                        (self.plugins.as_mut(), concurrency_rule_idx)
                    {
                        plugins.release_concurrency(idx);
                    }
                    record_otel_command(
                        &self.listener_name,
                        &self.service_name,
                        labels[2],
                        labels[3],
                        command_type,
                        labels[5],
                        "resultset",
                        started_at,
                        &crate::otel_metrics::CommandOtelAttrs::security(sec_decision, "none")
                            .with_execute_path(execute_path)
                            .with_wire_bytes(0),
                    );
                    finish_command_metrics(
                        &self.metrics,
                        &labels,
                        started_at,
                        execute_path,
                        0,
                    );
                    continue;
                }
                Ok(ExecuteOutcome::Complete(response)) => {
                    // Wire packets must not be type-mapped; logical results still may.
                    let response = match response {
                        GatewayResponse::Wire { .. } => response,
                        other => map_response_types(
                            other,
                            &self.backend.protocol(),
                            &self.frontend.protocol(),
                        ),
                    };
                    if pending_obligations.has_result_obligations() {
                        info!(
                            target: gateway_core::AUDIT_TARGET,
                            action = gateway_core::AuditAction::Query.as_str(),
                            listener = %self.listener_name,
                            service = %self.service_name,
                            mask_count = pending_obligations.column_masks.len(),
                            max_rows = ?pending_obligations.max_rows,
                            "security deferred result obligations to encode path"
                        );
                        self.pending_encode_obligations = Some(pending_obligations.clone());
                        response
                    } else {
                        response
                    }
                }
                Err(error) => GatewayResponse::Error {
                    code: "gateway_error".into(),
                    message: error.to_string(),
                },
            };

            let wire_bytes = match &response {
                GatewayResponse::Wire { packets } => {
                    packets.iter().map(|p| p.len() as u64).sum::<u64>()
                }
                _ => 0,
            };
            let outcome = match &response {
                GatewayResponse::Error { code, .. } => format!("error:{code}"),
                GatewayResponse::ResultSet { .. } if self.translation_policy.is_some() => {
                    "xproto_stream".to_owned()
                }
                GatewayResponse::ResultSet { .. } => "resultset".to_owned(),
                GatewayResponse::Wire { .. } => "passthrough".to_owned(),
                GatewayResponse::Ok { .. } => "ok".to_owned(),
                GatewayResponse::Pong => "pong".to_owned(),
                GatewayResponse::Bye => "bye".to_owned(),
                GatewayResponse::Prepared { .. } => "prepared".to_owned(),
                GatewayResponse::RowDescription { .. } => "row_description".to_owned(),
            };
            let execute_path = match &response {
                GatewayResponse::Wire { .. } => "passthrough",
                GatewayResponse::ResultSet { .. } if self.translation_policy.is_some() => {
                    "xproto_stream"
                }
                GatewayResponse::ResultSet { .. } => match self.stream_mode {
                    gateway_core::ExecuteMode::Streaming { .. } => "streaming",
                    gateway_core::ExecuteMode::Materialized => "materialized",
                    gateway_core::ExecuteMode::Passthrough => "passthrough",
                },
                _ => "n/a",
            };
            let sec_decision = if pending_obligations.has_result_obligations() {
                "allow_obligations"
            } else {
                "allow"
            };
            command_span.record("outcome", tracing::field::display(&outcome));
            command_span.record("security_decision", sec_decision);
            command_span.record("security_rule_class", "none");
            command_span.record("execute_path", execute_path);
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
            // B08: attach small result sample only for L2 + sample_enabled + ResultSet.
            // Prefer post-obligation rows when encode-path deferred masks are present.
            let sample_fields = self.build_audit_sample(&response, &pending_obligations);
            gateway_core::try_audit(gateway_core::AuditEvent {
                action: Some(gateway_core::AuditAction::Query.as_str().into()),
                decision: Some(gateway_core::AuditDecision::Execute.as_str().into()),
                subject_id: self.session.user.clone(),
                db_user: self.session.user.clone(),
                listener: Some(self.listener_name.clone()),
                service: Some(self.service_name.clone()),
                frontend_protocol: Some(
                    protocol_metric_name(&self.frontend.protocol()).to_owned(),
                ),
                backend_protocol: Some(
                    protocol_metric_name(&self.backend.protocol()).to_owned(),
                ),
                command_type: Some(command_type.to_owned()),
                endpoint: Some(label_owned[5].clone()),
                database: self.session.database.clone(),
                outcome: Some(outcome.clone()),
                latency_ms: Some(started_at.elapsed().as_millis() as u64),
                audit_level: Some(self.default_audit_level.clone()),
                sql_fingerprint: audit_sql.as_deref().map(gateway_core::sql_fingerprint),
                sql_text: audit_sql,
                tables: audit_tables,
                sample_body: sample_fields.as_ref().map(|s| s.0.clone()),
                sample_row_count: sample_fields.as_ref().map(|s| s.1),
                sample_bytes: sample_fields.as_ref().map(|s| s.2),
                sample_truncated: sample_fields.as_ref().map(|s| s.3).unwrap_or(false),
                ..gateway_core::AuditEvent::default()
            });

            if let (Some(plugins), Some(idx)) = (self.plugins.as_mut(), concurrency_rule_idx) {
                plugins.release_concurrency(idx);
            }

            self.encode_response_to_writer(response, writer).await?;
            record_otel_command(
                &self.listener_name,
                &self.service_name,
                labels[2],
                labels[3],
                command_type,
                labels[5],
                &outcome,
                started_at,
                &crate::otel_metrics::CommandOtelAttrs::security(sec_decision, "none")
                    .with_execute_path(execute_path)
                    .with_wire_bytes(wire_bytes),
            );
            finish_command_metrics(
                &self.metrics,
                &labels,
                started_at,
                execute_path,
                wire_bytes,
            );
        }

        Ok(())
    }
}

fn finish_command_metrics(
    metrics: &MySQLServerMetricsCollector,
    labels: &[&str],
    started_at: Instant,
    execute_path: &str,
    wire_bytes: u64,
) {
    metrics.set_sql_under_processing_dec(labels);
    metrics.set_sql_processed_total(labels);
    metrics.set_sql_processed_duration(labels, started_at.elapsed().as_secs_f64());
    // A05: path hit-rate + passthrough bytes (Prometheus, always on).
    metrics.record_execute_path(labels, execute_path, wire_bytes);
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
    attrs: &crate::otel_metrics::CommandOtelAttrs,
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
        attrs,
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
        GatewayCommand::QueryParams { .. } => "QUERY_PARAMS",
        GatewayCommand::Prepare { .. } => "PREPARE",
        GatewayCommand::Execute { .. } => "EXECUTE",
        GatewayCommand::CloseStatement { .. } => "CLOSE",
        GatewayCommand::DescribeSql { .. } => "DESCRIBE_SQL",
        GatewayCommand::ClientWire { .. } => "CLIENT_WIRE",
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

        match response {
            GatewayResponse::Wire { packets: wire } => packets.extend(wire),
            GatewayResponse::ResultSet { columns, rows } => {
                let mut writer = CollectingWriter::new();
                write_resultset_windowed(
                    frontend,
                    session,
                    columns,
                    rows,
                    256,
                    &mut writer,
                )
                .await?;
                packets.extend(writer.into_packets());
            }
            other => packets.extend(frontend.encode(other, session)?),
        }
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
        // S4: install process-wide audit pipeline from security.audit (idempotent).
        let _ = gateway_core::install_audit_pipeline(
            &config.security.audit,
            &config.security.default_audit_level,
        );
        // H05: ticket/vault state backend (memory default; file for shared disk).
        if let Err(e) = gateway_core::install_ticket_store(
            &config.security.state.backend,
            &config.security.state.ticket_path,
            &config.security.state.ticket_encrypt_key,
        ) {
            tracing::error!(target: "data_nexus::security", error = %e, "install ticket store failed");
        }
        if let Err(e) = gateway_core::install_vault_store(
            &config.security.state.backend,
            &config.security.state.vault_path,
            &config.security.state.vault_encrypt_key,
        ) {
            tracing::error!(target: "data_nexus::security", error = %e, "install vault store failed");
        }

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
    /// Result read mode derived from security.streaming.
    stream_mode: ExecuteMode,
    passthrough_enabled: bool,
    /// F32: copy of security.default_audit_level for event tagging.
    default_audit_level: String,
    /// B08: when true and level is L2, attach result samples on audit events.
    audit_sample_enabled: bool,
    audit_sample_max_rows: u32,
    audit_sample_max_bytes: u32,
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
        let mut stream_mode = ExecuteMode::from_streaming_config(
            config.security.streaming.window_rows,
            config.security.streaming.max_rows,
        );
        // A4: cross-protocol listeners always stream (never pure Materialized).
        if service.translation_policy.is_some() {
            if !matches!(stream_mode, ExecuteMode::Streaming { .. }) {
                stream_mode = ExecuteMode::from_streaming_config(
                    config.security.streaming.window_rows.max(1),
                    config.security.streaming.max_rows,
                );
            }
        }
        // Passthrough only for same-protocol; default true from security.streaming.
        let passthrough_enabled = config.security.streaming.passthrough;
        let default_audit_level = config.security.default_audit_level.clone();
        let audit_sample_enabled = config.security.audit.sample_enabled;
        let audit_sample_max_rows = config.security.audit.sample_max_rows;
        let audit_sample_max_bytes = config.security.audit.sample_max_bytes;

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
            stream_mode,
            passthrough_enabled,
            default_audit_level,
            audit_sample_enabled,
            audit_sample_max_rows,
            audit_sample_max_bytes,
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
            self.stream_mode,
            self.passthrough_enabled,
            self.default_audit_level.clone(),
            self.audit_sample_enabled,
            self.audit_sample_max_rows,
            self.audit_sample_max_bytes,
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
        GatewayCommand::QueryParams { sql, .. } if dialect.is_read_only(sql) => {
            RouteTargetRole::Read
        }
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
            "8.0.36".into(),
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
    use gateway_core::{write_resultset_windowed, CollectingWriter, Column as GatewayColumn, GatewayCommand, GatewayValue};
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

        async fn execute_with_mode(
            &self,
            command: GatewayCommand,
            _session: &mut SessionState,
            _mode: ExecuteMode,
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
                "8.0.36".into(),
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
                "8.0.36".into(),
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
        use gateway_core::{write_resultset_windowed, CollectingWriter, LocalPdp, SecurityPolicyConfig, SecurityRuleConfig};

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
        let pdp = LocalPdp::from_config_isolated(&security).expect("enabled pdp");

        let mut connection = CoreGatewayConnection::new(
            Box::new(MySqlFrontendProtocol::new(
                "app".into(),
                "secret".into(),
                "test".into(),
                "8.0.36".into(),
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
            ssl_mode: Default::default(),
            ssl_ca_file: None,
            ssl_accept_invalid_certs: true,
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
        ssl_mode: Default::default(),
        ssl_ca_file: None,
        ssl_accept_invalid_certs: true,
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
        ssl_mode: Default::default(),
        ssl_ca_file: None,
        ssl_accept_invalid_certs: true,
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
        // A4: translation path forces Streaming mode.
        let connection = plan.build_connection("mysql-listener").unwrap();
        assert_eq!(connection.frontend_protocol(), ProtocolKind::MySql);
        assert_eq!(connection.backend_protocol(), ProtocolKind::PostgreSql);
        assert!(connection.translation_policy.is_some());
        assert!(
            matches!(connection.stream_mode, ExecuteMode::Streaming { .. }),
            "cross-protocol must use Streaming mode, got {:?}",
            connection.stream_mode
        );
    }

    #[tokio::test]
    async fn cross_protocol_rewrites_sql_and_maps_result_types() {
        let mut connection = CoreGatewayConnection::new(
            Box::new(MySqlFrontendProtocol::new(
                "app".into(),
                "secret".into(),
                "test".into(),
                "8.0.36".into(),
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
                "8.0.36".into(),
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
