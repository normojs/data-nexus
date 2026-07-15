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

use std::sync::Arc;

use endpoint::endpoint::Endpoint;
use gateway_core::{
    BackendConnector, CommandSummary, EndpointConfig, EndpointRef, EndpointRole,
    FrontendProtocolAdapter, GatewayCommand, GatewayConfig, GatewayError, GatewayResponse,
    GatewayResult, ListenerConfig, PluginContext, PluginDecision, ProtocolKind, RoutePlan,
    ServiceConfig, SessionState, TransactionState,
};
use loadbalance::balance::{AlgorithmName, Balance, BalanceType, LoadBalance};
use parking_lot::Mutex;
use plugin::build_phase::PluginPhase;

use crate::{
    backend::{mysql::MySqlBackendConnector, postgresql::PostgreSqlBackendConnector},
    frontend::{mysql::MySqlFrontendProtocol, postgresql::PostgreSqlFrontendProtocol},
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
    service_name: String,
    route_policy: Option<CoreRoutePolicy>,
    plugins: Option<PluginPhase>,
}

impl CoreGatewayConnection {
    pub fn new(
        frontend: Box<dyn FrontendProtocolAdapter>,
        backend: Arc<dyn BackendConnector>,
        session: SessionState,
    ) -> Self {
        Self {
            frontend,
            backend,
            session,
            service_name: String::new(),
            route_policy: None,
            plugins: None,
        }
    }

    fn with_route_policy(
        frontend: Box<dyn FrontendProtocolAdapter>,
        backend: Arc<dyn BackendConnector>,
        session: SessionState,
        service_name: String,
        route_policy: CoreRoutePolicy,
    ) -> Self {
        Self {
            frontend,
            backend,
            session,
            service_name,
            route_policy: Some(route_policy),
            plugins: None,
        }
    }

    pub fn with_plugins(mut self, plugins: PluginPhase) -> Self {
        self.plugins = Some(plugins);
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
        let commands = self.frontend.decode(frame, &mut self.session)?;
        let mut packets = Vec::with_capacity(commands.len());

        for mut command in commands {
            let route_plan = if let Some(route_policy) = &self.route_policy {
                let plan = route_policy.plan_command(&command, &self.session)?;
                apply_route_plan(&plan, &mut self.session)?;
                Some(plan)
            } else {
                None
            };

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
                })? {
                    PluginDecision::Continue { concurrency_rule_idx: idx } => {
                        concurrency_rule_idx = idx;
                    }
                    PluginDecision::Reject { code, message } => {
                        let response = GatewayResponse::Error { code, message };
                        packets.extend(self.frontend.encode(response, &mut self.session)?);
                        continue;
                    }
                    PluginDecision::Rewrite { sql } => {
                        if let Some(rewritten) =
                            CommandSummary::from_command(&command).rewritten_sql(sql)
                        {
                            command = rewritten;
                        }
                    }
                }
            }

            let response = match self.backend.execute(command, &mut self.session).await {
                Ok(response) => response,
                Err(error) => GatewayResponse::Error {
                    code: "gateway_error".into(),
                    message: error.to_string(),
                },
            };

            if let (Some(plugins), Some(idx)) = (self.plugins.as_mut(), concurrency_rule_idx) {
                plugins.release_concurrency(idx);
            }

            packets.extend(self.frontend.encode(response, &mut self.session)?);
        }

        Ok(packets)
    }
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
        let route_policy = CoreRoutePolicy::build(route_policy_kind.as_deref(), endpoints.clone())?;
        let plugin_config = build_plugin_config(config, &service.plugin_policies)?;

        Ok(Self {
            listener: listener.clone(),
            service: service.clone(),
            endpoints,
            route_policy_kind,
            route_policy,
            plugin_config,
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
            self.service.name.clone(),
            self.route_policy.clone(),
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

#[derive(Debug, Clone)]
struct CoreRoutePolicy {
    endpoints: Vec<EndpointConfig>,
    kind: CoreRoutePolicyKind,
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
    ) -> GatewayResult<Self> {
        let kind = if is_read_write_splitting_policy(route_policy_kind) {
            CoreRoutePolicyKind::build_read_write(&endpoints)?
        } else if let Some(algorithm) = route_policy_kind.and_then(simple_load_balance_algorithm) {
            CoreRoutePolicyKind::Simple { balancer: build_balancer(algorithm, &endpoints) }
        } else {
            CoreRoutePolicyKind::First
        };

        Ok(Self { endpoints, kind })
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

        self.plan_for_role(command_target_role(command, session))
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

fn command_target_role(command: &GatewayCommand, session: &SessionState) -> RouteTargetRole {
    if session.transaction_state == TransactionState::Active {
        return RouteTargetRole::ReadWrite;
    }

    match command {
        GatewayCommand::Query { sql } if is_read_only_sql(sql) => RouteTargetRole::Read,
        _ => RouteTargetRole::ReadWrite,
    }
}

fn is_read_only_sql(sql: &str) -> bool {
    let sql = sql.trim_start();
    let upper = sql.to_ascii_uppercase();
    let first_token = upper.split_whitespace().next().unwrap_or_default().trim_end_matches(';');

    matches!(first_token, "SELECT" | "SHOW" | "EXPLAIN" | "DESCRIBE" | "DESC" | "WITH" | "VALUES")
        && !upper.contains(" FOR UPDATE")
        && !upper.contains(" FOR SHARE")
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
            err.to_string().contains("cross-protocol is disabled"),
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
}
