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

use gateway_core::{
    AuthPolicyConfig, AuthPolicyUserConfig, BackendConnector, EndpointConfig,
    FrontendProtocolAdapter, GatewayConfig, GatewayError, GatewayResponse, GatewayResult,
    ListenerConfig, ProtocolKind, RoutePlan, ServiceConfig, SessionState,
};

use crate::{
    backend::{mysql::MySqlBackendConnector, postgresql::PostgreSqlBackendConnector},
    frontend::{mysql::MySqlFrontendProtocol, postgresql::PostgreSqlFrontendProtocol},
};

/// Protocol-neutral execution path for one frontend connection.
///
/// Wire-specific code owns framing and handshake. Once a frontend frame is
/// available, this bridge keeps the request path on gateway_core contracts:
/// decode command, execute against a backend connector, then encode the response.
pub struct CoreGatewayConnection {
    frontend: Box<dyn FrontendProtocolAdapter>,
    backend: Arc<dyn BackendConnector>,
    session: SessionState,
}

impl CoreGatewayConnection {
    pub fn new(
        frontend: Box<dyn FrontendProtocolAdapter>,
        backend: Arc<dyn BackendConnector>,
        session: SessionState,
    ) -> Self {
        Self { frontend, backend, session }
    }

    pub fn frontend_protocol(&self) -> ProtocolKind {
        self.frontend.protocol()
    }

    pub fn backend_protocol(&self) -> ProtocolKind {
        self.backend.protocol()
    }

    pub fn last_backend_endpoint_label(&self) -> Option<String> {
        self.backend.last_endpoint_label()
    }

    pub fn session(&self) -> &SessionState {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut SessionState {
        &mut self.session
    }

    pub async fn handle_frame(&mut self, frame: &[u8]) -> GatewayResult<Vec<Vec<u8>>> {
        handle_gateway_frame(
            self.frontend.as_mut(),
            self.backend.as_ref(),
            &mut self.session,
            frame,
        )
        .await
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreGatewayRuntimePlan {
    listeners: Vec<CoreGatewayListenerPlan>,
}

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreGatewayListenerPlan {
    listener: ListenerConfig,
    service: ServiceConfig,
    endpoints: Vec<EndpointConfig>,
    route_plan: RoutePlan,
    auth_policy: Option<AuthPolicyConfig>,
}

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

        let auth_policy = listener
            .auth_policy
            .as_ref()
            .map(|policy_name| {
                config
                    .auth_policies
                    .iter()
                    .find(|policy| policy.name == *policy_name)
                    .cloned()
                    .ok_or_else(|| {
                        GatewayError::Configuration(format!(
                            "listener '{}' references missing auth policy '{}'",
                            listener.name, policy_name
                        ))
                    })
            })
            .transpose()?;

        let route_plan = RoutePlan::from_endpoints(endpoints.clone());

        Ok(Self {
            listener: listener.clone(),
            service: service.clone(),
            endpoints,
            route_plan,
            auth_policy,
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

    pub fn route_plan(&self) -> &RoutePlan {
        &self.route_plan
    }

    pub fn auth_policy(&self) -> Option<&AuthPolicyConfig> {
        self.auth_policy.as_ref()
    }

    pub fn default_database(&self) -> Option<&str> {
        self.endpoints.iter().find_map(|endpoint| endpoint.database.as_deref())
    }

    pub fn build_connection(&self) -> GatewayResult<CoreGatewayConnection> {
        let database = self.default_database().map(ToOwned::to_owned);
        let frontend =
            build_frontend_protocol(&self.listener, self.auth_policy.as_ref(), database.clone())?;
        let backend = build_backend_connector(&self.service, &self.endpoints)?;
        let session = SessionState { database, ..SessionState::default() };

        Ok(CoreGatewayConnection::new(frontend, backend, session))
    }
}

fn build_frontend_protocol(
    listener: &ListenerConfig,
    auth_policy: Option<&AuthPolicyConfig>,
    database: Option<String>,
) -> GatewayResult<Box<dyn FrontendProtocolAdapter>> {
    let auth_user = default_auth_user(auth_policy);
    match &listener.protocol {
        ProtocolKind::MySql => Ok(Box::new(MySqlFrontendProtocol::new(
            auth_user.map(|user| user.username.clone()).unwrap_or_default(),
            auth_user.map(|user| user.password.clone()).unwrap_or_default(),
            database.unwrap_or_default(),
            "8.0".into(),
        ))),
        ProtocolKind::PostgreSql => Ok(Box::new(PostgreSqlFrontendProtocol::new())),
    }
}

fn default_auth_user(auth_policy: Option<&AuthPolicyConfig>) -> Option<&AuthPolicyUserConfig> {
    auth_policy.and_then(|policy| policy.users.first())
}

fn build_backend_connector(
    service: &ServiceConfig,
    endpoints: &[EndpointConfig],
) -> GatewayResult<Arc<dyn BackendConnector>> {
    match &service.backend_protocol {
        ProtocolKind::MySql => Ok(Arc::new(MySqlBackendConnector::<(), ()>::new())),
        ProtocolKind::PostgreSql => {
            Ok(Arc::new(PostgreSqlBackendConnector::new(endpoints.to_vec())))
        }
    }
}

#[cfg(test)]
mod tests {
    use byteorder::{BigEndian, ByteOrder};
    use gateway_core::{EndpointRole, TransactionState};
    use mysql_protocol::{
        mysql_const::{COM_INIT_DB, COM_PING, COM_QUERY, COM_QUIT},
        server::codec::ok_packet,
    };

    use super::*;

    fn mysql_connection() -> CoreGatewayConnection {
        CoreGatewayConnection::new(
            Box::new(MySqlFrontendProtocol::new(
                "app".into(),
                "secret".into(),
                "test".into(),
                "8.0".into(),
            )),
            Arc::new(MySqlBackendConnector::<(), ()>::new()),
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
                frontend_protocols: vec![ProtocolKind::MySql],
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
                username: "root".into(),
                password: "backend-secret".into(),
                role: EndpointRole::ReadWrite,
                weight: 1,
            }],
            auth_policies: vec![AuthPolicyConfig {
                name: "orders-users".into(),
                kind: "static".into(),
                users: vec![AuthPolicyUserConfig {
                    username: "app".into(),
                    password: "secret".into(),
                    databases: vec!["orders_db".into()],
                }],
            }],
            ..GatewayConfig::default()
        }
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
        assert_eq!(connection.session().transaction_state, TransactionState::Active);

        let mut commit = vec![COM_QUERY];
        commit.extend_from_slice(b"commit");

        let packets = connection.handle_frame(&commit).await;

        assert_eq!(packets, Ok(vec![ok_packet()[4..].to_vec()]));
        assert_eq!(connection.session().transaction_state, TransactionState::Idle);
    }

    #[tokio::test]
    async fn handles_mysql_quit_through_core_traits() {
        let mut connection = mysql_connection();

        let packets = connection.handle_frame(&[COM_QUIT]).await;

        assert_eq!(packets, Ok(vec![ok_packet()[4..].to_vec()]));
    }

    #[tokio::test]
    async fn encodes_backend_error_for_unwired_mysql_queries() {
        let mut connection = mysql_connection();
        let mut frame = vec![COM_QUERY];
        frame.extend_from_slice(b"select 1");

        let packets = connection.handle_frame(&frame).await.unwrap();

        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].first(), Some(&0xff));
        assert!(String::from_utf8_lossy(&packets[0])
            .contains("mysql backend connector is not wired to execute"));
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
        assert_eq!(listener.default_database(), Some("orders_db"));
        assert!(matches!(
            listener.route_plan(),
            RoutePlan::Single { target } if target.endpoint.name == "orders-primary"
        ));
    }

    #[test]
    fn builds_broadcast_route_plan_for_multi_endpoint_service() {
        let mut config = mysql_config();
        config.services[0].endpoints.push("orders-replica".into());
        config.endpoints.push(EndpointConfig {
            name: "orders-replica".into(),
            protocol: ProtocolKind::MySql,
            address: "127.0.0.1:3307".into(),
            database: Some("orders_db".into()),
            username: "root".into(),
            password: "backend-secret".into(),
            role: EndpointRole::Read,
            weight: 1,
        });

        let plan = CoreGatewayRuntimePlan::from_config(&config).unwrap();
        let listener = plan.listener("mysql-listener").unwrap();

        assert!(matches!(
            listener.route_plan(),
            RoutePlan::Broadcast { targets }
                if targets.iter().map(|target| target.endpoint.name.as_str()).collect::<Vec<_>>()
                    == vec!["orders-primary", "orders-replica"]
        ));
    }

    #[test]
    fn resolves_listener_auth_policy_into_runtime_plan() {
        let mut config = mysql_config();
        config.listeners[0].auth_policy = Some("orders-users".into());

        let plan = CoreGatewayRuntimePlan::from_config(&config).unwrap();

        let auth_policy = plan.listener("mysql-listener").unwrap().auth_policy().unwrap();
        assert_eq!(auth_policy.kind, "static");
        assert_eq!(auth_policy.users[0].username, "app");
        assert_eq!(auth_policy.users[0].databases, vec!["orders_db"]);
    }

    #[test]
    fn builds_mysql_core_connection_from_runtime_plan() {
        let config = mysql_config();
        let plan = CoreGatewayRuntimePlan::from_config(&config).unwrap();

        let connection = plan.build_connection("mysql-listener").unwrap();

        assert_eq!(connection.frontend_protocol(), ProtocolKind::MySql);
        assert_eq!(connection.backend_protocol(), ProtocolKind::MySql);
        assert_eq!(connection.session().database, Some("orders_db".into()));
    }

    #[test]
    fn builds_postgresql_backend_connector_from_runtime_plan() {
        let mut config = mysql_config();
        config.services[0].backend_protocol = ProtocolKind::PostgreSql;
        config.endpoints[0].protocol = ProtocolKind::PostgreSql;
        let plan = CoreGatewayRuntimePlan::from_config(&config).unwrap();

        let connection = plan.build_connection("mysql-listener").unwrap();

        assert_eq!(connection.frontend_protocol(), ProtocolKind::MySql);
        assert_eq!(connection.backend_protocol(), ProtocolKind::PostgreSql);
    }

    #[test]
    fn builds_postgresql_frontend_adapter_from_runtime_plan() {
        let mut config = mysql_config();
        config.listeners[0].protocol = ProtocolKind::PostgreSql;
        config.services[0].frontend_protocols = vec![ProtocolKind::PostgreSql, ProtocolKind::MySql];
        let plan = CoreGatewayRuntimePlan::from_config(&config).unwrap();

        let connection = plan.build_connection("mysql-listener").unwrap();

        assert_eq!(connection.frontend_protocol(), ProtocolKind::PostgreSql);
        assert_eq!(connection.backend_protocol(), ProtocolKind::MySql);
    }

    #[tokio::test]
    async fn handles_postgresql_begin_through_core_traits() {
        let mut connection = CoreGatewayConnection::new(
            Box::new(PostgreSqlFrontendProtocol::new()),
            Arc::new(PostgreSqlBackendConnector::new(Vec::new())),
            SessionState::default(),
        );

        let mut frame = vec![b'Q', 0, 0, 0, 0];
        BigEndian::write_u32(&mut frame[1..5], 10);
        frame.extend_from_slice(b"BEGIN\0");

        let packets = connection.handle_frame(&frame).await.unwrap();

        let mut expected = vec![b'C', 0, 0, 0, 9];
        expected.extend_from_slice(b"OK 0\0");
        expected.extend_from_slice(&[b'Z', 0, 0, 0, 5, b'T']);
        assert_eq!(packets, vec![expected]);
        assert_eq!(connection.session().transaction_state, TransactionState::Active);
    }
}
