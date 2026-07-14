use std::{fmt, sync::Arc};

use async_trait::async_trait;
use conn_pool::{ConnAttr, ConnAttrMut, ConnLike, Pool};
use gateway_core::{
    BackendConnector, Column as GatewayColumn, EndpointConfig, EndpointRole, GatewayCommand,
    GatewayError, GatewayResponse, GatewayResult, GatewayValue, ProtocolKind, SessionState,
    TransactionState,
};
use parking_lot::Mutex;
use tokio_postgres::{Client, NoTls, SimpleQueryMessage};
use tracing::error;

const DEFAULT_POSTGRESQL_POOL_SIZE: usize = 16;

#[derive(Clone, Debug)]
pub struct PostgreSqlBackendConnector {
    endpoints: Arc<Mutex<Vec<EndpointConfig>>>,
    pool: Pool<PostgreSqlBackendConnection>,
}

impl Default for PostgreSqlBackendConnector {
    fn default() -> Self {
        Self::with_pool_size(Vec::new(), DEFAULT_POSTGRESQL_POOL_SIZE)
    }
}

impl PostgreSqlBackendConnector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_endpoints(endpoints: Vec<EndpointConfig>) -> Self {
        Self::with_pool_size(endpoints, DEFAULT_POSTGRESQL_POOL_SIZE)
    }

    pub fn with_pool_size(endpoints: Vec<EndpointConfig>, pool_size: usize) -> Self {
        let pool: Pool<PostgreSqlBackendConnection> = Pool::new(pool_size);
        for endpoint in &endpoints {
            if let Some(database) = endpoint.database.clone() {
                register_endpoint_factory(&pool, endpoint, database);
            }
        }

        Self { endpoints: Arc::new(Mutex::new(endpoints)), pool }
    }

    pub fn endpoints(&self) -> Vec<EndpointConfig> {
        self.endpoints.lock().clone()
    }

    fn select_endpoint(&self, session: &SessionState) -> GatewayResult<EndpointConfig> {
        if let Some(endpoint_name) = session.backend_endpoint.as_deref() {
            return self
                .endpoints
                .lock()
                .iter()
                .find(|endpoint| endpoint.name == endpoint_name)
                .cloned()
                .ok_or_else(|| {
                    GatewayError::Configuration(format!(
                        "postgresql backend connector has no configured endpoint '{}'",
                        endpoint_name
                    ))
                });
        }

        self.endpoints.lock().first().cloned().ok_or_else(|| {
            GatewayError::Configuration(
                "postgresql backend connector has no configured endpoints".into(),
            )
        })
    }

    async fn execute_simple_query(
        &self,
        endpoint: EndpointConfig,
        sql: &str,
        session: &SessionState,
    ) -> GatewayResult<GatewayResponse> {
        let pool_key = self.ensure_pool_factory_for_session(&endpoint, session)?;
        let session_attrs = postgresql_session_attrs(session);
        let conn = self.pool.get_conn_with_endpoint_session(&pool_key, &session_attrs).await?;
        let messages = conn.simple_query(sql).await?;
        simple_query_messages_to_gateway_response(messages)
    }

    fn ensure_pool_factory_for_session(
        &self,
        endpoint: &EndpointConfig,
        session: &SessionState,
    ) -> GatewayResult<String> {
        let _ = parse_endpoint_address(&endpoint.address)?;
        let database = effective_database(endpoint, session)?;
        let pool_key = postgresql_pool_key(endpoint, &database);

        if !self.pool.has_factory(&pool_key) {
            register_endpoint_factory(&self.pool, endpoint, database);
        }

        Ok(pool_key)
    }
}

#[async_trait]
impl BackendConnector for PostgreSqlBackendConnector {
    fn protocol(&self) -> ProtocolKind {
        ProtocolKind::PostgreSql
    }

    async fn execute(
        &self,
        command: GatewayCommand,
        session: &mut SessionState,
    ) -> GatewayResult<GatewayResponse> {
        match command {
            GatewayCommand::Ping => Ok(GatewayResponse::Pong),
            GatewayCommand::Quit => Ok(GatewayResponse::Bye),
            GatewayCommand::UseDatabase { database } => {
                session.database = Some(database);
                Ok(GatewayResponse::Ok { affected_rows: 0, last_insert_id: None })
            }
            GatewayCommand::Begin => {
                session.transaction_state = TransactionState::Active;
                Ok(GatewayResponse::Ok { affected_rows: 0, last_insert_id: None })
            }
            GatewayCommand::Commit | GatewayCommand::Rollback => {
                session.transaction_state = TransactionState::Idle;
                Ok(GatewayResponse::Ok { affected_rows: 0, last_insert_id: None })
            }
            GatewayCommand::Query { sql } => {
                let endpoint = self.select_endpoint(session)?;
                self.execute_simple_query(endpoint, &sql, session).await
            }
            command => Err(GatewayError::Unsupported(format!(
                "postgresql backend connector cannot execute {:?} yet",
                command
            ))),
        }
    }
}

struct PostgreSqlBackendConnection {
    endpoint: EndpointConfig,
    pool_key: String,
    database: String,
    client_encoding: Option<String>,
    client: Option<Client>,
}

impl Clone for PostgreSqlBackendConnection {
    fn clone(&self) -> Self {
        Self {
            endpoint: self.endpoint.clone(),
            pool_key: self.pool_key.clone(),
            database: self.database.clone(),
            client_encoding: self.client_encoding.clone(),
            client: None,
        }
    }
}

impl Default for PostgreSqlBackendConnection {
    fn default() -> Self {
        Self {
            endpoint: EndpointConfig {
                name: String::new(),
                protocol: ProtocolKind::PostgreSql,
                address: String::new(),
                database: None,
                role: EndpointRole::ReadWrite,
                username: String::new(),
                password: String::new(),
                weight: 0,
            },
            pool_key: String::new(),
            database: String::new(),
            client_encoding: None,
            client: None,
        }
    }
}

impl PostgreSqlBackendConnection {
    fn factory(endpoint: EndpointConfig, database: String) -> Self {
        let pool_key = postgresql_pool_key(&endpoint, &database);
        Self { endpoint, pool_key, database, client_encoding: None, client: None }
    }

    async fn simple_query(&self, sql: &str) -> GatewayResult<Vec<SimpleQueryMessage>> {
        self.client()?.simple_query(sql).await.map_err(postgresql_backend_error)
    }

    async fn set_client_encoding(&mut self, client_encoding: String) -> GatewayResult<()> {
        if self.client_encoding.as_deref() == Some(client_encoding.as_str()) {
            return Ok(());
        }

        let sql = postgresql_client_encoding_statement(&client_encoding);
        self.simple_query(&sql).await?;
        self.client_encoding = Some(client_encoding);
        Ok(())
    }

    fn client(&self) -> GatewayResult<&Client> {
        self.client.as_ref().ok_or_else(|| {
            GatewayError::Backend("postgresql backend connection is not open".into())
        })
    }
}

impl fmt::Debug for PostgreSqlBackendConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgreSqlBackendConnection")
            .field("endpoint", &self.endpoint)
            .field("pool_key", &self.pool_key)
            .field("database", &self.database)
            .field("client_encoding", &self.client_encoding)
            .field("connected", &self.client.is_some())
            .finish()
    }
}

#[async_trait]
impl ConnLike for PostgreSqlBackendConnection {
    type Error = GatewayError;

    async fn build_conn(&self) -> Result<Self, Self::Error> {
        let client = connect_endpoint(&self.endpoint, &self.database).await?;
        Ok(Self {
            endpoint: self.endpoint.clone(),
            pool_key: self.pool_key.clone(),
            database: self.database.clone(),
            client_encoding: None,
            client: Some(client),
        })
    }

    async fn ping(&mut self) -> Result<(), Self::Error> {
        self.simple_query("SELECT 1").await.map(|_| ())
    }
}

impl ConnAttr for PostgreSqlBackendConnection {
    fn get_host(&self) -> String {
        parse_endpoint_address(&self.endpoint.address).map(|(host, _)| host).unwrap_or_default()
    }

    fn get_port(&self) -> u16 {
        parse_endpoint_address(&self.endpoint.address).map(|(_, port)| port).unwrap_or_default()
    }

    fn get_user(&self) -> String {
        self.endpoint.username.clone()
    }

    fn get_endpoint(&self) -> String {
        self.pool_key.clone()
    }

    fn get_db(&self) -> Option<String> {
        Some(self.database.clone())
    }

    fn get_charset(&self) -> Option<String> {
        self.client_encoding.clone()
    }

    fn get_autocommit(&self) -> Option<String> {
        None
    }
}

#[async_trait]
impl ConnAttrMut for PostgreSqlBackendConnection {
    type Item = PostgreSqlSessionAttr;

    async fn init(&mut self, session: &[Self::Item]) {
        for attr in session {
            match attr {
                PostgreSqlSessionAttr::ClientEncoding(client_encoding) => {
                    if let Err(error) = self.set_client_encoding(client_encoding.clone()).await {
                        error!(
                            "postgresql backend failed to sync client_encoding '{}': {}",
                            client_encoding, error
                        );
                    }
                }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PostgreSqlSessionAttr {
    ClientEncoding(String),
}

async fn connect_endpoint(endpoint: &EndpointConfig, database: &str) -> GatewayResult<Client> {
    let (host, port) = parse_endpoint_address(&endpoint.address)?;

    let mut config = tokio_postgres::Config::new();
    config.host(&host);
    config.port(port);
    config.user(&endpoint.username);
    if !endpoint.password.is_empty() {
        config.password(&endpoint.password);
    }
    config.dbname(database);

    let (client, connection) = config.connect(NoTls).await.map_err(postgresql_backend_error)?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            error!("postgresql backend connection error: {}", error);
        }
    });

    Ok(client)
}

fn register_endpoint_factory(
    pool: &Pool<PostgreSqlBackendConnection>,
    endpoint: &EndpointConfig,
    database: String,
) {
    let pool_key = postgresql_pool_key(endpoint, &database);
    pool.set_factory(&pool_key, PostgreSqlBackendConnection::factory(endpoint.clone(), database));
}

fn effective_database(endpoint: &EndpointConfig, session: &SessionState) -> GatewayResult<String> {
    session.database.clone().or_else(|| endpoint.database.clone()).ok_or_else(|| {
        GatewayError::Configuration(
            "postgresql backend connector requires a database to be selected".into(),
        )
    })
}

fn postgresql_pool_key(endpoint: &EndpointConfig, database: &str) -> String {
    format!("{}|{}", endpoint.address, database)
}

fn postgresql_session_attrs(session: &SessionState) -> Vec<PostgreSqlSessionAttr> {
    session
        .charset
        .as_ref()
        .map(|client_encoding| vec![PostgreSqlSessionAttr::ClientEncoding(client_encoding.clone())])
        .unwrap_or_default()
}

fn postgresql_client_encoding_statement(client_encoding: &str) -> String {
    if client_encoding.eq_ignore_ascii_case("default") {
        "SET client_encoding TO DEFAULT".into()
    } else {
        format!("SET client_encoding TO '{}'", client_encoding.replace('\'', "''"))
    }
}

fn simple_query_messages_to_gateway_response(
    messages: Vec<SimpleQueryMessage>,
) -> GatewayResult<GatewayResponse> {
    let mut columns: Vec<GatewayColumn> = Vec::new();
    let mut rows = Vec::new();
    let mut affected_rows = 0;

    for message in messages {
        match message {
            SimpleQueryMessage::Row(row) => {
                if columns.is_empty() {
                    columns = row
                        .columns()
                        .iter()
                        .map(|column| GatewayColumn {
                            name: column.name().to_string(),
                            data_type: "text".into(),
                        })
                        .collect();
                }

                let values = (0..row.len())
                    .map(|idx| {
                        row.get(idx)
                            .map(|value| GatewayValue::String(value.to_string()))
                            .unwrap_or(GatewayValue::Null)
                    })
                    .collect::<Vec<_>>();
                rows.push(values);
            }
            SimpleQueryMessage::CommandComplete(count) => affected_rows = count,
            _ => {}
        }
    }

    if !columns.is_empty() {
        Ok(GatewayResponse::ResultSet { columns, rows })
    } else {
        Ok(GatewayResponse::Ok { affected_rows, last_insert_id: None })
    }
}

fn postgresql_backend_error(error: tokio_postgres::Error) -> GatewayError {
    GatewayError::Backend(error.to_string())
}

fn parse_endpoint_address(address: &str) -> GatewayResult<(String, u16)> {
    let (host, port) = address.rsplit_once(':').ok_or_else(|| {
        GatewayError::Configuration(format!(
            "postgresql endpoint address '{}' must be host:port",
            address
        ))
    })?;
    let port = port.parse::<u16>().map_err(|error| {
        GatewayError::Configuration(format!(
            "postgresql endpoint address '{}' has invalid port: {}",
            address, error
        ))
    })?;

    if host.is_empty() {
        return Err(GatewayError::Configuration(
            "postgresql endpoint host must not be empty".into(),
        ));
    }

    Ok((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint() -> EndpointConfig {
        EndpointConfig {
            name: "analytics-primary".into(),
            protocol: ProtocolKind::PostgreSql,
            address: "127.0.0.1:5432".into(),
            database: Some("analytics".into()),
            role: EndpointRole::ReadWrite,
            username: "postgres".into(),
            password: "secret".into(),
            weight: 1,
        }
    }

    #[test]
    fn registers_endpoint_database_factory_in_pool() {
        let endpoint = endpoint();
        let connector = PostgreSqlBackendConnector::with_pool_size(vec![endpoint.clone()], 4);
        let pool_key = postgresql_pool_key(&endpoint, "analytics");

        assert_eq!(connector.pool.capacity(), 4);
        assert!(connector.pool.has_factory(&pool_key));
        assert_eq!(connector.pool.factory_endpoints(), vec![pool_key]);
    }

    #[test]
    fn registers_session_database_factory_on_demand() {
        let endpoint = endpoint();
        let connector = PostgreSqlBackendConnector::with_endpoints(vec![endpoint.clone()]);
        let session = SessionState { database: Some("reporting".into()), ..Default::default() };

        let pool_key = connector.ensure_pool_factory_for_session(&endpoint, &session).unwrap();

        assert_eq!(pool_key, postgresql_pool_key(&endpoint, "reporting"));
        assert!(connector.pool.has_factory(&postgresql_pool_key(&endpoint, "analytics")));
        assert!(connector.pool.has_factory(&pool_key));
    }

    #[test]
    fn builds_session_attrs_from_client_encoding() {
        let session = SessionState { charset: Some("LATIN1".into()), ..Default::default() };

        assert_eq!(
            postgresql_session_attrs(&session),
            vec![PostgreSqlSessionAttr::ClientEncoding("LATIN1".into())]
        );
        assert!(postgresql_session_attrs(&SessionState::default()).is_empty());
    }

    #[test]
    fn builds_client_encoding_statement() {
        assert_eq!(postgresql_client_encoding_statement("UTF8"), "SET client_encoding TO 'UTF8'");
        assert_eq!(
            postgresql_client_encoding_statement("O'HARE"),
            "SET client_encoding TO 'O''HARE'"
        );
        assert_eq!(
            postgresql_client_encoding_statement("DEFAULT"),
            "SET client_encoding TO DEFAULT"
        );
    }

    #[tokio::test]
    async fn updates_session_for_control_commands() {
        let connector = PostgreSqlBackendConnector::with_endpoints(vec![endpoint()]);
        let mut session = SessionState::default();

        assert_eq!(
            connector
                .execute(GatewayCommand::UseDatabase { database: "app".into() }, &mut session)
                .await,
            Ok(GatewayResponse::Ok { affected_rows: 0, last_insert_id: None })
        );
        assert_eq!(session.database, Some("app".into()));

        assert_eq!(
            connector.execute(GatewayCommand::Begin, &mut session).await,
            Ok(GatewayResponse::Ok { affected_rows: 0, last_insert_id: None })
        );
        assert_eq!(session.transaction_state, TransactionState::Active);

        assert_eq!(
            connector.execute(GatewayCommand::Commit, &mut session).await,
            Ok(GatewayResponse::Ok { affected_rows: 0, last_insert_id: None })
        );
        assert_eq!(session.transaction_state, TransactionState::Idle);

        assert_eq!(
            connector.execute(GatewayCommand::Ping, &mut session).await,
            Ok(GatewayResponse::Pong)
        );
        assert_eq!(
            connector.execute(GatewayCommand::Quit, &mut session).await,
            Ok(GatewayResponse::Bye)
        );
    }

    #[tokio::test]
    async fn rejects_query_with_invalid_endpoint_address() {
        let mut endpoint = endpoint();
        endpoint.address = "invalid-address".into();
        let connector = PostgreSqlBackendConnector::with_endpoints(vec![endpoint]);
        let mut session = SessionState::default();

        let result =
            connector.execute(GatewayCommand::Query { sql: "select 1".into() }, &mut session).await;

        assert_eq!(
            result,
            Err(GatewayError::Configuration(
                "postgresql endpoint address 'invalid-address' must be host:port".into()
            ))
        );
    }

    #[tokio::test]
    async fn rejects_query_without_database_selection() {
        let mut endpoint = endpoint();
        endpoint.database = None;
        let connector = PostgreSqlBackendConnector::with_endpoints(vec![endpoint]);
        let mut session = SessionState::default();

        let result =
            connector.execute(GatewayCommand::Query { sql: "select 1".into() }, &mut session).await;

        assert_eq!(
            result,
            Err(GatewayError::Configuration(
                "postgresql backend connector requires a database to be selected".into()
            ))
        );
    }

    #[tokio::test]
    async fn rejects_query_without_endpoints() {
        let connector = PostgreSqlBackendConnector::new();
        let mut session = SessionState::default();

        let result =
            connector.execute(GatewayCommand::Query { sql: "select 1".into() }, &mut session).await;

        assert_eq!(
            result,
            Err(GatewayError::Configuration(
                "postgresql backend connector has no configured endpoints".into()
            ))
        );
    }
}
