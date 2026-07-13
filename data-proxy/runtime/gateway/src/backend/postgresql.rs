use std::sync::Arc;

use async_trait::async_trait;
use gateway_core::{
    BackendConnector, Column as GatewayColumn, EndpointConfig, GatewayCommand, GatewayError,
    GatewayResponse, GatewayResult, GatewayValue, ProtocolKind, SessionState, TransactionState,
};
use parking_lot::Mutex;
use tokio_postgres::{NoTls, SimpleQueryMessage};
use tracing::error;

#[derive(Clone, Debug, Default)]
pub struct PostgreSqlBackendConnector {
    endpoints: Arc<Mutex<Vec<EndpointConfig>>>,
}

impl PostgreSqlBackendConnector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_endpoints(endpoints: Vec<EndpointConfig>) -> Self {
        Self { endpoints: Arc::new(Mutex::new(endpoints)) }
    }

    pub fn endpoints(&self) -> Vec<EndpointConfig> {
        self.endpoints.lock().clone()
    }

    fn select_endpoint(&self) -> GatewayResult<EndpointConfig> {
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
        let client = connect_endpoint(&endpoint, session).await?;
        let messages = client.simple_query(sql).await.map_err(postgresql_backend_error)?;
        simple_query_messages_to_gateway_response(messages)
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
                let endpoint = self.select_endpoint()?;
                self.execute_simple_query(endpoint, &sql, session).await
            }
            command => Err(GatewayError::Unsupported(format!(
                "postgresql backend connector cannot execute {:?} yet",
                command
            ))),
        }
    }
}

async fn connect_endpoint(
    endpoint: &EndpointConfig,
    session: &SessionState,
) -> GatewayResult<tokio_postgres::Client> {
    let (host, port) = parse_endpoint_address(&endpoint.address)?;
    let database =
        session.database.as_deref().or(endpoint.database.as_deref()).ok_or_else(|| {
            GatewayError::Configuration(
                "postgresql backend connector requires a database to be selected".into(),
            )
        })?;

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
            username: "postgres".into(),
            password: "secret".into(),
            weight: 1,
        }
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
