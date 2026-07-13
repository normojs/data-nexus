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
    collections::VecDeque,
    sync::{Arc, Mutex as StdMutex},
};

use async_trait::async_trait;
use gateway_core::{
    BackendConnector, Column, EndpointConfig, GatewayCommand, GatewayError, GatewayResponse,
    GatewayResult, GatewayValue, ProtocolKind, SessionState, TransactionState,
};
use postgresql_protocol::{
    decode_backend_message, encode_password_message, encode_query, encode_startup_message,
    BackendMessage, FieldDescription, StartupParameter,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};

#[derive(Clone, Debug, Default)]
pub struct PostgreSqlBackendConnector {
    endpoints: Vec<EndpointConfig>,
    pool: Arc<Mutex<VecDeque<PostgreSqlBackendConnection>>>,
    last_endpoint_label: Arc<StdMutex<Option<String>>>,
}

#[derive(Debug)]
struct PostgreSqlBackendConnection {
    endpoint_name: String,
    stream: TcpStream,
}

impl PostgreSqlBackendConnector {
    pub fn new(endpoints: Vec<EndpointConfig>) -> Self {
        Self {
            endpoints,
            pool: Arc::new(Mutex::new(VecDeque::new())),
            last_endpoint_label: Arc::new(StdMutex::new(None)),
        }
    }

    fn endpoint(&self) -> GatewayResult<&EndpointConfig> {
        self.endpoints.first().ok_or_else(|| {
            GatewayError::Configuration(
                "postgresql backend connector has no configured endpoints".into(),
            )
        })
    }
}

#[async_trait]
impl BackendConnector for PostgreSqlBackendConnector {
    fn protocol(&self) -> ProtocolKind {
        ProtocolKind::PostgreSql
    }

    fn last_endpoint_label(&self) -> Option<String> {
        self.last_endpoint_label.lock().ok().and_then(|label| label.clone())
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
            GatewayCommand::Begin => self.execute_transaction_command("BEGIN", session).await,
            GatewayCommand::Commit => self.execute_transaction_command("COMMIT", session).await,
            GatewayCommand::Rollback => {
                self.execute_transaction_command("ROLLBACK", session).await
            }
            GatewayCommand::Query { sql } => self.execute_simple_query(&sql, session).await,
            command => Err(GatewayError::Unsupported(format!(
                "postgresql backend connector is not wired to execute {:?} through GatewayCommand yet",
                command
            ))),
        }
    }
}

impl PostgreSqlBackendConnector {
    async fn execute_transaction_command(
        &self,
        sql: &str,
        session: &mut SessionState,
    ) -> GatewayResult<GatewayResponse> {
        if self.endpoints.is_empty() {
            session.transaction_state = match sql {
                "BEGIN" => TransactionState::Active,
                _ => TransactionState::Idle,
            };
            return Ok(GatewayResponse::Ok { affected_rows: 0, last_insert_id: None });
        }

        self.execute_simple_query(sql, session).await
    }

    async fn execute_simple_query(
        &self,
        sql: &str,
        session: &mut SessionState,
    ) -> GatewayResult<GatewayResponse> {
        let endpoint = self.endpoint()?;
        self.set_last_endpoint_label(endpoint.name.clone());
        let mut connection = self.acquire_connection(endpoint, session).await?;

        let response = write_query_and_read_response(&mut connection.stream, sql, session).await;
        if response.is_ok() {
            self.release_connection(connection).await;
        }

        response
    }

    async fn acquire_connection(
        &self,
        endpoint: &EndpointConfig,
        session: &mut SessionState,
    ) -> GatewayResult<PostgreSqlBackendConnection> {
        let mut pool = self.pool.lock().await;
        if let Some(position) = pool.iter().position(|conn| conn.endpoint_name == endpoint.name) {
            return pool.remove(position).ok_or_else(|| {
                GatewayError::Backend(format!(
                    "postgresql connection pool lost endpoint '{}' while leasing it",
                    endpoint.name
                ))
            });
        }
        drop(pool);

        let mut stream = TcpStream::connect(&endpoint.address).await.map_err(|error| {
            GatewayError::Backend(format!("connect postgresql backend: {}", error))
        })?;
        startup(&mut stream, endpoint, session).await?;

        Ok(PostgreSqlBackendConnection { endpoint_name: endpoint.name.clone(), stream })
    }

    async fn release_connection(&self, connection: PostgreSqlBackendConnection) {
        self.pool.lock().await.push_back(connection);
    }

    fn set_last_endpoint_label(&self, label: String) {
        if let Ok(mut last_endpoint_label) = self.last_endpoint_label.lock() {
            *last_endpoint_label = Some(label);
        }
    }
}

async fn write_query_and_read_response<S>(
    stream: &mut S,
    sql: &str,
    session: &mut SessionState,
) -> GatewayResult<GatewayResponse>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream
        .write_all(&encode_query(sql))
        .await
        .map_err(|error| GatewayError::Backend(format!("write postgresql query: {}", error)))?;
    stream
        .flush()
        .await
        .map_err(|error| GatewayError::Backend(format!("flush postgresql query: {}", error)))?;

    read_query_response(stream, session).await
}

async fn startup<S>(
    stream: &mut S,
    endpoint: &EndpointConfig,
    session: &mut SessionState,
) -> GatewayResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let database =
        session.database.clone().or_else(|| endpoint.database.clone()).unwrap_or_default();
    let mut parameters =
        vec![StartupParameter { name: "user".into(), value: endpoint.username.clone() }];
    if !database.is_empty() {
        parameters.push(StartupParameter { name: "database".into(), value: database.clone() });
    }

    stream
        .write_all(&encode_startup_message(&parameters))
        .await
        .map_err(|error| GatewayError::Backend(format!("write postgresql startup: {}", error)))?;
    stream
        .flush()
        .await
        .map_err(|error| GatewayError::Backend(format!("flush postgresql startup: {}", error)))?;

    loop {
        match read_backend_message(stream).await? {
            BackendMessage::AuthenticationOk => {}
            BackendMessage::AuthenticationCleartextPassword => {
                stream.write_all(&encode_password_message(&endpoint.password)).await.map_err(
                    |error| GatewayError::Backend(format!("write postgresql password: {}", error)),
                )?;
                stream.flush().await.map_err(|error| {
                    GatewayError::Backend(format!("flush postgresql password: {}", error))
                })?;
            }
            BackendMessage::AuthenticationMd5Password { .. } => {
                return Err(GatewayError::Unsupported(
                    "postgresql md5 authentication is not implemented yet".into(),
                ));
            }
            BackendMessage::ParameterStatus { name, value } => {
                apply_parameter_status(session, &name, &value)
            }
            BackendMessage::BackendKeyData { .. } => {}
            BackendMessage::ReadyForQuery { transaction_status } => {
                session.transaction_state = transaction_state_from_status(transaction_status);
                if !database.is_empty() {
                    session.database = Some(database);
                }
                session.user = Some(endpoint.username.clone());
                return Ok(());
            }
            BackendMessage::ErrorResponse { fields } => {
                return Err(GatewayError::Backend(format!(
                    "postgresql startup failed: {:?}",
                    error_response_to_gateway(fields)
                )));
            }
            message => {
                return Err(GatewayError::Protocol(format!(
                    "unexpected postgresql startup message {:?}",
                    message
                )));
            }
        }
    }
}

async fn read_query_response<S>(
    stream: &mut S,
    session: &mut SessionState,
) -> GatewayResult<GatewayResponse>
where
    S: AsyncRead + Unpin,
{
    let mut columns: Option<Vec<Column>> = None;
    let mut rows: Vec<Vec<GatewayValue>> = Vec::new();
    let mut command_tag: Option<String> = None;
    let mut error_response: Option<GatewayResponse> = None;

    loop {
        match read_backend_message(stream).await? {
            BackendMessage::RowDescription { fields } => {
                columns = Some(fields.iter().map(column_from_field).collect());
            }
            BackendMessage::DataRow { values } => {
                rows.push(values.into_iter().map(gateway_value_from_text).collect());
            }
            BackendMessage::CommandComplete { tag } => command_tag = Some(tag),
            BackendMessage::ErrorResponse { fields } => {
                error_response = Some(error_response_to_gateway(fields));
            }
            BackendMessage::ReadyForQuery { transaction_status } => {
                session.transaction_state = transaction_state_from_status(transaction_status);
                if let Some(error_response) = error_response {
                    return Ok(error_response);
                }
                if let Some(columns) = columns {
                    return Ok(GatewayResponse::ResultSet { columns, rows });
                }
                return Ok(GatewayResponse::Ok {
                    affected_rows: command_tag
                        .as_deref()
                        .and_then(affected_rows_from_command_tag)
                        .unwrap_or(0),
                    last_insert_id: None,
                });
            }
            BackendMessage::ParameterStatus { name, value } => {
                apply_parameter_status(session, &name, &value)
            }
            BackendMessage::BackendKeyData { .. } => {}
            message => {
                return Err(GatewayError::Protocol(format!(
                    "unexpected postgresql query response message {:?}",
                    message
                )));
            }
        }
    }
}

async fn read_backend_message<S>(stream: &mut S) -> GatewayResult<BackendMessage>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0; 5];
    stream.read_exact(&mut header).await.map_err(|error| {
        GatewayError::Backend(format!("read postgresql backend header: {}", error))
    })?;
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if len < 4 {
        return Err(GatewayError::Protocol(format!(
            "postgresql backend message has invalid length {}",
            len
        )));
    }
    let mut frame = Vec::with_capacity(1 + len);
    frame.extend_from_slice(&header);
    frame.resize(1 + len, 0);
    stream.read_exact(&mut frame[5..]).await.map_err(|error| {
        GatewayError::Backend(format!("read postgresql backend payload: {}", error))
    })?;

    decode_backend_message(&frame).map_err(|error| GatewayError::Protocol(error.to_string()))
}

fn apply_parameter_status(session: &mut SessionState, name: &str, value: &str) {
    match name {
        "client_encoding" => session.charset = Some(value.to_string()),
        _ => {}
    }
}

fn transaction_state_from_status(status: u8) -> TransactionState {
    match status {
        b'T' => TransactionState::Active,
        b'E' => TransactionState::Failed,
        _ => TransactionState::Idle,
    }
}

fn column_from_field(field: &FieldDescription) -> Column {
    Column { name: field.name.clone(), data_type: postgresql_type_name(field.type_oid).into() }
}

fn postgresql_type_name(type_oid: i32) -> &'static str {
    match type_oid {
        16 => "bool",
        17 => "bytea",
        20 => "int8",
        21 => "int2",
        23 => "int4",
        700 => "float4",
        701 => "float8",
        1043 => "varchar",
        1082 => "date",
        1083 => "time",
        1114 => "timestamp",
        1184 => "timestamptz",
        1700 => "numeric",
        _ => "text",
    }
}

fn gateway_value_from_text(value: Option<Vec<u8>>) -> GatewayValue {
    match value {
        None => GatewayValue::Null,
        Some(value) => GatewayValue::String(String::from_utf8_lossy(&value).into_owned()),
    }
}

fn affected_rows_from_command_tag(tag: &str) -> Option<u64> {
    tag.rsplit(' ').next()?.parse().ok()
}

fn error_response_to_gateway(fields: Vec<(u8, String)>) -> GatewayResponse {
    let code = fields
        .iter()
        .find_map(|(field, value)| (*field == b'C').then_some(value.clone()))
        .unwrap_or_else(|| "XX000".into());
    let message = fields
        .iter()
        .find_map(|(field, value)| (*field == b'M').then_some(value.clone()))
        .unwrap_or_else(|| "postgresql backend error".into());
    GatewayResponse::Error { code, message }
}

#[cfg(test)]
mod tests {
    use gateway_core::EndpointRole;
    use tokio::net::TcpListener;

    use super::*;

    #[tokio::test]
    async fn reports_postgresql_protocol() {
        let connector = PostgreSqlBackendConnector::new(Vec::new());

        assert_eq!(connector.protocol(), ProtocolKind::PostgreSql);
    }

    #[tokio::test]
    async fn handles_session_only_commands() {
        let connector = PostgreSqlBackendConnector::new(Vec::new());
        let mut session = SessionState::default();

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
            connector
                .execute(GatewayCommand::UseDatabase { database: "analytics".into() }, &mut session)
                .await,
            Ok(GatewayResponse::Ok { affected_rows: 0, last_insert_id: None })
        );
        assert_eq!(session.database, Some("analytics".into()));
    }

    #[tokio::test]
    async fn rejects_query_without_configured_endpoint() {
        let connector = PostgreSqlBackendConnector::new(Vec::new());
        let mut session = SessionState::default();

        let error = connector
            .execute(GatewayCommand::Query { sql: "select 1".into() }, &mut session)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            GatewayError::Configuration(message)
                if message.contains("no configured endpoints")
        ));
    }

    #[tokio::test]
    async fn executes_simple_query_against_postgresql_backend() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let startup = read_startup_frame(&mut stream).await;
            assert!(startup.ends_with(b"user\0postgres\0database\0orders\0\0"));
            write_backend_message(&mut stream, b'R', &[0, 0, 0, 0]).await;
            write_backend_message(&mut stream, b'S', b"client_encoding\0UTF8\0").await;
            write_backend_message(&mut stream, b'K', &[0, 0, 0, 42, 0, 0, 0, 7]).await;
            write_backend_message(&mut stream, b'Z', b"I").await;

            let query = read_typed_frontend_frame(&mut stream).await;
            assert_eq!(query, b"Q\0\0\0\rselect 1\0".to_vec());

            let mut row_description = Vec::new();
            push_i16(&mut row_description, 1);
            row_description.extend_from_slice(b"one\0");
            push_i32(&mut row_description, 0);
            push_i16(&mut row_description, 0);
            push_i32(&mut row_description, 23);
            push_i16(&mut row_description, 4);
            push_i32(&mut row_description, -1);
            push_i16(&mut row_description, 0);
            write_backend_message(&mut stream, b'T', &row_description).await;

            let mut data_row = Vec::new();
            push_i16(&mut data_row, 1);
            push_i32(&mut data_row, 1);
            data_row.extend_from_slice(b"1");
            write_backend_message(&mut stream, b'D', &data_row).await;
            write_backend_message(&mut stream, b'C', b"SELECT 1\0").await;
            write_backend_message(&mut stream, b'S', b"client_encoding\0LATIN1\0").await;
            write_backend_message(&mut stream, b'Z', b"T").await;
        });

        let connector = PostgreSqlBackendConnector::new(vec![endpoint(address)]);
        let mut session = SessionState::default();

        let response =
            connector.execute(GatewayCommand::Query { sql: "select 1".into() }, &mut session).await;

        assert_eq!(
            response,
            Ok(GatewayResponse::ResultSet {
                columns: vec![Column { name: "one".into(), data_type: "int4".into() }],
                rows: vec![vec![GatewayValue::String("1".into())]],
            })
        );
        assert_eq!(session.user, Some("postgres".into()));
        assert_eq!(session.database, Some("orders".into()));
        assert_eq!(session.charset, Some("LATIN1".into()));
        assert_eq!(session.transaction_state, TransactionState::Active);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn reuses_postgresql_backend_connection_across_transaction_commands() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let startup = read_startup_frame(&mut stream).await;
            assert!(startup.ends_with(b"user\0postgres\0database\0orders\0\0"));
            write_backend_message(&mut stream, b'R', &[0, 0, 0, 0]).await;
            write_backend_message(&mut stream, b'S', b"client_encoding\0UTF8\0").await;
            write_backend_message(&mut stream, b'K', &[0, 0, 0, 42, 0, 0, 0, 7]).await;
            write_backend_message(&mut stream, b'Z', b"I").await;

            let begin = read_typed_frontend_frame(&mut stream).await;
            assert_eq!(begin, b"Q\0\0\0\nBEGIN\0".to_vec());
            write_backend_message(&mut stream, b'C', b"BEGIN\0").await;
            write_backend_message(&mut stream, b'Z', b"T").await;

            let query = read_typed_frontend_frame(&mut stream).await;
            assert_eq!(query, b"Q\0\0\0\rselect 1\0".to_vec());
            write_select_one_response(&mut stream).await;
            write_backend_message(&mut stream, b'Z', b"T").await;

            let commit = read_typed_frontend_frame(&mut stream).await;
            assert_eq!(commit, b"Q\0\0\0\x0bCOMMIT\0".to_vec());
            write_backend_message(&mut stream, b'C', b"COMMIT\0").await;
            write_backend_message(&mut stream, b'Z', b"I").await;
        });

        let connector = PostgreSqlBackendConnector::new(vec![endpoint(address)]);
        let mut session = SessionState::default();

        assert_eq!(
            connector.execute(GatewayCommand::Begin, &mut session).await,
            Ok(GatewayResponse::Ok { affected_rows: 0, last_insert_id: None })
        );
        assert_eq!(session.transaction_state, TransactionState::Active);

        assert_eq!(
            connector.execute(GatewayCommand::Query { sql: "select 1".into() }, &mut session).await,
            Ok(GatewayResponse::ResultSet {
                columns: vec![Column { name: "one".into(), data_type: "int4".into() }],
                rows: vec![vec![GatewayValue::String("1".into())]],
            })
        );
        assert_eq!(session.transaction_state, TransactionState::Active);

        assert_eq!(
            connector.execute(GatewayCommand::Commit, &mut session).await,
            Ok(GatewayResponse::Ok { affected_rows: 0, last_insert_id: None })
        );
        assert_eq!(session.transaction_state, TransactionState::Idle);

        server.await.unwrap();
    }

    fn endpoint(address: String) -> EndpointConfig {
        EndpointConfig {
            name: "pg-primary".into(),
            protocol: ProtocolKind::PostgreSql,
            address,
            database: Some("orders".into()),
            username: "postgres".into(),
            password: "secret".into(),
            role: EndpointRole::ReadWrite,
            weight: 1,
        }
    }

    async fn read_startup_frame<S>(stream: &mut S) -> Vec<u8>
    where
        S: AsyncRead + Unpin,
    {
        let mut header = [0; 4];
        stream.read_exact(&mut header).await.unwrap();
        let len = u32::from_be_bytes(header) as usize;
        let mut frame = Vec::with_capacity(len);
        frame.extend_from_slice(&header);
        frame.resize(len, 0);
        stream.read_exact(&mut frame[4..]).await.unwrap();
        frame
    }

    async fn read_typed_frontend_frame<S>(stream: &mut S) -> Vec<u8>
    where
        S: AsyncRead + Unpin,
    {
        let mut header = [0; 5];
        stream.read_exact(&mut header).await.unwrap();
        let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        let mut frame = Vec::with_capacity(1 + len);
        frame.extend_from_slice(&header);
        frame.resize(1 + len, 0);
        stream.read_exact(&mut frame[5..]).await.unwrap();
        frame
    }

    async fn write_backend_message<S>(stream: &mut S, message_type: u8, payload: &[u8])
    where
        S: AsyncWrite + Unpin,
    {
        let mut frame = vec![message_type];
        frame.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
        frame.extend_from_slice(payload);
        stream.write_all(&frame).await.unwrap();
        stream.flush().await.unwrap();
    }

    async fn write_select_one_response<S>(stream: &mut S)
    where
        S: AsyncWrite + Unpin,
    {
        let mut row_description = Vec::new();
        push_i16(&mut row_description, 1);
        row_description.extend_from_slice(b"one\0");
        push_i32(&mut row_description, 0);
        push_i16(&mut row_description, 0);
        push_i32(&mut row_description, 23);
        push_i16(&mut row_description, 4);
        push_i32(&mut row_description, -1);
        push_i16(&mut row_description, 0);
        write_backend_message(stream, b'T', &row_description).await;

        let mut data_row = Vec::new();
        push_i16(&mut data_row, 1);
        push_i32(&mut data_row, 1);
        data_row.extend_from_slice(b"1");
        write_backend_message(stream, b'D', &data_row).await;
        write_backend_message(stream, b'C', b"SELECT 1\0").await;
    }

    fn push_i16(payload: &mut Vec<u8>, value: i16) {
        payload.extend_from_slice(&value.to_be_bytes());
    }

    fn push_i32(payload: &mut Vec<u8>, value: i32) {
        payload.extend_from_slice(&value.to_be_bytes());
    }
}
