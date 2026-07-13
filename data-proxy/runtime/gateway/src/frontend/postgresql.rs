use gateway_core::{GatewayError, GatewayResult, ProtocolKind, SessionState};
use postgresql_protocol::{
    decode_startup_packet, encode_authentication_ok, encode_backend_key_data,
    encode_parameter_status, encode_ready_for_query, StartupMessage, StartupPacket,
    TransactionStatus, MAX_STARTUP_PACKET_LEN,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Clone, Debug)]
pub struct PostgreSqlFrontendProtocol {
    server_version: String,
    process_id: i32,
    secret_key: i32,
}

impl PostgreSqlFrontendProtocol {
    pub fn new(server_version: String) -> Self {
        Self { server_version, process_id: 0, secret_key: 0 }
    }

    pub fn with_backend_key(server_version: String, process_id: i32, secret_key: i32) -> Self {
        Self { server_version, process_id, secret_key }
    }

    pub fn protocol(&self) -> ProtocolKind {
        ProtocolKind::PostgreSql
    }

    pub async fn handshake<S>(&self, mut stream: S) -> GatewayResult<PostgreSqlHandshake<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        loop {
            let frame = read_startup_frame(&mut stream).await?;
            match decode_startup_packet(&frame).map_err(postgresql_protocol_error)? {
                StartupPacket::SslRequest => {
                    stream
                        .write_all(b"N")
                        .await
                        .map_err(|error| postgresql_io_error("write ssl response", error))?;
                    stream
                        .flush()
                        .await
                        .map_err(|error| postgresql_io_error("flush ssl response", error))?;
                }
                StartupPacket::CancelRequest { .. } => {
                    return Err(GatewayError::Unsupported(
                        "postgresql cancel request during startup is not supported".into(),
                    ))
                }
                StartupPacket::Startup(startup) => {
                    write_handshake_response(
                        &mut stream,
                        &self.server_version,
                        self.process_id,
                        self.secret_key,
                    )
                    .await?;

                    let session = session_from_startup(&startup);
                    return Ok(PostgreSqlHandshake { stream, startup, session });
                }
            }
        }
    }
}

pub struct PostgreSqlHandshake<S> {
    pub stream: S,
    pub startup: StartupMessage,
    pub session: SessionState,
}

async fn read_startup_frame<S>(stream: &mut S) -> GatewayResult<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut len_bytes = [0; 4];
    stream
        .read_exact(&mut len_bytes)
        .await
        .map_err(|error| postgresql_io_error("read startup length", error))?;

    let len = i32::from_be_bytes(len_bytes);
    if len < 8 || len as usize > MAX_STARTUP_PACKET_LEN {
        return Err(GatewayError::Protocol(format!(
            "invalid postgresql startup packet length {}",
            len
        )));
    }

    let len = len as usize;
    let mut frame = vec![0; len];
    frame[0..4].copy_from_slice(&len_bytes);
    stream
        .read_exact(&mut frame[4..])
        .await
        .map_err(|error| postgresql_io_error("read startup body", error))?;
    Ok(frame)
}

async fn write_handshake_response<S>(
    stream: &mut S,
    server_version: &str,
    process_id: i32,
    secret_key: i32,
) -> GatewayResult<()>
where
    S: AsyncWrite + Unpin,
{
    let mut response = Vec::new();
    response.extend_from_slice(&encode_authentication_ok());
    response.extend_from_slice(&encode_parameter_status("server_version", server_version));
    response.extend_from_slice(&encode_parameter_status("server_encoding", "UTF8"));
    response.extend_from_slice(&encode_parameter_status("client_encoding", "UTF8"));
    response.extend_from_slice(&encode_parameter_status("DateStyle", "ISO, MDY"));
    response.extend_from_slice(&encode_parameter_status("integer_datetimes", "on"));
    response.extend_from_slice(&encode_backend_key_data(process_id, secret_key));
    response.extend_from_slice(&encode_ready_for_query(TransactionStatus::Idle));

    stream
        .write_all(&response)
        .await
        .map_err(|error| postgresql_io_error("write handshake response", error))?;
    stream.flush().await.map_err(|error| postgresql_io_error("flush handshake response", error))?;
    Ok(())
}

fn session_from_startup(startup: &StartupMessage) -> SessionState {
    SessionState {
        user: startup.get("user").map(ToOwned::to_owned),
        database: startup.get("database").map(ToOwned::to_owned),
        ..SessionState::default()
    }
}

fn postgresql_protocol_error(error: postgresql_protocol::ProtocolError) -> GatewayError {
    GatewayError::Protocol(error.to_string())
}

fn postgresql_io_error(context: &str, error: std::io::Error) -> GatewayError {
    GatewayError::Protocol(format!("postgresql handshake {} failed: {}", context, error))
}

#[cfg(test)]
mod tests {
    use postgresql_protocol::{encode_ssl_request, encode_startup_message};
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn handshake_accepts_startup_and_updates_session() {
        let (server, mut client) = duplex(4096);
        let protocol = PostgreSqlFrontendProtocol::with_backend_key("14.0".into(), 17, 23);

        let server_task = tokio::spawn(async move { protocol.handshake(server).await });

        client
            .write_all(&encode_startup_message(&[("user", "app"), ("database", "orders")]))
            .await
            .unwrap();

        let mut response = Vec::new();
        read_until_ready_for_query(&mut client, &mut response).await;

        let handshake = server_task.await.unwrap().unwrap();
        assert_eq!(handshake.session.user, Some("app".into()));
        assert_eq!(handshake.session.database, Some("orders".into()));
        assert!(response.starts_with(&encode_authentication_ok()));
        assert!(response
            .windows(encode_backend_key_data(17, 23).len())
            .any(|window| window == encode_backend_key_data(17, 23)));
        assert!(response.ends_with(&encode_ready_for_query(TransactionStatus::Idle)));
    }

    #[tokio::test]
    async fn handshake_declines_ssl_then_accepts_startup() {
        let (server, mut client) = duplex(4096);
        let protocol = PostgreSqlFrontendProtocol::new("14.0".into());

        let server_task = tokio::spawn(async move { protocol.handshake(server).await });

        client.write_all(&encode_ssl_request()).await.unwrap();
        let mut ssl_response = [0; 1];
        client.read_exact(&mut ssl_response).await.unwrap();
        assert_eq!(ssl_response, [b'N']);

        client.write_all(&encode_startup_message(&[("user", "app")])).await.unwrap();
        let mut response = Vec::new();
        read_until_ready_for_query(&mut client, &mut response).await;

        let handshake = server_task.await.unwrap().unwrap();
        assert_eq!(handshake.session.user, Some("app".into()));
        assert_eq!(handshake.session.database, None);
        assert!(response.ends_with(&encode_ready_for_query(TransactionStatus::Idle)));
    }

    async fn read_until_ready_for_query(
        client: &mut tokio::io::DuplexStream,
        response: &mut Vec<u8>,
    ) {
        loop {
            let mut header = [0; 5];
            client.read_exact(&mut header).await.unwrap();
            response.extend_from_slice(&header);

            let len = i32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
            let mut body = vec![0; len - 4];
            client.read_exact(&mut body).await.unwrap();
            response.extend_from_slice(&body);

            if header[0] == b'Z' {
                break;
            }
        }
    }
}
