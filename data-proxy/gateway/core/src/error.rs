use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GatewayError {
    #[error("configuration error: {0}")]
    Configuration(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("backend error: {0}")]
    Backend(String),
    #[error("unsupported operation: {0}")]
    Unsupported(String),
}

pub type GatewayResult<T> = Result<T, GatewayError>;
