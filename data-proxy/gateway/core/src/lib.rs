//! Protocol-neutral contracts for the Data Nexus gateway.
//!
//! This crate intentionally has no dependency on a wire protocol, SQL parser,
//! connection pool, or runtime implementation. Protocol adapters and backend
//! connectors meet at these types instead.

mod config;
mod error;
mod model;
mod transport;

pub use config::{
    AuthPolicyConfig, AuthPolicyUserConfig, EndpointConfig, EndpointRole, GatewayConfig,
    ListenerConfig, PluginPolicyConfig, RoutePolicyConfig, ServiceConfig,
};
pub use error::{GatewayError, GatewayResult};
pub use model::{
    Column, GatewayCommand, GatewayResponse, GatewayValue, ProtocolKind, SessionState,
    TransactionState,
};
pub use transport::{BackendConnector, FrontendProtocolAdapter};
