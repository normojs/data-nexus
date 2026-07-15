//! Protocol-neutral contracts for the Data Nexus gateway.
//!
//! This crate intentionally has no dependency on a wire protocol, SQL parser,
//! connection pool, or runtime implementation. Protocol adapters and backend
//! connectors meet at these types instead.

mod config;
mod dialect;
mod error;
mod model;
mod plugin;
mod route;
mod transport;

pub use config::{
    AuthPolicyConfig, EndpointConfig, EndpointRole, GatewayConfig, ListenerConfig,
    PluginPolicyConfig, RoutePolicyConfig, ServiceConfig,
};
pub use dialect::{default_dialect_parser, DialectParser, HeuristicDialectParser};
pub use error::{GatewayError, GatewayResult};
pub use model::{
    Column, GatewayCommand, GatewayResponse, GatewayValue, ProtocolKind, SessionState,
    TransactionState,
};
pub use plugin::{CommandSummary, PluginContext, PluginDecision};
pub use route::{EndpointRef, RoutePlan, ShardTarget};
pub use transport::{BackendConnector, FrontendProtocolAdapter};
