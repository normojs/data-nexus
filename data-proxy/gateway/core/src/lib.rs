//! Protocol-neutral contracts for the Data Nexus gateway.
//!
//! This crate intentionally has no dependency on a wire protocol, SQL parser,
//! connection pool, or runtime implementation. Protocol adapters and backend
//! connectors meet at these types instead.

mod admin_auth;
mod config;
mod dialect;
mod error;
mod model;
mod plugin;
mod route;
mod sharding;
mod translation;
mod transport;
mod types;

pub use admin_auth::{
    required_permission, AdminAuthConfig, AdminAuthContext, AdminAuthMode, AdminPermission,
    AdminRole,
};
pub use config::{
    AuthPolicyConfig, AuthUserConfig, EndpointConfig, EndpointRole, GatewayConfig, ListenerConfig,
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
pub use sharding::{ShardingPlanner, UnsupportedShardingPlanner};
pub use translation::{
    check_translation_sql, default_allowed_statements, map_response_types,
    prepare_cross_protocol_command, rewrite_sql_for_backend, TranslationPolicyConfig,
    TranslationStatementKind,
};
pub use transport::{BackendConnector, FrontendProtocolAdapter};
pub use types::{map_column_type, parse_backend_type, CanonicalDataType};
