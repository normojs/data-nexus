//! Protocol-neutral contracts for the Data Nexus gateway.
//!
//! This crate intentionally has no dependency on a wire protocol, SQL parser,
//! connection pool, or runtime implementation. Protocol adapters and backend
//! connectors meet at these types instead.

mod admin_auth;
mod audit;
mod audit_pipeline;
mod config;
mod dialect;
mod error;
mod model;
mod object_set;
mod obligations;
mod pdp;
mod plugin;
mod route;
mod security;
mod sharding;
mod ticket;
mod translation;
mod transport;
mod types;

pub use admin_auth::{
    required_permission, AdminAuthConfig, AdminAuthContext, AdminAuthMode, AdminPermission,
    AdminRole,
};
pub use audit::{
    fields as audit_fields, AuditAction, AuditDecision, AuditEvent, AuditLevel, AUDIT_TARGET,
};
pub use audit_pipeline::{
    data_plane_event, global_audit_pipeline, install_audit_pipeline, try_audit, AuditPipeline,
    AuditPipelineStats,
};
pub use config::{
    AuthPolicyConfig, AuthUserConfig, EndpointConfig, EndpointRole, GatewayConfig, ListenerConfig,
    PluginPolicyConfig, RoutePolicyConfig, ServiceConfig,
};
pub use object_set::{ColumnAclOutcome, ObjectAccess, ObjectSet, StarPolicy};
pub use obligations::{
    apply_obligations_to_response, inject_row_filter, mask_gateway_value, MaskAlgorithm, MaskSpec,
    Obligations,
};
pub use pdp::{
    action_from_command, extract_table_names, sql_from_command, AccessRequest, LocalPdp,
    SecurityDecision, StatementAction, Subject,
};
pub use security::{
    SecurityAuditConfig, SecurityColumnTagConfig, SecurityHighRiskRuleConfig,
    SecurityMaskRuleConfig, SecurityPdpConfig, SecurityPolicyConfig, SecurityRuleConfig,
    SecurityStreamingConfig, SecuritySubjectConfig,
};
pub use ticket::{
    extract_ticket_id, global_ticket_store, is_write_without_where, sql_fingerprint,
    strip_ticket_comment, IssueTicketRequest, Ticket, TicketStore,
};
pub use dialect::{default_dialect_parser, DialectParser, HeuristicDialectParser};
pub use error::{GatewayError, GatewayResult};
pub use model::{
    Column, ExecuteMode, GatewayCommand, GatewayResponse, GatewayValue, ProtocolKind, SessionState,
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
pub use transport::{
    write_resultset_windowed, BackendConnector, CollectingWriter, FrontendProtocolAdapter,
    ResponseWriter,
};
pub use types::{map_column_type, parse_backend_type, CanonicalDataType};
