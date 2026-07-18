//! Protocol-neutral contracts for the Data Nexus gateway.
//!
//! This crate intentionally has no dependency on a wire protocol, SQL parser,
//! connection pool, or runtime implementation. Protocol adapters and backend
//! connectors meet at these types instead.

mod admin_auth;
mod audit;
mod audit_index;
#[cfg(feature = "audit-opendal")]
mod audit_opendal;
mod audit_pipeline;
#[cfg(feature = "security-cedar")]
mod cedar_pdp;
mod config;
mod dialect;
mod error;
mod model;
mod object_set;
mod obligations;
mod pdp;
mod plugin;
mod policy_file;
mod route;
mod security;
mod sharding;
mod state_crypto;
mod ticket;
mod time_rules;
mod translation;
mod transport;
mod types;
mod vault;

pub use admin_auth::{
    required_permission, AdminAuthConfig, AdminAuthContext, AdminAuthMode, AdminPermission,
    AdminRole,
};
pub use audit::{
    fields as audit_fields, apply_audit_level_payload, AuditAction, AuditDecision, AuditEvent,
    AuditLevel, AUDIT_TARGET,
};
pub use audit_index::{AuditIndex, AuditQueryFilter};
#[cfg(feature = "audit-opendal")]
pub use audit_opendal::OpendalArchive;
pub use audit_pipeline::{
    data_plane_event, global_audit_pipeline, install_audit_pipeline, set_audit_process_latency_hook,
    try_audit, AuditPipeline, AuditPipelineStats,
};
#[cfg(feature = "security-cedar")]
pub use cedar_pdp::{
    global_cedar_store, install_cedar_store, reload_global_cedar, CedarEngine, CedarPolicyStore,
    CedarReloadInfo, CedarStatus,
};
pub use config::{
    AuthPolicyConfig, AuthUserConfig, EndpointConfig, EndpointRole, EndpointSslMode, GatewayConfig, ListenerConfig,
    PluginPolicyConfig, RoutePolicyConfig, ServiceConfig,
};
pub use object_set::{ColumnAclOutcome, ObjectAccess, ObjectSet, StarPolicy};
pub use obligations::{
    apply_masks_to_rows, apply_obligations_to_response, apply_obligations_windowed,
    apply_watermark_to_resultset, build_mask_index, inject_row_filter, mask_gateway_value,
    MaskAlgorithm, MaskSpec, Obligations, WatermarkMode, WatermarkSpec,
};
pub use pdp::{
    action_from_command, extract_table_names, global_local_pdp_store, install_local_pdp,
    reload_global_local_pdp, security_local_pdp_hot_reloadable_only,
    security_requires_listener_rebuild, sql_from_command, AccessRequest, LocalPdp,
    LocalPdpReloadInfo, LocalPdpStore, SecurityDecision, StatementAction, Subject,
};
pub use policy_file::{
    load_local_pdp_policy_file, merge_local_pdp_from_file, persist_local_pdp_to_file,
    save_local_pdp_policy_file, LocalPdpPolicyFile,
};
pub use security::{
    SecurityAuditConfig, SecurityColumnTagConfig, SecurityHighRiskRuleConfig,
    SecurityMaskRuleConfig, SecurityPdpConfig, SecurityPolicyConfig, SecurityRuleConfig,
    SecurityStateConfig, SecurityStreamingConfig, SecuritySubjectConfig, SecurityWatermarkConfig,
};
pub use state_crypto::{
    decode_maybe_encrypted, decrypt_blob, encrypt_blob, parse_encrypt_key,
};
pub use time_rules::{
    is_inside_window, parse_hhmm, security_now_unix_secs, SecurityTimeRuleConfig,
};
pub use ticket::{
    extract_ticket_id, global_ticket_store, install_ticket_store, is_write_without_where,
    sql_fingerprint,
    strip_ticket_comment, ApproveTicketRequest, IssueTicketRequest, RejectTicketRequest, Ticket,
    TicketStatus, TicketStore,
};
pub use vault::{
    global_vault_store, install_vault_store, IssueVaultLeaseRequest, ProjectEnv,
    RenewVaultLeaseRequest,
    RevokeVaultLeaseRequest, VaultLease, VaultStore,
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
    write_resultset_windowed, write_resultset_windowed_with_obligations, write_streaming_query_with_obligations,
    StreamingEncodeStats,
    write_wire_relay, BackendConnector, CollectingWriter, ExecuteOutcome, FrontendProtocolAdapter,
    ResponseWriter, RowStream, StreamingQuery, VecRowStream, WireRelay, WireStream,
};
pub use types::{map_column_type, parse_backend_type, CanonicalDataType};
