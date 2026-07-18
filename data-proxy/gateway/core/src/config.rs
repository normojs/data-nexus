use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{GatewayError, GatewayResult, ProtocolKind};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerConfig {
    pub name: String,
    pub listen_addr: String,
    pub protocol: ProtocolKind,
    pub service: String,
    pub auth_policy: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub name: String,
    pub backend_protocol: ProtocolKind,
    pub endpoints: Vec<String>,
    pub route_policy: Option<String>,
    #[serde(default)]
    pub plugin_policies: Vec<String>,
    /// Optional named translation policy for cross-protocol access.
    /// Required (and must be enabled) when listener protocol != backend_protocol.
    #[serde(default)]
    pub translation_policy: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointConfig {
    pub name: String,
    pub protocol: ProtocolKind,
    pub address: String,
    pub database: Option<String>,
    #[serde(default)]
    pub role: EndpointRole,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default = "default_endpoint_weight")]
    pub weight: u32,
    /// A08: backend TLS mode for PostgreSQL (and future MySQL TLS).
    ///
    /// | value | meaning |
    /// |-------|---------|
    /// | `disable` (default) | plain TCP |
    /// | `prefer` | try SSLRequest; fall back to plain if server rejects |
    /// | `require` | must negotiate TLS; fail if server says no |
    #[serde(default)]
    pub ssl_mode: EndpointSslMode,
    /// A08: optional PEM file of extra CA cert(s) trusted for backend TLS.
    /// Used when `ssl_mode` is prefer/require. Production should pair with
    /// `ssl_accept_invalid_certs = false`.
    #[serde(default)]
    pub ssl_ca_file: Option<String>,
    /// A08: when true (default, MVP-compat), skip certificate / hostname
    /// verification. Set false to enforce system roots + optional `ssl_ca_file`.
    #[serde(default = "default_ssl_accept_invalid_certs")]
    pub ssl_accept_invalid_certs: bool,
}

fn default_endpoint_weight() -> u32 {
    1
}

fn default_ssl_accept_invalid_certs() -> bool {
    // Backward-compatible MVP default; pin CA via ssl_ca_file + false for prod.
    true
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            protocol: ProtocolKind::MySql,
            address: String::new(),
            database: None,
            role: EndpointRole::default(),
            username: String::new(),
            password: String::new(),
            weight: 1,
            ssl_mode: EndpointSslMode::Disable,
            ssl_ca_file: None,
            ssl_accept_invalid_certs: default_ssl_accept_invalid_certs(),
        }
    }
}

/// Backend TLS negotiation policy (A08).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum EndpointSslMode {
    #[default]
    Disable,
    Prefer,
    Require,
}

impl EndpointSslMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disable => "disable",
            Self::Prefer => "prefer",
            Self::Require => "require",
        }
    }

    pub fn wants_tls(self) -> bool {
        !matches!(self, Self::Disable)
    }

    pub fn requires_tls(self) -> bool {
        matches!(self, Self::Require)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EndpointRole {
    Read,
    ReadWrite,
}

impl Default for EndpointRole {
    fn default() -> Self {
        Self::ReadWrite
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutePolicyConfig {
    pub name: String,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthUserConfig {
    pub username: String,
    #[serde(default)]
    pub password: String,
}

/// Frontend authentication policy.
///
/// Supported kinds:
/// - `static`: validate against `users` (preferred) or single `username`/`password`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthPolicyConfig {
    pub name: String,
    pub kind: String,
    /// Single-user shorthand for static policies.
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    /// Multi-user static credentials. When non-empty, takes precedence.
    #[serde(default)]
    pub users: Vec<AuthUserConfig>,
}

impl AuthPolicyConfig {
    /// Resolve the primary static credential used by simple handshake adapters.
    pub fn primary_static_user(&self) -> Option<(String, String)> {
        if let Some(user) = self.users.first() {
            return Some((user.username.clone(), user.password.clone()));
        }
        if !self.username.is_empty() {
            return Some((self.username.clone(), self.password.clone()));
        }
        None
    }
}

/// Named governance policy referenced by `ServiceConfig.plugin_policies`.
///
/// Supported kinds:
/// - `circuit_break` / `audit`: reject SQL matching any `regex`
/// - `concurrency_control`: limit concurrent matching SQL with `max_concurrency` / `duration_secs`
/// - unknown kinds are ignored at runtime with a configuration error when rules are required
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginPolicyConfig {
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub regex: Vec<String>,
    #[serde(default)]
    pub case_insensitive: bool,
    #[serde(default)]
    pub max_concurrency: Option<u32>,
    /// Active window for concurrency control, seconds. Default 60 when kind is concurrency_control.
    #[serde(default)]
    pub duration_secs: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayConfig {
    #[serde(default)]
    pub listeners: Vec<ListenerConfig>,
    #[serde(default)]
    pub services: Vec<ServiceConfig>,
    #[serde(default)]
    pub endpoints: Vec<EndpointConfig>,
    #[serde(default)]
    pub route_policies: Vec<RoutePolicyConfig>,
    #[serde(default)]
    pub auth_policies: Vec<AuthPolicyConfig>,
    #[serde(default)]
    pub plugin_policies: Vec<PluginPolicyConfig>,
    #[serde(default)]
    pub translation_policies: Vec<crate::TranslationPolicyConfig>,
    /// Data-plane security shell (S0). Default disabled; does not change L0 behaviour.
    #[serde(default)]
    pub security: crate::SecurityPolicyConfig,
}

impl GatewayConfig {
    pub fn validate(&self) -> GatewayResult<()> {
        if self.listeners.is_empty() {
            return Err(GatewayError::Configuration(
                "gateway config must define at least one listener".into(),
            ));
        }
        if self.services.is_empty() {
            return Err(GatewayError::Configuration(
                "gateway config must define at least one service".into(),
            ));
        }
        if self.endpoints.is_empty() {
            return Err(GatewayError::Configuration(
                "gateway config must define at least one endpoint".into(),
            ));
        }

        validate_unique("listener", self.listeners.iter().map(|item| &item.name))?;
        validate_unique("service", self.services.iter().map(|item| &item.name))?;
        validate_unique("endpoint", self.endpoints.iter().map(|item| &item.name))?;
        validate_unique("route policy", self.route_policies.iter().map(|item| &item.name))?;
        validate_unique("auth policy", self.auth_policies.iter().map(|item| &item.name))?;
        validate_unique("plugin policy", self.plugin_policies.iter().map(|item| &item.name))?;
        validate_unique(
            "translation policy",
            self.translation_policies.iter().map(|item| &item.name),
        )?;

        for endpoint in &self.endpoints {
            if let Some(ca) = endpoint.ssl_ca_file.as_deref() {
                if ca.trim().is_empty() {
                    return Err(GatewayError::Configuration(format!(
                        "endpoint '{}' ssl_ca_file must be a non-empty path when set",
                        endpoint.name
                    )));
                }
            }
            if endpoint.ssl_mode == EndpointSslMode::Disable
                && (endpoint.ssl_ca_file.is_some() || !endpoint.ssl_accept_invalid_certs)
            {
                // Soft: allow config but warn via validation fail only if CA set with disable
                // (accept_invalid=false without TLS is meaningless noise — reject CA-only).
                if endpoint.ssl_ca_file.is_some() {
                    return Err(GatewayError::Configuration(format!(
                        "endpoint '{}' sets ssl_ca_file but ssl_mode=disable (TLS not used)",
                        endpoint.name
                    )));
                }
            }
        }

        let services: HashSet<&str> = self.services.iter().map(|item| item.name.as_str()).collect();
        let endpoints: HashSet<&str> =
            self.endpoints.iter().map(|item| item.name.as_str()).collect();
        let endpoint_protocols: HashMap<&str, &ProtocolKind> =
            self.endpoints.iter().map(|item| (item.name.as_str(), &item.protocol)).collect();
        let routes: HashSet<&str> =
            self.route_policies.iter().map(|item| item.name.as_str()).collect();
        let auth: HashSet<&str> =
            self.auth_policies.iter().map(|item| item.name.as_str()).collect();
        let plugins: HashSet<&str> =
            self.plugin_policies.iter().map(|item| item.name.as_str()).collect();
        let translations: HashMap<&str, &crate::TranslationPolicyConfig> = self
            .translation_policies
            .iter()
            .map(|item| (item.name.as_str(), item))
            .collect();

        for listener in &self.listeners {
            require_non_empty("listener name", &listener.name)?;
            require_non_empty("listener address", &listener.listen_addr)?;
            if !services.contains(listener.service.as_str()) {
                return Err(GatewayError::Configuration(format!(
                    "listener '{}' references missing service '{}'",
                    listener.name, listener.service
                )));
            }
            if let Some(policy) = &listener.auth_policy {
                if !auth.contains(policy.as_str()) {
                    return Err(GatewayError::Configuration(format!(
                        "listener '{}' references missing auth policy '{}'",
                        listener.name, policy
                    )));
                }
            }
            if let Some(service) =
                self.services.iter().find(|service| service.name == listener.service)
            {
                if listener.protocol != service.backend_protocol {
                    // Cross-protocol requires an explicit enabled translation_policy.
                    let policy_name = service.translation_policy.as_deref().ok_or_else(|| {
                        GatewayError::Configuration(format!(
                            "listener '{}' protocol '{}' does not match service '{}' backend protocol '{}' (set service.translation_policy and enable it)",
                            listener.name,
                            listener.protocol,
                            service.name,
                            service.backend_protocol
                        ))
                    })?;
                    let policy = translations.get(policy_name).ok_or_else(|| {
                        GatewayError::Configuration(format!(
                            "service '{}' references missing translation policy '{}'",
                            service.name, policy_name
                        ))
                    })?;
                    if !policy.enabled {
                        return Err(GatewayError::Configuration(format!(
                            "listener '{}' requires enabled translation policy '{}', but it is disabled",
                            listener.name, policy_name
                        )));
                    }
                    if policy.frontend_protocol != listener.protocol
                        || policy.backend_protocol != service.backend_protocol
                    {
                        return Err(GatewayError::Configuration(format!(
                            "translation policy '{}' is for {} -> {}, but listener/service need {} -> {}",
                            policy.name,
                            policy.frontend_protocol,
                            policy.backend_protocol,
                            listener.protocol,
                            service.backend_protocol
                        )));
                    }
                }
            }
        }

        for service in &self.services {
            require_non_empty("service name", &service.name)?;
            if service.endpoints.is_empty() {
                return Err(GatewayError::Configuration(format!(
                    "service '{}' has no endpoints",
                    service.name
                )));
            }
            for endpoint in &service.endpoints {
                if !endpoints.contains(endpoint.as_str()) {
                    return Err(GatewayError::Configuration(format!(
                        "service '{}' references missing endpoint '{}'",
                        service.name, endpoint
                    )));
                }
                let endpoint_protocol = endpoint_protocols.get(endpoint.as_str()).ok_or_else(|| {
                    GatewayError::Configuration(format!(
                        "service '{}' references missing endpoint '{}'",
                        service.name, endpoint
                    ))
                })?;
                if *endpoint_protocol != &service.backend_protocol {
                    return Err(GatewayError::Configuration(format!(
                        "service '{}' backend protocol '{}' does not match endpoint '{}' protocol '{}'",
                        service.name, service.backend_protocol, endpoint, endpoint_protocol
                    )));
                }
            }
            if let Some(policy) = &service.route_policy {
                if !routes.contains(policy.as_str()) {
                    return Err(GatewayError::Configuration(format!(
                        "service '{}' references missing route policy '{}'",
                        service.name, policy
                    )));
                }
            }
            for policy in &service.plugin_policies {
                if !plugins.contains(policy.as_str()) {
                    return Err(GatewayError::Configuration(format!(
                        "service '{}' references missing plugin policy '{}'",
                        service.name, policy
                    )));
                }
            }
            if let Some(policy) = &service.translation_policy {
                if !translations.contains_key(policy.as_str()) {
                    return Err(GatewayError::Configuration(format!(
                        "service '{}' references missing translation policy '{}'",
                        service.name, policy
                    )));
                }
            }
        }

        for endpoint in &self.endpoints {
            require_non_empty("endpoint name", &endpoint.name)?;
            require_non_empty("endpoint address", &endpoint.address)?;
        }

        self.security.validate()?;

        Ok(())
    }
}

fn validate_unique<'a>(kind: &str, names: impl Iterator<Item = &'a String>) -> GatewayResult<()> {
    let mut seen = HashSet::new();
    for name in names {
        require_non_empty(&format!("{} name", kind), name)?;
        if !seen.insert(name.as_str()) {
            return Err(GatewayError::Configuration(format!("duplicate {} '{}'", kind, name)));
        }
    }
    Ok(())
}

fn require_non_empty(field: &str, value: &str) -> GatewayResult<()> {
    if value.trim().is_empty() {
        return Err(GatewayError::Configuration(format!("{} must not be empty", field)));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> GatewayConfig {
        GatewayConfig {
            listeners: vec![ListenerConfig {
                name: "mysql-public".into(),
                listen_addr: "0.0.0.0:3306".into(),
                protocol: ProtocolKind::MySql,
                service: "orders".into(),
                auth_policy: Some("local-users".into()),
            }],
            services: vec![ServiceConfig {
                name: "orders".into(),
                backend_protocol: ProtocolKind::MySql,
                endpoints: vec!["orders-primary".into()],
                route_policy: Some("primary-only".into()),
                plugin_policies: vec!["audit".into()],
                translation_policy: None,
            }],
            endpoints: vec![EndpointConfig {
                name: "orders-primary".into(),
                protocol: ProtocolKind::MySql,
                address: "127.0.0.1:3306".into(),
                database: Some("orders".into()),
                role: EndpointRole::ReadWrite,
                username: "app".into(),
                password: "secret".into(),
                weight: 1,
                ssl_mode: Default::default(),
                ssl_ca_file: None,
                ssl_accept_invalid_certs: true,
            }],
            route_policies: vec![RoutePolicyConfig {
                name: "primary-only".into(),
                kind: "single".into(),
            }],
            auth_policies: vec![AuthPolicyConfig {
                name: "local-users".into(),
                kind: "static".into(),
                username: "app".into(),
                password: "secret".into(),
                users: vec![],
            }],
            plugin_policies: vec![PluginPolicyConfig {
                name: "audit".into(),
                kind: "audit".into(),
                regex: vec![],
                case_insensitive: false,
                max_concurrency: None,
                duration_secs: None,
            }],
            translation_policies: vec![],
            security: crate::SecurityPolicyConfig::default(),
        }
    }

    #[test]
    fn default_security_section_validates() {
        let config = config();
        assert!(!config.security.enabled);
        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn rejects_invalid_security_shell() {
        let mut config = config();
        config.security.default_audit_level = "full".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn parses_security_section_from_json_shape() {
        let security: crate::SecurityPolicyConfig = serde_json::from_str(
            r#"{
              "enabled": false,
              "fail_closed": true,
              "default_audit_level": "L0",
              "subject": { "sources": ["protocol_user"] },
              "pdp": { "backend": "local" },
              "streaming": { "window_rows": 128, "passthrough": true },
              "audit": {
                "queue_capacity": 1024,
                "overflow": "drop_new",
                "sinks": ["tracing"]
              }
            }"#,
        )
        .unwrap();
        assert!(!security.enabled);
        assert_eq!(security.streaming.window_rows, 128);
        assert_eq!(security.validate(), Ok(()));
    }

    #[test]
    fn accepts_a_complete_topology() {
        assert_eq!(config().validate(), Ok(()));
    }

    #[test]
    fn rejects_missing_references() {
        let mut config = config();
        config.listeners[0].service = "missing".into();
        assert_eq!(
            config.validate(),
            Err(GatewayError::Configuration(
                "listener 'mysql-public' references missing service 'missing'".into()
            ))
        );
    }

    #[test]
    fn rejects_service_endpoint_protocol_mismatch() {
        let mut config = config();
        config.endpoints[0].protocol = ProtocolKind::PostgreSql;

        assert_eq!(
            config.validate(),
            Err(GatewayError::Configuration(
                "service 'orders' backend protocol 'mysql' does not match endpoint 'orders-primary' protocol 'postgresql'".into()
            ))
        );
    }

    #[test]
    fn rejects_listener_backend_protocol_mismatch_without_translation_policy() {
        let mut config = config();
        config.listeners[0].protocol = ProtocolKind::PostgreSql;

        assert_eq!(
            config.validate(),
            Err(GatewayError::Configuration(
                "listener 'mysql-public' protocol 'postgresql' does not match service 'orders' backend protocol 'mysql' (set service.translation_policy and enable it)".into()
            ))
        );
    }

    #[test]
    fn accepts_cross_protocol_when_translation_policy_enabled() {
        let mut config = config();
        config.listeners[0].protocol = ProtocolKind::MySql;
        config.services[0].backend_protocol = ProtocolKind::PostgreSql;
        config.services[0].translation_policy = Some("mysql-to-pg".into());
        config.endpoints[0].protocol = ProtocolKind::PostgreSql;
        config.translation_policies = vec![crate::TranslationPolicyConfig {
            name: "mysql-to-pg".into(),
            enabled: true,
            frontend_protocol: ProtocolKind::MySql,
            backend_protocol: ProtocolKind::PostgreSql,
            allowed_statements: crate::default_allowed_statements(),
        }];

        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn rejects_cross_protocol_when_translation_policy_disabled() {
        let mut config = config();
        config.services[0].backend_protocol = ProtocolKind::PostgreSql;
        config.services[0].translation_policy = Some("mysql-to-pg".into());
        config.endpoints[0].protocol = ProtocolKind::PostgreSql;
        config.translation_policies = vec![crate::TranslationPolicyConfig {
            name: "mysql-to-pg".into(),
            enabled: false,
            frontend_protocol: ProtocolKind::MySql,
            backend_protocol: ProtocolKind::PostgreSql,
            allowed_statements: vec![],
        }];

        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("disabled"));
    }

    #[test]
    fn rejects_empty_listeners() {
        let mut config = config();
        config.listeners.clear();
        assert_eq!(
            config.validate(),
            Err(GatewayError::Configuration(
                "gateway config must define at least one listener".into()
            ))
        );
    }

    #[test]
    fn a08_ssl_fields_default_and_serde() {
        let ep: EndpointConfig = serde_json::from_str(
            r#"{
              "name": "pg",
              "protocol": "postgresql",
              "address": "127.0.0.1:5432",
              "username": "u",
              "password": "p",
              "ssl_mode": "require",
              "ssl_ca_file": "/etc/ssl/certs/pg-ca.pem",
              "ssl_accept_invalid_certs": false
            }"#,
        )
        .unwrap();
        assert_eq!(ep.ssl_mode, EndpointSslMode::Require);
        assert_eq!(ep.ssl_ca_file.as_deref(), Some("/etc/ssl/certs/pg-ca.pem"));
        assert!(!ep.ssl_accept_invalid_certs);

        let bare: EndpointConfig = serde_json::from_str(
            r#"{
              "name": "pg",
              "protocol": "postgresql",
              "address": "127.0.0.1:5432"
            }"#,
        )
        .unwrap();
        assert_eq!(bare.ssl_mode, EndpointSslMode::Disable);
        assert!(bare.ssl_ca_file.is_none());
        assert!(bare.ssl_accept_invalid_certs);
    }

    #[test]
    fn a08_rejects_ssl_ca_file_when_tls_disabled() {
        let mut config = config();
        config.endpoints[0].ssl_mode = EndpointSslMode::Disable;
        config.endpoints[0].ssl_ca_file = Some("/tmp/ca.pem".into());
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("ssl_ca_file") && err.to_string().contains("disable"),
            "{err}"
        );
    }

    #[test]
    fn a08_accepts_ssl_ca_file_with_require() {
        let mut config = config();
        // Keep topology consistent: mysql listener/service/endpoint.
        config.endpoints[0].ssl_mode = EndpointSslMode::Require;
        config.endpoints[0].ssl_ca_file = Some("/tmp/ca.pem".into());
        config.endpoints[0].ssl_accept_invalid_certs = false;
        assert_eq!(config.validate(), Ok(()));
    }
}
