//! Lightweight Admin API authorization (management plane only).
//!
//! Not a data-plane / table-level RBAC. When `enabled` is false, callers treat
//! auth as disabled (dev-compatible).

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{GatewayError, GatewayResult};

/// Built-in management roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminRole {
    Viewer,
    Operator,
    Admin,
}

impl AdminRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Operator => "operator",
            Self::Admin => "admin",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "viewer" | "view" | "readonly" | "read_only" => Some(Self::Viewer),
            "operator" | "ops" | "sre" => Some(Self::Operator),
            "admin" | "administrator" | "root" => Some(Self::Admin),
            _ => None,
        }
    }

    pub fn permissions(self) -> HashSet<AdminPermission> {
        use AdminPermission::*;
        match self {
            Self::Viewer => HashSet::from([TopologyRead, RuntimeRead, MetricsRead]),
            Self::Operator => HashSet::from([
                TopologyRead,
                RuntimeRead,
                MetricsRead,
                RuntimeRefresh,
                ListenerControl,
            ]),
            Self::Admin => HashSet::from([
                TopologyRead,
                RuntimeRead,
                MetricsRead,
                RuntimeRefresh,
                ListenerControl,
                ListenerWrite,
                PolicyWrite,
                ConfigReload,
            ]),
        }
    }
}

/// Atomic Admin API permissions (resource:action).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminPermission {
    TopologyRead,
    RuntimeRead,
    RuntimeRefresh,
    ListenerControl,
    ListenerWrite,
    PolicyWrite,
    ConfigReload,
    MetricsRead,
}

impl AdminPermission {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TopologyRead => "topology:read",
            Self::RuntimeRead => "runtime:read",
            Self::RuntimeRefresh => "runtime:refresh",
            Self::ListenerControl => "listener:control",
            Self::ListenerWrite => "listener:write",
            Self::PolicyWrite => "policy:write",
            Self::ConfigReload => "config:reload",
            Self::MetricsRead => "metrics:read",
        }
    }
}

/// How Admin API authenticates callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AdminAuthMode {
    /// No API auth (current default / local dev).
    #[default]
    None,
    /// HS256 JWT with shared secret (tests + simple break-glass).
    JwtHmac,
}

/// Admin API auth configuration (management plane).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminAuthConfig {
    /// Master switch. False keeps legacy open Admin API.
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: AdminAuthMode,
    /// HS256 secret when mode = jwt_hmac.
    #[serde(default)]
    pub jwt_secret: String,
    /// Expected `iss` claim (optional).
    #[serde(default)]
    pub issuer: String,
    /// Expected `aud` claim (optional).
    #[serde(default)]
    pub audience: String,
    /// Clock skew seconds for exp/nbf.
    #[serde(default = "default_leeway_secs")]
    pub leeway_secs: u64,
    /// Claim paths (dot notation) that may hold role/group strings.
    #[serde(default = "default_role_claim_paths")]
    pub role_claim_paths: Vec<String>,
    /// IdP group/role string → built-in AdminRole name (`viewer`/`operator`/`admin`).
    #[serde(default)]
    pub role_bindings: HashMap<String, String>,
    /// When true, GET /metrics skips auth (Prometheus scrape).
    #[serde(default = "default_true")]
    pub public_metrics: bool,
    /// Role for break-glass password tokens (future login endpoint).
    #[serde(default = "default_break_glass_role")]
    pub break_glass_role: String,
}

fn default_leeway_secs() -> u64 {
    60
}

fn default_role_claim_paths() -> Vec<String> {
    vec![
        "roles".into(),
        "groups".into(),
        "realm_access.roles".into(),
    ]
}

fn default_true() -> bool {
    true
}

fn default_break_glass_role() -> String {
    "admin".into()
}

impl Default for AdminAuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: AdminAuthMode::None,
            jwt_secret: String::new(),
            issuer: String::new(),
            audience: String::new(),
            leeway_secs: default_leeway_secs(),
            role_claim_paths: default_role_claim_paths(),
            role_bindings: default_role_bindings(),
            public_metrics: true,
            break_glass_role: default_break_glass_role(),
        }
    }
}

fn default_role_bindings() -> HashMap<String, String> {
    let mut map = HashMap::new();
    map.insert("data-nexus-viewers".into(), "viewer".into());
    map.insert("data-nexus-operators".into(), "operator".into());
    map.insert("data-nexus-admins".into(), "admin".into());
    map.insert("viewer".into(), "viewer".into());
    map.insert("operator".into(), "operator".into());
    map.insert("admin".into(), "admin".into());
    map
}

impl AdminAuthConfig {
    pub fn validate(&self) -> GatewayResult<()> {
        if !self.enabled {
            return Ok(());
        }
        match self.mode {
            AdminAuthMode::None => Err(GatewayError::Configuration(
                "admin_auth.enabled=true requires mode != none (use jwt_hmac)".into(),
            )),
            AdminAuthMode::JwtHmac => {
                if self.jwt_secret.trim().is_empty() {
                    return Err(GatewayError::Configuration(
                        "admin_auth.jwt_secret is required when mode=jwt_hmac".into(),
                    ));
                }
                if self.jwt_secret.len() < 16 {
                    return Err(GatewayError::Configuration(
                        "admin_auth.jwt_secret must be at least 16 characters".into(),
                    ));
                }
                Ok(())
            }
        }
    }

    /// Resolve built-in roles from raw IdP claim strings.
    pub fn map_claim_values(&self, values: &[String]) -> Vec<AdminRole> {
        let mut roles = HashSet::new();
        for value in values {
            let key = value.trim().to_ascii_lowercase();
            if key.is_empty() {
                continue;
            }
            // Direct built-in name.
            if let Some(role) = AdminRole::parse(&key) {
                roles.insert(role);
                continue;
            }
            // Binding table (case-insensitive keys).
            for (binding, role_name) in &self.role_bindings {
                if binding.eq_ignore_ascii_case(&key) {
                    if let Some(role) = AdminRole::parse(role_name) {
                        roles.insert(role);
                    }
                }
            }
        }
        let mut list: Vec<_> = roles.into_iter().collect();
        list.sort_by_key(|r| match r {
            AdminRole::Viewer => 0,
            AdminRole::Operator => 1,
            AdminRole::Admin => 2,
        });
        list
    }

    pub fn permissions_for_roles(roles: &[AdminRole]) -> HashSet<AdminPermission> {
        let mut set = HashSet::new();
        for role in roles {
            set.extend(role.permissions());
        }
        set
    }
}

/// Authenticated Admin caller (after JWT validation + mapping).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdminAuthContext {
    pub subject: String,
    pub roles: Vec<AdminRole>,
    pub permissions: Vec<AdminPermission>,
    pub auth_method: String,
}

impl AdminAuthContext {
    pub fn from_roles(subject: impl Into<String>, roles: Vec<AdminRole>, auth_method: &str) -> Self {
        let permissions: Vec<_> = AdminAuthConfig::permissions_for_roles(&roles)
            .into_iter()
            .collect();
        Self {
            subject: subject.into(),
            roles,
            permissions,
            auth_method: auth_method.to_owned(),
        }
    }

    pub fn allows(&self, permission: AdminPermission) -> bool {
        self.permissions.contains(&permission)
    }
}

/// Required permission for a method + path (Admin routes only).
pub fn required_permission(method: &str, path: &str) -> Option<AdminPermission> {
    let method = method.to_ascii_uppercase();
    let path = path.trim_end_matches('/');
    // Normalize path without query.
    let path = path.split('?').next().unwrap_or(path);

    if path == "/admin/me" || path == "/admin/auth/config" {
        // me: any authenticated; auth/config: public (handled by caller).
        return None;
    }

    match (method.as_str(), path) {
        ("GET", "/admin") | ("GET", "/admin/") => Some(AdminPermission::TopologyRead),
        ("GET", "/admin/config") | ("GET", "/config") => Some(AdminPermission::TopologyRead),
        ("GET", "/admin/listeners") => Some(AdminPermission::TopologyRead),
        ("GET", "/admin/services") => Some(AdminPermission::TopologyRead),
        ("GET", "/admin/endpoints") => Some(AdminPermission::TopologyRead),
        ("GET", "/admin/pools") => Some(AdminPermission::RuntimeRead),
        ("GET", "/admin/sessions") => Some(AdminPermission::RuntimeRead),
        ("POST", "/admin/reload") => Some(AdminPermission::ConfigReload),
        ("POST", "/admin/pools/refresh") => Some(AdminPermission::RuntimeRefresh),
        ("POST", p) if p.starts_with("/admin/pools/") && p.ends_with("/refresh") => {
            Some(AdminPermission::RuntimeRefresh)
        }
        ("POST", p) if p.starts_with("/admin/listeners/") && p.ends_with("/stop") => {
            Some(AdminPermission::ListenerControl)
        }
        ("POST", "/admin/listeners") => Some(AdminPermission::ListenerWrite),
        ("PUT", p) if p.starts_with("/admin/route-policies/") => Some(AdminPermission::PolicyWrite),
        ("GET", "/metrics") => Some(AdminPermission::MetricsRead),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_disabled_validates() {
        let cfg = AdminAuthConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.validate(), Ok(()));
    }

    #[test]
    fn enabled_hmac_requires_secret() {
        let mut cfg = AdminAuthConfig::default();
        cfg.enabled = true;
        cfg.mode = AdminAuthMode::JwtHmac;
        assert!(cfg.validate().is_err());
        cfg.jwt_secret = "short".into();
        assert!(cfg.validate().is_err());
        cfg.jwt_secret = "long-enough-secret!".into();
        assert_eq!(cfg.validate(), Ok(()));
    }

    #[test]
    fn maps_bindings_and_unions_permissions() {
        let cfg = AdminAuthConfig::default();
        let roles = cfg.map_claim_values(&[
            "data-nexus-viewers".into(),
            "data-nexus-operators".into(),
        ]);
        assert!(roles.contains(&AdminRole::Viewer));
        assert!(roles.contains(&AdminRole::Operator));
        let perms = AdminAuthConfig::permissions_for_roles(&roles);
        assert!(perms.contains(&AdminPermission::TopologyRead));
        assert!(perms.contains(&AdminPermission::RuntimeRefresh));
        assert!(!perms.contains(&AdminPermission::ConfigReload));
    }

    #[test]
    fn route_permission_table() {
        assert_eq!(
            required_permission("GET", "/admin/listeners"),
            Some(AdminPermission::TopologyRead)
        );
        assert_eq!(
            required_permission("POST", "/admin/reload"),
            Some(AdminPermission::ConfigReload)
        );
        assert_eq!(
            required_permission("POST", "/admin/listeners/x/stop"),
            Some(AdminPermission::ListenerControl)
        );
        assert_eq!(required_permission("GET", "/admin/me"), None);
        assert_eq!(required_permission("GET", "/healthz"), None);
    }
}
