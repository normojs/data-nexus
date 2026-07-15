//! Admin API authentication helpers (JWT HS256 + role mapping).
//!
//! Management-plane only. When `AdminAuthConfig.enabled` is false, checks are skipped.

use std::collections::HashSet;

use gateway_core::{
    required_permission, AdminAuthConfig, AdminAuthContext, AdminAuthMode, AdminPermission,
    AdminRole,
};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize)]
pub struct AdminMeResponse {
    pub subject: String,
    pub roles: Vec<&'static str>,
    pub permissions: Vec<&'static str>,
    pub auth_method: String,
    pub auth_enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminAuthPublicConfig {
    pub enabled: bool,
    pub mode: &'static str,
    pub public_metrics: bool,
    pub break_glass_login: bool,
}

impl From<&AdminAuthConfig> for AdminAuthPublicConfig {
    fn from(config: &AdminAuthConfig) -> Self {
        Self {
            enabled: config.enabled,
            mode: match config.mode {
                AdminAuthMode::None => "none",
                AdminAuthMode::JwtHmac => "jwt_hmac",
            },
            public_metrics: config.public_metrics,
            break_glass_login: config.break_glass_enabled(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdminLoginRequest {
    pub password: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminLoginResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub roles: Vec<&'static str>,
}

/// Exchange break-glass password for a short-lived HS256 JWT.
pub fn break_glass_login(
    config: &AdminAuthConfig,
    password: &str,
) -> Result<AdminLoginResponse, AdminAuthError> {
    if !config.break_glass_enabled() {
        return Err(AdminAuthError::Unauthorized(
            "break-glass password login is not configured".into(),
        ));
    }
    if password != config.break_glass_password {
        return Err(AdminAuthError::Unauthorized("invalid password".into()));
    }
    let role = config.break_glass_role_parsed();
    let ttl = config.token_ttl_secs.max(60);
    let token = issue_hmac_token(config, "break-glass", &[role], ttl as i64)?;
    Ok(AdminLoginResponse {
        access_token: token,
        token_type: "Bearer",
        expires_in: ttl,
        roles: vec![role.as_str()],
    })
}

#[derive(Debug)]
pub enum AdminAuthError {
    Unauthorized(String),
    Forbidden(String),
    Misconfigured(String),
}

impl AdminAuthError {
    pub fn status(&self) -> axum::http::StatusCode {
        match self {
            Self::Unauthorized(_) => axum::http::StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => axum::http::StatusCode::FORBIDDEN,
            Self::Misconfigured(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::Unauthorized(_) => "unauthorized",
            Self::Forbidden(_) => "forbidden",
            Self::Misconfigured(_) => "auth_misconfigured",
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Unauthorized(m) | Self::Forbidden(m) | Self::Misconfigured(m) => m.as_str(),
        }
    }
}

#[derive(Debug, Serialize)]
struct IssuedClaims {
    sub: String,
    exp: i64,
    iat: i64,
    nbf: i64,
    roles: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
}

/// Issue a short-lived HS256 admin token (tests + break-glass).
pub fn issue_hmac_token(
    config: &AdminAuthConfig,
    subject: &str,
    roles: &[AdminRole],
    ttl_secs: i64,
) -> Result<String, AdminAuthError> {
    if config.jwt_secret.is_empty() {
        return Err(AdminAuthError::Misconfigured("jwt_secret is empty".into()));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let claims = IssuedClaims {
        sub: subject.to_owned(),
        iat: now,
        nbf: now,
        exp: now + ttl_secs.max(60),
        roles: roles.iter().map(|r| r.as_str().to_owned()).collect(),
        iss: (!config.issuer.is_empty()).then(|| config.issuer.clone()),
        aud: (!config.audience.is_empty()).then(|| config.audience.clone()),
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
    )
    .map_err(|e| AdminAuthError::Misconfigured(format!("encode jwt: {e}")))
}

/// Authenticate an Authorization header value for Admin API.
pub fn authenticate_request(
    config: &AdminAuthConfig,
    authorization: Option<&str>,
    method: &str,
    path: &str,
) -> Result<Option<AdminAuthContext>, AdminAuthError> {
    // Public discovery / login endpoints.
    if path_is_public_auth_path(path) {
        return Ok(None);
    }

    if !config.enabled {
        return Ok(None);
    }

    // Metrics may stay public for Prometheus scrape.
    if config.public_metrics && is_metrics_path(path) && method.eq_ignore_ascii_case("GET") {
        return Ok(None);
    }

    let token = extract_bearer(authorization).ok_or_else(|| {
        AdminAuthError::Unauthorized("missing or invalid Authorization Bearer token".into())
    })?;

    let ctx = validate_hmac_token(config, token)?;
    if let Some(required) = required_permission(method, path) {
        if !ctx.allows(required) {
            return Err(AdminAuthError::Forbidden(format!(
                "missing permission {}",
                required.as_str()
            )));
        }
    }
    // Authenticated but no mapped roles → forbid protected routes that need any permission.
    if ctx.roles.is_empty() && required_permission(method, path).is_some() {
        return Err(AdminAuthError::Forbidden(
            "no mapped admin role in token claims".into(),
        ));
    }
    Ok(Some(ctx))
}

fn path_is_public_auth_path(path: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path).trim_end_matches('/');
    path == "/admin/auth/config" || path == "/admin/auth/login"
}

fn is_metrics_path(path: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path).trim_end_matches('/');
    path == "/metrics"
}

fn extract_bearer(authorization: Option<&str>) -> Option<&str> {
    let value = authorization?.trim();
    let token = value.strip_prefix("Bearer ").or_else(|| value.strip_prefix("bearer "))?;
    let token = token.trim();
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

fn validate_hmac_token(config: &AdminAuthConfig, token: &str) -> Result<AdminAuthContext, AdminAuthError> {
    if !matches!(config.mode, AdminAuthMode::JwtHmac) {
        return Err(AdminAuthError::Misconfigured(
            "admin auth enabled with unsupported mode".into(),
        ));
    }

    let mut validation = Validation::new(Algorithm::HS256);
    validation.leeway = config.leeway_secs;
    validation.validate_exp = true;
    if config.issuer.is_empty() {
        validation.set_required_spec_claims(&["exp", "sub"]);
    } else {
        validation.set_issuer(&[config.issuer.as_str()]);
        validation.set_required_spec_claims(&["exp", "sub", "iss"]);
    }
    if config.audience.is_empty() {
        validation.validate_aud = false;
    } else {
        validation.set_audience(&[config.audience.as_str()]);
    }

    let data = decode::<Value>(
        token,
        &DecodingKey::from_secret(config.jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|e| AdminAuthError::Unauthorized(format!("invalid token: {e}")))?;

    let claims = data.claims;
    let subject = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    if subject.is_empty() {
        return Err(AdminAuthError::Unauthorized("token missing sub".into()));
    }

    let raw_roles = collect_role_strings(&claims, &config.role_claim_paths);
    let roles = config.map_claim_values(&raw_roles);
    Ok(AdminAuthContext::from_roles(subject, roles, "jwt_hmac"))
}

fn collect_role_strings(claims: &Value, paths: &[String]) -> Vec<String> {
    let mut out = HashSet::new();
    for path in paths {
        if let Some(value) = dig_claim(claims, path) {
            push_strings(value, &mut out);
        }
    }
    // Always also scan top-level roles/groups for convenience.
    for key in ["roles", "groups"] {
        if let Some(value) = claims.get(key) {
            push_strings(value, &mut out);
        }
    }
    out.into_iter().collect()
}

fn dig_claim<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = value;
    for part in path.split('.') {
        cur = cur.get(part)?;
    }
    Some(cur)
}

fn push_strings(value: &Value, out: &mut HashSet<String>) {
    match value {
        Value::String(s) => {
            if !s.trim().is_empty() {
                out.insert(s.clone());
            }
        }
        Value::Array(items) => {
            for item in items {
                push_strings(item, out);
            }
        }
        Value::Object(map) => {
            // Keycloak-style { "roles": [...] } nested under realm_access already handled by path.
            if let Some(roles) = map.get("roles") {
                push_strings(roles, out);
            }
        }
        _ => {}
    }
}

pub fn me_response(ctx: Option<&AdminAuthContext>, auth_enabled: bool) -> AdminMeResponse {
    match ctx {
        Some(ctx) => AdminMeResponse {
            subject: ctx.subject.clone(),
            roles: ctx.roles.iter().map(|r| r.as_str()).collect(),
            permissions: ctx.permissions.iter().map(|p| p.as_str()).collect(),
            auth_method: ctx.auth_method.clone(),
            auth_enabled,
        },
        None => AdminMeResponse {
            subject: "anonymous".into(),
            roles: if auth_enabled {
                vec![]
            } else {
                vec![AdminRole::Admin.as_str()]
            },
            permissions: if auth_enabled {
                vec![]
            } else {
                AdminAuthConfig::permissions_for_roles(&[AdminRole::Admin])
                    .into_iter()
                    .map(|p| p.as_str())
                    .collect()
            },
            auth_method: if auth_enabled {
                "none".into()
            } else {
                "disabled".into()
            },
            auth_enabled,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_core::AdminAuthMode;

    fn enabled_hmac() -> AdminAuthConfig {
        AdminAuthConfig {
            enabled: true,
            mode: AdminAuthMode::JwtHmac,
            jwt_secret: "test-secret-16b!!".into(),
            issuer: "data-nexus-test".into(),
            audience: "data-nexus-admin".into(),
            ..AdminAuthConfig::default()
        }
    }

    #[test]
    fn disabled_allows_without_token() {
        let cfg = AdminAuthConfig::default();
        let result = authenticate_request(&cfg, None, "POST", "/admin/reload").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn enabled_requires_token_for_reload() {
        let cfg = enabled_hmac();
        let err = authenticate_request(&cfg, None, "POST", "/admin/reload").unwrap_err();
        assert!(matches!(err, AdminAuthError::Unauthorized(_)));
    }

    #[test]
    fn viewer_cannot_reload_admin_can() {
        let cfg = enabled_hmac();
        let viewer = issue_hmac_token(&cfg, "u1", &[AdminRole::Viewer], 3600).unwrap();
        let err = authenticate_request(
            &cfg,
            Some(&format!("Bearer {viewer}")),
            "POST",
            "/admin/reload",
        )
        .unwrap_err();
        assert!(matches!(err, AdminAuthError::Forbidden(_)));

        let admin = issue_hmac_token(&cfg, "u2", &[AdminRole::Admin], 3600).unwrap();
        let ctx = authenticate_request(
            &cfg,
            Some(&format!("Bearer {admin}")),
            "POST",
            "/admin/reload",
        )
        .unwrap()
        .unwrap();
        assert_eq!(ctx.subject, "u2");
        assert!(ctx.allows(AdminPermission::ConfigReload));
    }

    #[test]
    fn viewer_can_read_listeners() {
        let cfg = enabled_hmac();
        let token = issue_hmac_token(&cfg, "reader", &[AdminRole::Viewer], 3600).unwrap();
        let ctx = authenticate_request(
            &cfg,
            Some(&format!("Bearer {token}")),
            "GET",
            "/admin/listeners",
        )
        .unwrap()
        .unwrap();
        assert!(ctx.allows(AdminPermission::TopologyRead));
    }

    #[test]
    fn public_metrics_skips_auth() {
        let mut cfg = enabled_hmac();
        cfg.public_metrics = true;
        let result = authenticate_request(&cfg, None, "GET", "/metrics").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn auth_config_path_is_public() {
        let cfg = enabled_hmac();
        let result = authenticate_request(&cfg, None, "GET", "/admin/auth/config").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn break_glass_login_issues_admin_token() {
        let mut cfg = enabled_hmac();
        cfg.break_glass_password = "super-secret".into();
        let err = break_glass_login(&cfg, "wrong").unwrap_err();
        assert!(matches!(err, AdminAuthError::Unauthorized(_)));
        let token = break_glass_login(&cfg, "super-secret").unwrap();
        assert_eq!(token.token_type, "Bearer");
        assert!(token.roles.contains(&"admin"));
        let ctx = authenticate_request(
            &cfg,
            Some(&format!("Bearer {}", token.access_token)),
            "POST",
            "/admin/reload",
        )
        .unwrap()
        .unwrap();
        assert_eq!(ctx.subject, "break-glass");
        assert!(ctx.allows(AdminPermission::ConfigReload));
    }
}
