use std::collections::HashSet;

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
    pub plugin_policies: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointConfig {
    pub name: String,
    pub protocol: ProtocolKind,
    pub address: String,
    pub database: Option<String>,
    pub weight: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutePolicyConfig {
    pub name: String,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthPolicyConfig {
    pub name: String,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginPolicyConfig {
    pub name: String,
    pub kind: String,
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
}

impl GatewayConfig {
    pub fn validate(&self) -> GatewayResult<()> {
        validate_unique("listener", self.listeners.iter().map(|item| &item.name))?;
        validate_unique("service", self.services.iter().map(|item| &item.name))?;
        validate_unique("endpoint", self.endpoints.iter().map(|item| &item.name))?;
        validate_unique("route policy", self.route_policies.iter().map(|item| &item.name))?;
        validate_unique("auth policy", self.auth_policies.iter().map(|item| &item.name))?;
        validate_unique("plugin policy", self.plugin_policies.iter().map(|item| &item.name))?;

        let services: HashSet<&str> = self.services.iter().map(|item| item.name.as_str()).collect();
        let endpoints: HashSet<&str> =
            self.endpoints.iter().map(|item| item.name.as_str()).collect();
        let routes: HashSet<&str> =
            self.route_policies.iter().map(|item| item.name.as_str()).collect();
        let auth: HashSet<&str> =
            self.auth_policies.iter().map(|item| item.name.as_str()).collect();
        let plugins: HashSet<&str> =
            self.plugin_policies.iter().map(|item| item.name.as_str()).collect();

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
        }

        for endpoint in &self.endpoints {
            require_non_empty("endpoint name", &endpoint.name)?;
            require_non_empty("endpoint address", &endpoint.address)?;
        }

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
            }],
            endpoints: vec![EndpointConfig {
                name: "orders-primary".into(),
                protocol: ProtocolKind::MySql,
                address: "127.0.0.1:3306".into(),
                database: Some("orders".into()),
                weight: 1,
            }],
            route_policies: vec![RoutePolicyConfig {
                name: "primary-only".into(),
                kind: "single".into(),
            }],
            auth_policies: vec![AuthPolicyConfig {
                name: "local-users".into(),
                kind: "static".into(),
            }],
            plugin_policies: vec![PluginPolicyConfig {
                name: "audit".into(),
                kind: "audit".into(),
            }],
        }
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
}
