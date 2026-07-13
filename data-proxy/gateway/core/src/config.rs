use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{GatewayError, GatewayResult, ProtocolKind};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigSectionDiff {
    #[serde(default)]
    pub added: Vec<String>,
    #[serde(default)]
    pub removed: Vec<String>,
    #[serde(default)]
    pub updated: Vec<String>,
}

impl ConfigSectionDiff {
    pub fn has_changes(&self) -> bool {
        !self.added.is_empty() || !self.removed.is_empty() || !self.updated.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayConfigDiff {
    pub listeners: ConfigSectionDiff,
    pub services: ConfigSectionDiff,
    pub endpoints: ConfigSectionDiff,
    pub route_policies: ConfigSectionDiff,
    pub auth_policies: ConfigSectionDiff,
    pub plugin_policies: ConfigSectionDiff,
    #[serde(default)]
    pub listener_restarts: Vec<String>,
    #[serde(default)]
    pub endpoint_pool_refreshes: Vec<String>,
    #[serde(default)]
    pub route_policy_replacements: Vec<String>,
}

impl GatewayConfigDiff {
    pub fn has_changes(&self) -> bool {
        self.listeners.has_changes()
            || self.services.has_changes()
            || self.endpoints.has_changes()
            || self.route_policies.has_changes()
            || self.auth_policies.has_changes()
            || self.plugin_policies.has_changes()
    }
}

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
    pub frontend_protocols: Vec<ProtocolKind>,
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
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub role: EndpointRole,
    pub weight: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EndpointRole {
    Read,
    #[serde(alias = "read_write")]
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
pub struct AuthPolicyConfig {
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub users: Vec<AuthPolicyUserConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthPolicyUserConfig {
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub databases: Vec<String>,
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
    pub fn diff(&self, next: &GatewayConfig) -> GatewayConfigDiff {
        let listeners = diff_named(&self.listeners, &next.listeners, |item| &item.name);
        let services = diff_named(&self.services, &next.services, |item| &item.name);
        let endpoints = diff_named(&self.endpoints, &next.endpoints, |item| &item.name);
        let route_policies =
            diff_named(&self.route_policies, &next.route_policies, |item| &item.name);
        let auth_policies = diff_named(&self.auth_policies, &next.auth_policies, |item| &item.name);
        let plugin_policies =
            diff_named(&self.plugin_policies, &next.plugin_policies, |item| &item.name);

        let mut listener_restarts =
            union_names(&listeners.added, &listeners.removed, &listeners.updated);
        listener_restarts.sort();

        let endpoint_pool_refreshes = endpoint_pool_refreshes(self, next, &services, &endpoints);
        let mut route_policy_replacements = route_policies.updated.clone();
        route_policy_replacements.sort();

        GatewayConfigDiff {
            listeners,
            services,
            endpoints,
            route_policies,
            auth_policies,
            plugin_policies,
            listener_restarts,
            endpoint_pool_refreshes,
            route_policy_replacements,
        }
    }

    pub fn validate(&self) -> GatewayResult<()> {
        if self.listeners.is_empty() {
            return Err(GatewayError::Configuration(
                "gateway must define at least one listener".into(),
            ));
        }
        if self.services.is_empty() {
            return Err(GatewayError::Configuration(
                "gateway must define at least one service".into(),
            ));
        }

        validate_unique("listener", self.listeners.iter().map(|item| &item.name))?;
        validate_unique("service", self.services.iter().map(|item| &item.name))?;
        validate_unique("endpoint", self.endpoints.iter().map(|item| &item.name))?;
        validate_unique("route policy", self.route_policies.iter().map(|item| &item.name))?;
        validate_unique("auth policy", self.auth_policies.iter().map(|item| &item.name))?;
        validate_unique("plugin policy", self.plugin_policies.iter().map(|item| &item.name))?;

        let services: HashMap<&str, &ServiceConfig> =
            self.services.iter().map(|item| (item.name.as_str(), item)).collect();
        let endpoints: HashMap<&str, &EndpointConfig> =
            self.endpoints.iter().map(|item| (item.name.as_str(), item)).collect();
        let routes: HashSet<&str> =
            self.route_policies.iter().map(|item| item.name.as_str()).collect();
        let auth: HashSet<&str> =
            self.auth_policies.iter().map(|item| item.name.as_str()).collect();
        let plugins: HashSet<&str> =
            self.plugin_policies.iter().map(|item| item.name.as_str()).collect();

        for service in &self.services {
            require_non_empty("service name", &service.name)?;
            if service.frontend_protocols.is_empty() {
                return Err(GatewayError::Configuration(format!(
                    "service '{}' has no frontend protocols",
                    service.name
                )));
            }
        }

        for listener in &self.listeners {
            require_non_empty("listener name", &listener.name)?;
            require_non_empty("listener address", &listener.listen_addr)?;
            let Some(service) = services.get(listener.service.as_str()) else {
                return Err(GatewayError::Configuration(format!(
                    "listener '{}' references missing service '{}'",
                    listener.name, listener.service
                )));
            };
            if !service.frontend_protocols.contains(&listener.protocol) {
                return Err(GatewayError::Configuration(format!(
                    "listener '{}' uses protocol '{}' but service '{}' allows frontend protocols [{}]",
                    listener.name,
                    listener.protocol,
                    service.name,
                    format_protocol_list(&service.frontend_protocols)
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
            if service.endpoints.is_empty() {
                return Err(GatewayError::Configuration(format!(
                    "service '{}' has no endpoints",
                    service.name
                )));
            }
            for endpoint in &service.endpoints {
                let Some(endpoint_config) = endpoints.get(endpoint.as_str()) else {
                    return Err(GatewayError::Configuration(format!(
                        "service '{}' references missing endpoint '{}'",
                        service.name, endpoint
                    )));
                };
                if endpoint_config.protocol != service.backend_protocol {
                    return Err(GatewayError::Configuration(format!(
                        "service '{}' endpoint '{}' uses protocol '{}' but service backend protocol is '{}'",
                        service.name,
                        endpoint,
                        endpoint_config.protocol,
                        service.backend_protocol
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
            if endpoint.weight == 0 {
                return Err(GatewayError::Configuration(format!(
                    "endpoint '{}' weight must be greater than 0",
                    endpoint.name
                )));
            }
        }

        for policy in &self.route_policies {
            require_non_empty("route policy name", &policy.name)?;
            require_non_empty("route policy kind", &policy.kind)?;
        }

        for policy in &self.auth_policies {
            require_non_empty("auth policy name", &policy.name)?;
            require_non_empty("auth policy kind", &policy.kind)?;
            for user in &policy.users {
                require_non_empty("auth policy user", &user.username)?;
            }
        }

        for policy in &self.plugin_policies {
            require_non_empty("plugin policy name", &policy.name)?;
            require_non_empty("plugin policy kind", &policy.kind)?;
        }

        Ok(())
    }
}

fn diff_named<T: PartialEq>(
    previous: &[T],
    next: &[T],
    name: impl Fn(&T) -> &String,
) -> ConfigSectionDiff {
    let previous_by_name: HashMap<&str, &T> =
        previous.iter().map(|item| (name(item).as_str(), item)).collect();
    let next_by_name: HashMap<&str, &T> =
        next.iter().map(|item| (name(item).as_str(), item)).collect();

    let mut added = next_by_name
        .keys()
        .filter(|item| !previous_by_name.contains_key(**item))
        .map(|item| (*item).to_string())
        .collect::<Vec<_>>();
    let mut removed = previous_by_name
        .keys()
        .filter(|item| !next_by_name.contains_key(**item))
        .map(|item| (*item).to_string())
        .collect::<Vec<_>>();
    let mut updated = next_by_name
        .iter()
        .filter_map(|(item_name, next_item)| {
            previous_by_name
                .get(item_name)
                .filter(|previous_item| **previous_item != *next_item)
                .map(|_| (*item_name).to_string())
        })
        .collect::<Vec<_>>();

    added.sort();
    removed.sort();
    updated.sort();

    ConfigSectionDiff { added, removed, updated }
}

fn endpoint_pool_refreshes(
    previous: &GatewayConfig,
    next: &GatewayConfig,
    services: &ConfigSectionDiff,
    endpoints: &ConfigSectionDiff,
) -> Vec<String> {
    let changed_endpoints = union_names(&endpoints.added, &endpoints.removed, &endpoints.updated);
    let service_changes = union_names(&services.added, &services.removed, &services.updated);

    let previous_services: HashMap<&str, &ServiceConfig> =
        previous.services.iter().map(|item| (item.name.as_str(), item)).collect();
    let next_services: HashMap<&str, &ServiceConfig> =
        next.services.iter().map(|item| (item.name.as_str(), item)).collect();

    let mut refreshes = HashSet::new();
    for service_name in service_changes {
        refreshes.insert(service_name);
    }

    for endpoint_name in changed_endpoints {
        for service in previous.services.iter().chain(next.services.iter()) {
            if service.endpoints.iter().any(|endpoint| endpoint == &endpoint_name) {
                refreshes.insert(service.name.clone());
            }
        }
    }

    for service_name in services.updated.iter() {
        let previous = previous_services.get(service_name.as_str());
        let next = next_services.get(service_name.as_str());
        if let (Some(previous), Some(next)) = (previous, next) {
            if previous.endpoints != next.endpoints
                || previous.backend_protocol != next.backend_protocol
            {
                refreshes.insert(service_name.clone());
            }
        }
    }

    let mut refreshes = refreshes.into_iter().collect::<Vec<_>>();
    refreshes.sort();
    refreshes
}

fn union_names(left: &[String], middle: &[String], right: &[String]) -> Vec<String> {
    left.iter()
        .chain(middle.iter())
        .chain(right.iter())
        .cloned()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect()
}

fn format_protocol_list(protocols: &[ProtocolKind]) -> String {
    protocols.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
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
                frontend_protocols: vec![ProtocolKind::MySql],
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
                username: "root".into(),
                password: "secret".into(),
                role: EndpointRole::ReadWrite,
                weight: 1,
            }],
            route_policies: vec![RoutePolicyConfig {
                name: "primary-only".into(),
                kind: "single".into(),
            }],
            auth_policies: vec![AuthPolicyConfig {
                name: "local-users".into(),
                kind: "static".into(),
                users: vec![AuthPolicyUserConfig {
                    username: "app".into(),
                    password: "secret".into(),
                    databases: vec!["orders".into()],
                }],
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

    #[test]
    fn rejects_service_endpoint_protocol_mismatches() {
        let mut config = config();
        config.endpoints[0].protocol = ProtocolKind::PostgreSql;
        assert_eq!(
            config.validate(),
            Err(GatewayError::Configuration(
                "service 'orders' endpoint 'orders-primary' uses protocol 'postgre_sql' but service backend protocol is 'my_sql'"
                    .into()
            ))
        );
    }

    #[test]
    fn rejects_empty_topology() {
        assert_eq!(
            GatewayConfig::default().validate(),
            Err(GatewayError::Configuration("gateway must define at least one listener".into()))
        );
    }

    #[test]
    fn rejects_listener_protocol_not_allowed_by_service() {
        let mut config = config();
        config.listeners[0].protocol = ProtocolKind::PostgreSql;
        assert_eq!(
            config.validate(),
            Err(GatewayError::Configuration(
                "listener 'mysql-public' uses protocol 'postgre_sql' but service 'orders' allows frontend protocols [my_sql]"
                    .into()
            ))
        );
    }

    #[test]
    fn rejects_service_without_frontend_protocols() {
        let mut config = config();
        config.services[0].frontend_protocols.clear();
        assert_eq!(
            config.validate(),
            Err(GatewayError::Configuration("service 'orders' has no frontend protocols".into()))
        );
    }

    #[test]
    fn rejects_zero_weight_endpoint() {
        let mut config = config();
        config.endpoints[0].weight = 0;
        assert_eq!(
            config.validate(),
            Err(GatewayError::Configuration(
                "endpoint 'orders-primary' weight must be greater than 0".into()
            ))
        );
    }

    #[test]
    fn rejects_empty_policy_kinds() {
        let mut config = config();
        config.route_policies[0].kind.clear();
        assert_eq!(
            config.validate(),
            Err(GatewayError::Configuration("route policy kind must not be empty".into()))
        );
    }

    #[test]
    fn diff_reports_no_changes_for_identical_configs() {
        let config = config();
        let diff = config.diff(&config);

        assert!(!diff.has_changes());
        assert!(diff.listener_restarts.is_empty());
        assert!(diff.endpoint_pool_refreshes.is_empty());
        assert!(diff.route_policy_replacements.is_empty());
    }

    #[test]
    fn diff_reports_reload_actions_for_changed_topology() {
        let previous = config();
        let mut next = previous.clone();
        next.listeners[0].listen_addr = "0.0.0.0:3307".into();
        next.services[0].endpoints.push("orders-replica".into());
        next.endpoints.push(EndpointConfig {
            name: "orders-replica".into(),
            protocol: ProtocolKind::MySql,
            address: "127.0.0.1:3307".into(),
            database: Some("orders".into()),
            username: "root".into(),
            password: "secret".into(),
            role: EndpointRole::Read,
            weight: 1,
        });
        next.route_policies[0].kind = "read-write-splitting".into();

        let diff = previous.diff(&next);

        assert!(diff.has_changes());
        assert_eq!(diff.listeners.updated, vec!["mysql-public"]);
        assert_eq!(diff.services.updated, vec!["orders"]);
        assert_eq!(diff.endpoints.added, vec!["orders-replica"]);
        assert_eq!(diff.route_policies.updated, vec!["primary-only"]);
        assert_eq!(diff.listener_restarts, vec!["mysql-public"]);
        assert_eq!(diff.endpoint_pool_refreshes, vec!["orders"]);
        assert_eq!(diff.route_policy_replacements, vec!["primary-only"]);
    }
}
