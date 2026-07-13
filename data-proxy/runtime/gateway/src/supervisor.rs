use std::collections::{HashMap, HashSet};

use gateway_core::{GatewayConfig, GatewayError, GatewayResult};
use tokio::task::JoinHandle;
use tracing::error;

use crate::gateway::{GatewayRuntime, GatewayRuntimeShutdownHandle};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GatewayRuntimeReloadPlan {
    pub start_listeners: Vec<String>,
    pub stop_listeners: Vec<String>,
    pub restart_listeners: Vec<String>,
}

impl GatewayRuntimeReloadPlan {
    pub fn has_changes(&self) -> bool {
        !self.start_listeners.is_empty()
            || !self.stop_listeners.is_empty()
            || !self.restart_listeners.is_empty()
    }
}

struct RunningListener {
    shutdown: GatewayRuntimeShutdownHandle,
    task: JoinHandle<()>,
}

pub struct GatewayRuntimeSupervisor {
    config: GatewayConfig,
    version: String,
    listeners: HashMap<String, RunningListener>,
}

impl GatewayRuntimeSupervisor {
    pub fn new(config: GatewayConfig, version: String) -> GatewayResult<Self> {
        config.validate()?;
        Ok(Self { config, version, listeners: HashMap::new() })
    }

    pub fn config(&self) -> &GatewayConfig {
        &self.config
    }

    pub fn active_listeners(&self) -> Vec<String> {
        let mut listeners = self.listeners.keys().cloned().collect::<Vec<_>>();
        listeners.sort();
        listeners
    }

    pub fn plan_reload(&self, next: &GatewayConfig) -> GatewayResult<GatewayRuntimeReloadPlan> {
        plan_runtime_reload(&self.config, next)
    }

    pub fn start_all(&mut self) -> GatewayResult<GatewayRuntimeReloadPlan> {
        let mut started = Vec::new();
        let listener_names =
            self.config.listeners.iter().map(|listener| listener.name.clone()).collect::<Vec<_>>();

        for listener_name in listener_names {
            self.start_listener(listener_name.clone(), self.config.clone())?;
            started.push(listener_name);
        }

        started.sort();
        Ok(GatewayRuntimeReloadPlan {
            start_listeners: started,
            stop_listeners: Vec::new(),
            restart_listeners: Vec::new(),
        })
    }

    pub async fn apply_config(
        &mut self,
        next: GatewayConfig,
    ) -> GatewayResult<GatewayRuntimeReloadPlan> {
        let plan = self.plan_reload(&next)?;

        for listener_name in plan.stop_listeners.iter().chain(plan.restart_listeners.iter()) {
            self.stop_listener(listener_name).await;
        }

        for listener_name in plan.start_listeners.iter().chain(plan.restart_listeners.iter()) {
            self.start_listener(listener_name.clone(), next.clone())?;
        }

        self.config = next;
        Ok(plan)
    }

    pub async fn stop_all(&mut self) {
        let listener_names = self.listeners.keys().cloned().collect::<Vec<_>>();
        for listener_name in listener_names {
            self.stop_listener(&listener_name).await;
        }
    }

    async fn stop_listener(&mut self, listener_name: &str) {
        let Some(listener) = self.listeners.remove(listener_name) else {
            return;
        };

        listener.shutdown.shutdown();
        let _ = listener.task.await;
    }

    fn start_listener(
        &mut self,
        listener_name: String,
        config: GatewayConfig,
    ) -> GatewayResult<()> {
        if self.listeners.contains_key(&listener_name) {
            return Err(GatewayError::Configuration(format!(
                "gateway listener '{}' is already running",
                listener_name
            )));
        }

        let mut runtime =
            GatewayRuntime::from_gateway_config(config, &listener_name, self.version.clone())?;
        let shutdown = runtime.shutdown_handle();
        let task_listener_name = listener_name.clone();
        let task = tokio::spawn(async move {
            if let Err(error) = proxy::factory::Proxy::start(&mut runtime).await {
                error!("gateway listener '{}' stopped with error {:?}", task_listener_name, error);
            }
        });

        self.listeners.insert(listener_name, RunningListener { shutdown, task });
        Ok(())
    }
}

impl Drop for GatewayRuntimeSupervisor {
    fn drop(&mut self) {
        for listener in self.listeners.values() {
            listener.shutdown.shutdown();
            listener.task.abort();
        }
    }
}

pub fn plan_runtime_reload(
    previous: &GatewayConfig,
    next: &GatewayConfig,
) -> GatewayResult<GatewayRuntimeReloadPlan> {
    previous.validate()?;
    next.validate()?;

    let diff = previous.diff(next);
    let previous_listener_names =
        previous.listeners.iter().map(|listener| listener.name.as_str()).collect::<HashSet<_>>();
    let next_listener_names =
        next.listeners.iter().map(|listener| listener.name.as_str()).collect::<HashSet<_>>();

    let start = diff.listeners.added.into_iter().collect::<HashSet<_>>();
    let stop = diff.listeners.removed.into_iter().collect::<HashSet<_>>();
    let mut restart = diff.listeners.updated.into_iter().collect::<HashSet<_>>();

    let changed_services = changed_service_names(previous, next, &diff.endpoint_pool_refreshes);
    for listener_name in listeners_for_services(previous, next, &changed_services) {
        if previous_listener_names.contains(listener_name.as_str())
            && next_listener_names.contains(listener_name.as_str())
            && !start.contains(&listener_name)
            && !stop.contains(&listener_name)
        {
            restart.insert(listener_name);
        }
    }

    let changed_route_policies = diff.route_policy_replacements.into_iter().collect::<HashSet<_>>();
    for listener_name in listeners_for_route_policies(previous, next, &changed_route_policies) {
        if previous_listener_names.contains(listener_name.as_str())
            && next_listener_names.contains(listener_name.as_str())
            && !start.contains(&listener_name)
            && !stop.contains(&listener_name)
        {
            restart.insert(listener_name);
        }
    }

    let mut start_listeners = start.into_iter().collect::<Vec<_>>();
    let mut stop_listeners = stop.into_iter().collect::<Vec<_>>();
    let mut restart_listeners = restart.into_iter().collect::<Vec<_>>();
    start_listeners.sort();
    stop_listeners.sort();
    restart_listeners.sort();

    Ok(GatewayRuntimeReloadPlan { start_listeners, stop_listeners, restart_listeners })
}

fn changed_service_names(
    previous: &GatewayConfig,
    next: &GatewayConfig,
    endpoint_pool_refreshes: &[String],
) -> HashSet<String> {
    let mut service_names = endpoint_pool_refreshes.iter().cloned().collect::<HashSet<_>>();
    let diff = previous.diff(next);
    service_names.extend(diff.services.added);
    service_names.extend(diff.services.removed);
    service_names.extend(diff.services.updated);
    service_names
}

fn listeners_for_services(
    previous: &GatewayConfig,
    next: &GatewayConfig,
    service_names: &HashSet<String>,
) -> HashSet<String> {
    previous
        .listeners
        .iter()
        .chain(next.listeners.iter())
        .filter(|listener| service_names.contains(&listener.service))
        .map(|listener| listener.name.clone())
        .collect()
}

fn listeners_for_route_policies(
    previous: &GatewayConfig,
    next: &GatewayConfig,
    policy_names: &HashSet<String>,
) -> HashSet<String> {
    let mut service_names = HashSet::new();
    for service in previous.services.iter().chain(next.services.iter()) {
        if service
            .route_policy
            .as_ref()
            .is_some_and(|policy_name| policy_names.contains(policy_name))
        {
            service_names.insert(service.name.clone());
        }
    }

    listeners_for_services(previous, next, &service_names)
}

#[cfg(test)]
mod tests {
    use gateway_core::{
        EndpointConfig, EndpointRole, GatewayConfig, ListenerConfig, ProtocolKind,
        RoutePolicyConfig, ServiceConfig,
    };

    use super::*;

    fn config() -> GatewayConfig {
        GatewayConfig {
            listeners: vec![ListenerConfig {
                name: "mysql-public".into(),
                listen_addr: "127.0.0.1:3307".into(),
                protocol: ProtocolKind::MySql,
                service: "orders".into(),
                auth_policy: None,
            }],
            services: vec![ServiceConfig {
                name: "orders".into(),
                frontend_protocols: vec![ProtocolKind::MySql],
                backend_protocol: ProtocolKind::MySql,
                endpoints: vec!["orders-primary".into()],
                route_policy: Some("primary".into()),
                plugin_policies: vec![],
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
                name: "primary".into(),
                kind: "single".into(),
            }],
            ..GatewayConfig::default()
        }
    }

    #[test]
    fn plans_added_and_removed_listeners() {
        let previous = config();
        let mut next = previous.clone();
        next.listeners.clear();
        next.listeners.push(ListenerConfig {
            name: "mysql-private".into(),
            listen_addr: "127.0.0.1:3308".into(),
            protocol: ProtocolKind::MySql,
            service: "orders".into(),
            auth_policy: None,
        });

        let plan = plan_runtime_reload(&previous, &next).unwrap();

        assert_eq!(plan.start_listeners, vec!["mysql-private"]);
        assert_eq!(plan.stop_listeners, vec!["mysql-public"]);
        assert!(plan.restart_listeners.is_empty());
    }

    #[test]
    fn plans_restart_for_listener_endpoint_and_route_policy_changes() {
        let previous = config();
        let mut next = previous.clone();
        next.listeners[0].listen_addr = "127.0.0.1:3309".into();
        next.endpoints[0].address = "127.0.0.1:3310".into();
        next.route_policies[0].kind = "read-write-splitting".into();

        let plan = plan_runtime_reload(&previous, &next).unwrap();

        assert!(plan.start_listeners.is_empty());
        assert!(plan.stop_listeners.is_empty());
        assert_eq!(plan.restart_listeners, vec!["mysql-public"]);
    }

    #[test]
    fn supervisor_reports_active_listeners_in_stable_order() {
        let supervisor = GatewayRuntimeSupervisor::new(config(), "8.0".into()).unwrap();

        assert!(supervisor.active_listeners().is_empty());
        assert_eq!(supervisor.config().listeners[0].name, "mysql-public");
    }
}
