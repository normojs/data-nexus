use serde::{Deserialize, Serialize};

/// Stable reference to a configured backend endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointRef {
    pub name: String,
    pub address: String,
}

impl EndpointRef {
    pub fn new(name: impl Into<String>, address: impl Into<String>) -> Self {
        Self { name: name.into(), address: address.into() }
    }
}

/// Protocol-neutral routing decision produced by Gateway Core.
///
/// Core currently materializes `Single` into `SessionState.backend_endpoint`.
/// `Broadcast` / `Sharded` are reserved for later multi-endpoint execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "payload")]
pub enum RoutePlan {
    Single { endpoint: EndpointRef },
    Broadcast { endpoints: Vec<EndpointRef> },
    Sharded { shards: Vec<ShardTarget> },
    Reject { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardTarget {
    pub endpoint: EndpointRef,
    pub rewritten_sql: Option<String>,
}

impl RoutePlan {
    pub fn single(name: impl Into<String>, address: impl Into<String>) -> Self {
        Self::Single { endpoint: EndpointRef::new(name, address) }
    }

    pub fn reject(reason: impl Into<String>) -> Self {
        Self::Reject { reason: reason.into() }
    }

    pub fn as_single_endpoint(&self) -> Option<&EndpointRef> {
        match self {
            Self::Single { endpoint } => Some(endpoint),
            _ => None,
        }
    }

    pub fn is_reject(&self) -> bool {
        matches!(self, Self::Reject { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_plan_exposes_endpoint() {
        let plan = RoutePlan::single("primary", "127.0.0.1:3306");
        assert_eq!(plan.as_single_endpoint().unwrap().name, "primary");
        assert!(!plan.is_reject());
    }

    #[test]
    fn reject_plan() {
        let plan = RoutePlan::reject("no healthy endpoint");
        assert!(plan.is_reject());
        assert!(plan.as_single_endpoint().is_none());
    }
}
