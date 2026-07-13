// Copyright 2022 SphereEx Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use endpoint::endpoint::Endpoint;
use gateway_core::{EndpointConfig, EndpointRole, RoutePlan, RouteTarget};
use indexmap::{IndexMap, IndexSet};
use loadbalance::balance::{BalanceTarget, BalanceType, LoadBalance};
use thiserror::Error;

use crate::{
    config::{self, TargetRole},
    readwritesplitting::{
        ReadWriteEndpoint, ReadWriteSplittingDynamic, ReadWriteSplittingDynamicBuilder,
        ReadWriteSplittingStatic, ReadWriteSplittingStaticBuilder,
    },
};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StragegyError {
    #[error("build node name not found {0:?}")]
    EndpointNotFound(String),

    #[error("build node group name not found {0:?}")]
    NodeGroupNotFound(String),
}

#[derive(Debug)]
#[non_exhaustive]
pub enum RouteInputTyp {
    Statement,
    Transaction,
    None,
}
/// RouteInput may have more fields or variants added in the future,
/// As parameter of Route trait, Possible values are  `sql statement`, `sql ast`,etc.
#[derive(Debug)]
#[non_exhaustive]
pub enum RouteInput<'a> {
    Statement(&'a str),
    Transaction(&'a str),
    Sharding(Endpoint),
    ShardingStatement(&'a str, String),
    ShardingTransaction(&'a str, String),
    None,
}

#[derive(Debug)]
pub enum ShardingRouteInput<'a> {
    ShardingReadWriteSplitting(ReadWriteSplittingRouteInput<'a>, String),
    Sharding(Endpoint),
}

#[derive(Debug)]
pub enum ReadWriteSplittingRouteInput<'a> {
    Statement(&'a str),
    Transaction(&'a str),
}

/// Route trait, Used to decide on which endpoint to execute the sql statement.
pub trait Route {
    type Error;

    // The dispatch function returns a protocol-neutral route plan.
    fn dispatch(&mut self, input: &RouteInput) -> Result<RoutePlan, Self::Error>;
}

pub fn endpoint_to_route_target(endpoint: Endpoint, role: TargetRole) -> RouteTarget {
    let weight = u32::try_from(endpoint.weight).ok().filter(|weight| *weight > 0).unwrap_or(1);
    RouteTarget {
        endpoint: EndpointConfig {
            name: endpoint.name,
            protocol: endpoint.node_type,
            address: endpoint.addr,
            database: if endpoint.db.is_empty() { None } else { Some(endpoint.db) },
            username: endpoint.user,
            password: endpoint.password,
            role: target_role_to_endpoint_role(role),
            weight,
        },
    }
}

pub fn route_target_to_endpoint(target: RouteTarget) -> Endpoint {
    Endpoint {
        node_type: target.endpoint.protocol,
        weight: i64::from(target.endpoint.weight),
        name: target.endpoint.name,
        db: target.endpoint.database.unwrap_or_default(),
        user: target.endpoint.username,
        password: target.endpoint.password,
        addr: target.endpoint.address,
    }
}

pub fn route_plan_single_endpoint(plan: RoutePlan) -> Result<Endpoint, BoxError> {
    match plan {
        RoutePlan::Single { target } => Ok(route_target_to_endpoint(target)),
        RoutePlan::Reject { reason } => {
            Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, reason)))
        }
        RoutePlan::Broadcast { .. } => Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "route plan contains multiple broadcast targets where one endpoint is required",
        ))),
        RoutePlan::Sharded { .. } => Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "route plan contains multiple sharded targets where one endpoint is required",
        ))),
    }
}

fn target_role_to_endpoint_role(role: TargetRole) -> EndpointRole {
    match role {
        TargetRole::Read => EndpointRole::Read,
        TargetRole::ReadWrite => EndpointRole::ReadWrite,
    }
}

/// Route rule, Currrently support `Regex` only.
pub trait RouteRuleMatch {
    fn is_match(&self, input: &RouteInput) -> bool;
}

/// RouteBalance trait, Used with RouteRuleMatch trait to get a balance type.
pub trait RouteBalance<T = Endpoint>
where
    T: BalanceTarget,
{
    fn get(&mut self, input: &RouteInput) -> (&mut BalanceType<T>, TargetRole);
}

/// Supported routing strategies
pub enum RouteStrategy {
    ReadWriteSplitting(ReadWriteSplittingRouteStrategy),
    ShardingReadWriteSplitting(ReadWriteSplittingRouteStrategy),
    Sharding(BalanceType),
    Simple(BalanceType),
    None,
}

pub enum ReadWriteSplittingRouteStrategy {
    Static(ReadWriteSplittingStatic),
    Dynamic(ReadWriteSplittingDynamic),
    None,
}

pub enum ShardingRouteStrategy {
    ShardingReadWriteSplitting(ReadWriteSplittingRouteStrategy),
    Sharding,
}

impl ReadWriteSplittingRouteStrategy {
    pub fn new(
        config: config::ReadWriteSplitting,
        node_group_config: Option<config::NodeGroup>,
        endpoint_group: IndexMap<String, ReadWriteEndpoint>,
        rw_endpoint: ReadWriteEndpoint,
    ) -> Self {
        if let Some(config) = config.statics {
            return Self::Static(ReadWriteSplittingStaticBuilder::build(
                config,
                node_group_config,
                endpoint_group,
                rw_endpoint,
            ));
        }

        if let Some(config) = config.dynamic {
            return Self::Dynamic(ReadWriteSplittingDynamicBuilder::build(
                config,
                node_group_config,
                endpoint_group,
                rw_endpoint,
            ));
        }

        // Just to return
        Self::None
    }
}

impl RouteStrategy {
    pub fn new(
        config: config::ReadWriteSplitting,
        node_group_config: &Option<config::NodeGroup>,
        rw_endpoint: ReadWriteEndpoint,
        has_sharding: bool,
    ) -> Result<Self, StragegyError> {
        let endpoint_group = Self::get_endpoint_group(node_group_config, &rw_endpoint)?;

        let rw_strategy = ReadWriteSplittingRouteStrategy::new(
            config,
            node_group_config.clone(),
            endpoint_group,
            rw_endpoint,
        );
        if has_sharding {
            Ok(Self::ShardingReadWriteSplitting(rw_strategy))
        } else {
            Ok(Self::ReadWriteSplitting(rw_strategy))
        }
    }

    pub fn new_with_simple_route(balance: BalanceType) -> Self {
        Self::Simple(balance)
    }

    pub fn new_with_sharding_only(balance: BalanceType) -> Self {
        Self::Sharding(balance)
    }

    pub fn get_endpoint_group(
        nodegroup: &Option<config::NodeGroup>,
        rw_endpoint: &ReadWriteEndpoint,
    ) -> Result<IndexMap<String, ReadWriteEndpoint>, StragegyError> {
        let mut endpoint_group = IndexMap::<String, ReadWriteEndpoint>::new();

        match nodegroup {
            Some(group) => {
                let set: IndexSet<&String> = rw_endpoint.read.iter().map(|x| &x.name).collect();

                for member in group.members.iter() {
                    let currset: IndexSet<&String> = member.reads.iter().collect();
                    let intersec = set.intersection(&currset).collect::<Vec<_>>();
                    let read = intersec
                        .into_iter()
                        .filter_map(|x| rw_endpoint.read.iter().find(|r| &r.name == *x))
                        .cloned()
                        .collect::<Vec<_>>();
                    let readwrite = rw_endpoint
                        .readwrite
                        .iter()
                        .find(|x| x.name == member.readwrite)
                        .cloned()
                        .ok_or(StragegyError::EndpointNotFound(member.readwrite.clone()))?;

                    let rw = ReadWriteEndpoint { read, readwrite: vec![readwrite] };

                    endpoint_group.insert(member.name.clone(), rw);
                }

                Ok(endpoint_group)
            }
            None => Ok(endpoint_group),
        }
    }

    fn readwritesplitting_dispatch(
        strategy: &mut ReadWriteSplittingRouteStrategy,
        input: &RouteInput,
    ) -> Result<RoutePlan, BoxError> {
        match strategy {
            ReadWriteSplittingRouteStrategy::Static(ins) => ins.dispatch(input),
            ReadWriteSplittingRouteStrategy::Dynamic(ins) => ins.dispatch(input),
            _ => unreachable!(),
        }
    }
}

impl Route for RouteStrategy {
    type Error = BoxError;

    fn dispatch(&mut self, input: &RouteInput) -> Result<RoutePlan, Self::Error> {
        match self {
            Self::ReadWriteSplitting(strategy) => {
                Self::readwritesplitting_dispatch(strategy, input)
            }

            Self::ShardingReadWriteSplitting(strateyy) => {
                Self::readwritesplitting_dispatch(strateyy, input)
            }

            Self::Sharding(ins) => {
                if let RouteInput::Sharding(input) = input {
                    Ok(RoutePlan::Single {
                        target: endpoint_to_route_target(input.clone(), TargetRole::ReadWrite),
                    })
                } else {
                    Ok(ins
                        .next()
                        .map(|endpoint| RoutePlan::Single {
                            target: endpoint_to_route_target(endpoint, TargetRole::ReadWrite),
                        })
                        .unwrap_or_else(|| RoutePlan::Reject {
                            reason: "route strategy selected no sharding endpoint".into(),
                        }))
                }
            }

            Self::Simple(ins) => Ok(ins
                .next()
                .map(|endpoint| RoutePlan::Single {
                    target: endpoint_to_route_target(endpoint, TargetRole::ReadWrite),
                })
                .unwrap_or_else(|| RoutePlan::Reject {
                    reason: "route strategy selected no simple endpoint".into(),
                })),

            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use endpoint::endpoint::Endpoint;
    use gateway_core::{EndpointRole, ProtocolKind, RoutePlan};
    use loadbalance::balance::{AlgorithmName, Balance, LoadBalance};

    use super::{route_plan_single_endpoint, Route, RouteInput, RouteStrategy};

    fn endpoint(name: &str, addr: &str) -> Endpoint {
        Endpoint {
            node_type: ProtocolKind::MySql,
            weight: 2,
            name: name.into(),
            db: "orders".into(),
            user: "root".into(),
            password: "secret".into(),
            addr: addr.into(),
        }
    }

    #[test]
    fn simple_route_dispatches_protocol_neutral_single_plan() {
        let mut balance = Balance.build_balance(AlgorithmName::Random);
        balance.add(endpoint("orders-primary", "127.0.0.1:3306"));
        let mut strategy = RouteStrategy::new_with_simple_route(balance);

        let plan = strategy.dispatch(&RouteInput::Statement("select 1")).unwrap();

        assert!(matches!(
            plan,
            RoutePlan::Single { target }
                if target.endpoint.name == "orders-primary"
                    && target.endpoint.address == "127.0.0.1:3306"
                    && target.endpoint.database == Some("orders".into())
                    && target.endpoint.role == EndpointRole::ReadWrite
                    && target.endpoint.weight == 2
        ));
    }

    #[test]
    fn route_plan_single_endpoint_converts_back_for_legacy_callers() {
        let mut balance = Balance.build_balance(AlgorithmName::Random);
        balance.add(endpoint("orders-primary", "127.0.0.1:3306"));
        let mut strategy = RouteStrategy::new_with_simple_route(balance);

        let endpoint = route_plan_single_endpoint(
            strategy.dispatch(&RouteInput::Statement("select 1")).unwrap(),
        )
        .unwrap();

        assert_eq!(endpoint.name, "orders-primary");
        assert_eq!(endpoint.addr, "127.0.0.1:3306");
        assert_eq!(endpoint.db, "orders");
        assert_eq!(endpoint.weight, 2);
    }

    #[test]
    fn route_plan_single_endpoint_rejects_multi_target_plans() {
        let error =
            route_plan_single_endpoint(RoutePlan::Broadcast { targets: vec![] }).unwrap_err();

        assert!(error.to_string().contains("multiple broadcast targets"));
    }
}
