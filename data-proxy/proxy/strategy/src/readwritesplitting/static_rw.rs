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

use gateway_core::RoutePlan;
use indexmap::IndexMap;
use loadbalance::balance::LoadBalance;

use super::{
    rule_match::{RulesMatch, RulesMatchBuilder},
    ReadWriteEndpoint,
};
use crate::{
    config::{self, NodeGroup},
    route::{endpoint_to_route_target, BoxError, RouteBalance},
    Route, RouteInput,
};

pub struct ReadWriteSplittingStaticBuilder;

impl ReadWriteSplittingStaticBuilder {
    pub fn build(
        config: config::ReadWriteSplittingStatic,
        node_group_config: Option<NodeGroup>,
        endpoint_group: IndexMap<String, ReadWriteEndpoint>,
        rw_endpoint: ReadWriteEndpoint,
    ) -> ReadWriteSplittingStatic {
        let rules_match = RulesMatchBuilder::build(
            config.rules,
            config.default_target,
            node_group_config,
            endpoint_group,
            rw_endpoint,
        );

        ReadWriteSplittingStatic { rules_match }
    }
}

pub struct ReadWriteSplittingStatic {
    rules_match: RulesMatch,
}

impl Route for ReadWriteSplittingStatic {
    type Error = BoxError;
    fn dispatch(&mut self, input: &RouteInput) -> Result<RoutePlan, Self::Error> {
        let b = self.rules_match.get(input);
        Ok(b.0
            .next()
            .map(|endpoint| RoutePlan::Single { target: endpoint_to_route_target(endpoint, b.1) })
            .unwrap_or_else(|| RoutePlan::Reject {
                reason: "read/write splitting selected no endpoint".into(),
            }))
    }
}

#[cfg(test)]
mod test {
    use endpoint::endpoint::Endpoint;
    use indexmap::IndexMap;
    use loadbalance::balance::AlgorithmName;

    use crate::{
        config::{ReadWriteSplittingRule, RegexRule, TargetRole},
        readwritesplitting::{static_rw::ReadWriteSplittingStaticBuilder, ReadWriteEndpoint},
        route::{Route, RouteInput},
    };

    fn selected_addr(plan: gateway_core::RoutePlan) -> String {
        match plan {
            gateway_core::RoutePlan::Single { target } => target.endpoint.address,
            other => panic!("expected single target, got {:?}", other),
        }
    }

    #[test]
    fn test_route() {
        let rules = vec![
            ReadWriteSplittingRule::Regex(RegexRule {
                name: String::from("t1"),
                rule_type: String::from("regex"),
                regex: vec![String::from("^select")],
                target: TargetRole::Read,
                algorithm_name: AlgorithmName::Random,
                node_group_name: vec![],
            }),
            ReadWriteSplittingRule::Regex(RegexRule {
                name: String::from("t2"),
                rule_type: String::from("regex"),
                regex: vec![String::from("^insert")],
                target: TargetRole::ReadWrite,
                algorithm_name: AlgorithmName::Random,
                node_group_name: vec![],
            }),
        ];

        let default_target = TargetRole::ReadWrite;

        let rw_endpoint = ReadWriteEndpoint {
            read: vec![Endpoint {
                node_type: gateway_core::ProtocolKind::MySql,
                weight: 1,
                name: String::from("test1"),
                db: String::from("db"),
                user: String::from("user"),
                password: String::from("password"),
                addr: String::from("127.0.0.1"),
            }],
            readwrite: vec![Endpoint {
                node_type: gateway_core::ProtocolKind::MySql,
                weight: 1,
                name: String::from("test2"),
                db: String::from("db"),
                user: String::from("user"),
                password: String::from("password"),
                addr: String::from("127.0.0.2"),
            }],
        };

        let config = super::config::ReadWriteSplitting {
            statics: Some(super::config::ReadWriteSplittingStatic { default_target, rules }),
            dynamic: None,
        };

        let endpoint_group: IndexMap<String, ReadWriteEndpoint> = IndexMap::new();
        let mut rws = ReadWriteSplittingStaticBuilder::build(
            config.statics.unwrap(),
            None,
            endpoint_group,
            rw_endpoint,
        );
        let input = RouteInput::Statement("insert");
        let res = rws.dispatch(&input).unwrap();
        assert_eq!(selected_addr(res), "127.0.0.2");

        let input = RouteInput::Statement("set");
        let res = rws.dispatch(&input).unwrap();
        assert_eq!(selected_addr(res), "127.0.0.2");

        let input = RouteInput::None;
        let res = rws.dispatch(&input).unwrap();
        assert_eq!(selected_addr(res), "127.0.0.2");

        let input = RouteInput::Statement("select 1");
        let res = rws.dispatch(&input).unwrap();
        assert_eq!(selected_addr(res), "127.0.0.1");

        let input = RouteInput::Transaction("begin");
        let res = rws.dispatch(&input).unwrap();
        assert_eq!(selected_addr(res), "127.0.0.2");
    }
}
