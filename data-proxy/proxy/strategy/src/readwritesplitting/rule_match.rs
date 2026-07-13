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

use std::error::Error;

use endpoint::endpoint::Endpoint;
use indexmap::IndexMap;
use loadbalance::balance::{AlgorithmName, Balance, BalanceTarget, BalanceType, LoadBalance};
use regex::Regex;

use super::ReadWriteEndpoint;
use crate::{
    config::{GenericRule, NodeGroup, ReadWriteSplittingRule, RegexRule, TargetRole},
    readwritesplitting::*,
    route::{RouteBalance, RouteRuleMatch, StragegyError},
    RouteInput,
};

pub struct RulesMatchBuilder;

impl RulesMatchBuilder {
    pub fn build<T>(
        rules: Vec<ReadWriteSplittingRule>,
        default_target: TargetRole,
        _node_group_config: Option<NodeGroup>,
        endpoint_group: IndexMap<String, ReadWriteEndpoint<T>>,
        rw_endpoint: ReadWriteEndpoint<T>,
    ) -> RulesMatch<T>
    where
        T: BalanceTarget,
    {
        let inner = RulesMatchBuilder::build_rules(
            rules.clone(),
            endpoint_group,
            rw_endpoint.clone(),
            default_target.clone(),
        );
        let default_balance =
            RulesMatchBuilder::build_default_balance(&default_target, rw_endpoint.clone());

        let default_trans_balance =
            RulesMatchBuilder::build_default_balance(&TargetRole::ReadWrite, rw_endpoint);

        let rules_match = RulesMatch {
            default_target: default_target.clone(),
            default_trans_balance,
            inner,
            default_balance,
        };

        return rules_match;
    }

    pub fn build_rules<T>(
        rules: Vec<ReadWriteSplittingRule>,
        endpoint_group: IndexMap<String, ReadWriteEndpoint<T>>,
        rw_endpoint: ReadWriteEndpoint<T>,
        default_target: TargetRole,
    ) -> Vec<RulesMatchInner<T>>
    where
        T: BalanceTarget,
    {
        let mut instances: Vec<RulesMatchInner<T>> = Vec::with_capacity(rules.clone().len());
        let mut generic_instances: Vec<RulesMatchInner<T>> =
            Vec::with_capacity(rules.clone().len());
        for r in &rules {
            match r {
                ReadWriteSplittingRule::Regex(r) => {
                    let inner = RegexRuleMatchInner::new(
                        r.clone(),
                        endpoint_group.clone(),
                        rw_endpoint.clone(),
                    )
                    .unwrap();
                    instances.push(RulesMatchInner::Regex(inner));
                }
                ReadWriteSplittingRule::Generic(r) => {
                    let inner = GenericRuleMatchInner::new(
                        r.clone(),
                        default_target.clone(),
                        rw_endpoint.clone(),
                    );
                    generic_instances.push(RulesMatchInner::Generic(inner));
                }
            }
        }

        instances.extend_from_slice(&generic_instances);

        instances
    }

    pub fn build_default_balance<T>(
        default_target: &TargetRole,
        rw_endpoint: ReadWriteEndpoint<T>,
    ) -> BalanceType<T>
    where
        T: BalanceTarget,
    {
        let mut default_balance = Balance.build_balance(AlgorithmName::Random);
        match default_target {
            TargetRole::Read => balance_add_endpoint(&mut default_balance, rw_endpoint.read),
            TargetRole::ReadWrite => {
                balance_add_endpoint(&mut default_balance, rw_endpoint.readwrite)
            }
        }
        default_balance
    }
}

pub struct RulesMatch<T = Endpoint>
where
    T: BalanceTarget,
{
    pub default_target: TargetRole,
    pub default_balance: BalanceType<T>,
    // Default transaction balance
    pub default_trans_balance: BalanceType<T>,
    pub inner: Vec<RulesMatchInner<T>>,
}

#[derive(Clone)]
pub enum RulesMatchInner<T = Endpoint>
where
    T: BalanceTarget,
{
    Regex(RegexRuleMatchInner<T>),
    Generic(GenericRuleMatchInner<T>),
}

// Retrun balance when match success, otherwise return default_balance
impl<T> RouteBalance<T> for RulesMatch<T>
where
    T: BalanceTarget,
{
    fn get(&mut self, input: &RouteInput) -> (&mut BalanceType<T>, TargetRole) {
        // Currently, if RouteInput variant type is Transaction, return readwrite balnace directly.
        if let RouteInput::Transaction(_) = input {
            return (&mut self.default_trans_balance, TargetRole::ReadWrite);
        }

        for rule in self.inner.iter_mut() {
            match rule {
                RulesMatchInner::Regex(inner) => {
                    if inner.is_match(input) {
                        return inner.get(input);
                    }
                }
                RulesMatchInner::Generic(inner) => {
                    if inner.is_match(input) {
                        return inner.get(input);
                    }
                }
            }
        }

        (&mut self.default_balance, self.default_target.clone())
    }
}

#[derive(Clone)]
pub struct RegexRuleMatchInner<T = Endpoint>
where
    T: BalanceTarget,
{
    rule: RegexRule,
    regexs: Vec<Regex>,
    balance: IndexMap<String, BalanceType<T>>,
}

impl<T> RegexRuleMatchInner<T>
where
    T: BalanceTarget,
{
    fn new(
        rule: RegexRule,
        endpoint_group: IndexMap<String, ReadWriteEndpoint<T>>,
        rw_endpoint: ReadWriteEndpoint<T>,
    ) -> Result<RegexRuleMatchInner<T>, Box<dyn Error>> {
        let balance = RegexRuleMatchInner::build_balance(
            &rule,
            rule.algorithm_name.clone(),
            endpoint_group,
            rw_endpoint,
        )?;
        let regexs: Vec<Regex> = rule
            .regex
            .iter()
            .map(|r| Regex::new(r))
            .collect::<Result<Vec<Regex>, regex::Error>>()?;

        Ok(RegexRuleMatchInner { rule, regexs, balance })
    }

    fn build_balance(
        rule: &RegexRule,
        algorithm_name: AlgorithmName,
        endpoint_group: IndexMap<String, ReadWriteEndpoint<T>>,
        rw_endpoint: ReadWriteEndpoint<T>,
    ) -> Result<IndexMap<String, BalanceType<T>>, Box<dyn Error>> {
        let target = &rule.target;
        let mut balances = IndexMap::<String, BalanceType<T>>::new();
        let mut global_balance = Balance.build_balance(algorithm_name.clone());
        Self::build_balance_inner(&mut global_balance, target, rw_endpoint.clone());

        if endpoint_group.is_empty() || rule.node_group_name.is_empty() {
            balances.insert("GLOBAL".to_string(), global_balance);
            return Ok(balances);
        }

        balances.insert("GLOBAL".to_string(), global_balance);

        for group in rule.node_group_name.iter() {
            let mut balance = Balance.build_balance(algorithm_name.clone());
            let rw_endpoint = endpoint_group.get(group);
            match rw_endpoint {
                Some(rw) => {
                    Self::build_balance_inner(&mut balance, target, rw.clone());
                }

                None => {
                    return Err(Box::new(StragegyError::NodeGroupNotFound(group.clone())));
                }
            }

            balances.insert(group.to_string(), balance);
        }

        Ok(balances)
    }

    fn build_balance_inner(
        balance: &mut BalanceType<T>,
        target: &TargetRole,
        rw_endpoint: ReadWriteEndpoint<T>,
    ) {
        match target {
            TargetRole::Read => {
                if rw_endpoint.read.len() == 0 {
                    balance_add_endpoint(balance, rw_endpoint.readwrite);
                } else {
                    balance_add_endpoint(balance, rw_endpoint.read);
                }
            }

            TargetRole::ReadWrite => {
                balance_add_endpoint(balance, rw_endpoint.readwrite);
            }
        }
    }
}

impl<T> RouteRuleMatch for RegexRuleMatchInner<T>
where
    T: BalanceTarget,
{
    fn is_match(&self, input: &RouteInput) -> bool {
        match input {
            RouteInput::Statement(val) | RouteInput::Transaction(val) => {
                self.regexs.iter().any(|r| r.is_match(val))
            }

            RouteInput::ShardingStatement(val, _) => self.regexs.iter().any(|r| r.is_match(val)),

            RouteInput::ShardingTransaction(val, _) => self.regexs.iter().any(|r| r.is_match(val)),

            RouteInput::None => false,
            _ => unreachable!(),
        }
    }
}

impl<T> RouteBalance<T> for RegexRuleMatchInner<T>
where
    T: BalanceTarget,
{
    fn get(&mut self, input: &RouteInput) -> (&mut BalanceType<T>, TargetRole) {
        match input {
            RouteInput::ShardingStatement(_, node_group)
            | RouteInput::ShardingTransaction(_, node_group) => {
                let key = if self.balance.contains_key(node_group) {
                    node_group.as_str()
                } else {
                    "GLOBAL"
                };
                let balance = self
                    .balance
                    .get_mut(key)
                    .expect("regex rule balance is initialized with at least one target group");
                (balance, self.rule.target.clone())
            }

            _ => {
                let balance = self
                    .balance
                    .get_mut("GLOBAL")
                    .expect("regex rule balance is initialized with a GLOBAL target group");
                (balance, self.rule.target.clone())
            }
        }
    }
}

fn balance_add_endpoint<T>(balance: &mut BalanceType<T>, endpoints: Vec<T>)
where
    T: BalanceTarget,
{
    for ep in endpoints {
        balance.add(ep);
    }
}

#[derive(Clone)]
pub struct GenericRuleMatchInner<T = Endpoint>
where
    T: BalanceTarget,
{
    r_balance: BalanceType<T>,
    rw_balance: BalanceType<T>,
    default_balance: BalanceType<T>,
    default_target_role: TargetRole,
}

impl<T> GenericRuleMatchInner<T>
where
    T: BalanceTarget,
{
    fn new(
        rule: GenericRule,
        default_target_role: TargetRole,
        rw_endpoint: ReadWriteEndpoint<T>,
    ) -> GenericRuleMatchInner<T> {
        let r_balance = GenericRuleMatchInner::build_balance(
            TargetRole::Read,
            rule.algorithm_name.clone(),
            rw_endpoint.clone(),
        );
        let rw_balance = GenericRuleMatchInner::build_balance(
            TargetRole::ReadWrite,
            rule.algorithm_name.clone(),
            rw_endpoint.clone(),
        );
        let default_balance = GenericRuleMatchInner::build_balance(
            default_target_role.clone(),
            rule.algorithm_name,
            rw_endpoint,
        );
        GenericRuleMatchInner { r_balance, rw_balance, default_balance, default_target_role }
    }

    fn build_balance(
        role: TargetRole,
        algorithm_name: AlgorithmName,
        rw_endpoint: ReadWriteEndpoint<T>,
    ) -> BalanceType<T> {
        let mut balance = Balance.build_balance(algorithm_name);

        match role {
            TargetRole::Read => {
                if rw_endpoint.read.len() == 0 {
                    balance_add_endpoint(&mut balance, rw_endpoint.readwrite);
                }
                balance_add_endpoint(&mut balance, rw_endpoint.read);
            }

            TargetRole::ReadWrite => {
                balance_add_endpoint(&mut balance, rw_endpoint.readwrite);
            }
        };

        balance
    }
}

impl<T> RouteRuleMatch for GenericRuleMatchInner<T>
where
    T: BalanceTarget,
{
    fn is_match(&self, input: &RouteInput) -> bool {
        match input {
            RouteInput::Statement(sql) | RouteInput::Transaction(sql) => {
                let str_vec: Vec<&str> = sql.split(" ").collect();
                let token = str_vec[0].to_uppercase();
                if GENERIC_RULE_TOKEN.contains_key(&*token) {
                    return true;
                } else {
                    return false;
                }
            }

            RouteInput::None => false,
            _ => unreachable!(),
        }
    }
}

impl<T> RouteBalance<T> for GenericRuleMatchInner<T>
where
    T: BalanceTarget,
{
    fn get(&mut self, input: &RouteInput) -> (&mut BalanceType<T>, TargetRole) {
        match input {
            RouteInput::Statement(sql) => match sql.split_once(' ') {
                Some(key_word) => {
                    let key_word = key_word.0.to_uppercase();
                    let token = key_word.trim();
                    match token {
                        "SELECT" => (&mut self.r_balance, TargetRole::Read),
                        "INSERT" => (&mut self.rw_balance, TargetRole::ReadWrite),
                        "UPDATE" => (&mut self.rw_balance, TargetRole::ReadWrite),
                        "DELETE" => (&mut self.rw_balance, TargetRole::ReadWrite),
                        "SET" => (&mut self.rw_balance, TargetRole::ReadWrite),
                        "START" => (&mut self.rw_balance, TargetRole::ReadWrite),
                        _ => (&mut self.default_balance, self.default_target_role.clone()),
                    }
                }
                None => (&mut self.default_balance, self.default_target_role.clone()),
            },
            RouteInput::Transaction(_) => (&mut self.rw_balance, TargetRole::ReadWrite),
            RouteInput::None => (&mut self.default_balance, self.default_target_role.clone()),
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod test {
    use endpoint::endpoint::Endpoint;
    use gateway_core::{EndpointConfig, EndpointRole, ProtocolKind};
    use indexmap::IndexMap;
    use loadbalance::balance::*;

    use super::RulesMatchBuilder;
    use crate::{config::*, readwritesplitting::ReadWriteEndpoint, RouteBalance, RouteInput};

    fn gateway_endpoint(name: &str, role: EndpointRole) -> EndpointConfig {
        EndpointConfig {
            name: name.into(),
            protocol: ProtocolKind::PostgreSql,
            address: format!("127.0.0.1:{}", if role == EndpointRole::Read { 5433 } else { 5432 }),
            database: Some("orders".into()),
            username: "app".into(),
            password: "secret".into(),
            role,
            weight: 1,
        }
    }

    #[test]
    fn test_regex_match() {
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
                target: TargetRole::Read,
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

        let endpoint_group = IndexMap::new();
        let mut m =
            RulesMatchBuilder::build(rules, default_target, None, endpoint_group, rw_endpoint);
        let (b, target) = m.get(&RouteInput::Statement("insert"));
        let endpoint = b.next();
        assert_eq!(target, TargetRole::Read);
        assert_eq!(endpoint.unwrap().name, "test1");
        let (b, target) = m.get(&RouteInput::Statement("create"));
        let endpoint = b.next();
        assert_eq!(target, TargetRole::ReadWrite);
        assert_eq!(endpoint.unwrap().name, "test2");
    }

    #[test]
    fn rules_match_gateway_endpoint_config_targets() {
        let rules = vec![ReadWriteSplittingRule::Generic(GenericRule {
            name: "generic".into(),
            rule_type: "generic".into(),
            algorithm_name: AlgorithmName::RoundRobin,
            node_group_name: vec![],
        })];

        let rw_endpoint = ReadWriteEndpoint {
            read: vec![gateway_endpoint("pg-replica", EndpointRole::Read)],
            readwrite: vec![gateway_endpoint("pg-primary", EndpointRole::ReadWrite)],
        };

        let endpoint_group = IndexMap::new();
        let mut matcher = RulesMatchBuilder::build(
            rules,
            TargetRole::ReadWrite,
            None,
            endpoint_group,
            rw_endpoint,
        );

        let (balance, target) = matcher.get(&RouteInput::Statement("select 1"));
        let selected = balance.next().unwrap();
        assert_eq!(target, TargetRole::Read);
        assert_eq!(selected.name, "pg-replica");
        assert_eq!(selected.protocol, ProtocolKind::PostgreSql);

        let (balance, target) = matcher.get(&RouteInput::Statement("insert into t values (1)"));
        let selected = balance.next().unwrap();
        assert_eq!(target, TargetRole::ReadWrite);
        assert_eq!(selected.name, "pg-primary");
        assert_eq!(selected.protocol, ProtocolKind::PostgreSql);
    }
}
