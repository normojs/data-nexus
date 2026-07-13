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
use gateway_core::EndpointConfig;
use serde::{Deserialize, Serialize};

use crate::{random_weighted::RandomWeighted, roundrobin_weighted::RoundRobinWeighted};
pub struct Balance;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum AlgorithmName {
    Random,
    RoundRobin,
}

impl Default for AlgorithmName {
    fn default() -> Self {
        AlgorithmName::Random
    }
}

pub trait BalanceTarget: Clone {
    fn balance_name(&self) -> &str;
    fn balance_weight(&self) -> i64;
}

impl BalanceTarget for Endpoint {
    fn balance_name(&self) -> &str {
        &self.name
    }

    fn balance_weight(&self) -> i64 {
        self.weight
    }
}

impl BalanceTarget for EndpointConfig {
    fn balance_name(&self) -> &str {
        &self.name
    }

    fn balance_weight(&self) -> i64 {
        i64::from(self.weight)
    }
}

pub trait LoadBalance<T = Endpoint>
where
    T: BalanceTarget,
{
    fn next(&mut self) -> Option<T>;
    fn add(&mut self, endpoint: T);
    fn item_exists(&self, endpoint: &T) -> bool;
    fn get_all(&mut self) -> &Vec<T>;
    fn remove_item(&mut self, endpoint: T);
    fn remove_all(&mut self);
}

#[derive(Debug, Clone)]
pub enum BalanceType<T = Endpoint>
where
    T: BalanceTarget,
{
    Random(RandomWeighted<T>),
    RoundRobin(RoundRobinWeighted<T>),
}

impl<T> LoadBalance<T> for BalanceType<T>
where
    T: BalanceTarget,
{
    fn next(&mut self) -> Option<T> {
        match self {
            BalanceType::Random(inner_random) => inner_random.next(),
            BalanceType::RoundRobin(inner_roundrobin) => inner_roundrobin.next(),
        }
    }

    fn add(&mut self, endpoint: T) {
        match self {
            BalanceType::Random(inner_random) => inner_random.add(endpoint),
            BalanceType::RoundRobin(inner_roundrobin) => inner_roundrobin.add(endpoint),
        }
    }

    fn item_exists(&self, endpoint: &T) -> bool {
        match self {
            BalanceType::Random(inner_random) => inner_random.item_exists(endpoint),
            BalanceType::RoundRobin(inner_roundrobin) => inner_roundrobin.item_exists(endpoint),
        }
    }

    fn get_all(&mut self) -> &Vec<T> {
        match self {
            BalanceType::Random(inner_random) => inner_random.get_all(),
            BalanceType::RoundRobin(inner_roundrobin) => inner_roundrobin.get_all(),
        }
    }
    fn remove_item(&mut self, endpoint: T) {
        match self {
            BalanceType::Random(inner_random) => inner_random.remove_item(endpoint),
            BalanceType::RoundRobin(inner_roundrobin) => inner_roundrobin.remove_item(endpoint),
        }
    }

    fn remove_all(&mut self) {
        match self {
            BalanceType::Random(inner_random) => inner_random.remove_all(),
            BalanceType::RoundRobin(inner_roundrobin) => inner_roundrobin.remove_all(),
        }
    }
}

impl Balance {
    pub fn build_balance<T>(&mut self, algorithm_name: AlgorithmName) -> BalanceType<T>
    where
        T: BalanceTarget,
    {
        match algorithm_name {
            AlgorithmName::Random => BalanceType::Random(RandomWeighted::default()),
            AlgorithmName::RoundRobin => BalanceType::RoundRobin(RoundRobinWeighted::default()),
        }
    }
}

#[cfg(test)]
mod test {
    use gateway_core::{EndpointConfig, EndpointRole, ProtocolKind};

    use super::*;

    #[test]
    fn load_balancer() {
        // let mut balance = Balance.build_balance(AlgorithmName::Random);
        let mut balance = Balance.build_balance(AlgorithmName::RoundRobin);
        let ep1 = Endpoint {
            node_type: ProtocolKind::MySql,
            weight: 1,
            name: String::from("dasheng001"),
            db: String::from("db001"),
            user: String::from("root"),
            password: String::from("root"),
            addr: String::from("127.0.0.1:3306"),
        };
        let ep2 = Endpoint {
            node_type: ProtocolKind::MySql,
            weight: 1,
            name: String::from("dasheng002"),
            db: String::from("db002"),
            user: String::from("root"),
            password: String::from("root"),
            addr: String::from("127.0.0.1:3307"),
        };
        balance.add(ep1);
        balance.add(ep2);
        assert_eq!(balance.next().unwrap().name, String::from("dasheng001"));
        assert_eq!(balance.next().unwrap().name, String::from("dasheng002"));
    }

    #[test]
    fn gateway_endpoint_config_load_balancer() {
        let mut balance = Balance.build_balance::<EndpointConfig>(AlgorithmName::RoundRobin);
        balance.add(EndpointConfig {
            name: "pg-primary".into(),
            protocol: ProtocolKind::PostgreSql,
            address: "127.0.0.1:5432".into(),
            database: Some("orders".into()),
            username: "app".into(),
            password: "secret".into(),
            role: EndpointRole::ReadWrite,
            weight: 1,
        });
        balance.add(EndpointConfig {
            name: "pg-replica".into(),
            protocol: ProtocolKind::PostgreSql,
            address: "127.0.0.1:5433".into(),
            database: Some("orders".into()),
            username: "app".into(),
            password: "secret".into(),
            role: EndpointRole::Read,
            weight: 1,
        });

        assert_eq!(balance.next().unwrap().name, "pg-primary");
        assert_eq!(balance.next().unwrap().protocol, ProtocolKind::PostgreSql);
        assert_eq!(balance.next().unwrap().name, "pg-primary");
    }
}
