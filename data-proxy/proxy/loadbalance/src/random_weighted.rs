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

use chrono::prelude::*;
use endpoint::endpoint::Endpoint;
use rand::{rngs::StdRng, Rng, SeedableRng};

use crate::balance::{BalanceTarget, LoadBalance};

#[derive(Debug, Clone)]
pub struct RandomWeighted<T = Endpoint>
where
    T: BalanceTarget,
{
    pub items: Vec<T>,
    pub n: i64,
    pub sum_of_weights: i64,
    pub r: StdRng,
}

impl<T> Default for RandomWeighted<T>
where
    T: BalanceTarget,
{
    fn default() -> RandomWeighted<T> {
        RandomWeighted {
            items: vec![],
            n: 0,
            sum_of_weights: 0,
            r: StdRng::seed_from_u64(Utc::now().timestamp_subsec_nanos().into()),
        }
    }
}

impl<T> LoadBalance<T> for RandomWeighted<T>
where
    T: BalanceTarget,
{
    // next: get next endpoint
    fn next(&mut self) -> Option<T> {
        if self.n == 0 {
            return None;
        }

        if self.sum_of_weights <= 0 {
            return None;
        }
        let mut random_weight = self.r.gen_range(0..self.sum_of_weights) + 1;
        for i in &self.items {
            random_weight -= i.balance_weight();
            if random_weight <= 0 {
                return Some(i.clone());
            }
        }

        self.items.get(self.items.len() - 1).map(|endpoint| endpoint.clone())
    }

    // add: add endpoint
    fn add(&mut self, endpoint: T) {
        if !self.item_exists(&endpoint) {
            self.sum_of_weights += endpoint.balance_weight();
            self.n += 1;
            self.items.push(endpoint);
        }
    }

    // item_exists: endpoint exists
    fn item_exists(&self, endpoint: &T) -> bool {
        self.items.iter().any(|x| x.balance_name() == endpoint.balance_name())
    }

    // get_all: get all endpoint
    fn get_all(&mut self) -> &Vec<T> {
        &self.items
    }

    // remove_item: remove item
    fn remove_item(&mut self, endpoint: T) {
        if let Some(index) =
            self.items.iter().position(|x| x.balance_name() == endpoint.balance_name())
        {
            let removed = self.items.remove(index);
            self.sum_of_weights -= removed.balance_weight();
            self.n -= 1;
        }
    }

    // remove_all: remove all item
    fn remove_all(&mut self) {
        self.items = vec![];
        self.n = 0;
        self.sum_of_weights = 0;
        self.r = StdRng::seed_from_u64(Utc::now().timestamp_subsec_nanos().into());
    }
}
