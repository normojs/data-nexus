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

use crate::balance::{BalanceTarget, LoadBalance};

#[derive(Debug, Clone)]
pub struct RoundRobinWeighted<T = Endpoint>
where
    T: BalanceTarget,
{
    pub items: Vec<T>,
    pub n: i64,
    pub gcd: i64,
    pub max_weight: i64,
    pub i: i64,
    pub cw: i64,
}

impl<T> Default for RoundRobinWeighted<T>
where
    T: BalanceTarget,
{
    fn default() -> Self {
        Self { items: vec![], n: 0, gcd: 0, max_weight: 0, i: -1, cw: 0 }
    }
}

impl<T> LoadBalance<T> for RoundRobinWeighted<T>
where
    T: BalanceTarget,
{
    fn add(&mut self, endpoint: T) {
        if self.item_exists(&endpoint) {
            return;
        }

        let weight = endpoint.balance_weight();
        if weight > 0 {
            if self.gcd == 0 {
                self.gcd = weight;
                self.max_weight = weight;
                self.i = -1;
                self.cw = 0
            } else {
                self.gcd = gcd(self.gcd, weight);
                if self.max_weight < weight {
                    self.max_weight = weight;
                }
            }
        }
        self.items.push(endpoint);
        self.n += 1;
    }

    fn next(&mut self) -> Option<T> {
        if self.n == 0 {
            return None;
        }

        if self.n == 1 {
            return self.items.get(0).map(|endpoint| endpoint.clone());
        }

        loop {
            self.i = (self.i + 1) % self.n;
            if self.i == 0 {
                self.cw -= self.gcd;
                if self.cw <= 0 {
                    self.cw = self.max_weight;
                    if self.cw == 0 {
                        return None;
                    }
                }
            }

            if self.items[self.i as usize].balance_weight() >= self.cw {
                return self.items.get(self.i as usize).map(|endpoint| endpoint.clone());
            }
        }
    }

    fn item_exists(&self, endpoint: &T) -> bool {
        self.items.iter().any(|x| x.balance_name() == endpoint.balance_name())
    }

    fn get_all(&mut self) -> &Vec<T> {
        &self.items
    }

    fn remove_item(&mut self, endpoint: T) {
        if let Some(index) =
            self.items.iter().position(|x| x.balance_name() == endpoint.balance_name())
        {
            self.items.remove(index);
            self.rebuild_weight_state();
        }
    }
    fn remove_all(&mut self) {
        self.items = vec![];
        self.n = 0;
        self.gcd = 0;
        self.max_weight = 0;
        self.i = -1;
        self.cw = 0;
    }
}

impl<T> RoundRobinWeighted<T>
where
    T: BalanceTarget,
{
    fn rebuild_weight_state(&mut self) {
        self.n = 0;
        self.gcd = 0;
        self.max_weight = 0;
        self.i = -1;
        self.cw = 0;

        for item in &self.items {
            let weight = item.balance_weight();
            if weight > 0 {
                self.gcd = if self.gcd == 0 { weight } else { gcd(self.gcd, weight) };
                if self.max_weight < weight {
                    self.max_weight = weight;
                }
            }
            self.n += 1;
        }
    }
}

#[inline]
fn gcd(mut x: i64, mut y: i64) -> i64 {
    loop {
        let t = x % y;
        if t > 0 {
            x = y;
            y = t;
        } else {
            return y;
        }
    }
}
