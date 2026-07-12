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

use pisa_error::error::Error;
use tokio::task::JoinHandle;

pub enum ProxyKind {
    #[deprecated(note = "使用UNISQL")]
    MySQL,
    UNISQL,
    ShardingSphereProxy,
    PostgreSQL,
}

pub struct StartSource {
    pub thread_handles: Vec<JoinHandle<()>>,
    // pub sender: crossbeam_channel::Sender<()>,
}

#[async_trait::async_trait]
pub trait Proxy {
    // async fn start(&mut self, start_source: &StartSource) -> Result<StartSource, Error>;
    async fn start(&mut self) -> Result<StartSource, Error>;
    async fn stop(&mut self) -> Result<(), Error>;
}

pub trait ProxyFactory {
    fn build_proxy(&self) -> Box<dyn Proxy + Send>;
}
