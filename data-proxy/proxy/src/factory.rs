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
use tokio_util::sync::CancellationToken;

pub enum ProxyKind {
    #[deprecated(note = "使用UNISQL")]
    MySQL,
    UNISQL,
    ShardingSphereProxy,
    PostgreSQL,
}

#[derive(Clone, Debug)]
pub struct ShutdownHandle {
    token: CancellationToken,
}

impl ShutdownHandle {
    pub fn new() -> Self {
        Self { token: CancellationToken::new() }
    }

    pub fn shutdown(&self) {
        self.token.cancel();
    }

    pub fn is_shutdown_requested(&self) -> bool {
        self.token.is_cancelled()
    }

    pub async fn cancelled(&self) {
        self.token.cancelled().await;
    }
}

impl Default for ShutdownHandle {
    fn default() -> Self {
        Self::new()
    }
}

pub struct StartSource {
    pub thread_handles: Vec<JoinHandle<()>>,
    pub shutdown_handle: ShutdownHandle,
}

impl StartSource {
    pub fn new(shutdown_handle: ShutdownHandle) -> Self {
        Self { thread_handles: Vec::new(), shutdown_handle }
    }
}

impl Default for StartSource {
    fn default() -> Self {
        Self::new(ShutdownHandle::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shutdown_handle_notifies_clones() {
        let handle = ShutdownHandle::new();
        let cloned = handle.clone();

        handle.shutdown();
        cloned.cancelled().await;

        assert!(cloned.is_shutdown_requested());
    }
}

#[async_trait::async_trait]
pub trait Proxy {
    // async fn start(&mut self, start_source: &StartSource) -> Result<StartSource, Error>;
    async fn start(&mut self) -> Result<StartSource, Error>;
    async fn stop(&mut self) -> Result<(), Error>;
    fn shutdown_handle(&self) -> ShutdownHandle;
}

pub trait ProxyFactory {
    fn build_proxy(&self) -> Box<dyn Proxy + Send>;
}
