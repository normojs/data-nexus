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

use std::io::Error;

use tokio::net::{TcpListener, TcpStream};
use tracing::info;

/// TCP listener bootstrap for one gateway frontend.
///
/// `protocol` is informational (logging only). Routing and backend selection
/// use gateway_core ProtocolKind / RoutePlan, not this string field.
pub struct Listener {
    pub name: String,
    pub listen_addr: String,
    /// Frontend protocol label for logs (e.g. "mysql", "postgresql").
    pub protocol: String,
    pub server_version: String,
}

impl Listener {
    pub fn build_listener(&mut self) -> Result<TcpListener, Error> {
        info!(
            "gateway listener {:?} protocol={:?} addr={:?} server_version={:?}",
            self.name, self.protocol, self.listen_addr, self.server_version
        );
        let listener = {
            let std_listener = match std::net::TcpListener::bind(self.listen_addr.clone()) {
                Err(err) => return Err(err),
                Ok(listener) => listener,
            };
            if let Err(err) = std_listener.set_nonblocking(true) {
                return Err(err);
            }
            TcpListener::from_std(std_listener).expect("listener must be valid")
        };
        Ok(listener)
    }

    pub async fn accept(&mut self, listener: &TcpListener) -> Result<TcpStream, Error> {
        let (socket, addr) = match listener.accept().await {
            Ok((socket, addr)) => (socket, addr),
            Err(err) => return Err(err),
        };

        info!(
            "gateway listener {:?} accepted client_ip={:?} protocol={:?}",
            self.name,
            addr.ip(),
            self.protocol
        );

        socket.set_nodelay(true)?;
        Ok(socket)
    }
}
