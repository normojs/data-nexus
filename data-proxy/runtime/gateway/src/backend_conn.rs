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

use conn_pool::{ConnAttrMut, Pool, PoolConn};
use mysql_protocol::client::conn::ClientConn;
use pisa_error::error::{Error, ErrorKind};
use tracing::debug;

pub async fn check_get_conn<A>(
    pool: Pool<ClientConn>,
    endpoint: &str,
    attrs: &[A],
) -> Result<PoolConn<ClientConn>, Error>
where
    ClientConn: ConnAttrMut<Item = A>,
    A: Send + Sync,
{
    match pool.get_conn_with_endpoint_session(endpoint, attrs).await {
        Ok(client_conn) => {
            if !client_conn.is_ready().await {
                return pool
                    .rebuild_conn_with_session(endpoint, attrs)
                    .await
                    .map_err(|e| Error::new(ErrorKind::Protocol(e)));
            }
            Ok(client_conn)
        }
        Err(err) => {
            debug!("check_get_conn err {:?}", err);
            Err(Error::new(ErrorKind::Protocol(err)))
        }
    }
}
