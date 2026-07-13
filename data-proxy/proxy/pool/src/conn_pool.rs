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

use std::{
    fmt::Debug,
    ops::{Deref, DerefMut},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use async_trait::async_trait;
use crossbeam_queue::ArrayQueue;
use dashmap::DashMap;
use tokio::time::{sleep, Duration};
use tracing::{debug, info};

/// In order to be managed by the connection pool, Both the `ConnLike` and `ConnAttr` trait
/// needs to be implemented.
#[async_trait]
pub trait ConnLike: Sized + Send + Sync + std::fmt::Debug + 'static {
    type Error: Send + std::fmt::Debug + 'static;

    // Method for create connection.
    async fn build_conn(&self) -> Result<Self, Self::Error>;

    // Method for connection health check.
    async fn ping(&mut self) -> Result<(), Self::Error>;
}

/// `ConnAttr` traits is used to get attribute of current connection  
pub trait ConnAttr {
    fn get_host(&self) -> String;
    fn get_port(&self) -> u16;
    fn get_user(&self) -> String;
    fn get_endpoint(&self) -> String;
    // Get current db on conn
    fn get_db(&self) -> Option<String>;
    // Get current charset
    fn get_charset(&self) -> Option<String>;
    // Get current autocommit status
    fn get_autocommit(&self) -> Option<String>;
}

#[async_trait]
pub trait ConnAttrMut {
    type Item: Send + Sync;
    async fn init(&mut self, _items: &[Self::Item]) {}
}

#[derive(Debug)]
pub struct PoolInner<T: ConnLike + ConnAttr + ConnAttrMut> {
    pub inner: ArrayQueue<T>,
    generation: AtomicU64,
}

impl<T: ConnLike + ConnAttr + ConnAttrMut> PoolInner<T> {
    fn new(size: usize) -> PoolInner<T> {
        PoolInner { inner: ArrayQueue::new(size), generation: AtomicU64::new(0) }
    }

    fn get_conn(&self) -> Option<T> {
        self.inner.pop()
    }

    fn put_conn(&self, conn: T) {
        if !self.inner.is_full() {
            let _ = self.inner.push(conn);
        }
    }

    fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    fn refresh(&self) -> usize {
        let mut cleared = 0;
        while self.inner.pop().is_some() {
            cleared += 1;
        }
        self.generation.fetch_add(1, Ordering::SeqCst);
        cleared
    }
}

#[derive(Debug)]
pub struct PoolConn<T>
where
    T: ConnLike + ConnAttr + ConnAttrMut,
{
    pub pool: Arc<DashMap<String, PoolInner<T>>>,
    pub conn: Option<T>,
    generation: u64,
}

#[derive(Debug, Clone)]
pub struct Pool<T>
where
    T: ConnLike + ConnAttr + ConnAttrMut,
{
    factory: Arc<DashMap<String, T>>,
    size: usize,
    pool: Arc<DashMap<String, PoolInner<T>>>,
}

impl<T> Pool<T>
where
    T: ConnLike + ConnAttr + ConnAttrMut + std::default::Default,
{
    pub fn new(size: usize) -> Pool<T> {
        Pool {
            factory: Arc::new(DashMap::new()),
            size,
            pool: Arc::new(DashMap::<String, PoolInner<T>>::new()),
        }
    }

    pub fn set_factory(&self, endpoint: &str, factory: T) {
        if self.factory.get(endpoint).is_none() {
            self.factory.insert(endpoint.to_string(), factory);
        }
    }

    pub async fn rebuild_conn(&self, endpoint: &str) -> Result<PoolConn<T>, T::Error> {
        let generation = self.ensure_pool_inner(endpoint);
        let conn = self.factory.get(endpoint).as_ref().unwrap().build_conn().await?;
        Ok(PoolConn { pool: Arc::clone(&self.pool), conn: Some(conn), generation })
    }

    pub async fn rebuild_conn_with_session(
        &self,
        endpoint: &str,
        attrs: &[<T as ConnAttrMut>::Item],
    ) -> Result<PoolConn<T>, T::Error> {
        let generation = self.ensure_pool_inner(endpoint);
        let mut conn = self.factory.get(endpoint).as_ref().unwrap().build_conn().await?;
        self.reinit_session(&mut conn, attrs).await;
        Ok(PoolConn { pool: Arc::clone(&self.pool), conn: Some(conn), generation })
    }

    pub async fn get_conn_with_endpoint_session(
        &self,
        endpoint: &str,
        attrs: &[<T as ConnAttrMut>::Item],
    ) -> Result<PoolConn<T>, T::Error> {
        let (mut conn, generation) = self.get_conn_with_endpoint_with_generation(endpoint).await?;
        self.reinit_session(&mut conn, attrs).await;

        Ok(PoolConn { pool: Arc::clone(&self.pool), conn: Some(conn), generation })
    }

    // Get connection by endpoint attribute
    pub async fn get_conn_with_endpoint(&self, endpoint: &str) -> Result<T, T::Error> {
        self.get_conn_with_endpoint_with_generation(endpoint).await.map(|(conn, _generation)| conn)
    }

    async fn get_conn_with_endpoint_with_generation(
        &self,
        endpoint: &str,
    ) -> Result<(T, u64), T::Error> {
        let generation = self.ensure_pool_inner(endpoint);
        let conn = self.pool.get(endpoint);
        let conn = match conn {
            Some(val) => val.get_conn(),
            None => None,
        };

        let conn = match conn {
            Some(conn) => Some(conn),
            None => {
                if !self.pool.contains_key(endpoint) {
                    self.pool.insert(endpoint.to_string(), PoolInner::new(self.size));
                }

                let try_conn = self.factory.get(endpoint).as_ref().unwrap().build_conn().await;
                match try_conn {
                    Ok(conn) => return Ok((conn, generation)),
                    Err(_) => None,
                }
            }
        };

        if let Some(mut conn) = conn {
            if let Ok(_) = conn.ping().await {
                return Ok((conn, generation));
            }
        }

        // TODO: interval as a parameter, the default is 3 seconds.
        let mut interval = 3;
        // TODO: The count of retries as a parameter, the default is 10.
        for i in 0..10 {
            let try_conn = self.factory.get(endpoint).as_ref().unwrap().build_conn().await;
            match try_conn {
                Ok(conn) => {
                    info!("Retry successful");
                    return Ok((conn, generation));
                }
                Err(err) => {
                    // error!("Retry failed: {}", Err(err.into()));
                    println!("Retry failed: {:?}", err);
                    if i == 9 {
                        info!("Exceeded retry count of {}", 10);
                        return Err(err);
                    }
                }
            }

            info!("The {} retry build conn", i + 1);

            sleep(Duration::from_secs(interval)).await;
            interval *= 2;
        }

        unreachable!()
    }

    async fn reinit_session(&self, conn: &mut T, attrs: &[<T as ConnAttrMut>::Item]) {
        conn.init(attrs).await
    }

    pub fn len(&self, endpoint: &str) -> usize {
        match self.pool.get(endpoint) {
            Some(inner) => inner.inner.len(),
            None => 0,
        }
    }

    pub fn refresh_endpoint(&self, endpoint: &str) -> usize {
        match self.pool.get(endpoint) {
            Some(inner) => inner.refresh(),
            None => 0,
        }
    }

    pub fn capacity(&self) -> usize {
        self.size
    }

    pub fn factory_endpoints(&self) -> Vec<String> {
        self.factory.iter().map(|entry| entry.key().clone()).collect()
    }

    pub fn pooled_endpoints(&self) -> Vec<String> {
        self.pool.iter().map(|entry| entry.key().clone()).collect()
    }

    pub fn has_factory(&self, endpoint: &str) -> bool {
        self.factory.contains_key(endpoint)
    }

    fn ensure_pool_inner(&self, endpoint: &str) -> u64 {
        if !self.pool.contains_key(endpoint) {
            self.pool.insert(endpoint.to_string(), PoolInner::new(self.size));
        }
        self.pool.get(endpoint).map(|inner| inner.generation()).unwrap_or_default()
    }
}

impl<T> Deref for PoolConn<T>
where
    T: ConnLike + ConnAttr + ConnAttrMut,
{
    type Target = T;

    fn deref(&self) -> &T {
        self.conn.as_ref().unwrap()
    }
}

impl<T> DerefMut for PoolConn<T>
where
    T: ConnLike + ConnAttr + ConnAttrMut,
{
    fn deref_mut(&mut self) -> &mut T {
        self.conn.as_mut().unwrap()
    }
}

impl<T> Drop for PoolConn<T>
where
    T: ConnLike + ConnAttr + ConnAttrMut,
{
    fn drop(&mut self) {
        if self.conn.is_some() {
            debug!("put conn {:?}", &self.conn);
            let conn = self.conn.take().unwrap();
            let endpoint = conn.get_endpoint();
            match self.pool.get_mut(&endpoint) {
                Some(inner) if inner.generation() == self.generation => inner.put_conn(conn),
                Some(_) => debug!("discard stale pooled connection for endpoint {}", endpoint),
                None => debug!("discard pooled connection for missing endpoint {}", endpoint),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, Default)]
    struct TestConn {
        endpoint: String,
    }

    #[async_trait]
    impl ConnLike for TestConn {
        type Error = ();

        async fn build_conn(&self) -> Result<Self, Self::Error> {
            Ok(self.clone())
        }

        async fn ping(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    impl ConnAttr for TestConn {
        fn get_host(&self) -> String {
            "127.0.0.1".to_string()
        }

        fn get_port(&self) -> u16 {
            3306
        }

        fn get_user(&self) -> String {
            "root".to_string()
        }

        fn get_endpoint(&self) -> String {
            self.endpoint.clone()
        }

        fn get_db(&self) -> Option<String> {
            None
        }

        fn get_charset(&self) -> Option<String> {
            None
        }

        fn get_autocommit(&self) -> Option<String> {
            None
        }
    }

    impl ConnAttrMut for TestConn {
        type Item = ();
    }

    fn test_pool() -> Pool<TestConn> {
        let pool = Pool::new(4);
        pool.set_factory("127.0.0.1:3306", TestConn { endpoint: "127.0.0.1:3306".to_string() });
        pool
    }

    #[tokio::test]
    async fn refresh_endpoint_clears_idle_connections() {
        let pool = test_pool();
        let conn = pool.get_conn_with_endpoint_session("127.0.0.1:3306", &[]).await.unwrap();
        drop(conn);

        assert_eq!(pool.len("127.0.0.1:3306"), 1);

        let cleared = pool.refresh_endpoint("127.0.0.1:3306");

        assert_eq!(cleared, 1);
        assert_eq!(pool.len("127.0.0.1:3306"), 0);
    }

    #[tokio::test]
    async fn refresh_endpoint_discards_checked_out_connections_on_return() {
        let pool = test_pool();
        let conn = pool.get_conn_with_endpoint_session("127.0.0.1:3306", &[]).await.unwrap();

        assert_eq!(pool.refresh_endpoint("127.0.0.1:3306"), 0);
        drop(conn);

        assert_eq!(pool.len("127.0.0.1:3306"), 0);
    }
}
