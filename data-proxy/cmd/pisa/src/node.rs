use proxy::factory::ShutdownHandle;
use tokio::task::JoinHandle;

//
pub struct NodeInstances {
    pub node_instances: Vec<NodeInstance>,
}

impl NodeInstances {
    pub fn start(&self, _name: String) {}
    pub fn stop(&self) {
        for node in &self.node_instances {
            node.shutdown();
        }
    }
    pub fn restart(&self) {}
}

pub struct NodeInstance {
    pub name: String,
    pub shutdown_handle: Option<ShutdownHandle>,
    // 线程类型，thread::spawn的返回类型
    pub join_handle: JoinHandle<()>,
}

impl NodeInstance {
    pub fn new(
        name: String,
        join_handle: JoinHandle<()>,
        shutdown_handle: Option<ShutdownHandle>,
    ) -> Self {
        Self { name, shutdown_handle, join_handle }
    }

    pub fn shutdown(&self) {
        match &self.shutdown_handle {
            Some(handle) => handle.shutdown(),
            None => self.join_handle.abort(),
        }
    }
}
