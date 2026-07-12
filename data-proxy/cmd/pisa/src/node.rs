use tokio::task::JoinHandle;

//
pub struct NodeInstances {
    pub node_instances: Vec<NodeInstance>,
}

impl NodeInstances {
    pub fn start(&self, xxx: String) {}
    pub fn stop(&self) {}
    pub fn restart(&self) {}
}

pub struct NodeInstance {
    pub name: String,
    // 线程类型，thread::spawn的返回类型
    pub joinHandle: JoinHandle<()>,
}

impl NodeInstance {
    pub fn new(name: String, joinHandle: JoinHandle<()>) -> Self {
        Self { name, joinHandle }
    }
}
