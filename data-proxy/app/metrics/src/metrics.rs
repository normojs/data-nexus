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

use prometheus::{Encoder, Registry};
use runtime_gateway::server::metrics::{
    install_audit_metrics_hooks, refresh_audit_queue_metrics, GATEWAY_AUDIT_PROCESS_DURATION,
    GATEWAY_AUDIT_QUEUE_LEN, GATEWAY_ENCODE_BYTES_TOTAL, GATEWAY_ENCODE_PEAK_WINDOW_BYTES,
    GATEWAY_ENCODE_PEAK_WINDOW_ROWS, GATEWAY_ENCODE_WINDOWS_TOTAL, GATEWAY_EXECUTE_PATH_TOTAL,
    GATEWAY_MASK_ROWS_TOTAL, GATEWAY_PASSTHROUGH_BYTES_TOTAL, GATEWAY_PORTAL_RESUME_TOTAL,
    SQL_PROCESSED_DURATION, SQL_PROCESSED_TOTAL, SQL_UNDER_PROCESSING,
};

const METRICS_NAMESPACE: &str = "unisql_proxy";

#[derive(Clone, Default, Debug)]
pub struct MetricsManager {
    registry: Registry,
}

impl MetricsManager {
    pub fn new() -> Self {
        let registry = Registry::new_custom(Some(METRICS_NAMESPACE.to_string()), None).unwrap();
        Self::register_metrics(&registry);

        MetricsManager { registry }
    }

    pub fn get_server(&self) -> Registry {
        self.registry.clone()
    }

    pub fn register_metrics(registry: &Registry) {
        registry.register(Box::new(SQL_PROCESSED_TOTAL.clone())).unwrap();
        registry.register(Box::new(SQL_PROCESSED_DURATION.clone())).unwrap();
        registry.register(Box::new(SQL_UNDER_PROCESSING.clone())).unwrap();
        // A05: execute_path hit-rate + passthrough wire bytes.
        registry
            .register(Box::new(GATEWAY_EXECUTE_PATH_TOTAL.clone()))
            .unwrap();
        registry
            .register(Box::new(GATEWAY_PASSTHROUGH_BYTES_TOTAL.clone()))
            .unwrap();
        // O01: Secure path + audit queue/latency.
        registry
            .register(Box::new(GATEWAY_MASK_ROWS_TOTAL.clone()))
            .unwrap();
        registry
            .register(Box::new(GATEWAY_ENCODE_WINDOWS_TOTAL.clone()))
            .unwrap();
        registry
            .register(Box::new(GATEWAY_ENCODE_BYTES_TOTAL.clone()))
            .unwrap();
        // A06: logical peak encode window rows (high-water gauge).
        registry
            .register(Box::new(GATEWAY_ENCODE_PEAK_WINDOW_ROWS.clone()))
            .unwrap();
        // A06: logical peak encode window bytes (high-water gauge; not process RSS).
        registry
            .register(Box::new(GATEWAY_ENCODE_PEAK_WINDOW_BYTES.clone()))
            .unwrap();
        // A10: PortalSuspended multi-Execute resume strategy (hold vs logical_skip).
        registry
            .register(Box::new(GATEWAY_PORTAL_RESUME_TOTAL.clone()))
            .unwrap();
        registry
            .register(Box::new(GATEWAY_AUDIT_QUEUE_LEN.clone()))
            .unwrap();
        registry
            .register(Box::new(GATEWAY_AUDIT_PROCESS_DURATION.clone()))
            .unwrap();
        install_audit_metrics_hooks();
    }

    pub fn gather(&self) -> Vec<u8> {
        refresh_audit_queue_metrics();
        let mut buf: Vec<u8> = vec![];
        let encoder = prometheus::TextEncoder::new();
        encoder.encode(&self.registry.gather(), &mut buf).unwrap();

        buf
    }
}
