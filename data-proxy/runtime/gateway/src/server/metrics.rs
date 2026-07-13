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

use gateway_core::ProtocolKind;
use once_cell::sync::Lazy;
use prometheus::{opts, GaugeVec, HistogramOpts, HistogramVec, IntCounterVec};

// LABEL_NAME_DOMAIN refers to the name of current working proxy runtime
const LABEL_NAME_DOMAIN: &'static str = "domain";
// LABEL_NAME_SERVICE refers to the routed gateway service.
const LABEL_NAME_SERVICE: &'static str = "service";
// LABEL_NAME_FRONTEND_PROTOCOL refers to the client-facing protocol.
const LABEL_NAME_FRONTEND_PROTOCOL: &'static str = "frontend_protocol";
// LABEL_NAME_BACKEND_PROTOCOL refers to the backend database protocol.
const LABEL_NAME_BACKEND_PROTOCOL: &'static str = "backend_protocol";
// LABEL_NAME_TYPE refers to the type of current working command type
const LABEL_NAME_TYPE: &'static str = "type";
// LABEL_NAME_ENDPOINT refers to the backend endpoint selected for the SQL.
const LABEL_NAME_ENDPOINT: &'static str = "endpoint";

const SQL_LABELS: [&str; 6] = [
    LABEL_NAME_DOMAIN,
    LABEL_NAME_SERVICE,
    LABEL_NAME_FRONTEND_PROTOCOL,
    LABEL_NAME_BACKEND_PROTOCOL,
    LABEL_NAME_TYPE,
    LABEL_NAME_ENDPOINT,
];

pub static SQL_PROCESSED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    IntCounterVec::new(opts!("sql_processed_total", "The total of processed SQL"), &SQL_LABELS)
        .expect("Could not create SQL_PROCESSED_TOTAL")
});

pub static SQL_PROCESSED_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    let opt = HistogramOpts {
        common_opts: opts!("sql_processed_duration", "The duration of processed SQL"),
        buckets: Vec::<f64>::new(),
    };
    HistogramVec::new(opt, &SQL_LABELS).expect("Cound not create SQL_PROCESSED_DURATION")
});

pub static SQL_UNDER_PROCESSING: Lazy<GaugeVec> = Lazy::new(|| {
    GaugeVec::new(opts!("sql_under_processing", "The active SQL under processing"), &SQL_LABELS)
        .expect("Cound not create SQL_UNDER_PROCESSING")
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayMetricsContext {
    pub domain: String,
    pub service: String,
    pub frontend_protocol: ProtocolKind,
    pub backend_protocol: ProtocolKind,
}

impl GatewayMetricsContext {
    pub fn legacy_mysql(domain: impl Into<String>) -> Self {
        let domain = domain.into();
        Self {
            service: domain.clone(),
            domain,
            frontend_protocol: ProtocolKind::MySql,
            backend_protocol: ProtocolKind::MySql,
        }
    }

    fn label_values<'a>(&'a self, command_type: &'a str, endpoint: &'a str) -> [&'a str; 6] {
        [
            self.domain.as_str(),
            self.service.as_str(),
            self.frontend_protocol.as_label(),
            self.backend_protocol.as_label(),
            command_type,
            endpoint,
        ]
    }
}

#[derive(Clone, Copy)]
pub struct MySQLServerMetricsCollector;

impl MySQLServerMetricsCollector {
    pub fn new() -> Self {
        MySQLServerMetricsCollector {}
    }
    pub fn set_sql_processed_total(
        &self,
        context: &GatewayMetricsContext,
        command_type: &str,
        endpoint: &str,
    ) {
        SQL_PROCESSED_TOTAL.with_label_values(&context.label_values(command_type, endpoint)).inc();
    }

    pub fn set_sql_processed_duration(
        &self,
        context: &GatewayMetricsContext,
        command_type: &str,
        endpoint: &str,
        duration: f64,
    ) {
        SQL_PROCESSED_DURATION
            .with_label_values(&context.label_values(command_type, endpoint))
            .observe(duration);
    }

    pub fn set_sql_under_processing_inc(
        &self,
        context: &GatewayMetricsContext,
        command_type: &str,
        endpoint: &str,
    ) {
        SQL_UNDER_PROCESSING.with_label_values(&context.label_values(command_type, endpoint)).inc();
    }

    pub fn set_sql_under_processing_dec(
        &self,
        context: &GatewayMetricsContext,
        command_type: &str,
        endpoint: &str,
    ) {
        SQL_UNDER_PROCESSING.with_label_values(&context.label_values(command_type, endpoint)).dec();
    }
}

macro_rules! collect_sql_processed_total {
    ($s:expr, $x:expr, $c:expr) => {
        $s.metrics_collector.set_sql_processed_total(&$s.metrics_context, $x, $c);
    };
}

macro_rules! collect_sql_processed_duration {
    ($s:expr, $x:expr, $c:expr, $e:expr) => {
        $s.metrics_collector.set_sql_processed_duration(
            &$s.metrics_context,
            $x,
            $c,
            $e.as_secs_f64(),
        );
    };
}

macro_rules! collect_sql_under_processing_inc {
    ($s:expr, $x:expr, $c:expr) => {
        $s.metrics_collector.set_sql_under_processing_inc(&$s.metrics_context, $x, $c);
    };
}

macro_rules! collect_sql_under_processing_dec {
    ($s:expr, $x:expr, $c:expr) => {
        $s.metrics_collector.set_sql_under_processing_dec(&$s.metrics_context, $x, $c);
    };
}

#[cfg(test)]
mod tests {
    use gateway_core::ProtocolKind;

    use super::GatewayMetricsContext;

    #[test]
    fn builds_protocol_aware_sql_metric_labels() {
        let context = GatewayMetricsContext {
            domain: "listener-a".into(),
            service: "orders".into(),
            frontend_protocol: ProtocolKind::MySql,
            backend_protocol: ProtocolKind::PostgreSql,
        };

        assert_eq!(
            context.label_values("COM_QUERY", "127.0.0.1:5432"),
            ["listener-a", "orders", "my_sql", "postgre_sql", "COM_QUERY", "127.0.0.1:5432",]
        );
    }
}
