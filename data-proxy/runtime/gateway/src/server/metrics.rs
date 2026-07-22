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

use once_cell::sync::Lazy;
use prometheus::{opts, GaugeVec, HistogramOpts, HistogramVec, IntCounterVec};

// LABEL_NAME_DOMAIN refers to the name of current working proxy runtime
const LABEL_NAME_DOMAIN: &'static str = "domain";
// LABEL_NAME_SERVICE refers to the service selected by the listener.
const LABEL_NAME_SERVICE: &'static str = "service";
// LABEL_NAME_FRONTEND_PROTOCOL refers to the client-facing protocol.
const LABEL_NAME_FRONTEND_PROTOCOL: &'static str = "frontend_protocol";
// LABEL_NAME_BACKEND_PROTOCOL refers to the backend database protocol.
const LABEL_NAME_BACKEND_PROTOCOL: &'static str = "backend_protocol";
// LABEL_NAME_TYPE refers to the type of current working command type
const LABEL_NAME_TYPE: &'static str = "type";
// LABEL_NAME_ENDPOINT refers to the backend database endpoint.
const LABEL_NAME_ENDPOINT: &'static str = "endpoint";

const SQL_METRIC_LABELS: &[&str] = &[
    LABEL_NAME_DOMAIN,
    LABEL_NAME_SERVICE,
    LABEL_NAME_FRONTEND_PROTOCOL,
    LABEL_NAME_BACKEND_PROTOCOL,
    LABEL_NAME_TYPE,
    LABEL_NAME_ENDPOINT,
];

pub static SQL_PROCESSED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    IntCounterVec::new(
        opts!("sql_processed_total", "The total of processed SQL"),
        SQL_METRIC_LABELS,
    )
    .expect("Could not create SQL_PROCESSED_TOTAL")
});

pub static SQL_PROCESSED_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    let opt = HistogramOpts {
        common_opts: opts!("sql_processed_duration", "The duration of processed SQL"),
        buckets: Vec::<f64>::new(),
    };
    HistogramVec::new(opt, SQL_METRIC_LABELS).expect("Cound not create SQL_PROCESSED_DURATION")
});

pub static SQL_UNDER_PROCESSING: Lazy<GaugeVec> = Lazy::new(|| {
    GaugeVec::new(
        opts!("sql_under_processing", "The active SQL under processing"),
        SQL_METRIC_LABELS,
    )
    .expect("Cound not create SQL_UNDER_PROCESSING")
});

// A05: execute path + passthrough bytes (Prometheus; always available).
// Labels match B03 execute_path plus A08 honesty:
// passthrough | passthrough_extended | passthrough_rewrite | streaming | streaming_demote | materialized | xproto_stream | n/a
const LABEL_NAME_EXECUTE_PATH: &str = "execute_path";
const EXECUTE_PATH_LABELS: &[&str] = &[
    LABEL_NAME_DOMAIN,
    LABEL_NAME_SERVICE,
    LABEL_NAME_FRONTEND_PROTOCOL,
    LABEL_NAME_BACKEND_PROTOCOL,
    LABEL_NAME_TYPE,
    LABEL_NAME_ENDPOINT,
    LABEL_NAME_EXECUTE_PATH,
];

/// Commands finished, labeled by execute_path (A05 hit-rate numerator/denominator).
pub static GATEWAY_EXECUTE_PATH_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    IntCounterVec::new(
        opts!(
            "gateway_execute_path_total",
            "Gateway commands by execute_path (passthrough|passthrough_extended|passthrough_rewrite|streaming|streaming_demote|materialized|xproto_stream|n/a)"
        ),
        EXECUTE_PATH_LABELS,
    )
    .expect("Could not create GATEWAY_EXECUTE_PATH_TOTAL")
});

/// Wire bytes on same-protocol passthrough responses (A05).
pub static GATEWAY_PASSTHROUGH_BYTES_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    IntCounterVec::new(
        opts!(
            "gateway_passthrough_bytes_total",
            "Total payload bytes relayed on wire passthrough path"
        ),
        SQL_METRIC_LABELS,
    )
    .expect("Could not create GATEWAY_PASSTHROUGH_BYTES_TOTAL")
});

// O01: Secure / streaming encode path observability (always-on Prometheus).
/// Rows that passed through a non-empty mask obligation during encode.
pub static GATEWAY_MASK_ROWS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    IntCounterVec::new(
        opts!(
            "gateway_mask_rows_total",
            "Rows masked on Secure encode path (per window mask application)"
        ),
        SQL_METRIC_LABELS,
    )
    .expect("Could not create GATEWAY_MASK_ROWS_TOTAL")
});

/// Number of encode windows written (streaming or windowed ResultSet).
pub static GATEWAY_ENCODE_WINDOWS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    IntCounterVec::new(
        opts!(
            "gateway_encode_windows_total",
            "Result encode windows written (windowed streaming / ResultSet path)"
        ),
        SQL_METRIC_LABELS,
    )
    .expect("Could not create GATEWAY_ENCODE_WINDOWS_TOTAL")
});

/// Approximate encoded row-packet bytes (frontend encode payload, not TCP framing).
pub static GATEWAY_ENCODE_BYTES_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    IntCounterVec::new(
        opts!(
            "gateway_encode_bytes_total",
            "Approximate encoded result payload bytes on windowed encode path"
        ),
        SQL_METRIC_LABELS,
    )
    .expect("Could not create GATEWAY_ENCODE_BYTES_TOTAL")
});

/// A06 honesty: observed max rows in one encode window (logical peak, not process RSS).
/// Gauge holds the high-water mark of `StreamingEncodeStats.peak_window_rows` since process start.
pub static GATEWAY_ENCODE_PEAK_WINDOW_ROWS: Lazy<GaugeVec> = Lazy::new(|| {
    GaugeVec::new(
        opts!(
            "gateway_encode_peak_window_rows",
            "High-water mark of rows held in a single encode window (A06 logical peak ≤ window_rows)"
        ),
        SQL_METRIC_LABELS,
    )
    .expect("Could not create GATEWAY_ENCODE_PEAK_WINDOW_ROWS")
});

/// A10 honesty: PortalSuspended multi-Execute resume strategy.
/// mode=hold — remainder kept as process-local RowStream (not SQL WITH HOLD).
/// mode=logical_skip — re-run SQL and skip prior rows (fallback).
/// mode=resume_hold — next Execute consumed the held RowStream without re-SQL.
pub static GATEWAY_PORTAL_RESUME_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    IntCounterVec::new(
        opts!(
            "gateway_portal_resume_total",
            "PG PortalSuspended multi-Execute resume events (hold|logical_skip|resume_hold; not SQL WITH HOLD)"
        ),
        &["mode"],
    )
    .expect("Could not create GATEWAY_PORTAL_RESUME_TOTAL")
});

/// Audit pipeline queue depth snapshot (main + priority), refreshed on /metrics gather.
pub static GATEWAY_AUDIT_QUEUE_LEN: Lazy<GaugeVec> = Lazy::new(|| {
    GaugeVec::new(
        opts!(
            "gateway_audit_queue_len",
            "Audit pipeline in-memory queue depth (queue=main|priority)"
        ),
        &["queue"],
    )
    .expect("Could not create GATEWAY_AUDIT_QUEUE_LEN")
});

/// Audit worker process latency samples (seconds), observed on worker drain.
pub static GATEWAY_AUDIT_PROCESS_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    let opt = HistogramOpts {
        common_opts: opts!(
            "gateway_audit_process_duration_seconds",
            "Audit worker per-event process latency (sink + optional index insert)"
        ),
        // Sub-ms to multi-second: cover hot path worker + slow disk/index.
        buckets: vec![
            0.000_1, 0.000_5, 0.001, 0.002_5, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
        ],
    };
    HistogramVec::new(opt, &["sink"]).expect("Could not create GATEWAY_AUDIT_PROCESS_DURATION")
});

#[derive(Clone, Copy)]
pub struct MySQLServerMetricsCollector;

impl MySQLServerMetricsCollector {
    pub fn new() -> Self {
        MySQLServerMetricsCollector {}
    }
    pub fn set_sql_processed_total(&self, labels: &[&str]) {
        SQL_PROCESSED_TOTAL.with_label_values(labels).inc();
    }

    pub fn set_sql_processed_duration(&self, labels: &[&str], duration: f64) {
        SQL_PROCESSED_DURATION.with_label_values(labels).observe(duration);
    }

    pub fn set_sql_under_processing_inc(&self, labels: &[&str]) {
        SQL_UNDER_PROCESSING.with_label_values(labels).inc();
    }

    pub fn set_sql_under_processing_dec(&self, labels: &[&str]) {
        SQL_UNDER_PROCESSING.with_label_values(labels).dec();
    }

    /// A05: record execute_path (+ optional passthrough bytes).
    /// `labels` are the 6 SQL metric labels; `execute_path` is appended.
    pub fn record_execute_path(&self, labels: &[&str], execute_path: &str, wire_bytes: u64) {
        if labels.len() != 6 {
            return;
        }
        let path = normalize_execute_path(execute_path);
        let mut path_labels = [""; 7];
        path_labels[..6].copy_from_slice(labels);
        path_labels[6] = path;
        GATEWAY_EXECUTE_PATH_TOTAL
            .with_label_values(&path_labels)
            .inc();
        if matches!(
            path,
            "passthrough" | "passthrough_rewrite" | "passthrough_extended"
        ) && wire_bytes > 0
        {
            GATEWAY_PASSTHROUGH_BYTES_TOTAL
                .with_label_values(labels)
                .inc_by(wire_bytes);
        }
    }

    /// O01: Secure encode path counters (mask / windows / encoded bytes).
    /// A06: also tracks logical peak window rows (high-water gauge).
    pub fn record_secure_encode(
        &self,
        labels: &[&str],
        masked_rows: u64,
        windows: u64,
        encoded_bytes: u64,
    ) {
        self.record_secure_encode_peak(labels, masked_rows, windows, encoded_bytes, 0);
    }

    /// O01 + A06: Secure encode counters including peak window rows.
    pub fn record_secure_encode_peak(
        &self,
        labels: &[&str],
        masked_rows: u64,
        windows: u64,
        encoded_bytes: u64,
        peak_window_rows: u64,
    ) {
        if labels.len() != 6 {
            return;
        }
        if masked_rows > 0 {
            GATEWAY_MASK_ROWS_TOTAL
                .with_label_values(labels)
                .inc_by(masked_rows);
        }
        if windows > 0 {
            GATEWAY_ENCODE_WINDOWS_TOTAL
                .with_label_values(labels)
                .inc_by(windows);
        }
        if encoded_bytes > 0 {
            GATEWAY_ENCODE_BYTES_TOTAL
                .with_label_values(labels)
                .inc_by(encoded_bytes);
        }
        if peak_window_rows > 0 {
            let g = GATEWAY_ENCODE_PEAK_WINDOW_ROWS.with_label_values(labels);
            // High-water mark across queries for this label set.
            let cur = g.get();
            if peak_window_rows as f64 > cur {
                g.set(peak_window_rows as f64);
            }
        }
    }

    /// A10: PortalSuspended multi-Execute resume honesty counter.
    /// `mode` is collapsed to hold | logical_skip | resume_hold | n/a.
    pub fn record_portal_resume(&self, mode: &str) {
        let mode = normalize_portal_resume_mode(mode);
        GATEWAY_PORTAL_RESUME_TOTAL.with_label_values(&[mode]).inc();
    }
}

/// Collapse free-form portal resume mode strings.
pub fn normalize_portal_resume_mode(mode: &str) -> &'static str {
    match mode.trim().to_ascii_lowercase().as_str() {
        "hold" | "hold_remainder" | "rowstream_hold" => "hold",
        "logical_skip" | "skip" | "logical" => "logical_skip",
        "resume_hold" | "resume" | "held_resume" => "resume_hold",
        _ => "n/a",
    }
}

/// Collapse free-form path strings to the B03/A05 controlled set.
pub fn normalize_execute_path(path: &str) -> &'static str {
    match path.trim().to_ascii_lowercase().as_str() {
        "passthrough" | "pass_through" | "wire" => "passthrough",
        // A08: extended text-bind re-encoded as backend Parse/Bind/Execute/Sync TCP
        // (not original client frames). Alias passthrough_rewrite for prior smoke/docs.
        "passthrough_extended"
        | "extended"
        | "extended_wire"
        | "passthrough_rewrite"
        | "rewrite"
        | "rewrite_wire"
        | "passthrough-rewrite" => "passthrough_extended",
        // A08: extended under passthrough demotes to Streaming (not TCP bind relay).
        "streaming_demote" | "demote" | "demoted_streaming" => "streaming_demote",
        "streaming" | "stream" => "streaming",
        "materialized" | "materialise" | "full" => "materialized",
        "xproto_stream" | "xproto" | "cross_protocol" => "xproto_stream",
        _ => "n/a",
    }
}

/// O01: refresh audit queue depth gauges from the live pipeline (call from /metrics).
pub fn refresh_audit_queue_metrics() {
    if let Some(pipe) = gateway_core::global_audit_pipeline() {
        let s = pipe.stats();
        GATEWAY_AUDIT_QUEUE_LEN
            .with_label_values(&["main"])
            .set(s.queue_len as f64);
        GATEWAY_AUDIT_QUEUE_LEN
            .with_label_values(&["priority"])
            .set(s.priority_queue_len as f64);
    }
}

/// O01: observe one audit worker process sample (seconds).
pub fn observe_audit_process_duration(seconds: f64) {
    if seconds.is_finite() && seconds >= 0.0 {
        GATEWAY_AUDIT_PROCESS_DURATION
            .with_label_values(&["pipeline"])
            .observe(seconds);
    }
}

/// Install audit worker latency hook once (idempotent).
pub fn install_audit_metrics_hooks() {
    gateway_core::set_audit_process_latency_hook(|secs| {
        observe_audit_process_duration(secs);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_execute_path_values() {
        assert_eq!(normalize_execute_path("passthrough"), "passthrough");
        assert_eq!(
            normalize_execute_path("passthrough_extended"),
            "passthrough_extended"
        );
        assert_eq!(
            normalize_execute_path("passthrough_rewrite"),
            "passthrough_extended"
        );
        assert_eq!(normalize_execute_path("rewrite"), "passthrough_extended");
        assert_eq!(normalize_execute_path("STREAMING"), "streaming");
        assert_eq!(normalize_execute_path("streaming_demote"), "streaming_demote");
        assert_eq!(normalize_execute_path("demote"), "streaming_demote");
        assert_eq!(normalize_execute_path("materialized"), "materialized");
        assert_eq!(normalize_execute_path("xproto_stream"), "xproto_stream");
        assert_eq!(normalize_execute_path("other"), "n/a");
    }

    #[test]
    fn normalize_portal_resume_mode_values() {
        assert_eq!(normalize_portal_resume_mode("hold"), "hold");
        assert_eq!(normalize_portal_resume_mode("hold_remainder"), "hold");
        assert_eq!(normalize_portal_resume_mode("logical_skip"), "logical_skip");
        assert_eq!(normalize_portal_resume_mode("resume_hold"), "resume_hold");
        assert_eq!(normalize_portal_resume_mode("weird"), "n/a");
    }

    #[test]
    fn record_portal_resume_increments_counter() {
        let m = MySQLServerMetricsCollector::new();
        m.record_portal_resume("hold");
        m.record_portal_resume("resume_hold");
        m.record_portal_resume("logical_skip");
        let hold = GATEWAY_PORTAL_RESUME_TOTAL
            .with_label_values(&["hold"])
            .get();
        let resume = GATEWAY_PORTAL_RESUME_TOTAL
            .with_label_values(&["resume_hold"])
            .get();
        let skip = GATEWAY_PORTAL_RESUME_TOTAL
            .with_label_values(&["logical_skip"])
            .get();
        assert!(hold >= 1, "hold={hold}");
        assert!(resume >= 1, "resume_hold={resume}");
        assert!(skip >= 1, "logical_skip={skip}");
    }

    #[test]
    fn record_execute_path_increments_counters() {
        let m = MySQLServerMetricsCollector::new();
        let labels = [
            "listener-a05",
            "svc",
            "mysql",
            "mysql",
            "query",
            "ep",
        ];
        m.record_execute_path(&labels, "passthrough", 42);
        m.record_execute_path(&labels, "streaming", 0);
        // Prometheus registry is process-global; just ensure no panic and values move.
        let pt = GATEWAY_EXECUTE_PATH_TOTAL
            .with_label_values(&[
                "listener-a05",
                "svc",
                "mysql",
                "mysql",
                "query",
                "ep",
                "passthrough",
            ])
            .get();
        assert!(pt >= 1, "passthrough path counter={pt}");
        let bytes = GATEWAY_PASSTHROUGH_BYTES_TOTAL
            .with_label_values(&labels)
            .get();
        assert!(bytes >= 42, "passthrough bytes={bytes}");
    }

    #[test]
    fn record_secure_encode_increments() {
        let m = MySQLServerMetricsCollector::new();
        let labels = [
            "listener-o01",
            "svc",
            "mysql",
            "mysql",
            "query",
            "ep",
        ];
        m.record_secure_encode_peak(&labels, 3, 2, 100, 7);
        let masked = GATEWAY_MASK_ROWS_TOTAL.with_label_values(&labels).get();
        assert!(masked >= 3, "masked={masked}");
        let windows = GATEWAY_ENCODE_WINDOWS_TOTAL.with_label_values(&labels).get();
        assert!(windows >= 2, "windows={windows}");
        let bytes = GATEWAY_ENCODE_BYTES_TOTAL.with_label_values(&labels).get();
        assert!(bytes >= 100, "bytes={bytes}");
        let peak = GATEWAY_ENCODE_PEAK_WINDOW_ROWS.with_label_values(&labels).get();
        assert!(peak >= 7.0, "peak_window_rows={peak}");
        // High-water: lower peak must not decrease the gauge.
        m.record_secure_encode_peak(&labels, 0, 1, 10, 3);
        let peak2 = GATEWAY_ENCODE_PEAK_WINDOW_ROWS.with_label_values(&labels).get();
        assert!(peak2 >= 7.0, "peak should stay high-water, got {peak2}");
    }

    #[test]
    fn observe_audit_process_duration_accepts_sample() {
        observe_audit_process_duration(0.001);
        // no panic; histogram is process-global
    }
}

macro_rules! collect_sql_processed_total {
    ($s:expr, $x:expr, $c:expr) => {
        $s.metrics_collector.set_sql_processed_total(&[
            $s.name.as_str(),
            $s.service.as_str(),
            $s.frontend_protocol.as_str(),
            $s.backend_protocol.as_str(),
            $x,
            $c,
        ]);
    };
}

macro_rules! collect_sql_processed_duration {
    ($s:expr, $x:expr, $c:expr, $e:expr) => {
        $s.metrics_collector.set_sql_processed_duration(
            &[
                $s.name.as_str(),
                $s.service.as_str(),
                $s.frontend_protocol.as_str(),
                $s.backend_protocol.as_str(),
                $x,
                $c,
            ],
            $e.as_secs_f64(),
        );
    };
}

macro_rules! collect_sql_under_processing_inc {
    ($s:expr, $x:expr, $c:expr) => {
        $s.metrics_collector.set_sql_under_processing_inc(&[
            $s.name.as_str(),
            $s.service.as_str(),
            $s.frontend_protocol.as_str(),
            $s.backend_protocol.as_str(),
            $x,
            $c,
        ]);
    };
}

macro_rules! collect_sql_under_processing_dec {
    ($s:expr, $x:expr, $c:expr) => {
        $s.metrics_collector.set_sql_under_processing_dec(&[
            $s.name.as_str(),
            $s.service.as_str(),
            $s.frontend_protocol.as_str(),
            $s.backend_protocol.as_str(),
            $x,
            $c,
        ]);
    };
}
