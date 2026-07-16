//! Async audit pipeline (S4): bounded queue + worker + JSONL/memory sinks.
//!
//! Hot path only `try_send`s; never blocks the query path. Overflow is counted
//! and optionally drops oldest/newest per config.

use crate::audit::AuditEvent;
use crate::security::SecurityAuditConfig;
use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

/// Global process-wide pipeline (installed from gateway config).
static GLOBAL: OnceLock<Arc<AuditPipeline>> = OnceLock::new();

/// Install (or replace metadata on first call) the process audit pipeline.
///
/// Subsequent calls update file path preferences when possible but keep the
/// same worker; capacity is fixed at first install.
pub fn install_audit_pipeline(config: &SecurityAuditConfig) -> Arc<AuditPipeline> {
    if let Some(existing) = GLOBAL.get() {
        existing.reconfigure(config);
        return existing.clone();
    }
    let pipe = Arc::new(AuditPipeline::new(config));
    pipe.spawn_worker();
    let _ = GLOBAL.set(pipe.clone());
    pipe
}

/// Current global pipeline, if installed.
pub fn global_audit_pipeline() -> Option<Arc<AuditPipeline>> {
    GLOBAL.get().cloned()
}

/// Best-effort enqueue; never panics or blocks.
pub fn try_audit(event: AuditEvent) {
    if let Some(pipe) = global_audit_pipeline() {
        pipe.try_send(event);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OverflowPolicy {
    DropNew,
    DropOld,
    Sample,
    Block, // treated as drop_new on hot path (never block query)
}

impl OverflowPolicy {
    fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "drop_old" => Self::DropOld,
            "sample" => Self::Sample,
            "block" => Self::Block,
            _ => Self::DropNew,
        }
    }
}

struct SharedState {
    queue: VecDeque<AuditEvent>,
    /// Recent events for Admin query (ring, newest last).
    recent: VecDeque<AuditEvent>,
    closed: bool,
}

/// Bounded audit pipeline shared across connections.
pub struct AuditPipeline {
    capacity: usize,
    recent_capacity: usize,
    overflow: OverflowPolicy,
    file_path: Mutex<Option<PathBuf>>,
    write_file: AtomicBool,
    write_tracing: AtomicBool,
    state: Mutex<SharedState>,
    cv: Condvar,
    dropped: AtomicU64,
    accepted: AtomicU64,
    written: AtomicU64,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl AuditPipeline {
    pub fn new(config: &SecurityAuditConfig) -> Self {
        let capacity = config.queue_capacity.max(1) as usize;
        let recent_capacity = capacity.min(4096).max(64);
        let sinks = config
            .sinks
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect::<Vec<_>>();
        let write_file = sinks.iter().any(|s| s == "file" || s == "jsonl");
        let write_tracing = sinks.is_empty() || sinks.iter().any(|s| s == "tracing");
        let file_path = if config.file_path.trim().is_empty() {
            None
        } else {
            Some(PathBuf::from(config.file_path.trim()))
        };
        Self {
            capacity,
            recent_capacity,
            overflow: OverflowPolicy::parse(&config.overflow),
            file_path: Mutex::new(file_path),
            write_file: AtomicBool::new(write_file),
            write_tracing: AtomicBool::new(write_tracing),
            state: Mutex::new(SharedState {
                queue: VecDeque::with_capacity(capacity),
                recent: VecDeque::with_capacity(recent_capacity),
                closed: false,
            }),
            cv: Condvar::new(),
            dropped: AtomicU64::new(0),
            accepted: AtomicU64::new(0),
            written: AtomicU64::new(0),
            worker: Mutex::new(None),
        }
    }

    fn reconfigure(&self, config: &SecurityAuditConfig) {
        let sinks = config
            .sinks
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect::<Vec<_>>();
        let write_file = sinks.iter().any(|s| s == "file" || s == "jsonl");
        let write_tracing = sinks.is_empty() || sinks.iter().any(|s| s == "tracing");
        self.write_file.store(write_file, Ordering::Relaxed);
        self.write_tracing.store(write_tracing, Ordering::Relaxed);
        if !config.file_path.trim().is_empty() {
            if let Ok(mut path) = self.file_path.lock() {
                *path = Some(PathBuf::from(config.file_path.trim()));
            }
        }
    }

    fn spawn_worker(self: &Arc<Self>) {
        let this = Arc::clone(self);
        let handle = thread::Builder::new()
            .name("data-nexus-audit".into())
            .spawn(move || this.worker_loop())
            .expect("spawn audit worker");
        *self.worker.lock().expect("worker lock") = Some(handle);
    }

    pub fn try_send(&self, mut event: AuditEvent) {
        if event.event_id.is_none() {
            event.event_id = Some(new_event_id());
        }
        if event.ts_unix_ms.is_none() {
            event.ts_unix_ms = Some(now_unix_ms());
        }

        let mut state = self.state.lock().expect("audit state");
        if state.closed {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }

        if state.queue.len() >= self.capacity {
            match self.overflow {
                OverflowPolicy::DropOld => {
                    let _ = state.queue.pop_front();
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                }
                OverflowPolicy::Sample => {
                    // Keep ~50% under pressure.
                    if self.accepted.load(Ordering::Relaxed) % 2 == 0 {
                        self.dropped.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    let _ = state.queue.pop_front();
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                }
                OverflowPolicy::DropNew | OverflowPolicy::Block => {
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
        }

        // Ring for Admin API (always retain, independent of worker lag).
        if state.recent.len() >= self.recent_capacity {
            state.recent.pop_front();
        }
        state.recent.push_back(event.clone());

        state.queue.push_back(event);
        self.accepted.fetch_add(1, Ordering::Relaxed);
        self.cv.notify_one();
    }

    /// Query recent in-memory events (newest last). Filters are AND.
    pub fn query(
        &self,
        decision: Option<&str>,
        subject_id: Option<&str>,
        service: Option<&str>,
        limit: usize,
    ) -> Vec<AuditEvent> {
        let state = self.state.lock().expect("audit state");
        let limit = limit.clamp(1, 1000);
        let mut out: Vec<AuditEvent> = state
            .recent
            .iter()
            .filter(|e| {
                if let Some(d) = decision {
                    if e.decision.as_deref().map(|x| x.eq_ignore_ascii_case(d)) != Some(true) {
                        return false;
                    }
                }
                if let Some(s) = subject_id {
                    if e.subject_id.as_deref().map(|x| x.eq_ignore_ascii_case(s)) != Some(true) {
                        return false;
                    }
                }
                if let Some(svc) = service {
                    if e.service.as_deref().map(|x| x.eq_ignore_ascii_case(svc)) != Some(true) {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();
        if out.len() > limit {
            out = out.split_off(out.len() - limit);
        }
        out
    }

    pub fn stats(&self) -> AuditPipelineStats {
        AuditPipelineStats {
            accepted: self.accepted.load(Ordering::Relaxed),
            written: self.written.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            queue_capacity: self.capacity as u64,
            recent_len: self
                .state
                .lock()
                .map(|s| s.recent.len() as u64)
                .unwrap_or(0),
        }
    }

    fn worker_loop(&self) {
        loop {
            let event = {
                let mut state = self.state.lock().expect("audit state");
                while state.queue.is_empty() && !state.closed {
                    state = self.cv.wait(state).expect("audit wait");
                }
                if state.queue.is_empty() && state.closed {
                    break;
                }
                state.queue.pop_front()
            };
            let Some(event) = event else {
                continue;
            };
            self.dispatch(&event);
            self.written.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn dispatch(&self, event: &AuditEvent) {
        if self.write_tracing.load(Ordering::Relaxed) {
            tracing::info!(
                target: crate::audit::AUDIT_TARGET,
                event_id = event.event_id.as_deref().unwrap_or(""),
                action = event.action.as_deref().unwrap_or(""),
                decision = event.decision.as_deref().unwrap_or(""),
                subject_id = event.subject_id.as_deref().unwrap_or(""),
                service = event.service.as_deref().unwrap_or(""),
                listener = event.listener.as_deref().unwrap_or(""),
                outcome = event.outcome.as_deref().unwrap_or(""),
                rule = event.rule.as_deref().unwrap_or(""),
                "audit pipeline event"
            );
        }
        if self.write_file.load(Ordering::Relaxed) {
            if let Ok(guard) = self.file_path.lock() {
                if let Some(path) = guard.as_ref() {
                    let _ = append_jsonl(path, event);
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct AuditPipelineStats {
    pub accepted: u64,
    pub written: u64,
    pub dropped: u64,
    pub queue_capacity: u64,
    pub recent_len: u64,
}

fn append_jsonl(path: &Path, event: &AuditEvent) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let line = serde_json::to_string(event)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn new_event_id() -> String {
    // Lightweight unique-ish id without uuid crate.
    format!("ae-{}-{:x}", now_unix_ms(), simple_nonce())
}

fn simple_nonce() -> u64 {
    use std::cell::Cell;
    thread_local! {
        static N: Cell<u64> = Cell::new(0xcbf29ce484222325);
    }
    N.with(|c| {
        let mut v = c.get();
        v = v.wrapping_mul(0x100000001b3) ^ now_unix_ms();
        c.set(v);
        v
    })
}

/// Helper to build a data-plane audit event quickly.
pub fn data_plane_event(
    decision: &str,
    subject_id: Option<&str>,
    listener: &str,
    service: &str,
    command_type: &str,
    outcome: Option<&str>,
) -> AuditEvent {
    AuditEvent {
        action: Some(crate::audit::AuditAction::Query.as_str().into()),
        decision: Some(decision.into()),
        subject_id: subject_id.map(|s| s.to_owned()),
        listener: Some(listener.into()),
        service: Some(service.into()),
        command_type: Some(command_type.into()),
        outcome: outcome.map(|s| s.to_owned()),
        audit_level: Some("L0".into()),
        ..AuditEvent::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::SecurityAuditConfig;
    use std::time::Duration;

    #[test]
    fn try_send_and_query_recent() {
        let mut cfg = SecurityAuditConfig::default();
        cfg.queue_capacity = 128;
        cfg.sinks = vec!["tracing".into()];
        cfg.overflow = "drop_new".into();
        let pipe = AuditPipeline::new(&cfg);
        // No worker needed for recent ring.
        for i in 0..5 {
            let mut e = AuditEvent::default();
            e.decision = Some(if i % 2 == 0 { "deny" } else { "execute" }.into());
            e.subject_id = Some(format!("u{i}"));
            e.service = Some("orders".into());
            pipe.try_send(e);
        }
        let denies = pipe.query(Some("deny"), None, Some("orders"), 10);
        assert_eq!(denies.len(), 3);
        assert!(denies.iter().all(|e| e.decision.as_deref() == Some("deny")));
        let stats = pipe.stats();
        assert_eq!(stats.accepted, 5);
        assert_eq!(stats.dropped, 0);
    }

    #[test]
    fn drop_new_under_pressure() {
        let mut cfg = SecurityAuditConfig::default();
        cfg.queue_capacity = 2;
        cfg.overflow = "drop_new".into();
        cfg.sinks = vec!["tracing".into()];
        let pipe = AuditPipeline::new(&cfg);
        // Fill queue without worker draining → capacity 2
        for i in 0..5 {
            let mut e = AuditEvent::default();
            e.decision = Some("execute".into());
            e.message = Some(format!("{i}"));
            pipe.try_send(e);
        }
        let stats = pipe.stats();
        assert!(stats.dropped >= 3, "{stats:?}");
        assert_eq!(stats.accepted + stats.dropped, 5);
    }

    #[test]
    fn jsonl_writer_appends() {
        let dir = std::env::temp_dir().join(format!("dn-audit-{}", now_unix_ms()));
        let path = dir.join("events.jsonl");
        let mut e = AuditEvent::default();
        e.decision = Some("deny".into());
        e.subject_id = Some("alice".into());
        append_jsonl(&path, &e).unwrap();
        append_jsonl(&path, &e).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body.lines().count(), 2);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn worker_drains_queue() {
        let mut cfg = SecurityAuditConfig::default();
        cfg.queue_capacity = 64;
        cfg.sinks = vec!["tracing".into()];
        let pipe = Arc::new(AuditPipeline::new(&cfg));
        pipe.spawn_worker();
        for _ in 0..10 {
            let mut e = AuditEvent::default();
            e.decision = Some("execute".into());
            pipe.try_send(e);
        }
        // Wait for worker
        for _ in 0..50 {
            if pipe.stats().written >= 10 {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(pipe.stats().written >= 10, "{:?}", pipe.stats());
    }
}
