//! Async audit pipeline (S4): bounded queue + worker + JSONL/memory sinks.
//!
//! Hot path only `try_send`s; never blocks the query path. Overflow is counted
//! and optionally drops oldest/newest per config.
//!
//! B04: optional size-based rotation, age prune, and keep-N for JSONL files.

use crate::audit::AuditEvent;
use crate::security::SecurityAuditConfig;
use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static GLOBAL: OnceLock<Arc<AuditPipeline>> = OnceLock::new();

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

pub fn global_audit_pipeline() -> Option<Arc<AuditPipeline>> {
    GLOBAL.get().cloned()
}

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
    Block,
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

#[derive(Debug, Clone)]
struct FileSinkPolicy {
    max_file_bytes: u64,
    retain_days: u32,
    rotate_keep: u32,
    archive_dir: Option<PathBuf>,
}

impl FileSinkPolicy {
    fn from_config(config: &SecurityAuditConfig) -> Self {
        Self {
            max_file_bytes: config.max_file_bytes,
            retain_days: config.retain_days,
            rotate_keep: config.rotate_keep,
            archive_dir: {
                let d = config.archive_dir.trim();
                if d.is_empty() {
                    None
                } else {
                    Some(PathBuf::from(d))
                }
            },
        }
    }
}

struct SharedState {
    queue: VecDeque<AuditEvent>,
    recent: VecDeque<AuditEvent>,
    closed: bool,
}

pub struct AuditPipeline {
    capacity: usize,
    recent_capacity: usize,
    overflow: OverflowPolicy,
    file_path: Mutex<Option<PathBuf>>,
    file_policy: Mutex<FileSinkPolicy>,
    write_file: AtomicBool,
    write_tracing: AtomicBool,
    state: Mutex<SharedState>,
    cv: Condvar,
    dropped: AtomicU64,
    accepted: AtomicU64,
    written: AtomicU64,
    rotated: AtomicU64,
    pruned: AtomicU64,
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
            file_policy: Mutex::new(FileSinkPolicy::from_config(config)),
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
            rotated: AtomicU64::new(0),
            pruned: AtomicU64::new(0),
            worker: Mutex::new(None),
        }
    }

    pub fn reconfigure(&self, config: &SecurityAuditConfig) {
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
        if let Ok(mut pol) = self.file_policy.lock() {
            *pol = FileSinkPolicy::from_config(config);
        }
    }

    pub fn spawn_worker(self: &Arc<Self>) {
        let mut guard = self.worker.lock().expect("audit worker lock");
        if guard.is_some() {
            return;
        }
        let this = Arc::clone(self);
        let handle = thread::Builder::new()
            .name("data-nexus-audit".into())
            .spawn(move || this.worker_loop())
            .expect("spawn audit worker");
        *guard = Some(handle);
    }

    pub fn try_send(&self, mut event: AuditEvent) {
        if event.event_id.is_none() {
            event.event_id = Some(new_event_id());
        }
        if event.ts_unix_ms.is_none() {
            event.ts_unix_ms = Some(now_unix_ms());
        }
        {
            let mut state = self.state.lock().expect("audit state");
            if state.recent.len() >= self.recent_capacity {
                state.recent.pop_front();
            }
            state.recent.push_back(event.clone());
        }

        let mut state = self.state.lock().expect("audit state");
        if state.closed {
            return;
        }
        if state.queue.len() >= self.capacity {
            match self.overflow {
                OverflowPolicy::DropOld => {
                    let _ = state.queue.pop_front();
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                }
                OverflowPolicy::Sample => {
                    if now_unix_ms() % 2 == 0 {
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
        state.queue.push_back(event);
        self.accepted.fetch_add(1, Ordering::Relaxed);
        self.cv.notify_one();
    }

    pub fn query(
        &self,
        decision: Option<&str>,
        subject_id: Option<&str>,
        service: Option<&str>,
        limit: usize,
    ) -> Vec<AuditEvent> {
        let state = self.state.lock().expect("audit state");
        let limit = limit.clamp(1, 500);
        state
            .recent
            .iter()
            .rev()
            .filter(|e| {
                decision
                    .map(|d| e.decision.as_deref() == Some(d))
                    .unwrap_or(true)
                    && subject_id
                        .map(|s| e.subject_id.as_deref() == Some(s))
                        .unwrap_or(true)
                    && service
                        .map(|s| e.service.as_deref() == Some(s))
                        .unwrap_or(true)
            })
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn stats(&self) -> AuditPipelineStats {
        let recent_len = self
            .state
            .lock()
            .map(|s| s.recent.len() as u64)
            .unwrap_or(0);
        AuditPipelineStats {
            accepted: self.accepted.load(Ordering::Relaxed),
            written: self.written.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            queue_capacity: self.capacity as u64,
            recent_len,
            rotated: self.rotated.load(Ordering::Relaxed),
            pruned: self.pruned.load(Ordering::Relaxed),
        }
    }

    pub fn run_retention_now(&self) {
        let path = match self.file_path.lock() {
            Ok(g) => g.clone(),
            Err(_) => return,
        };
        let Some(active) = path else {
            return;
        };
        let policy = match self.file_policy.lock() {
            Ok(g) => g.clone(),
            Err(_) => return,
        };
        let pruned = prune_rotated_files(&active, &policy);
        if pruned > 0 {
            self.pruned.fetch_add(pruned, Ordering::Relaxed);
        }
    }

    fn worker_loop(&self) {
        let mut since_prune = 0u64;
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
            since_prune += 1;
            if since_prune >= 256 {
                since_prune = 0;
                self.run_retention_now();
            }
        }
        self.run_retention_now();
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
                    let policy = self
                        .file_policy
                        .lock()
                        .map(|g| g.clone())
                        .unwrap_or(FileSinkPolicy {
                            max_file_bytes: 0,
                            retain_days: 0,
                            rotate_keep: 0,
                            archive_dir: None,
                        });
                    match append_jsonl_with_rotate(path, event, &policy) {
                        Ok(RotateOutcome::Rotated) => {
                            self.rotated.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(RotateOutcome::Appended) => {}
                        Err(_) => {}
                    }
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
    pub rotated: u64,
    pub pruned: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RotateOutcome {
    Appended,
    Rotated,
}

fn append_jsonl_with_rotate(
    path: &Path,
    event: &AuditEvent,
    policy: &FileSinkPolicy,
) -> std::io::Result<RotateOutcome> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let mut rotated = false;
    if policy.max_file_bytes > 0 {
        if let Ok(meta) = fs::metadata(path) {
            if meta.len() >= policy.max_file_bytes {
                rotate_active_file(path, policy)?;
                rotated = true;
            }
        }
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let line = serde_json::to_string(event)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(if rotated {
        RotateOutcome::Rotated
    } else {
        RotateOutcome::Appended
    })
}

fn rotate_active_file(path: &Path, policy: &FileSinkPolicy) -> std::io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let ts = now_unix_ms();
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("events.jsonl");
    let rotated_name = format!("{file_name}.{ts}");
    let dest_dir = policy
        .archive_dir
        .clone()
        .or_else(|| path.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    fs::create_dir_all(&dest_dir)?;
    let dest = dest_dir.join(rotated_name);
    if fs::rename(path, &dest).is_err() {
        fs::copy(path, &dest)?;
        let _ = fs::remove_file(path);
    }
    Ok(())
}

/// Delete rotated siblings by age and keep-N.
fn prune_rotated_files(active: &Path, policy: &FileSinkPolicy) -> u64 {
    let dir = policy
        .archive_dir
        .clone()
        .or_else(|| active.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    let prefix = active
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("events.jsonl");
    let Ok(rd) = fs::read_dir(&dir) else {
        return 0;
    };
    let mut candidates: Vec<(PathBuf, SystemTime)> = Vec::new();
    for entry in rd.flatten() {
        let path = entry.path();
        if path == *active {
            continue;
        }
        let name = match path.file_name().and_then(|s| s.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if !name.starts_with(prefix) || name == prefix {
            continue;
        }
        let rest = &name[prefix.len()..];
        if !rest.starts_with('.') {
            continue;
        }
        let suffix = &rest[1..];
        if suffix.is_empty() || !suffix.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let modified = entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        candidates.push((path, modified));
    }
    candidates.sort_by_key(|(_, t)| *t);
    let mut pruned = 0u64;
    let now = SystemTime::now();
    if policy.retain_days > 0 {
        let max_age = Duration::from_secs(u64::from(policy.retain_days) * 86_400);
        candidates.retain(|(path, modified)| {
            let old = now.duration_since(*modified).unwrap_or_default() > max_age;
            if old {
                if fs::remove_file(path).is_ok() {
                    pruned += 1;
                }
                false
            } else {
                true
            }
        });
    }
    if policy.rotate_keep > 0 && candidates.len() > policy.rotate_keep as usize {
        let excess = candidates.len() - policy.rotate_keep as usize;
        for (path, _) in candidates.into_iter().take(excess) {
            if fs::remove_file(path).is_ok() {
                pruned += 1;
            }
        }
    }
    pruned
}

fn append_jsonl(path: &Path, event: &AuditEvent) -> std::io::Result<()> {
    append_jsonl_with_rotate(
        path,
        event,
        &FileSinkPolicy {
            max_file_bytes: 0,
            retain_days: 0,
            rotate_keep: 0,
            archive_dir: None,
        },
    )
    .map(|_| ())
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn new_event_id() -> String {
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
    fn rotate_on_size_and_prune_keep() {
        let dir = std::env::temp_dir().join(format!("dn-audit-rot-{}", now_unix_ms()));
        let path = dir.join("events.jsonl");
        fs::create_dir_all(&dir).unwrap();
        let policy = FileSinkPolicy {
            max_file_bytes: 80,
            retain_days: 0,
            rotate_keep: 2,
            archive_dir: None,
        };
        let mut e = AuditEvent::default();
        e.decision = Some("execute".into());
        e.message = Some("x".repeat(40));
        for _ in 0..20 {
            let _ = append_jsonl_with_rotate(&path, &e, &policy).unwrap();
        }
        let rotated_before: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|x| x.path())
            .filter(|p| p != &path)
            .collect();
        assert!(!rotated_before.is_empty(), "expected rotated files in {dir:?}");
        let _pruned = prune_rotated_files(&path, &policy);
        let rotated_after: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|x| x.path())
            .filter(|p| p != &path)
            .collect();
        assert!(
            rotated_after.len() <= 2,
            "keep=2 but got {}",
            rotated_after.len()
        );
        let _ = fs::remove_dir_all(dir);
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
        for _ in 0..50 {
            if pipe.stats().written >= 10 {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(pipe.stats().written >= 10, "{:?}", pipe.stats());
    }
}
