//! Async audit pipeline (S4): bounded queue + worker + JSONL/memory sinks.
//!
//! Hot path only `try_send`s; never blocks the query path. Overflow is counted
//! and optionally drops oldest/newest per config.
//!
//! B04: optional size-based rotation, age prune, and keep-N for JSONL files.
//! B06: optional SQLite side-index (`index_path`) for Admin search beyond the
//! in-memory recent ring; worker inserts after dequeue (never on hot path).
//! B07: deny / require_approval use a separate bounded priority queue so a
//! flood of allow/execute under `drop_new` cannot discard critical events.

use crate::audit::{apply_audit_level_payload, AuditEvent, AuditLevel};
use crate::audit_index::{AuditIndex, AuditQueryFilter};
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

pub fn install_audit_pipeline(
    config: &SecurityAuditConfig,
    default_audit_level: &str,
) -> Arc<AuditPipeline> {
    configure_opendal_archive(config);
    if let Some(existing) = GLOBAL.get() {
        existing.reconfigure(config, default_audit_level);
        return existing.clone();
    }
    let pipe = Arc::new(AuditPipeline::new(config, default_audit_level));
    pipe.spawn_worker();
    let _ = GLOBAL.set(pipe.clone());
    pipe
}

fn configure_opendal_archive(config: &SecurityAuditConfig) {
    #[cfg(feature = "audit-opendal")]
    {
        match crate::audit_opendal::OpendalArchive::from_config(config) {
            Ok(arch) => crate::audit_opendal::set_global_archive(arch),
            Err(e) => {
                tracing::error!(
                    target: "data_nexus::audit",
                    error = %e,
                    "failed to configure OpenDAL audit archive"
                );
                crate::audit_opendal::set_global_archive(None);
            }
        }
    }
    #[cfg(not(feature = "audit-opendal"))]
    {
        let _ = config;
        if !config.opendal_scheme.trim().is_empty() {
            tracing::warn!(
                target: "data_nexus::audit",
                scheme = %config.opendal_scheme,
                "opendal_scheme set but binary built without audit-opendal feature"
            );
        }
    }
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

/// Critical security decisions that must not lose to allow/execute floods. B07.
fn is_priority_decision(decision: Option<&str>) -> bool {
    matches!(
        decision.map(|d| d.trim().to_ascii_lowercase()).as_deref(),
        Some("deny") | Some("require_approval") | Some("require_ticket")
    )
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
    /// Normal priority (allow / execute / …).
    queue: VecDeque<AuditEvent>,
    /// High priority (deny / require_approval). Drained before `queue`. B07.
    priority_queue: VecDeque<AuditEvent>,
    recent: VecDeque<AuditEvent>,
    closed: bool,
}

pub struct AuditPipeline {
    capacity: usize,
    /// Separate capacity for priority events; 0 → priority uses main queue only.
    priority_capacity: usize,
    recent_capacity: usize,
    overflow: OverflowPolicy,
    /// F32: configured default audit level for payload trim.
    payload_level: Mutex<AuditLevel>,
    /// F32: max SQL chars at L1/L2.
    sql_text_max_chars: Mutex<usize>,
    file_path: Mutex<Option<PathBuf>>,
    file_policy: Mutex<FileSinkPolicy>,
    write_file: AtomicBool,
    write_tracing: AtomicBool,
    /// B06: SQLite side-index; `None` when `index_path` empty.
    index: Mutex<Option<Arc<AuditIndex>>>,
    state: Mutex<SharedState>,
    cv: Condvar,
    dropped: AtomicU64,
    /// Drops from the priority queue only (still counted in `dropped`).
    priority_dropped: AtomicU64,
    accepted: AtomicU64,
    /// Accepted into the priority queue.
    priority_accepted: AtomicU64,
    written: AtomicU64,
    rotated: AtomicU64,
    pruned: AtomicU64,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl AuditPipeline {
    pub fn new(config: &SecurityAuditConfig, default_audit_level: &str) -> Self {
        let capacity = config.queue_capacity.max(1) as usize;
        let priority_capacity = config.priority_queue_capacity as usize;
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
        let index = open_index(config.index_path.trim());
        let level = AuditLevel::parse(default_audit_level).unwrap_or(AuditLevel::L0);
        let max_sql = if config.sql_text_max_chars == 0 {
            AuditLevel::DEFAULT_SQL_TEXT_MAX_CHARS
        } else {
            config.sql_text_max_chars as usize
        };
        Self {
            capacity,
            priority_capacity,
            recent_capacity,
            overflow: OverflowPolicy::parse(&config.overflow),
            payload_level: Mutex::new(level),
            sql_text_max_chars: Mutex::new(max_sql),
            file_path: Mutex::new(file_path),
            file_policy: Mutex::new(FileSinkPolicy::from_config(config)),
            write_file: AtomicBool::new(write_file),
            write_tracing: AtomicBool::new(write_tracing),
            index: Mutex::new(index),
            state: Mutex::new(SharedState {
                queue: VecDeque::with_capacity(capacity),
                priority_queue: VecDeque::with_capacity(priority_capacity.max(1)),
                recent: VecDeque::with_capacity(recent_capacity),
                closed: false,
            }),
            cv: Condvar::new(),
            dropped: AtomicU64::new(0),
            priority_dropped: AtomicU64::new(0),
            accepted: AtomicU64::new(0),
            priority_accepted: AtomicU64::new(0),
            written: AtomicU64::new(0),
            rotated: AtomicU64::new(0),
            pruned: AtomicU64::new(0),
            worker: Mutex::new(None),
        }
    }

    pub fn reconfigure(&self, config: &SecurityAuditConfig, default_audit_level: &str) {
        let sinks = config
            .sinks
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect::<Vec<_>>();
        let write_file = sinks.iter().any(|s| s == "file" || s == "jsonl");
        let write_tracing = sinks.is_empty() || sinks.iter().any(|s| s == "tracing");
        self.write_file.store(write_file, Ordering::Relaxed);
        self.write_tracing.store(write_tracing, Ordering::Relaxed);
        if let Ok(mut lvl) = self.payload_level.lock() {
            *lvl = AuditLevel::parse(default_audit_level).unwrap_or(AuditLevel::L0);
        }
        if let Ok(mut max) = self.sql_text_max_chars.lock() {
            *max = if config.sql_text_max_chars == 0 {
                AuditLevel::DEFAULT_SQL_TEXT_MAX_CHARS
            } else {
                config.sql_text_max_chars as usize
            };
        }
        if !config.file_path.trim().is_empty() {
            if let Ok(mut path) = self.file_path.lock() {
                *path = Some(PathBuf::from(config.file_path.trim()));
            }
        }
        if let Ok(mut pol) = self.file_policy.lock() {
            *pol = FileSinkPolicy::from_config(config);
        }
        // Re-open index only when path changes (or enable/disable).
        if let Ok(mut guard) = self.index.lock() {
            let want = config.index_path.trim();
            let current = guard.as_ref().map(|i| i.path().to_string_lossy().to_string());
            let need_reopen = match (want.is_empty(), &current) {
                (true, None) => false,
                (true, Some(_)) => true,
                (false, None) => true,
                (false, Some(cur)) => cur != want,
            };
            if need_reopen {
                *guard = open_index(want);
            }
        }
        configure_opendal_archive(config);
    }

    /// B06: shared handle to the SQLite index when configured.
    pub fn index(&self) -> Option<Arc<AuditIndex>> {
        self.index.lock().ok().and_then(|g| g.clone())
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
        // F32: enforce L0/L1/L2 payload policy before ring/queue/index.
        let level = self
            .payload_level
            .lock()
            .map(|g| *g)
            .unwrap_or(AuditLevel::L0);
        let max_sql = self
            .sql_text_max_chars
            .lock()
            .map(|g| *g)
            .unwrap_or(AuditLevel::DEFAULT_SQL_TEXT_MAX_CHARS);
        apply_audit_level_payload(&mut event, level, max_sql);
        {
            let mut state = self.state.lock().expect("audit state");
            if state.recent.len() >= self.recent_capacity {
                state.recent.pop_front();
            }
            state.recent.push_back(event.clone());
        }

        let priority = self.priority_capacity > 0
            && is_priority_decision(event.decision.as_deref());

        let mut state = self.state.lock().expect("audit state");
        if state.closed {
            return;
        }

        if priority {
            if !self.enqueue(
                &mut state.priority_queue,
                self.priority_capacity,
                event,
                true,
            ) {
                return;
            }
            self.priority_accepted.fetch_add(1, Ordering::Relaxed);
        } else if !self.enqueue(&mut state.queue, self.capacity, event, false) {
            return;
        }
        self.accepted.fetch_add(1, Ordering::Relaxed);
        self.cv.notify_one();
    }

    /// Push into a bounded queue applying overflow policy. Returns false if dropped.
    fn enqueue(
        &self,
        queue: &mut VecDeque<AuditEvent>,
        capacity: usize,
        event: AuditEvent,
        is_priority: bool,
    ) -> bool {
        if queue.len() >= capacity {
            match self.overflow {
                OverflowPolicy::DropOld => {
                    let _ = queue.pop_front();
                    self.record_drop(is_priority);
                }
                OverflowPolicy::Sample => {
                    if now_unix_ms() % 2 == 0 {
                        self.record_drop(is_priority);
                        return false;
                    }
                    let _ = queue.pop_front();
                    self.record_drop(is_priority);
                }
                OverflowPolicy::DropNew | OverflowPolicy::Block => {
                    self.record_drop(is_priority);
                    return false;
                }
            }
        }
        queue.push_back(event);
        true
    }

    fn record_drop(&self, is_priority: bool) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
        if is_priority {
            self.priority_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Query recent ring and/or SQLite index (B06).
    ///
    /// When an index is configured, results come from SQLite (survives beyond
    /// the in-memory ring). Otherwise falls back to the recent ring filter.
    pub fn query(
        &self,
        decision: Option<&str>,
        subject_id: Option<&str>,
        service: Option<&str>,
        limit: usize,
    ) -> Vec<AuditEvent> {
        self.query_filter(&AuditQueryFilter {
            decision: decision.map(|s| s.to_owned()),
            subject_id: subject_id.map(|s| s.to_owned()),
            service: service.map(|s| s.to_owned()),
            limit,
            ..Default::default()
        })
    }

    /// Full filter API used by Admin (event_id / time range). B06.
    pub fn query_filter(&self, filter: &AuditQueryFilter) -> Vec<AuditEvent> {
        let limit = filter.limit_clamped().min(1000);
        if let Some(idx) = self.index() {
            let mut f = filter.clone();
            f.limit = limit;
            match idx.query(&f) {
                Ok(rows) => return rows,
                Err(e) => {
                    tracing::warn!(
                        target: "data_nexus::audit",
                        error = %e,
                        "audit index query failed; falling back to recent ring"
                    );
                }
            }
        }
        self.query_recent(filter, limit)
    }

    fn query_recent(&self, filter: &AuditQueryFilter, limit: usize) -> Vec<AuditEvent> {
        let state = self.state.lock().expect("audit state");
        state
            .recent
            .iter()
            .rev()
            .filter(|e| {
                filter
                    .event_id
                    .as_deref()
                    .map(|id| e.event_id.as_deref() == Some(id))
                    .unwrap_or(true)
                    && filter
                        .decision
                        .as_deref()
                        .map(|d| e.decision.as_deref() == Some(d))
                        .unwrap_or(true)
                    && filter
                        .subject_id
                        .as_deref()
                        .map(|s| e.subject_id.as_deref() == Some(s))
                        .unwrap_or(true)
                    && filter
                        .service
                        .as_deref()
                        .map(|s| e.service.as_deref() == Some(s))
                        .unwrap_or(true)
                    && filter
                        .from_ms
                        .map(|from| e.ts_unix_ms.unwrap_or(0) >= from)
                        .unwrap_or(true)
                    && filter
                        .to_ms
                        .map(|to| e.ts_unix_ms.unwrap_or(u64::MAX) <= to)
                        .unwrap_or(true)
            })
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn stats(&self) -> AuditPipelineStats {
        let (recent_len, queue_len, priority_queue_len) = self
            .state
            .lock()
            .map(|s| {
                (
                    s.recent.len() as u64,
                    s.queue.len() as u64,
                    s.priority_queue.len() as u64,
                )
            })
            .unwrap_or((0, 0, 0));
        let (index_enabled, index_rows, index_inserted, index_errors, index_pruned) =
            match self.index() {
                Some(idx) => (
                    true,
                    idx.row_count(),
                    idx.inserted(),
                    idx.errors(),
                    idx.pruned(),
                ),
                None => (false, 0, 0, 0, 0),
            };
        AuditPipelineStats {
            accepted: self.accepted.load(Ordering::Relaxed),
            written: self.written.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            queue_capacity: self.capacity as u64,
            priority_queue_capacity: self.priority_capacity as u64,
            priority_accepted: self.priority_accepted.load(Ordering::Relaxed),
            priority_dropped: self.priority_dropped.load(Ordering::Relaxed),
            queue_len,
            priority_queue_len,
            recent_len,
            rotated: self.rotated.load(Ordering::Relaxed),
            pruned: self.pruned.load(Ordering::Relaxed),
            index_enabled,
            index_rows,
            index_inserted,
            index_errors,
            index_pruned,
        }
    }

    pub fn run_retention_now(&self) {
        let path = match self.file_path.lock() {
            Ok(g) => g.clone(),
            Err(_) => None,
        };
        let policy = match self.file_policy.lock() {
            Ok(g) => g.clone(),
            Err(_) => return,
        };
        if let Some(active) = path {
            let pruned = prune_rotated_files(&active, &policy);
            if pruned > 0 {
                self.pruned.fetch_add(pruned, Ordering::Relaxed);
            }
        }
        // B06: age-prune SQLite index with the same retain_days as JSONL.
        if let Some(idx) = self.index() {
            let _ = idx.prune_older_than_days(policy.retain_days);
        }
    }

    fn worker_loop(&self) {
        let mut since_prune = 0u64;
        loop {
            let event = {
                let mut state = self.state.lock().expect("audit state");
                while state.queue.is_empty()
                    && state.priority_queue.is_empty()
                    && !state.closed
                {
                    state = self.cv.wait(state).expect("audit wait");
                }
                if state.queue.is_empty() && state.priority_queue.is_empty() && state.closed {
                    break;
                }
                // Drain priority first so deny/require_approval write ahead of allow floods.
                state
                    .priority_queue
                    .pop_front()
                    .or_else(|| state.queue.pop_front())
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
        // B06: side-index insert on worker only (never blocks try_send).
        if let Some(idx) = self.index() {
            if let Err(e) = idx.insert(event) {
                idx.record_error();
                tracing::warn!(
                    target: "data_nexus::audit",
                    error = %e,
                    "audit index insert failed"
                );
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
    /// B07: capacity of the independent deny/require_approval queue (0 = disabled).
    pub priority_queue_capacity: u64,
    pub priority_accepted: u64,
    pub priority_dropped: u64,
    pub queue_len: u64,
    pub priority_queue_len: u64,
    pub recent_len: u64,
    pub rotated: u64,
    pub pruned: u64,
    /// B06: SQLite side-index is open.
    pub index_enabled: bool,
    pub index_rows: u64,
    pub index_inserted: u64,
    pub index_errors: u64,
    pub index_pruned: u64,
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
    #[cfg(feature = "audit-opendal")]
    {
        let _ = crate::audit_opendal::try_archive_rotated_file(&dest);
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

fn open_index(path: &str) -> Option<Arc<AuditIndex>> {
    let path = path.trim();
    if path.is_empty() {
        return None;
    }
    match AuditIndex::open(path) {
        Ok(idx) => {
            tracing::info!(
                target: "data_nexus::audit",
                path = %path,
                "audit SQLite index enabled"
            );
            Some(Arc::new(idx))
        }
        Err(e) => {
            tracing::error!(
                target: "data_nexus::audit",
                path = %path,
                error = %e,
                "failed to open audit SQLite index"
            );
            None
        }
    }
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
        let pipe = AuditPipeline::new(&cfg, "L0");
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
        let pipe = AuditPipeline::new(&cfg, "L0");
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
    fn priority_deny_survives_main_queue_flood() {
        // B07: main queue full under drop_new must not drop deny / require_approval.
        let mut cfg = SecurityAuditConfig::default();
        cfg.queue_capacity = 2;
        cfg.priority_queue_capacity = 8;
        cfg.overflow = "drop_new".into();
        cfg.sinks = vec!["tracing".into()];
        let pipe = AuditPipeline::new(&cfg, "L0");

        for i in 0..10 {
            let mut e = AuditEvent::default();
            e.decision = Some("execute".into());
            e.message = Some(format!("exec-{i}"));
            pipe.try_send(e);
        }
        let after_flood = pipe.stats();
        assert!(after_flood.dropped >= 8, "{after_flood:?}");
        assert_eq!(after_flood.priority_accepted, 0);

        let mut deny = AuditEvent::default();
        deny.decision = Some("deny".into());
        deny.rule = Some("secret-table".into());
        pipe.try_send(deny);

        let mut ticket = AuditEvent::default();
        ticket.decision = Some("require_approval".into());
        ticket.rule = Some("ddl".into());
        pipe.try_send(ticket);

        let stats = pipe.stats();
        assert_eq!(stats.priority_accepted, 2, "{stats:?}");
        assert_eq!(stats.priority_dropped, 0, "{stats:?}");
        assert_eq!(stats.priority_queue_len, 2, "{stats:?}");
        // Main queue still only holds capacity execute events.
        assert!(stats.queue_len <= 2, "{stats:?}");

        let denies = pipe.query(Some("deny"), None, None, 10);
        assert_eq!(denies.len(), 1);
        assert_eq!(denies[0].rule.as_deref(), Some("secret-table"));
        let tickets = pipe.query(Some("require_approval"), None, None, 10);
        assert_eq!(tickets.len(), 1);
    }

    #[test]
    fn worker_drains_priority_before_normal() {
        let mut cfg = SecurityAuditConfig::default();
        cfg.queue_capacity = 64;
        cfg.priority_queue_capacity = 16;
        cfg.sinks = vec!["tracing".into()];
        // Do not spawn worker yet — fill both queues, then drain order via pop logic.
        let pipe = AuditPipeline::new(&cfg, "L0");
        for _ in 0..3 {
            let mut e = AuditEvent::default();
            e.decision = Some("execute".into());
            pipe.try_send(e);
        }
        let mut deny = AuditEvent::default();
        deny.decision = Some("deny".into());
        deny.message = Some("critical".into());
        pipe.try_send(deny);

        // Manually exercise drain order the worker uses.
        let mut state = pipe.state.lock().unwrap();
        let first = state
            .priority_queue
            .pop_front()
            .or_else(|| state.queue.pop_front())
            .unwrap();
        assert_eq!(first.decision.as_deref(), Some("deny"));
        assert_eq!(first.message.as_deref(), Some("critical"));
        let second = state
            .priority_queue
            .pop_front()
            .or_else(|| state.queue.pop_front())
            .unwrap();
        assert_eq!(second.decision.as_deref(), Some("execute"));
    }

    #[test]
    fn priority_queue_zero_disables_split() {
        let mut cfg = SecurityAuditConfig::default();
        cfg.queue_capacity = 2;
        cfg.priority_queue_capacity = 0;
        cfg.overflow = "drop_new".into();
        cfg.sinks = vec!["tracing".into()];
        let pipe = AuditPipeline::new(&cfg, "L0");
        for i in 0..4 {
            let mut e = AuditEvent::default();
            e.decision = Some(if i == 3 { "deny" } else { "execute" }.into());
            pipe.try_send(e);
        }
        let stats = pipe.stats();
        // With priority disabled, deny competes on the main queue under drop_new.
        assert_eq!(stats.priority_queue_capacity, 0);
        assert_eq!(stats.priority_accepted, 0);
        assert!(stats.dropped >= 2, "{stats:?}");
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
        let pipe = Arc::new(AuditPipeline::new(&cfg, "L0"));
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

    #[test]
    fn index_survives_beyond_recent_ring() {
        // B06: SQLite index keeps events after the in-memory recent ring rolls.
        let dir = std::env::temp_dir().join(format!("dn-audit-idx-pipe-{}", now_unix_ms()));
        let _ = fs::create_dir_all(&dir);
        let index_path = dir.join("index.sqlite");

        let mut cfg = SecurityAuditConfig::default();
        // recent_capacity = capacity.min(4096).max(64). Keep queue large; pace sends
        // so the worker drains without drop_new losses.
        cfg.queue_capacity = 128;
        cfg.priority_queue_capacity = 32;
        cfg.overflow = "drop_new".into();
        cfg.sinks = vec!["tracing".into()];
        cfg.index_path = index_path.to_string_lossy().into();
        let pipe = Arc::new(AuditPipeline::new(&cfg, "L0"));
        assert!(pipe.index().is_some());
        pipe.spawn_worker();

        let mut first = AuditEvent::default();
        first.decision = Some("deny".into());
        first.subject_id = Some("early-alice".into());
        first.service = Some("orders".into());
        first.rule = Some("seed".into());
        pipe.try_send(first);

        // 200 > recent_capacity (128) so early deny leaves the in-memory ring.
        for i in 0..200 {
            let mut e = AuditEvent::default();
            e.decision = Some("execute".into());
            e.subject_id = Some(format!("u{i}"));
            e.service = Some("orders".into());
            pipe.try_send(e);
            // Pace so worker can drain; avoid drop_new under flood.
            if i % 16 == 15 {
                for _ in 0..50 {
                    if pipe.stats().queue_len < 32 {
                        break;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
            }
        }

        for _ in 0..200 {
            let s = pipe.stats();
            if s.written >= 201 && s.index_inserted >= 201 && s.queue_len == 0 {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        let stats = pipe.stats();
        assert!(stats.index_enabled, "{stats:?}");
        assert!(stats.index_inserted >= 201, "{stats:?}");
        assert_eq!(stats.index_errors, 0, "{stats:?}");
        assert_eq!(stats.dropped, 0, "{stats:?}");
        // Ring has rolled; early-alice is no longer in recent.
        assert!(
            !pipe
                .query_recent(
                    &AuditQueryFilter {
                        subject_id: Some("early-alice".into()),
                        limit: 10,
                        ..Default::default()
                    },
                    10
                )
                .iter()
                .any(|e| e.subject_id.as_deref() == Some("early-alice")),
            "expected early-alice to fall out of recent ring"
        );

        let denies = pipe.query(Some("deny"), Some("early-alice"), Some("orders"), 10);
        assert_eq!(denies.len(), 1, "{denies:?}");
        assert_eq!(denies[0].rule.as_deref(), Some("seed"));

        let by_filter = pipe.query_filter(&AuditQueryFilter {
            subject_id: Some("early-alice".into()),
            limit: 5,
            ..Default::default()
        });
        assert_eq!(by_filter.len(), 1);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn empty_index_path_keeps_recent_only() {
        let mut cfg = SecurityAuditConfig::default();
        cfg.queue_capacity = 32;
        cfg.sinks = vec!["tracing".into()];
        cfg.index_path = String::new();
        let pipe = AuditPipeline::new(&cfg, "L0");
        assert!(pipe.index().is_none());
        let stats = pipe.stats();
        assert!(!stats.index_enabled);
        assert_eq!(stats.index_rows, 0);
    }

    #[test]
    fn f32_try_send_strips_sql_at_l0() {
        let mut cfg = SecurityAuditConfig::default();
        cfg.queue_capacity = 32;
        cfg.sinks = vec!["tracing".into()];
        let pipe = AuditPipeline::new(&cfg, "L0");
        let mut e = AuditEvent::default();
        e.decision = Some("execute".into());
        e.sql_text = Some("SELECT secret FROM t".into());
        e.sql_fingerprint = Some("fp".into());
        e.audit_level = Some("L1".into()); // capped by configured L0
        pipe.try_send(e);
        let recent = pipe.query(None, None, None, 10);
        assert_eq!(recent.len(), 1);
        assert!(recent[0].sql_text.is_none());
        assert_eq!(recent[0].sql_fingerprint.as_deref(), Some("fp"));
        assert_eq!(recent[0].audit_level.as_deref(), Some("L0"));
    }

    #[test]
    fn f32_try_send_keeps_truncated_sql_at_l1() {
        let mut cfg = SecurityAuditConfig::default();
        cfg.queue_capacity = 32;
        cfg.sql_text_max_chars = 8;
        cfg.sinks = vec!["tracing".into()];
        let pipe = AuditPipeline::new(&cfg, "L1");
        let mut e = AuditEvent::default();
        e.decision = Some("execute".into());
        e.sql_text = Some("1234567890abcdef".into());
        e.audit_level = Some("L1".into());
        pipe.try_send(e);
        let recent = pipe.query(None, None, None, 10);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].sql_text.as_deref(), Some("12345678…"));
    }

}
