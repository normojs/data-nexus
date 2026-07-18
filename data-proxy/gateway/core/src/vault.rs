//! S6 portal / vault: short-lived endpoint credentials + project metadata.
//!
//! Vault leases hide production endpoint passwords from the browser. The portal
//! SQL path never returns endpoint secrets; it executes through the PEP.
//!
//! H03: revoke / renew / prune. Backend passwords stay process-memory only and
//! are never serialized on **public** lease JSON (Admin API).
//!
//! H05/H08: optional AES-256-GCM file envelope (`security.state.vault_encrypt_key`)
//! stores sealed lease metadata **and** backend secrets for multi-instance
//! recovery. Without a key, file backend remains plaintext metadata only.

use crate::state_crypto::{
    decode_maybe_encrypted, encrypt_blob, parse_encrypt_key,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;

static GLOBAL: OnceLock<Arc<VaultStore>> = OnceLock::new();

/// Magic prefix for encrypted vault files (H05/H08).
const VAULT_ENC_MAGIC: &str = "DNVAULT1:";

pub fn global_vault_store() -> Arc<VaultStore> {
    GLOBAL
        .get_or_init(|| Arc::new(VaultStore::new()))
        .clone()
}

/// H05: install / reconfigure vault store.
///
/// `encrypt_key_hex`: empty → plaintext file (no passwords on disk); 64 hex chars
/// → AES-256-GCM sealed file that may restore backend secrets across processes.
pub fn install_vault_store(
    backend: &str,
    path: &str,
    encrypt_key_hex: &str,
) -> Result<Arc<VaultStore>, String> {
    let key = parse_encrypt_key(encrypt_key_hex)?;
    let store = match backend.trim().to_ascii_lowercase().as_str() {
        "memory" | "" => Arc::new(VaultStore::new()),
        "file" => Arc::new(VaultStore::with_file(PathBuf::from(path), key)?),
        other => {
            return Err(format!(
                "vault store backend '{other}' not supported (use memory or file)"
            ))
        }
    };
    if let Some(existing) = GLOBAL.get() {
        existing.reconfigure_from(&store)?;
        return Ok(existing.clone());
    }
    let _ = GLOBAL.set(store.clone());
    Ok(store)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectEnv {
    pub name: String,
    pub environment: String,
    /// Gateway service the portal should target for this project/env.
    pub service: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultLease {
    pub lease_id: String,
    pub project: String,
    pub environment: String,
    pub service: String,
    pub endpoint: String,
    pub protocol: String,
    pub address: String,
    pub database: Option<String>,
    /// Short-lived username exposed to operators (not the raw endpoint password).
    pub username: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    /// Opaque token for portal SQL; never includes backend password.
    pub access_token: String,
    /// H03: true after explicit revoke (invalid even before expiry).
    #[serde(default)]
    pub revoked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IssueVaultLeaseRequest {
    pub project: String,
    pub environment: String,
    #[serde(default = "default_ttl")]
    pub ttl_secs: u64,
    #[serde(default)]
    pub issued_by: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RenewVaultLeaseRequest {
    /// Extend TTL from *now* by this many seconds (default 900).
    #[serde(default = "default_ttl")]
    pub ttl_secs: u64,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RevokeVaultLeaseRequest {
    #[serde(default)]
    pub revoked_by: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

fn default_ttl() -> u64 {
    900
}

#[derive(Debug)]
struct LeaseRecord {
    lease: VaultLease,
    /// Backend password kept only server-side; never in VaultLease JSON.
    backend_password: String,
    backend_username: String,
}

#[derive(Debug)]
pub struct VaultStore {
    leases: Mutex<HashMap<String, LeaseRecord>>,
    projects: Mutex<Vec<ProjectEnv>>,
    seq: AtomicU64,
    /// H05: optional JSON path.
    path: Mutex<Option<PathBuf>>,
    /// H05/H08: AES-256 key for sealed file (None = plaintext metadata only).
    encrypt_key: Mutex<Option<[u8; 32]>>,
}

/// On-disk lease row when encryption is enabled (includes backend secret).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SealedLeaseRecord {
    #[serde(flatten)]
    lease: VaultLease,
    #[serde(default)]
    backend_username: String,
    #[serde(default)]
    backend_password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct VaultFile {
    projects: Vec<ProjectEnv>,
    /// Plaintext mode: public leases only.
    #[serde(default)]
    leases: Vec<VaultLease>,
    /// Encrypted mode payload uses `sealed_leases` inside ciphertext; kept here
    /// only for intermediate serde of the cleartext envelope body.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    sealed_leases: Vec<SealedLeaseRecord>,
}

impl VaultStore {
    pub fn new() -> Self {
        Self {
            leases: Mutex::new(HashMap::new()),
            projects: Mutex::new(Vec::new()),
            seq: AtomicU64::new(1),
            path: Mutex::new(None),
            encrypt_key: Mutex::new(None),
        }
    }

    pub fn with_file(path: PathBuf, encrypt_key: Option<[u8; 32]>) -> Result<Self, String> {
        let store = Self {
            leases: Mutex::new(HashMap::new()),
            projects: Mutex::new(Vec::new()),
            seq: AtomicU64::new(1),
            path: Mutex::new(Some(path)),
            encrypt_key: Mutex::new(encrypt_key),
        };
        store.load_from_disk()?;
        Ok(store)
    }

    fn reconfigure_from(&self, other: &VaultStore) -> Result<(), String> {
        let leases = other.leases.lock().map_err(|e| e.to_string())?;
        let projects = other.projects.lock().map_err(|e| e.to_string())?.clone();
        let path = other.path.lock().map_err(|e| e.to_string())?.clone();
        let key = *other.encrypt_key.lock().map_err(|e| e.to_string())?;
        let seq = other.seq.load(Ordering::Relaxed);
        *self.leases.lock().map_err(|e| e.to_string())? = leases
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    LeaseRecord {
                        lease: v.lease.clone(),
                        backend_password: v.backend_password.clone(),
                        backend_username: v.backend_username.clone(),
                    },
                )
            })
            .collect();
        *self.projects.lock().map_err(|e| e.to_string())? = projects;
        *self.path.lock().map_err(|e| e.to_string())? = path;
        *self.encrypt_key.lock().map_err(|e| e.to_string())? = key;
        self.seq.store(seq, Ordering::Relaxed);
        Ok(())
    }

    fn load_from_disk(&self) -> Result<(), String> {
        let path = self.path.lock().map_err(|e| e.to_string())?.clone();
        let Some(path) = path else { return Ok(()) };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        if !path.exists() {
            let lock = open_state_lock(&path)?;
            lock.lock_exclusive().map_err(|e| e.to_string())?;
            self.write_file_locked(&path, &[], &HashMap::new())?;
            let _ = lock.unlock();
            return Ok(());
        }
        let lock = open_state_lock(&path)?;
        lock.lock_shared().map_err(|e| e.to_string())?;
        let mut f = File::open(&path).map_err(|e| e.to_string())?;
        let mut raw = String::new();
        f.read_to_string(&mut raw).map_err(|e| e.to_string())?;
        let _ = lock.unlock();
        if raw.trim().is_empty() {
            return Ok(());
        }
        let key = *self.encrypt_key.lock().map_err(|e| e.to_string())?;
        let file = decode_vault_file(&raw, key.as_ref())?;
        *self.projects.lock().map_err(|e| e.to_string())? = file.projects;
        let mut map = HashMap::new();
        let mut max_seq = 1u64;
        if key.is_some() && !file.sealed_leases.is_empty() {
            for rec in file.sealed_leases {
                if let Some(n) = rec
                    .lease
                    .lease_id
                    .rsplit('-')
                    .next()
                    .and_then(|s| s.parse::<u64>().ok())
                {
                    max_seq = max_seq.max(n + 1);
                }
                map.insert(
                    rec.lease.lease_id.clone(),
                    LeaseRecord {
                        lease: rec.lease,
                        backend_password: rec.backend_password,
                        backend_username: rec.backend_username,
                    },
                );
            }
        } else {
            for lease in file.leases {
                if let Some(n) = lease
                    .lease_id
                    .rsplit('-')
                    .next()
                    .and_then(|s| s.parse::<u64>().ok())
                {
                    max_seq = max_seq.max(n + 1);
                }
                map.insert(
                    lease.lease_id.clone(),
                    LeaseRecord {
                        lease,
                        backend_password: String::new(),
                        backend_username: String::new(),
                    },
                );
            }
        }
        self.seq.store(max_seq, Ordering::Relaxed);
        *self.leases.lock().map_err(|e| e.to_string())? = map;
        Ok(())
    }

    fn persist(&self) -> Result<(), String> {
        let path = self.path.lock().map_err(|e| e.to_string())?.clone();
        let Some(path) = path else { return Ok(()) };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let projects = self.projects.lock().map_err(|e| e.to_string())?.clone();
        let leases_guard = self.leases.lock().map_err(|e| e.to_string())?;
        let lock = open_state_lock(&path)?;
        lock.lock_exclusive().map_err(|e| e.to_string())?;
        self.write_file_locked(&path, &projects, &leases_guard)?;
        let _ = lock.unlock();
        Ok(())
    }

    fn write_file_locked(
        &self,
        path: &std::path::Path,
        projects: &[ProjectEnv],
        leases_map: &HashMap<String, LeaseRecord>,
    ) -> Result<(), String> {
        let key = *self.encrypt_key.lock().map_err(|e| e.to_string())?;
        let data = if let Some(key) = key {
            let mut sealed: Vec<SealedLeaseRecord> = leases_map
                .values()
                .map(|r| SealedLeaseRecord {
                    lease: r.lease.clone(),
                    backend_username: r.backend_username.clone(),
                    backend_password: r.backend_password.clone(),
                })
                .collect();
            sealed.sort_by(|a, b| b.lease.issued_at_unix_ms.cmp(&a.lease.issued_at_unix_ms));
            let body = VaultFile {
                projects: projects.to_vec(),
                leases: Vec::new(),
                sealed_leases: sealed,
            };
            let plain = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
            encrypt_blob(VAULT_ENC_MAGIC, &key, &plain)?
        } else {
            let mut leases: Vec<VaultLease> =
                leases_map.values().map(|r| r.lease.clone()).collect();
            leases.sort_by(|a, b| b.issued_at_unix_ms.cmp(&a.issued_at_unix_ms));
            let file = VaultFile {
                projects: projects.to_vec(),
                leases,
                sealed_leases: Vec::new(),
            };
            serde_json::to_vec_pretty(&file).map_err(|e| e.to_string())?
        };
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, data).map_err(|e| e.to_string())?;
        fs::rename(&tmp, path).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn set_projects(&self, projects: Vec<ProjectEnv>) {
        *self.projects.lock().expect("projects") = projects;
        let _ = self.persist();
    }

    pub fn list_projects(&self) -> Vec<ProjectEnv> {
        self.projects.lock().expect("projects").clone()
    }

    pub fn ensure_default_projects_from_services(&self, services: &[String]) {
        let mut guard = self.projects.lock().expect("projects");
        if !guard.is_empty() {
            return;
        }
        for (i, svc) in services.iter().enumerate() {
            guard.push(ProjectEnv {
                name: if i == 0 {
                    "default".into()
                } else {
                    svc.clone()
                },
                environment: "dev".into(),
                service: svc.clone(),
                description: format!("auto project for service {svc}"),
            });
        }
    }

    pub fn issue_lease(
        &self,
        req: IssueVaultLeaseRequest,
        service: &str,
        endpoint_name: &str,
        protocol: &str,
        address: &str,
        database: Option<String>,
        username: &str,
        password: &str,
    ) -> VaultLease {
        let now = now_ms();
        let id = format!(
            "lease-{}-{}",
            now,
            self.seq.fetch_add(1, Ordering::Relaxed)
        );
        let token = format!("pvt-{}", simple_nonce(now));
        let lease = VaultLease {
            lease_id: id.clone(),
            project: req.project,
            environment: req.environment,
            service: service.to_owned(),
            endpoint: endpoint_name.to_owned(),
            protocol: protocol.to_owned(),
            address: address.to_owned(),
            database,
            username: username.to_owned(),
            issued_at_unix_ms: now,
            expires_at_unix_ms: now.saturating_add(req.ttl_secs.saturating_mul(1000)),
            access_token: token,
            revoked: false,
            revoked_at_unix_ms: None,
            revoked_by: None,
        };
        self.leases.lock().expect("leases").insert(
            id,
            LeaseRecord {
                lease: lease.clone(),
                backend_password: password.to_owned(),
                backend_username: username.to_owned(),
            },
        );
        let _ = self.persist();
        lease
    }

    fn is_active(lease: &VaultLease, now: u64) -> bool {
        !lease.revoked && lease.expires_at_unix_ms >= now
    }

    pub fn get_valid_lease_by_token(&self, token: &str) -> Option<VaultLease> {
        let now = now_ms();
        let guard = self.leases.lock().ok()?;
        guard
            .values()
            .find(|r| r.lease.access_token == token && Self::is_active(&r.lease, now))
            .map(|r| r.lease.clone())
    }

    pub fn get_valid_lease(&self, lease_id: &str) -> Option<VaultLease> {
        let now = now_ms();
        let guard = self.leases.lock().ok()?;
        let rec = guard.get(lease_id)?;
        if !Self::is_active(&rec.lease, now) {
            return None;
        }
        Some(rec.lease.clone())
    }

    pub fn get_lease(&self, lease_id: &str) -> Option<VaultLease> {
        self.leases
            .lock()
            .ok()?
            .get(lease_id)
            .map(|r| r.lease.clone())
    }

    pub fn list_leases(&self, limit: usize) -> Vec<VaultLease> {
        self.list_leases_filtered(limit, false)
    }

    pub fn list_leases_filtered(&self, limit: usize, include_inactive: bool) -> Vec<VaultLease> {
        let now = now_ms();
        let guard = self.leases.lock().expect("leases");
        let mut v: Vec<_> = guard
            .values()
            .filter(|r| include_inactive || Self::is_active(&r.lease, now))
            .map(|r| r.lease.clone())
            .collect();
        v.sort_by(|a, b| b.issued_at_unix_ms.cmp(&a.issued_at_unix_ms));
        v.truncate(limit.clamp(1, 200));
        v
    }

    pub fn revoke(&self, lease_id: &str, revoked_by: Option<&str>) -> Result<VaultLease, String> {
        let now = now_ms();
        let mut guard = self.leases.lock().expect("leases");
        let rec = guard
            .get_mut(lease_id)
            .ok_or_else(|| format!("lease '{lease_id}' not found"))?;
        if rec.lease.revoked {
            return Err(format!("lease '{lease_id}' already revoked"));
        }
        rec.lease.revoked = true;
        rec.lease.revoked_at_unix_ms = Some(now);
        rec.lease.revoked_by = revoked_by.map(|s| s.to_owned());
        rec.lease.access_token = format!("revoked-{}", rec.lease.lease_id);
        rec.lease.expires_at_unix_ms = now;
        rec.backend_password.clear();
        let out = rec.lease.clone();
        drop(guard);
        let _ = self.persist();
        Ok(out)
    }

    pub fn renew(&self, lease_id: &str, ttl_secs: u64) -> Result<VaultLease, String> {
        let now = now_ms();
        let mut guard = self.leases.lock().expect("leases");
        let rec = guard
            .get_mut(lease_id)
            .ok_or_else(|| format!("lease '{lease_id}' not found"))?;
        if rec.lease.revoked {
            return Err(format!("lease '{lease_id}' is revoked"));
        }
        let ttl = ttl_secs.max(1);
        rec.lease.expires_at_unix_ms = now.saturating_add(ttl.saturating_mul(1000));
        rec.lease.access_token = format!("pvt-{}", simple_nonce(now ^ ttl));
        let out = rec.lease.clone();
        drop(guard);
        let _ = self.persist();
        Ok(out)
    }

    pub fn prune_expired(&self) -> usize {
        let now = now_ms();
        let mut guard = self.leases.lock().expect("leases");
        let before = guard.len();
        guard.retain(|_, r| Self::is_active(&r.lease, now));
        let removed = before.saturating_sub(guard.len());
        drop(guard);
        if removed > 0 {
            let _ = self.persist();
        }
        removed
    }

    pub fn backend_identity(&self, lease_id: &str) -> Option<(String, String)> {
        let now = now_ms();
        let guard = self.leases.lock().ok()?;
        let rec = guard.get(lease_id)?;
        if !Self::is_active(&rec.lease, now) {
            return None;
        }
        // H05 file reload without encrypt key never restores passwords; empty = unavailable.
        if rec.backend_password.is_empty() {
            return None;
        }
        Some((rec.backend_username.clone(), rec.backend_password.clone()))
    }
}

impl Default for VaultStore {
    fn default() -> Self {
        Self::new()
    }
}

fn decode_vault_file(raw: &str, key: Option<&[u8; 32]>) -> Result<VaultFile, String> {
    let bytes = decode_maybe_encrypted(VAULT_ENC_MAGIC, raw, key)?;
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}

fn open_state_lock(path: &std::path::Path) -> Result<File, String> {
    let lock_path = path.with_extension("json.lock");
    OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(lock_path)
        .map_err(|e| e.to_string())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn simple_nonce(seed: u64) -> u64 {
    seed.wrapping_mul(0x9e3779b97f4a7c15) ^ 0xdeadbeef
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issue(store: &VaultStore) -> VaultLease {
        store.issue_lease(
            IssueVaultLeaseRequest {
                project: "demo".into(),
                environment: "dev".into(),
                ttl_secs: 600,
                issued_by: None,
            },
            "orders",
            "ep1",
            "mysql",
            "127.0.0.1:3306",
            Some("orders".into()),
            "root",
            "secret-pass",
        )
    }

    #[test]
    fn lease_hides_password_and_expires() {
        let store = VaultStore::new();
        let lease = issue(&store);
        let json = serde_json::to_string(&lease).unwrap();
        assert!(!json.contains("secret-pass"));
        assert!(store.get_valid_lease(&lease.lease_id).is_some());
        assert!(store.get_valid_lease_by_token(&lease.access_token).is_some());
    }

    #[test]
    fn revoke_invalidates_token_and_wipes_backend_secret() {
        let store = VaultStore::new();
        let lease = issue(&store);
        let token = lease.access_token.clone();
        assert!(store.backend_identity(&lease.lease_id).is_some());
        let revoked = store.revoke(&lease.lease_id, Some("admin")).unwrap();
        assert!(revoked.revoked);
        assert!(store.get_valid_lease(&lease.lease_id).is_none());
        assert!(store.get_valid_lease_by_token(&token).is_none());
        assert!(store.backend_identity(&lease.lease_id).is_none());
        assert!(store.revoke(&lease.lease_id, None).is_err());
    }

    #[test]
    fn renew_extends_and_rotates_token() {
        let store = VaultStore::new();
        let lease = issue(&store);
        let old_token = lease.access_token.clone();
        let renewed = store.renew(&lease.lease_id, 1200).unwrap();
        assert_ne!(renewed.access_token, old_token);
        assert!(store.get_valid_lease_by_token(&old_token).is_none());
        assert!(store
            .get_valid_lease_by_token(&renewed.access_token)
            .is_some());
        store.revoke(&lease.lease_id, None).unwrap();
        assert!(store.renew(&lease.lease_id, 60).is_err());
    }

    #[test]
    fn prune_removes_revoked() {
        let store = VaultStore::new();
        let a = issue(&store);
        let b = issue(&store);
        store.revoke(&a.lease_id, None).unwrap();
        let n = store.prune_expired();
        assert!(n >= 1);
        assert!(store.get_lease(&a.lease_id).is_none());
        assert!(store.get_valid_lease(&b.lease_id).is_some());
    }

    #[test]
    fn h05_vault_file_roundtrip_no_passwords() {
        let dir = std::env::temp_dir().join(format!("dn-h05-vault-{}", now_ms()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("vault.json");
        let store = VaultStore::with_file(path.clone(), None).unwrap();
        store.set_projects(vec![ProjectEnv {
            name: "p".into(),
            environment: "dev".into(),
            service: "orders".into(),
            description: String::new(),
        }]);
        let lease = store.issue_lease(
            IssueVaultLeaseRequest {
                project: "p".into(),
                environment: "dev".into(),
                ttl_secs: 600,
                issued_by: None,
            },
            "orders",
            "ep1",
            "mysql",
            "127.0.0.1:3306",
            Some("db".into()),
            "root",
            "s3cret",
        );
        assert!(store.backend_identity(&lease.lease_id).is_some());
        drop(store);
        let store2 = VaultStore::with_file(path.clone(), None).unwrap();
        let got = store2.get_lease(&lease.lease_id).expect("lease meta");
        assert_eq!(got.service, "orders");
        // Password must not survive plaintext file reload.
        assert!(store2.backend_identity(&lease.lease_id).is_none());
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("s3cret"));
        assert!(!raw.starts_with(VAULT_ENC_MAGIC));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn h05_vault_encrypted_file_restores_passwords() {
        let dir = std::env::temp_dir().join(format!("dn-h05-vault-enc-{}", now_ms()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("vault.json");
        let key_hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let key = parse_encrypt_key(key_hex).unwrap();
        let store = VaultStore::with_file(path.clone(), key).unwrap();
        let lease = issue(&store);
        assert!(store.backend_identity(&lease.lease_id).is_some());
        drop(store);

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.starts_with(VAULT_ENC_MAGIC), "expected sealed file");
        assert!(!raw.contains("secret-pass"));

        let store2 = VaultStore::with_file(path.clone(), key).unwrap();
        let id = store2
            .backend_identity(&lease.lease_id)
            .expect("restored secret");
        assert_eq!(id.0, "root");
        assert_eq!(id.1, "secret-pass");

        // Wrong / missing key must not silently load secrets.
        assert!(VaultStore::with_file(path.clone(), None).is_err());
        let bad = parse_encrypt_key(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        .unwrap();
        assert!(VaultStore::with_file(path, bad).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn h05_vault_encrypt_key_hex_parse() {
        assert!(parse_encrypt_key("").unwrap().is_none());
        assert!(parse_encrypt_key("dead").is_err());
        assert!(parse_encrypt_key(
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        )
        .unwrap()
        .is_some());
    }
}
