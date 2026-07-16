//! S6 portal / vault: short-lived endpoint credentials + project metadata.
//!
//! Vault leases hide production endpoint passwords from the browser. The portal
//! SQL path never returns endpoint secrets; it executes through the PEP.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

static GLOBAL: OnceLock<Arc<VaultStore>> = OnceLock::new();

pub fn global_vault_store() -> Arc<VaultStore> {
    GLOBAL
        .get_or_init(|| Arc::new(VaultStore::new()))
        .clone()
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

fn default_ttl() -> u64 {
    900
}

#[derive(Debug)]
struct LeaseRecord {
    lease: VaultLease,
    /// Backend password kept only server-side for optional future use.
    #[allow(dead_code)]
    backend_password: String,
    backend_username: String,
}

#[derive(Debug)]
pub struct VaultStore {
    leases: Mutex<HashMap<String, LeaseRecord>>,
    projects: Mutex<Vec<ProjectEnv>>,
    seq: AtomicU64,
}

impl VaultStore {
    pub fn new() -> Self {
        Self {
            leases: Mutex::new(HashMap::new()),
            projects: Mutex::new(Vec::new()),
            seq: AtomicU64::new(1),
        }
    }

    pub fn set_projects(&self, projects: Vec<ProjectEnv>) {
        *self.projects.lock().expect("projects") = projects;
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
        };
        self.leases.lock().expect("leases").insert(
            id,
            LeaseRecord {
                lease: lease.clone(),
                backend_password: password.to_owned(),
                backend_username: username.to_owned(),
            },
        );
        // Public response must not include backend password — already doesn't.
        lease
    }

    pub fn get_valid_lease_by_token(&self, token: &str) -> Option<VaultLease> {
        let now = now_ms();
        let guard = self.leases.lock().ok()?;
        guard
            .values()
            .find(|r| r.lease.access_token == token && r.lease.expires_at_unix_ms >= now)
            .map(|r| r.lease.clone())
    }

    pub fn get_valid_lease(&self, lease_id: &str) -> Option<VaultLease> {
        let now = now_ms();
        let guard = self.leases.lock().ok()?;
        let rec = guard.get(lease_id)?;
        if rec.lease.expires_at_unix_ms < now {
            return None;
        }
        Some(rec.lease.clone())
    }

    pub fn list_leases(&self, limit: usize) -> Vec<VaultLease> {
        let now = now_ms();
        let guard = self.leases.lock().expect("leases");
        let mut v: Vec<_> = guard
            .values()
            .filter(|r| r.lease.expires_at_unix_ms >= now)
            .map(|r| r.lease.clone())
            .collect();
        v.sort_by(|a, b| b.issued_at_unix_ms.cmp(&a.issued_at_unix_ms));
        v.truncate(limit.clamp(1, 200));
        v
    }

    pub fn backend_identity(&self, lease_id: &str) -> Option<(String, String)> {
        let now = now_ms();
        let guard = self.leases.lock().ok()?;
        let rec = guard.get(lease_id)?;
        if rec.lease.expires_at_unix_ms < now {
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

    #[test]
    fn lease_hides_password_and_expires() {
        let store = VaultStore::new();
        store.set_projects(vec![ProjectEnv {
            name: "demo".into(),
            environment: "dev".into(),
            service: "orders".into(),
            description: String::new(),
        }]);
        let lease = store.issue_lease(
            IssueVaultLeaseRequest {
                project: "demo".into(),
                environment: "dev".into(),
                ttl_secs: 60,
                issued_by: None,
            },
            "orders",
            "ep1",
            "mysql",
            "127.0.0.1:3306",
            Some("orders".into()),
            "root",
            "secret-pass",
        );
        let json = serde_json::to_string(&lease).unwrap();
        assert!(!json.contains("secret-pass"));
        assert!(store.get_valid_lease(&lease.lease_id).is_some());
        assert!(store.get_valid_lease_by_token(&lease.access_token).is_some());
    }
}
