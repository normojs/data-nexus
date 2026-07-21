//! F31: Remote PDP HTTP adapter (table/action gate).
//!
//! Used when `security.pdp.backend = "remote"`. The PEP still owns mask/row
//! rewrite obligations via Local rules; the remote service answers only
//! **allow / deny** for subject + action + tables.
//!
//! Contract (POST JSON to `remote_url`):
//!
//! ```json
//! // request
//! {
//!   "subject_id": "alice",
//!   "service": "orders",
//!   "action": "select",
//!   "tables": ["employees", "secret_tokens"],
//!   "sql_fingerprint": "optional"
//! }
//! // response
//! { "allow": true }
//! // or
//! { "allow": false, "rule": "remote-deny", "message": "..." }
//! ```
//!
//! Timeouts / transport / parse errors: **fail-closed** when
//! `remote_fail_closed=true` (default). Never call this on the per-row mask path.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::security::SecurityPdpConfig;
use crate::{GatewayError, GatewayResult, StatementAction};

/// F31 remote authorize request body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemotePdpRequest {
    pub subject_id: String,
    pub service: String,
    pub action: String,
    pub tables: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sql_fingerprint: Option<String>,
}

/// F31 remote authorize response body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemotePdpResponse {
    pub allow: bool,
    #[serde(default)]
    pub rule: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

/// HTTP client for one Remote PDP endpoint (cheap to clone).
#[derive(Debug, Clone)]
pub struct RemotePdpClient {
    url: String,
    timeout: Duration,
    token: Option<String>,
    fail_closed: bool,
    /// Injected for unit tests; production uses real blocking client.
    transport: RemoteTransport,
}

#[derive(Clone)]
enum RemoteTransport {
    Http,
    /// Test double: fixed response or error message.
    Fixed(Result<RemotePdpResponse, String>),
}

impl std::fmt::Debug for RemoteTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http => write!(f, "Http"),
            Self::Fixed(Ok(r)) => write!(f, "Fixed(Ok(allow={}))", r.allow),
            Self::Fixed(Err(e)) => write!(f, "Fixed(Err({e}))"),
        }
    }
}

impl RemotePdpClient {
    pub fn from_config(pdp: &SecurityPdpConfig) -> GatewayResult<Self> {
        let url = pdp.remote_url.trim().to_owned();
        if url.is_empty() {
            return Err(GatewayError::Configuration(
                "security.pdp.remote_url is required for backend=remote".into(),
            ));
        }
        let timeout_ms = pdp.remote_timeout_ms.clamp(1, 30_000);
        let token = {
            let t = pdp.remote_token.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_owned())
            }
        };
        Ok(Self {
            url,
            timeout: Duration::from_millis(timeout_ms),
            token,
            fail_closed: pdp.remote_fail_closed,
            transport: RemoteTransport::Http,
        })
    }

    /// Test helper: client that always returns the given decision.
    pub fn fixed_for_test(resp: RemotePdpResponse, fail_closed: bool) -> Self {
        Self {
            url: "http://test.local/pdp".into(),
            timeout: Duration::from_millis(50),
            token: None,
            fail_closed,
            transport: RemoteTransport::Fixed(Ok(resp)),
        }
    }

    /// Test helper: client that always fails transport.
    pub fn transport_error_for_test(msg: &str, fail_closed: bool) -> Self {
        Self {
            url: "http://test.local/pdp".into(),
            timeout: Duration::from_millis(50),
            token: None,
            fail_closed,
            transport: RemoteTransport::Fixed(Err(msg.to_owned())),
        }
    }

    pub fn fail_closed(&self) -> bool {
        self.fail_closed
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Authorize subject/action/tables. On error returns `Err` string for logging;
    /// callers map to Deny when fail_closed.
    pub fn authorize_tables(
        &self,
        subject_id: &str,
        service: &str,
        action: StatementAction,
        tables: &[String],
        sql_fingerprint: Option<&str>,
    ) -> Result<(), String> {
        let req = RemotePdpRequest {
            subject_id: subject_id.to_owned(),
            service: service.to_owned(),
            action: action.as_str().to_owned(),
            tables: tables.to_vec(),
            sql_fingerprint: sql_fingerprint.map(|s| s.to_owned()),
        };
        let resp = self.post_authorize(&req)?;
        if resp.allow {
            return Ok(());
        }
        let rule = resp.rule.as_deref().unwrap_or("remote");
        let message = resp.message.unwrap_or_else(|| {
            format!(
                "remote PDP deny: subject '{subject_id}' action '{}' tables={tables:?}",
                action.as_str()
            )
        });
        Err(format!("{rule}: {message}"))
    }

    fn post_authorize(&self, req: &RemotePdpRequest) -> Result<RemotePdpResponse, String> {
        match &self.transport {
            RemoteTransport::Fixed(r) => r.clone(),
            RemoteTransport::Http => self.post_authorize_http(req),
        }
    }

    fn post_authorize_http(&self, req: &RemotePdpRequest) -> Result<RemotePdpResponse, String> {
        // PEP authorize runs on the async runtime worker. `reqwest::blocking`
        // must not run there (drops/creates a runtime → panic / lost connection).
        // Offload the entire blocking client to a short-lived OS thread.
        let url = self.url.clone();
        let timeout = self.timeout;
        let token = self.token.clone();
        let body = req.clone();
        std::thread::Builder::new()
            .name("dn-remote-pdp".into())
            .spawn(move || {
                let client = reqwest::blocking::Client::builder()
                    .timeout(timeout)
                    .build()
                    .map_err(|e| format!("remote PDP client build: {e}"))?;
                let mut builder = client.post(&url).json(&body);
                if let Some(token) = &token {
                    builder = builder.bearer_auth(token);
                }
                let response = builder
                    .send()
                    .map_err(|e| format!("remote PDP transport: {e}"))?;
                let status = response.status();
                if !status.is_success() {
                    let body = response.text().unwrap_or_default();
                    return Err(format!(
                        "remote PDP HTTP {status}: {}",
                        body.chars().take(200).collect::<String>()
                    ));
                }
                response
                    .json::<RemotePdpResponse>()
                    .map_err(|e| format!("remote PDP response JSON: {e}"))
            })
            .map_err(|e| format!("remote PDP thread spawn: {e}"))?
            .join()
            .map_err(|_| "remote PDP worker thread panicked".to_string())?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f31_fixed_allow() {
        let c = RemotePdpClient::fixed_for_test(
            RemotePdpResponse {
                allow: true,
                rule: None,
                message: None,
            },
            true,
        );
        c.authorize_tables(
            "alice",
            "orders",
            StatementAction::Select,
            &["employees".into()],
            None,
        )
        .unwrap();
    }

    #[test]
    fn f31_fixed_deny_message() {
        let c = RemotePdpClient::fixed_for_test(
            RemotePdpResponse {
                allow: false,
                rule: Some("opa-deny".into()),
                message: Some("no secret".into()),
            },
            true,
        );
        let err = c
            .authorize_tables(
                "alice",
                "orders",
                StatementAction::Select,
                &["secret_tokens".into()],
                None,
            )
            .unwrap_err();
        assert!(err.contains("opa-deny"), "{err}");
        assert!(err.contains("no secret"), "{err}");
    }

    #[test]
    fn f31_transport_error_surfaces() {
        let c = RemotePdpClient::transport_error_for_test("timeout", true);
        let err = c
            .authorize_tables("alice", "orders", StatementAction::Select, &[], None)
            .unwrap_err();
        assert!(err.contains("timeout"), "{err}");
    }
}
