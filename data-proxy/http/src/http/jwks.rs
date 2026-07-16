//! Minimal JWKS fetch + cache for Admin JWT validation (RS256).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use jsonwebtoken::DecodingKey;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use serde::Deserialize;
use tracing::{debug, warn};

use super::admin_auth::AdminAuthError;

#[derive(Debug, Clone, Deserialize)]
struct JwksDocument {
    keys: Vec<JwkKey>,
}

#[derive(Debug, Clone, Deserialize)]
struct JwkKey {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default)]
    r#use: Option<String>,
    /// RSA modulus (base64url).
    #[serde(default)]
    n: Option<String>,
    /// RSA exponent (base64url).
    #[serde(default)]
    e: Option<String>,
}

struct CacheEntry {
    fetched_at: Instant,
    /// kid -> PEM-less decoding material as (n, e) base64url.
    keys: HashMap<String, (String, String)>,
    /// First RSA key when kid is absent.
    default: Option<(String, String)>,
}

static JWKS_CACHE: Lazy<RwLock<HashMap<String, CacheEntry>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

/// Resolve a DecodingKey for the given JWKS URL and optional kid.
pub fn decoding_key_for(
    jwks_url: &str,
    kid: Option<&str>,
    cache_ttl: Duration,
) -> Result<DecodingKey, AdminAuthError> {
    let entry = get_or_fetch(jwks_url, cache_ttl)?;
    let (n, e) = if let Some(kid) = kid {
        entry
            .keys
            .get(kid)
            .cloned()
            .or_else(|| entry.default.clone())
            .ok_or_else(|| {
                AdminAuthError::Unauthorized(format!("no JWKS key for kid '{kid}'"))
            })?
    } else {
        entry.default.clone().ok_or_else(|| {
            AdminAuthError::Unauthorized("JWKS has no usable RSA key".into())
        })?
    };
    DecodingKey::from_rsa_components(&n, &e).map_err(|err| {
        AdminAuthError::Unauthorized(format!("invalid RSA JWK components: {err}"))
    })
}

/// Test helper: inject RSA n/e for a fake JWKS URL without network.
#[cfg(test)]
pub fn inject_test_key(jwks_url: &str, kid: &str, n_b64url: &str, e_b64url: &str) {
    let mut map = HashMap::new();
    map.insert(kid.to_owned(), (n_b64url.to_owned(), e_b64url.to_owned()));
    JWKS_CACHE.write().insert(
        jwks_url.to_owned(),
        CacheEntry {
            fetched_at: Instant::now(),
            default: Some((n_b64url.to_owned(), e_b64url.to_owned())),
            keys: map,
        },
    );
}

#[cfg(test)]
pub fn clear_cache() {
    JWKS_CACHE.write().clear();
}

fn get_or_fetch(jwks_url: &str, cache_ttl: Duration) -> Result<CacheEntry, AdminAuthError> {
    {
        let cache = JWKS_CACHE.read();
        if let Some(entry) = cache.get(jwks_url) {
            if entry.fetched_at.elapsed() < cache_ttl {
                return Ok(CacheEntry {
                    fetched_at: entry.fetched_at,
                    keys: entry.keys.clone(),
                    default: entry.default.clone(),
                });
            }
        }
    }
    let doc = fetch_jwks(jwks_url)?;
    let entry = document_to_entry(doc);
    if entry.keys.is_empty() && entry.default.is_none() {
        return Err(AdminAuthError::Misconfigured(format!(
            "JWKS at {jwks_url} has no RSA signature keys"
        )));
    }
    debug!(
        target: "data_nexus::admin_auth",
        url = %jwks_url,
        keys = entry.keys.len(),
        "JWKS refreshed"
    );
    JWKS_CACHE.write().insert(jwks_url.to_owned(), entry.clone());
    Ok(entry)
}

fn fetch_jwks(jwks_url: &str) -> Result<JwksDocument, AdminAuthError> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| AdminAuthError::Misconfigured(format!("http client: {e}")))?;
    let response = client
        .get(jwks_url)
        .header("Accept", "application/json")
        .send()
        .map_err(|e| AdminAuthError::Unauthorized(format!("JWKS fetch failed: {e}")))?;
    if !response.status().is_success() {
        return Err(AdminAuthError::Unauthorized(format!(
            "JWKS fetch HTTP {}",
            response.status()
        )));
    }
    response
        .json::<JwksDocument>()
        .map_err(|e| AdminAuthError::Unauthorized(format!("JWKS parse failed: {e}")))
}

fn document_to_entry(doc: JwksDocument) -> CacheEntry {
    let mut keys = HashMap::new();
    let mut default = None;
    for key in doc.keys {
        if !key.kty.eq_ignore_ascii_case("RSA") {
            continue;
        }
        if let Some(u) = &key.r#use {
            if !u.eq_ignore_ascii_case("sig") {
                continue;
            }
        }
        if let Some(alg) = &key.alg {
            if !(alg.eq_ignore_ascii_case("RS256")
                || alg.eq_ignore_ascii_case("RS384")
                || alg.eq_ignore_ascii_case("RS512"))
            {
                // Allow missing alg; skip explicit non-RSA algs.
                if alg.starts_with("ES") || alg.starts_with("HS") || alg.starts_with("PS") {
                    continue;
                }
            }
        }
        let (Some(n), Some(e)) = (key.n, key.e) else {
            continue;
        };
        // Normalize padding: jsonwebtoken accepts either; keep as-is after light fix.
        let n = normalize_b64url(&n);
        let e = normalize_b64url(&e);
        if default.is_none() {
            default = Some((n.clone(), e.clone()));
        }
        if let Some(kid) = key.kid {
            keys.insert(kid, (n, e));
        }
    }
    CacheEntry {
        fetched_at: Instant::now(),
        keys,
        default,
    }
}

fn normalize_b64url(value: &str) -> String {
    // Accept both padded and unpadded input; re-encode unpadded form preferred by jwt crate.
    let raw = URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .or_else(|_| URL_SAFE.decode(value.as_bytes()))
        .unwrap_or_else(|_| {
            warn!(target: "data_nexus::admin_auth", "JWKS base64url decode soft-failed; passing through");
            value.as_bytes().to_vec()
        });
    URL_SAFE_NO_PAD.encode(raw)
}

impl Clone for CacheEntry {
    fn clone(&self) -> Self {
        Self {
            fetched_at: self.fetched_at,
            keys: self.keys.clone(),
            default: self.default.clone(),
        }
    }
}
