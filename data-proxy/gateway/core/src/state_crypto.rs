//! H05 shared AES-256-GCM envelope for file-backed security state (ticket/vault).
//!
//! Format: `{MAGIC}{base64(nonce)}:{base64(ciphertext)}`
//! Nonce is 12 bytes; key is 32 bytes (64 hex chars in config).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use std::time::{SystemTime, UNIX_EPOCH};

/// Parse optional 64-hex AES-256 key. Empty → `None` (plaintext mode).
pub fn parse_encrypt_key(hex: &str) -> Result<Option<[u8; 32]>, String> {
    let hex = hex.trim();
    if hex.is_empty() {
        return Ok(None);
    }
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(
            "encrypt key must be empty or 64 hex characters (32-byte AES key)".into(),
        );
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("encrypt key hex parse: {e}"))?;
    }
    Ok(Some(out))
}

/// Encrypt plaintext; returns full file bytes including `magic` prefix.
pub fn encrypt_blob(magic: &str, key: &[u8; 32], plain: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    // 96-bit nonce from time + mix (adequate for low-rate state writes).
    let mut nonce_bytes = [0u8; 12];
    let t = now_ms().to_le_bytes();
    nonce_bytes[..8].copy_from_slice(&t);
    let mix = simple_nonce(now_ms()).to_le_bytes();
    nonce_bytes[8..].copy_from_slice(&mix[..4]);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plain)
        .map_err(|e| format!("state encrypt: {e}"))?;
    let mut out = Vec::with_capacity(magic.len() + 16 + ct.len());
    out.extend_from_slice(magic.as_bytes());
    out.extend_from_slice(B64.encode(nonce_bytes).as_bytes());
    out.push(b':');
    out.extend_from_slice(B64.encode(ct).as_bytes());
    Ok(out)
}

/// Decrypt body after magic strip (`base64(nonce):base64(ct)`).
pub fn decrypt_blob(key: &[u8; 32], body: &str) -> Result<Vec<u8>, String> {
    let (n_b64, c_b64) = body
        .split_once(':')
        .ok_or_else(|| "ciphertext missing nonce separator".to_string())?;
    let nonce_bytes = B64
        .decode(n_b64.trim())
        .map_err(|e| format!("nonce b64: {e}"))?;
    if nonce_bytes.len() != 12 {
        return Err(format!("nonce must be 12 bytes, got {}", nonce_bytes.len()));
    }
    let ct = B64
        .decode(c_b64.trim())
        .map_err(|e| format!("ciphertext b64: {e}"))?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(nonce, ct.as_ref())
        .map_err(|e| format!("decrypt failed (wrong key?): {e}"))
}

/// Decode raw file: if starts with `magic`, decrypt; else treat as plaintext JSON.
pub fn decode_maybe_encrypted(
    magic: &str,
    raw: &str,
    key: Option<&[u8; 32]>,
) -> Result<Vec<u8>, String> {
    let raw = raw.trim();
    if let Some(rest) = raw.strip_prefix(magic) {
        let key = key.ok_or_else(|| {
            format!("file is encrypted ({magic}…) but encrypt key is not set")
        })?;
        decrypt_blob(key, rest)
    } else {
        Ok(raw.as_bytes().to_vec())
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
    fn h05_parse_encrypt_key() {
        assert!(parse_encrypt_key("").unwrap().is_none());
        assert!(parse_encrypt_key("dead").is_err());
        assert!(parse_encrypt_key(
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        )
        .unwrap()
        .is_some());
    }

    #[test]
    fn h05_encrypt_decrypt_roundtrip() {
        let key = parse_encrypt_key(
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        )
        .unwrap()
        .unwrap();
        let plain = br#"{"tickets":[]}"#;
        let enc = encrypt_blob("DNTICKET1:", &key, plain).unwrap();
        let s = String::from_utf8(enc).unwrap();
        assert!(s.starts_with("DNTICKET1:"));
        let dec = decode_maybe_encrypted("DNTICKET1:", &s, Some(&key)).unwrap();
        assert_eq!(dec, plain);
        // Wrong key fails.
        let bad = parse_encrypt_key(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        .unwrap()
        .unwrap();
        assert!(decode_maybe_encrypted("DNTICKET1:", &s, Some(&bad)).is_err());
        // Missing key fails on encrypted file.
        assert!(decode_maybe_encrypted("DNTICKET1:", &s, None).is_err());
        // Plaintext passes through.
        let p = decode_maybe_encrypted("DNTICKET1:", r#"{"ok":1}"#, None).unwrap();
        assert_eq!(p, br#"{"ok":1}"#);
    }
}
