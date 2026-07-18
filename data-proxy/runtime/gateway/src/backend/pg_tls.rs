//! A08: shared PostgreSQL backend TLS connector builder.
//!
//! Used by both the TCP frame-relay path (`pg_tcp_relay`) and the pool path
//! (`postgresql::connect_endpoint`). Certificate policy:
//!
//! | `ssl_accept_invalid_certs` | `ssl_ca_file` | behavior |
//! |----------------------------|--------------|----------|
//! | `true` (default, MVP)      | any          | skip cert/hostname verification |
//! | `false`                    | `None`       | system trust roots + hostname |
//! | `false`                    | `Some(path)` | system roots + PEM CA(s) from file |

use std::fs;
use std::path::Path;

use gateway_core::{EndpointConfig, GatewayError, GatewayResult};

/// Build a `native_tls::TlsConnector` from endpoint SSL settings.
pub fn build_native_tls_connector(endpoint: &EndpointConfig) -> GatewayResult<native_tls::TlsConnector> {
    let mut builder = native_tls::TlsConnector::builder();

    if endpoint.ssl_accept_invalid_certs {
        builder.danger_accept_invalid_certs(true);
        // Hostname check is meaningless when we accept any cert.
        builder.danger_accept_invalid_hostnames(true);
    } else if let Some(ca_path) = endpoint.ssl_ca_file.as_deref() {
        add_ca_pem_file(&mut builder, ca_path)?;
    }

    builder
        .build()
        .map_err(|e| GatewayError::Backend(format!("pg tls connector: {e}")))
}

/// Host name used for SNI / cert validation (strip `:port` from endpoint address).
pub fn tls_server_name(endpoint: &EndpointConfig) -> String {
    let addr = endpoint.address.as_str();
    match addr.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            // Strip IPv6 brackets if present: "[::1]:5432"
            host.trim_matches(|c| c == '[' || c == ']').to_owned()
        }
        _ => addr.trim_matches(|c| c == '[' || c == ']').to_owned(),
    }
}

fn add_ca_pem_file(
    builder: &mut native_tls::TlsConnectorBuilder,
    ca_path: &str,
) -> GatewayResult<()> {
    let path = Path::new(ca_path);
    let bytes = fs::read(path).map_err(|e| {
        GatewayError::Configuration(format!(
            "endpoint ssl_ca_file '{}': read failed: {e}",
            path.display()
        ))
    })?;
    if bytes.is_empty() {
        return Err(GatewayError::Configuration(format!(
            "endpoint ssl_ca_file '{}' is empty",
            path.display()
        )));
    }

    // Support single cert or multi-cert PEM bundles.
    let pem = String::from_utf8_lossy(&bytes);
    let mut loaded = 0usize;
    for chunk in split_pem_certs(&pem) {
        let cert = native_tls::Certificate::from_pem(chunk.as_bytes()).map_err(|e| {
            GatewayError::Configuration(format!(
                "endpoint ssl_ca_file '{}': invalid PEM certificate: {e}",
                path.display()
            ))
        })?;
        builder.add_root_certificate(cert);
        loaded += 1;
    }
    if loaded == 0 {
        // Fallback: try whole file as one cert (from_pem also accepts single DER-in-PEM).
        let cert = native_tls::Certificate::from_pem(&bytes).map_err(|e| {
            GatewayError::Configuration(format!(
                "endpoint ssl_ca_file '{}': no PEM certificates found: {e}",
                path.display()
            ))
        })?;
        builder.add_root_certificate(cert);
        loaded = 1;
    }
    tracing::debug!(
        target: "data_nexus::gateway",
        ca_file = %path.display(),
        certs = loaded,
        "A08 loaded backend TLS CA cert(s)"
    );
    Ok(())
}

/// Split a PEM blob into individual `-----BEGIN CERTIFICATE-----` blocks.
fn split_pem_certs(pem: &str) -> Vec<String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(start) = rest.find(BEGIN) {
        let from = &rest[start..];
        let Some(end_rel) = from.find(END) else {
            break;
        };
        let end = end_rel + END.len();
        out.push(from[..end].to_owned());
        rest = &from[end..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_core::{EndpointConfig, EndpointSslMode, ProtocolKind};
    use std::io::Write;

    fn ep() -> EndpointConfig {
        EndpointConfig {
            name: "analytics-primary".into(),
            protocol: ProtocolKind::PostgreSql,
            address: "db.example.com:5432".into(),
            database: Some("analytics".into()),
            role: Default::default(),
            username: "postgres".into(),
            password: "postgres".into(),
            weight: 1,
            ssl_mode: EndpointSslMode::Require,
            ssl_ca_file: None,
            ssl_accept_invalid_certs: true,
        }
    }

    #[test]
    fn a08_tls_server_name_strips_port_and_brackets() {
        let mut e = ep();
        assert_eq!(tls_server_name(&e), "db.example.com");
        e.address = "[::1]:5432".into();
        assert_eq!(tls_server_name(&e), "::1");
        e.address = "localhost".into();
        assert_eq!(tls_server_name(&e), "localhost");
    }

    #[test]
    fn a08_build_connector_accept_invalid_default() {
        let e = ep();
        let c = build_native_tls_connector(&e).unwrap();
        // Connector is opaque; just ensure build succeeds under danger mode.
        let _ = c;
    }

    #[test]
    fn a08_build_connector_loads_ca_pem() {
        let dir = tempfile_dir();
        let ca_path = dir.join("ca.pem");
        // Generate via openssl in test setup would be heavy; use a minimal invalid
        // path check first, then a real self-signed if openssl available.
        let pem = std::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                dir.join("key.pem").to_str().unwrap(),
                "-out",
                ca_path.to_str().unwrap(),
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=data-nexus-a08-unit",
            ])
            .output();
        let pem_ok = pem.map(|o| o.status.success()).unwrap_or(false);
        if !pem_ok {
            // Environment without openssl: still verify missing-file error path.
            let mut e = ep();
            e.ssl_accept_invalid_certs = false;
            e.ssl_ca_file = Some(dir.join("missing.pem").to_string_lossy().into());
            let err = build_native_tls_connector(&e).unwrap_err();
            assert!(err.to_string().contains("ssl_ca_file"), "{err}");
            return;
        }

        let mut e = ep();
        e.ssl_accept_invalid_certs = false;
        e.ssl_ca_file = Some(ca_path.to_string_lossy().into());
        let c = build_native_tls_connector(&e).unwrap();
        let _ = c;

        // Multi-cert bundle: concatenate twice.
        let mut bundle = fs::read_to_string(&ca_path).unwrap();
        bundle.push('\n');
        bundle.push_str(&fs::read_to_string(&ca_path).unwrap());
        let bundle_path = dir.join("bundle.pem");
        fs::write(&bundle_path, bundle).unwrap();
        e.ssl_ca_file = Some(bundle_path.to_string_lossy().into());
        build_native_tls_connector(&e).unwrap();
    }

    #[test]
    fn a08_build_connector_rejects_missing_ca() {
        let mut e = ep();
        e.ssl_accept_invalid_certs = false;
        e.ssl_ca_file = Some("/no/such/data-nexus-a08-ca.pem".into());
        let err = build_native_tls_connector(&e).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("ssl_ca_file") || msg.contains("read failed"), "{msg}");
    }

    #[test]
    fn a08_split_pem_certs_multi() {
        let one = "-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----\n";
        let two = format!("{one}{one}");
        assert_eq!(split_pem_certs(&two).len(), 2);
        assert!(split_pem_certs("not a cert").is_empty());
    }

    fn tempfile_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "dn-a08-tls-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[allow(dead_code)]
    fn write_file(path: &Path, data: &[u8]) {
        let mut f = fs::File::create(path).unwrap();
        f.write_all(data).unwrap();
    }
}
