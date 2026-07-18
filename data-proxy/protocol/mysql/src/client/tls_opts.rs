//! A08: optional MySQL client TLS options for backend connections.

use std::fs;
use std::path::Path;

use tokio_native_tls::native_tls::{Certificate, TlsConnector};

use crate::err::ProtocolError;

/// TLS settings for a MySQL client connection (backend path).
#[derive(Debug, Clone)]
pub struct ClientTlsOpts {
    /// SNI / cert hostname (without port).
    pub server_name: String,
    /// When true, skip cert + hostname verification (MVP default).
    pub accept_invalid_certs: bool,
    /// Optional PEM CA file (single cert or bundle).
    pub ca_file: Option<String>,
}

impl ClientTlsOpts {
    pub fn build_connector(&self) -> Result<TlsConnector, ProtocolError> {
        let mut builder = TlsConnector::builder();
        if self.accept_invalid_certs {
            builder.danger_accept_invalid_certs(true);
            builder.danger_accept_invalid_hostnames(true);
            // Keep SNI off when accepting any cert (legacy make_tls behaviour).
            builder.use_sni(false);
        } else if let Some(ca) = self.ca_file.as_deref() {
            add_ca_pem_file(&mut builder, ca)?;
        }
        builder.build().map_err(ProtocolError::from)
    }
}

fn add_ca_pem_file(
    builder: &mut tokio_native_tls::native_tls::TlsConnectorBuilder,
    ca_path: &str,
) -> Result<(), ProtocolError> {
    let path = Path::new(ca_path);
    let bytes = fs::read(path).map_err(|e| {
        ProtocolError::InvalidPacket {
            method: format!("ssl_ca_file read '{}': {e}", path.display()),
            data: vec![],
        }
    })?;
    if bytes.is_empty() {
        return Err(ProtocolError::InvalidPacket {
            method: format!("ssl_ca_file '{}' is empty", path.display()),
            data: vec![],
        });
    }
    let pem = String::from_utf8_lossy(&bytes);
    let mut loaded = 0usize;
    for chunk in split_pem_certs(&pem) {
        let cert = Certificate::from_pem(chunk.as_bytes()).map_err(|e| {
            ProtocolError::InvalidPacket {
                method: format!("ssl_ca_file invalid PEM: {e}"),
                data: vec![],
            }
        })?;
        builder.add_root_certificate(cert);
        loaded += 1;
    }
    if loaded == 0 {
        let cert = Certificate::from_pem(&bytes).map_err(|e| ProtocolError::InvalidPacket {
            method: format!("ssl_ca_file no certificates: {e}"),
            data: vec![],
        })?;
        builder.add_root_certificate(cert);
    }
    Ok(())
}

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

    #[test]
    fn a08_split_pem_multi() {
        let one = "-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----\n";
        assert_eq!(split_pem_certs(&format!("{one}{one}")).len(), 2);
    }

    #[test]
    fn a08_build_connector_accept_invalid() {
        let opts = ClientTlsOpts {
            server_name: "localhost".into(),
            accept_invalid_certs: true,
            ca_file: None,
        };
        opts.build_connector().unwrap();
    }

    #[test]
    fn a08_build_connector_missing_ca_file_errors() {
        let opts = ClientTlsOpts {
            server_name: "db.example.com".into(),
            accept_invalid_certs: false,
            ca_file: Some("/no/such/data-nexus-mysql-a08-ca.pem".into()),
        };
        let err = opts.build_connector().unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("ssl_ca_file") || msg.contains("read"),
            "{msg}"
        );
    }

    #[test]
    fn a08_build_connector_empty_ca_file_errors() {
        let dir = std::env::temp_dir().join(format!(
            "dn-mysql-a08-empty-ca-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let ca_path = dir.join("empty.pem");
        fs::write(&ca_path, b"").unwrap();
        let opts = ClientTlsOpts {
            server_name: "localhost".into(),
            accept_invalid_certs: false,
            ca_file: Some(ca_path.to_string_lossy().into()),
        };
        let err = opts.build_connector().unwrap_err();
        assert!(err.to_string().contains("empty"), "{err}");
        let _ = fs::remove_dir_all(&dir);
    }
}
