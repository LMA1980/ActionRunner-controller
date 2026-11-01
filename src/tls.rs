use arc_swap::ArcSwap;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use sha2::Digest;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::{error, info};
use x509_parser::prelude::*;

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("I/O error: {0}")]
    Io(String),
    #[error("PEM parsing error: {0}")]
    Pem(String),
    #[error("WebPKI error: {0}")]
    WebPki(String),
    #[error("Rustls error: {0}")]
    Rustls(String),
    #[error("No certificates found in '{0}'")]
    NoCertificatesFound(String),
    #[error("No private key found in '{0}'")]
    NoPrivateKeyFound(String),
    #[error("X.509 certificate parse error: {0}")]
    CertParseError(String),
    #[error("File watcher error: {0}")]
    WatcherError(String),
}

/// Load PEM-encoded certificate chain from disk.
pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let file = std::fs::File::open(path).map_err(|e| TlsError::Io(e.to_string()))?;
    let mut reader = std::io::BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::Pem(e.to_string()))?;
    if certs.is_empty() {
        return Err(TlsError::NoCertificatesFound(path.display().to_string()));
    }
    Ok(certs)
}

/// Load PEM-encoded private key (PKCS#8, PKCS#1, or SEC1) from disk.
pub fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    let file = std::fs::File::open(path).map_err(|e| TlsError::Io(e.to_string()))?;
    let mut reader = std::io::BufReader::new(file);
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| TlsError::Pem(e.to_string()))?
        .ok_or_else(|| TlsError::NoPrivateKeyFound(path.display().to_string()))?;
    Ok(key)
}

/// Load CA certificate bundle and construct RootCertStore for mTLS client verification.
pub fn load_root_cert_store(ca_bundle_path: &Path) -> Result<RootCertStore, TlsError> {
    let ca_certs = load_certs(ca_bundle_path)?;
    let mut root_store = RootCertStore::empty();
    for cert in ca_certs {
        root_store
            .add(cert)
            .map_err(|e| TlsError::WebPki(e.to_string()))?;
    }
    Ok(root_store)
}

/// Build rustls ServerConfig with mTLS client certificate verification enabled.
pub fn build_mtls_server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    root_cert_store: RootCertStore,
) -> Result<ServerConfig, TlsError> {
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_cert_store))
        .build()
        .map_err(|e| TlsError::WebPki(e.to_string()))?;

    let server_config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(cert_chain, key)
        .map_err(|e| TlsError::Rustls(e.to_string()))?;

    Ok(server_config)
}

/// Build rustls ServerConfig directly from file paths.
pub fn build_server_config_from_files(
    server_cert_path: &Path,
    server_key_path: &Path,
    ca_cert_path: &Path,
) -> Result<ServerConfig, TlsError> {
    let certs = load_certs(server_cert_path)?;
    let key = load_private_key(server_key_path)?;
    let root_store = load_root_cert_store(ca_cert_path)?;
    build_mtls_server_config(certs, key, root_store)
}

/// Extract SHA-256 fingerprint hex string from DER certificate bytes.
pub fn extract_cert_fingerprint(cert_der: &[u8]) -> String {
    let hash = sha2::Sha256::digest(cert_der);
    hex::encode(hash)
}

/// Extract all DNS SANs from client certificate DER bytes.
pub fn extract_client_cert_sans(cert_der: &[u8]) -> Result<Vec<String>, TlsError> {
    let (_, x509) =
        X509Certificate::from_der(cert_der).map_err(|e| TlsError::CertParseError(e.to_string()))?;

    let mut sans = Vec::new();
    for ext in x509.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for general_name in &san.general_names {
                if let GeneralName::DNSName(dns_name) = general_name {
                    sans.push(dns_name.to_string());
                }
            }
        }
    }
    Ok(sans)
}

/// Verify that client certificate contains a Subject Alternative Name (SAN) matching expected domain suffix.
pub fn verify_client_cert_san(
    cert_der: &[u8],
    expected_domain_suffix: &str,
) -> Result<bool, TlsError> {
    let sans = extract_client_cert_sans(cert_der)?;
    let suffix = expected_domain_suffix.trim_start_matches('.');

    for san in &sans {
        if san == suffix || san.ends_with(&format!(".{}", suffix)) {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Hot-reloading watcher for TLS certificate rotation using ArcSwap.
pub struct CertReloadWatcher {
    config_swap: Arc<ArcSwap<ServerConfig>>,
    server_cert_path: PathBuf,
    server_key_path: PathBuf,
    ca_cert_path: PathBuf,
    _watcher: Option<notify::RecommendedWatcher>,
    last_fingerprint: Arc<Mutex<Option<String>>>,
}

impl CertReloadWatcher {
    pub fn new(
        server_cert_path: PathBuf,
        server_key_path: PathBuf,
        ca_cert_path: PathBuf,
    ) -> Result<Self, TlsError> {
        let initial_config =
            build_server_config_from_files(&server_cert_path, &server_key_path, &ca_cert_path)?;
        let initial_certs = load_certs(&server_cert_path)?;
        let initial_fingerprint = initial_certs
            .first()
            .map(|c| extract_cert_fingerprint(c.as_ref()));

        let config_swap = Arc::new(ArcSwap::from_pointee(initial_config));
        let last_fingerprint = Arc::new(Mutex::new(initial_fingerprint));

        let config_clone = Arc::clone(&config_swap);
        let s_cert = server_cert_path.clone();
        let s_key = server_key_path.clone();
        let c_cert = ca_cert_path.clone();
        let fp_clone = Arc::clone(&last_fingerprint);

        let watcher_res = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                match event.kind {
                    EventKind::Modify(_) | EventKind::Create(_) => {
                        match build_server_config_from_files(&s_cert, &s_key, &c_cert) {
                            Ok(new_cfg) => {
                                if let Ok(certs) = load_certs(&s_cert) {
                                    let fp =
                                        certs.first().map(|c| extract_cert_fingerprint(c.as_ref()));
                                    if let Ok(mut lock) = fp_clone.lock() {
                                        *lock = fp;
                                    }
                                }
                                config_clone.store(Arc::new(new_cfg));
                                info!("Hot-reloaded TLS server configuration with renewed certificate");
                            }
                            Err(e) => {
                                error!(error = %e, "Failed to reload TLS server configuration on disk event");
                            }
                        }
                    }
                    _ => {}
                }
            }
        });

        let watcher = match watcher_res {
            Ok(mut w) => {
                let watch_dir = server_cert_path.parent().unwrap_or(Path::new("."));
                if let Err(e) = w.watch(watch_dir, RecursiveMode::NonRecursive) {
                    error!(error = %e, "Failed to register directory watcher for TLS certificates");
                    None
                } else {
                    Some(w)
                }
            }
            Err(e) => {
                error!(error = %e, "Failed to initialize notify recommended watcher");
                None
            }
        };

        Ok(Self {
            config_swap,
            server_cert_path,
            server_key_path,
            ca_cert_path,
            _watcher: watcher,
            last_fingerprint,
        })
    }

    /// Explicitly trigger a certificate reload from disk.
    pub fn reload(&self) -> Result<(), TlsError> {
        let new_cfg = build_server_config_from_files(
            &self.server_cert_path,
            &self.server_key_path,
            &self.ca_cert_path,
        )?;
        let certs = load_certs(&self.server_cert_path)?;
        let fp = certs.first().map(|c| extract_cert_fingerprint(c.as_ref()));

        if let Ok(mut lock) = self.last_fingerprint.lock() {
            *lock = fp;
        }

        self.config_swap.store(Arc::new(new_cfg));
        Ok(())
    }

    /// Get atomic snapshot of current rustls ServerConfig.
    pub fn get_config(&self) -> Arc<ServerConfig> {
        self.config_swap.load_full()
    }

    /// Get current certificate SHA-256 fingerprint.
    pub fn get_cert_fingerprint(&self) -> Option<String> {
        self.last_fingerprint.lock().ok().and_then(|g| g.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
    use tempfile::tempdir;

    fn generate_cert(domain: &str) -> (String, String, Vec<u8>) {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(vec![domain.to_string()]).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, domain);
        params.distinguished_name = dn;
        let cert = params.self_signed(&key_pair).unwrap();
        (cert.pem(), key_pair.serialize_pem(), cert.der().to_vec())
    }

    #[test]
    fn test_client_cert_san_verification_passes_and_fails_closed() {
        // Valid internal node SAN
        let (_cert_pem, _key_pem, valid_der) = generate_cert("worker-1.ci.ci.internal");

        assert!(
            verify_client_cert_san(&valid_der, "ci.ci.internal").unwrap(),
            "Valid .ci.ci.internal client certificate must pass SAN check"
        );

        // Invalid domain suffix
        let (_cert_pem, _key_pem, invalid_der) = generate_cert("attacker.external.com");

        assert!(
            !verify_client_cert_san(&invalid_der, "ci.ci.internal").unwrap(),
            "External or mismatched SAN must fail closed"
        );

        // Missing cert bytes must fail closed with error
        assert!(
            verify_client_cert_san(&[], "ci.ci.internal").is_err(),
            "Empty cert DER must return error"
        );
    }

    #[test]
    fn test_mtls_server_config_construction() {
        let dir = tempdir().unwrap();
        let ca_path = dir.path().join("ca.crt");
        let server_cert_path = dir.path().join("server.crt");
        let server_key_path = dir.path().join("server.key");

        let (srv_pem, srv_key, _) = generate_cert("controller.ci.ci.internal");

        std::fs::write(&ca_path, &srv_pem).unwrap();
        std::fs::write(&server_cert_path, &srv_pem).unwrap();
        std::fs::write(&server_key_path, &srv_key).unwrap();

        let config = build_server_config_from_files(&server_cert_path, &server_key_path, &ca_path)
            .expect("mTLS server config should build successfully");

        assert_eq!(config.max_early_data_size, 0);
    }

    #[test]
    fn test_cert_reload_watcher_atomic_swap() {
        let dir = tempdir().unwrap();
        let ca_path = dir.path().join("ca.crt");
        let server_cert_path = dir.path().join("server.crt");
        let server_key_path = dir.path().join("server.key");

        let (srv_pem_1, srv_key_1, _) = generate_cert("controller.ci.ci.internal");

        std::fs::write(&ca_path, &srv_pem_1).unwrap();
        std::fs::write(&server_cert_path, &srv_pem_1).unwrap();
        std::fs::write(&server_key_path, &srv_key_1).unwrap();

        let watcher = CertReloadWatcher::new(
            server_cert_path.clone(),
            server_key_path.clone(),
            ca_path.clone(),
        )
        .expect("Watcher should initialize with cert 1");

        let initial_fp = watcher
            .get_cert_fingerprint()
            .expect("Should have initial fingerprint");

        // Rotate certificate on disk (generate cert 2)
        let (srv_pem_2, srv_key_2, _) = generate_cert("controller.ci.ci.internal");

        std::fs::write(&server_cert_path, &srv_pem_2).unwrap();
        std::fs::write(&server_key_path, &srv_key_2).unwrap();

        // Trigger reload
        watcher.reload().expect("Reload should succeed");

        let rotated_fp = watcher
            .get_cert_fingerprint()
            .expect("Should have rotated fingerprint");

        assert_ne!(
            initial_fp, rotated_fp,
            "Rotated certificate must produce a different SHA-256 fingerprint"
        );

        let active_cfg = watcher.get_config();
        assert_eq!(active_cfg.max_early_data_size, 0);
    }
}
