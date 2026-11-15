//! TLS for the client ⇄ host link.
//!
//! The host generates a self-signed certificate on install. Clients pin its SHA-256
//! fingerprint the first time they connect (trust-on-first-use, like SSH `known_hosts`)
//! and refuse to connect if it ever changes.

use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring as ring_provider, CryptoProvider};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};

pub use rustls::pki_types::ServerName;
pub use tokio_rustls::client::TlsStream;
pub use tokio_rustls::{TlsAcceptor, TlsConnector};

fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring_provider::default_provider())
}

/// Create `cert.pem` / `key.pem` in `dir` if they don't exist yet.
pub fn ensure_host_cert(dir: &Path, host_name: &str) -> Result<()> {
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    if cert_path.exists() && key_path.exists() {
        return Ok(());
    }
    let ck = rcgen::generate_simple_self_signed(vec![host_name.to_string(), "localhost".into()])
        .context("generate host certificate")?;
    std::fs::write(&cert_path, ck.cert.pem())?;
    std::fs::write(&key_path, ck.key_pair.serialize_pem())?;
    restrict_permissions(&key_path);
    Ok(())
}

#[cfg(unix)]
fn restrict_permissions(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn restrict_permissions(_p: &Path) {
    // On Windows the data directory itself is ACL'd to SYSTEM + Administrators at install.
}

/// Server-side TLS acceptor from the certificate in `dir`. Also returns its fingerprint.
pub fn host_acceptor(dir: &Path) -> Result<(TlsAcceptor, String)> {
    let cert = CertificateDer::from_pem_file(dir.join("cert.pem")).context("read cert.pem")?;
    let key = PrivateKeyDer::from_pem_file(dir.join("key.pem")).context("read key.pem")?;
    let fp = fingerprint(&cert);
    let cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    Ok((TlsAcceptor::from(Arc::new(cfg)), fp))
}

/// Fingerprint of the certificate file in `dir`.
pub fn host_fingerprint(dir: &Path) -> Result<String> {
    let cert = CertificateDer::from_pem_file(dir.join("cert.pem")).context("read cert.pem")?;
    Ok(fingerprint(&cert))
}

/// SHA-256 of the DER certificate, as colon-separated hex.
pub fn fingerprint(cert: &CertificateDer<'_>) -> String {
    let d = Sha256::digest(cert.as_ref());
    d.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

/// Verifier that pins a fingerprint (if known) and records what the server presented.
/// The handshake signature is still verified against the presented certificate.
#[derive(Debug)]
pub struct PinnedVerifier {
    expected: Option<String>,
    seen: Mutex<Option<String>>,
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl PinnedVerifier {
    pub fn seen_fingerprint(&self) -> Option<String> {
        self.seen.lock().unwrap().clone()
    }
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fp = fingerprint(end_entity);
        *self.seen.lock().unwrap() = Some(fp.clone());
        match &self.expected {
            Some(exp) if *exp != fp => Err(rustls::Error::General(format!(
                "HOST CERTIFICATE CHANGED (expected {exp}, got {fp}). Possible man-in-the-middle. \
                 Run `rd-client forget <host>` only if you know why it changed."
            ))),
            _ => Ok(ServerCertVerified::assertion()),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// Client-side connector. `expected` is the pinned fingerprint, if this host is already known.
pub fn client_connector(expected: Option<String>) -> Result<(TlsConnector, Arc<PinnedVerifier>)> {
    let prov = provider();
    let verifier = Arc::new(PinnedVerifier {
        expected,
        seen: Mutex::new(None),
        algs: prov.signature_verification_algorithms,
    });
    let cfg = rustls::ClientConfig::builder_with_provider(prov)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    Ok((TlsConnector::from(Arc::new(cfg)), verifier))
}
