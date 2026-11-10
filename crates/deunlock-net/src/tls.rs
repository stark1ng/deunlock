//! TLS 1.3 endpoint configuration with certificate pinning.
//!
//! The server half is an ordinary `tokio-rustls` server using [`LanIdentity`].
//! The client half exists so the *desktop* can test the pinning contract the
//! phone implements — and so an integration test can prove that a wrong pin
//! really does stop the handshake instead of merely being a comment in Kotlin.
//!
//! ALPN is `deunlock/2` on both sides: a stray HTTPS client that finds the port
//! through a port scan cannot complete a handshake, and we never speak anything
//! but our own protocol.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio_rustls::TlsAcceptor;

use crate::error::NetError;
use crate::identity::{FINGERPRINT_BYTES, LanIdentity};

/// ALPN protocol identifier for the LAN transport.
pub const ALPN_PROTOCOL: &[u8] = b"deunlock/2";

/// Build the server-side TLS configuration for `identity`.
///
/// # Errors
///
/// [`NetError::TlsConfig`] when the certificate or key is rejected by rustls
/// (a corrupt identity file, in practice).
pub fn server_config(identity: &LanIdentity) -> Result<Arc<ServerConfig>, NetError> {
    let cert = CertificateDer::from(identity.cert_der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.key_der().to_vec()));
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| NetError::TlsConfig(e.to_string()))?;
    config.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];
    Ok(Arc::new(config))
}

/// Wrap a serving config in a `tokio-rustls` acceptor.
///
/// # Errors
///
/// Propagates [`server_config`]'s errors.
pub fn acceptor(identity: &LanIdentity) -> Result<TlsAcceptor, NetError> {
    Ok(TlsAcceptor::from(server_config(identity)?))
}

/// Build a client configuration that trusts exactly one certificate — the one
/// whose `SHA-256(cert DER)` equals `expected_fingerprint`.
///
/// # Errors
///
/// Never in practice; the signature returns a `Result` only to mirror
/// [`server_config`].
pub fn pinned_client_config(expected_fingerprint: [u8; FINGERPRINT_BYTES]) -> Arc<ClientConfig> {
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCert::new(expected_fingerprint)))
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];
    Arc::new(config)
}

/// A verifier that accepts one pinned certificate and nothing else.
#[derive(Debug)]
struct PinnedCert {
    expected: [u8; FINGERPRINT_BYTES],
}

impl PinnedCert {
    fn new(expected: [u8; FINGERPRINT_BYTES]) -> Self {
        Self { expected }
    }
}

impl ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let digest = hasher.finalize();
        if constant_time_eq(&digest, &self.expected) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "presented certificate does not match the pinned fingerprint".to_owned(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Compare two byte slices without an early return.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_comparison_ignores_only_identical_slices() {
        assert!(constant_time_eq(b"abcd", b"abcd"));
        assert!(!constant_time_eq(b"abcd", b"abce"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    #[test]
    fn both_sides_offer_the_same_alpn() {
        let identity = LanIdentity::generate().expect("identity");
        let server = server_config(&identity).expect("server");
        let client = pinned_client_config(identity.fingerprint());
        assert_eq!(server.alpn_protocols, vec![ALPN_PROTOCOL.to_vec()]);
        assert_eq!(client.alpn_protocols, vec![ALPN_PROTOCOL.to_vec()]);
    }
}
