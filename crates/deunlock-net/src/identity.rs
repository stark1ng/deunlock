//! The desktop's LAN identity: a self-signed certificate plus the fingerprint a
//! phone pins during pairing.
//!
//! Why a certificate and not just the bond key: TLS 1.3 needs *some* server
//! credential, and a self-signed cert is the cheapest thing that also gives the
//! phone something stable to pin. The pin is `SHA-256(cert DER)` — 32 bytes,
//! cheap to render in a QR code and cheap to check on Android
//! (`MessageDigest.getInstance("SHA-256")`).
//!
//! Both files are written `0600` inside a `0700` directory and are **never**
//! silently regenerated: a lost cert means every phone has to pair again, so a
//! malformed cert is an error the operator has to look at, not something we
//! quietly repair (same rule as `deunlock-core`'s host key).

use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::NetError;

/// Directory mode for the identity's parent.
pub const IDENTITY_DIR_MODE: u32 = 0o700;

/// File mode for the certificate and its private key.
pub const IDENTITY_FILE_MODE: u32 = 0o600;

/// Length of a certificate fingerprint in bytes.
pub const FINGERPRINT_BYTES: usize = 32;

/// A loaded (or freshly generated) TLS identity.
pub struct LanIdentity {
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
}

impl std::fmt::Debug for LanIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LanIdentity")
            .field("fingerprint_hex", &self.fingerprint_hex())
            .field("key_der", &"<redacted>")
            .finish()
    }
}

impl LanIdentity {
    /// Load the certificate and key at `cert_path`/`key_path`, generating a new
    /// self-signed pair when the certificate does not exist yet.
    ///
    /// A missing **key** with an existing certificate is an error (someone
    /// deleted half of the identity); so is a key with group/other access.
    ///
    /// # Errors
    ///
    /// [`NetError::IdentityIo`] for filesystem problems,
    /// [`NetError::PermissionsTooLoose`] for a key readable by others,
    /// [`NetError::IdentityMalformed`] for an unreadable key,
    /// [`NetError::Certificate`] when generation fails.
    pub fn load_or_create(cert_path: &Path, key_path: &Path) -> Result<Self, NetError> {
        Self::ensure_parent_dir(cert_path)?;
        Self::ensure_parent_dir(key_path)?;

        match (cert_path.exists(), key_path.exists()) {
            (true, true) => {
                Self::check_mode(key_path)?;
                let cert_der = fs::read(cert_path).map_err(|source| NetError::IdentityIo {
                    path: cert_path.to_path_buf(),
                    source,
                })?;
                let key_der = fs::read(key_path).map_err(|source| NetError::IdentityIo {
                    path: key_path.to_path_buf(),
                    source,
                })?;
                if cert_der.is_empty() || key_der.is_empty() {
                    return Err(NetError::IdentityMalformed {
                        path: if cert_der.is_empty() { cert_path } else { key_path }.to_path_buf(),
                        reason: "file is empty".to_owned(),
                    });
                }
                Ok(Self { cert_der, key_der })
            }
            (false, false) => {
                let identity = Self::generate()?;
                identity.persist(cert_path, key_path)?;
                Ok(identity)
            }
            (true, false) => Err(NetError::IdentityMalformed {
                path: key_path.to_path_buf(),
                reason: "certificate exists but its private key is missing".to_owned(),
            }),
            (false, true) => Err(NetError::IdentityMalformed {
                path: cert_path.to_path_buf(),
                reason: "private key exists but its certificate is missing".to_owned(),
            }),
        }
    }

    /// Build a fresh self-signed identity in memory (no files touched).
    ///
    /// # Errors
    ///
    /// [`NetError::Certificate`] when rcgen refuses to build the pair.
    pub fn generate() -> Result<Self, NetError> {
        let issued = rcgen::generate_simple_self_signed(vec!["deunlock.local".to_owned()])
            .map_err(|e| NetError::Certificate(e.to_string()))?;
        let cert_der = issued.cert.der().to_vec();
        let key_der = issued.key_pair.serialize_der();
        Ok(Self { cert_der, key_der })
    }

    /// The certificate in DER form.
    #[must_use]
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// The private key in PKCS#8 DER form.
    #[must_use]
    pub fn key_der(&self) -> &[u8] {
        &self.key_der
    }

    /// `SHA-256(cert DER)` — what a phone pins.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; FINGERPRINT_BYTES] {
        let mut hasher = Sha256::new();
        hasher.update(&self.cert_der);
        let digest = hasher.finalize();
        let mut out = [0u8; FINGERPRINT_BYTES];
        out.copy_from_slice(&digest);
        out
    }

    /// The fingerprint as lowercase hex — the form printed by `deunlock doctor`
    /// and encoded in the pairing QR.
    #[must_use]
    pub fn fingerprint_hex(&self) -> String {
        self.fingerprint().iter().map(|b| format!("{b:02x}")).collect()
    }

    fn persist(&self, cert_path: &Path, key_path: &Path) -> Result<(), NetError> {
        write_private(cert_path, &self.cert_der)?;
        write_private(key_path, &self.key_der)?;
        Ok(())
    }

    fn ensure_parent_dir(path: &Path) -> Result<(), NetError> {
        let Some(parent) = path.parent() else {
            return Ok(());
        };
        if parent.as_os_str().is_empty() {
            return Ok(());
        }
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|source| NetError::IdentityIo {
                path: PathBuf::from(parent),
                source,
            })?;
            fs::set_permissions(parent, fs::Permissions::from_mode(IDENTITY_DIR_MODE)).map_err(
                |source| NetError::IdentityIo {
                    path: PathBuf::from(parent),
                    source,
                },
            )?;
        }
        Ok(())
    }

    fn check_mode(path: &Path) -> Result<(), NetError> {
        let mode = fs::metadata(path)
            .map_err(|source| NetError::IdentityIo {
                path: path.to_path_buf(),
                source,
            })?
            .permissions()
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            return Err(NetError::PermissionsTooLoose {
                path: path.to_path_buf(),
            });
        }
        Ok(())
    }
}

/// Write `bytes` to `path` with `0600`, replacing atomically.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), NetError> {
    let tmp = path.with_extension("tmp");
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(IDENTITY_FILE_MODE)
            .open(&tmp)
            .map_err(|source| NetError::IdentityIo {
                path: tmp.clone(),
                source,
            })?;
        use std::io::Write as _;
        file.write_all(bytes).map_err(|source| NetError::IdentityIo {
            path: tmp.clone(),
            source,
        })?;
        file.sync_all().map_err(|source| NetError::IdentityIo {
            path: tmp.clone(),
            source,
        })?;
    }
    fs::rename(&tmp, path).map_err(|source| NetError::IdentityIo {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_identity_lands_on_disk_with_tight_permissions() {
        let dir = tempfile::tempdir().expect("tmp");
        let cert = dir.path().join("sub/net.crt");
        let key = dir.path().join("sub/net.key");
        let identity = LanIdentity::load_or_create(&cert, &key).expect("create");
        assert!(cert.exists() && key.exists());
        for path in [&cert, &key] {
            let mode = fs::metadata(path).expect("mode").permissions().mode() & 0o777;
            assert_eq!(mode, IDENTITY_FILE_MODE, "{path:?}");
        }
        let dir_mode = fs::metadata(dir.path().join("sub"))
            .expect("dir mode")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, IDENTITY_DIR_MODE);
        assert_eq!(identity.fingerprint().len(), FINGERPRINT_BYTES);
        assert_eq!(identity.fingerprint_hex().len(), 64);
    }

    #[test]
    fn reloading_yields_the_same_fingerprint() {
        let dir = tempfile::tempdir().expect("tmp");
        let cert = dir.path().join("net.crt");
        let key = dir.path().join("net.key");
        let first = LanIdentity::load_or_create(&cert, &key).expect("create");
        let second = LanIdentity::load_or_create(&cert, &key).expect("reload");
        assert_eq!(first.fingerprint(), second.fingerprint());
    }

    #[test]
    fn a_key_readable_by_others_is_refused() {
        let dir = tempfile::tempdir().expect("tmp");
        let cert = dir.path().join("net.crt");
        let key = dir.path().join("net.key");
        LanIdentity::load_or_create(&cert, &key).expect("create");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).expect("chmod");
        match LanIdentity::load_or_create(&cert, &key) {
            Err(NetError::PermissionsTooLoose { .. }) => {}
            other => panic!("expected PermissionsTooLoose, got {other:?}"),
        }
    }

    #[test]
    fn half_an_identity_is_never_silently_repaired() {
        let dir = tempfile::tempdir().expect("tmp");
        let cert = dir.path().join("net.crt");
        let key = dir.path().join("net.key");
        LanIdentity::load_or_create(&cert, &key).expect("create");
        fs::remove_file(&key).expect("rm key");
        match LanIdentity::load_or_create(&cert, &key) {
            Err(NetError::IdentityMalformed { .. }) => {}
            other => panic!("expected IdentityMalformed, got {other:?}"),
        }
        assert!(!key.exists(), "a broken identity must not be regenerated");
    }
}
