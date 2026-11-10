//! The desktop's persistent Ed25519 identity.
//!
//! ## Why this exists
//!
//! Before this module, `deunlock pair` generated a throwaway host key per
//! invocation and never persisted it (see `deunlock-cli::run_pair_cli`). Two
//! consequences:
//!
//! 1. The phone pinned a public key that no longer existed after the process
//!    exited, so the desktop had no identity the phone could recognise later.
//! 2. The v2 transcript cannot bind `host_id` to anything stable, and the v2
//!    challenge would be forgeable in the "which desktop is asking" sense that
//!    AUDIT-001 D-02 describes.
//!
//! [`HostIdentity`] fixes that: one Ed25519 key per machine, stored at
//! `/etc/deunlock/host.key` with mode `0600` in a `0700` directory, loaded once
//! at daemon boot and reused by the pairing CLI.
//!
//! `host_id` is `BLAKE3(public_key)[..32]`. It is safe to hand to the phone and
//! to put in transcripts: the hash reveals nothing about the key, and the phone
//! compares it against the value it stored at pairing time.
//!
//! ## Threat notes
//!
//! - The secret is a **signing** key, not an encryption key. Losing it lets an
//!   attacker impersonate this desktop to a phone that trusts it; it does not
//!   decrypt anything.
//! - A `0600` file still loses to root. That is the documented T-007 residual:
//!   root on the host is post-compromise.
//! - The file is written atomically (`NamedTempFile` + `persist`) so a crash
//!   mid-write cannot leave a truncated key that would silently become a new
//!   identity on the next boot.

use std::{
    fs,
    io::Write as _,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
};

use blake3;
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

/// Bytes in an Ed25519 secret key seed.
pub const HOST_KEY_SECRET_BYTES: usize = 32;

/// Bytes in an Ed25519 public key.
pub const HOST_KEY_PUBLIC_BYTES: usize = 32;

/// Bytes in a `host_id`.
pub const HOST_ID_BYTES: usize = 32;

/// File mode required for the host key file.
pub const HOST_KEY_FILE_MODE: u32 = 0o600;

/// Directory mode required for the host key's parent.
pub const HOST_KEY_DIR_MODE: u32 = 0o700;

/// Default on-disk location of the host key.
pub const DEFAULT_HOST_KEY_PATH: &str = "/etc/deunlock/host.key";

/// Typed failures from loading or storing the host identity.
#[derive(Debug, thiserror::Error)]
pub enum HostError {
    /// Filesystem failure, with the offending path.
    #[error("host key i/o failed at {path}")]
    Io {
        /// Path the operation touched.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },
    /// The file did not hold exactly [`HOST_KEY_SECRET_BYTES`] bytes.
    #[error("host key file must be {HOST_KEY_SECRET_BYTES} bytes, got {got}")]
    BadLength {
        /// Actual byte count read.
        got: usize,
    },
    /// The key file was readable by group or other.
    ///
    /// Refusing to load a world-readable secret is deliberate: silently
    /// accepting it would hide a real misconfiguration on a machine that now
    /// signs challenges.
    #[error("host key file {path} must be mode {HOST_KEY_FILE_MODE:o}, found {found:o}")]
    PermissionsTooLoose {
        /// Offending file.
        path: PathBuf,
        /// Mode actually found.
        found: u32,
    },
}

/// The desktop's long-lived signing identity.
pub struct HostIdentity {
    signing: SigningKey,
}

impl HostIdentity {
    /// Generate a brand-new identity from the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut seed = Zeroizing::new([0u8; HOST_KEY_SECRET_BYTES]);
        OsRng.fill_bytes(seed.as_mut());
        Self::from_secret_bytes(&seed)
    }

    /// Build an identity from a raw 32-byte seed.
    #[must_use]
    pub fn from_secret_bytes(seed: &[u8; HOST_KEY_SECRET_BYTES]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// The Ed25519 public key.
    #[must_use]
    pub fn public_key(&self) -> [u8; HOST_KEY_PUBLIC_BYTES] {
        self.signing.verifying_key().to_bytes()
    }

    /// The `host_id` carried in transcripts: `BLAKE3(public_key)[..32]`.
    #[must_use]
    pub fn host_id(&self) -> [u8; HOST_ID_BYTES] {
        let hash = blake3::hash(&self.public_key());
        let mut out = [0u8; HOST_ID_BYTES];
        out.copy_from_slice(&hash.as_bytes()[..HOST_ID_BYTES]);
        out
    }

    /// Borrow the signing key (used by the pairing flow).
    #[must_use]
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }

    /// The raw seed, for persisting. Zeroized on drop by the caller.
    #[must_use]
    pub fn secret_bytes(&self) -> Zeroizing<[u8; HOST_KEY_SECRET_BYTES]> {
        Zeroizing::new(self.signing.to_bytes())
    }

    /// Load the identity at `path`, creating one if the file is absent.
    ///
    /// # Errors
    ///
    /// Propagates [`HostError`] from [`Self::load`] or [`Self::save`]. A
    /// present-but-broken file is **not** replaced: silently minting a new
    /// identity would break every existing bond.
    pub fn load_or_create(path: &Path) -> Result<Self, HostError> {
        match Self::load(path) {
            Ok(identity) => Ok(identity),
            Err(HostError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
                let identity = Self::generate();
                identity.save(path)?;
                Ok(identity)
            }
            Err(err) => Err(err),
        }
    }

    /// Load and validate the identity at `path`.
    ///
    /// # Errors
    ///
    /// [`HostError::Io`] for read failures, [`HostError::BadLength`] for a
    /// truncated key, [`HostError::PermissionsTooLoose`] when the file is
    /// readable by anyone but the owner.
    pub fn load(path: &Path) -> Result<Self, HostError> {
        let meta = fs::metadata(path).map_err(|source| HostError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(HostError::PermissionsTooLoose {
                path: path.to_path_buf(),
                found: mode,
            });
        }
        let bytes = fs::read(path).map_err(|source| HostError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        if bytes.len() != HOST_KEY_SECRET_BYTES {
            return Err(HostError::BadLength { got: bytes.len() });
        }
        let mut seed = Zeroizing::new([0u8; HOST_KEY_SECRET_BYTES]);
        seed.copy_from_slice(&bytes);
        Ok(Self::from_secret_bytes(&seed))
    }

    /// Write the identity to `path` with mode `0600`, atomically.
    ///
    /// # Errors
    ///
    /// [`HostError::Io`] for any filesystem failure, including a parent
    /// directory that cannot be created.
    pub fn save(&self, path: &Path) -> Result<(), HostError> {
        let parent = path.parent().ok_or_else(|| HostError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "host key path has no parent directory"),
        })?;
        ensure_dir(parent)?;

        let mut tmp = tempfile::NamedTempFile::new_in(parent).map_err(|source| HostError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(HOST_KEY_FILE_MODE))
            .map_err(|source| HostError::Io {
                path: tmp.path().to_path_buf(),
                source,
            })?;
        let seed = self.secret_bytes();
        tmp.write_all(seed.as_ref()).map_err(|source| HostError::Io {
            path: tmp.path().to_path_buf(),
            source,
        })?;
        tmp.as_file().sync_all().map_err(|source| HostError::Io {
            path: tmp.path().to_path_buf(),
            source,
        })?;
        tmp.persist(path).map_err(|err| HostError::Io {
            path: path.to_path_buf(),
            source: err.error,
        })?;
        Ok(())
    }
}

impl core::fmt::Debug for HostIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never render the secret, and do not render the full id either: a
        // debug line ends up in logs.
        f.debug_struct("HostIdentity").field("host_id", &"<redacted>").finish()
    }
}

fn ensure_dir(dir: &Path) -> Result<(), HostError> {
    match fs::create_dir_all(dir) {
        Ok(()) => {}
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(source) => {
            return Err(HostError::Io {
                path: dir.to_path_buf(),
                source,
            });
        }
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(HOST_KEY_DIR_MODE)).map_err(|source| HostError::Io {
        path: dir.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn key_path(td: &TempDir) -> PathBuf {
        td.path().join("deunlock").join("host.key")
    }

    #[test]
    fn generate_is_random_and_stable_per_instance() {
        let a = HostIdentity::generate();
        let b = HostIdentity::generate();
        assert_ne!(a.public_key(), b.public_key(), "two generations must differ");
        assert_eq!(a.public_key(), a.public_key(), "public key is stable");
        assert_eq!(a.host_id(), a.host_id(), "host id is stable");
    }

    #[test]
    fn host_id_is_the_hash_of_the_public_key() {
        let identity = HostIdentity::from_secret_bytes(&[7u8; 32]);
        let expected = blake3::hash(&identity.public_key());
        assert_eq!(&identity.host_id(), &expected.as_bytes()[..HOST_ID_BYTES]);
        assert_ne!(identity.host_id(), identity.public_key(), "host_id must not be the key itself");
    }

    #[test]
    fn save_then_load_roundtrips_the_identity() {
        let td = TempDir::new().expect("tempdir");
        let path = key_path(&td);

        let original = HostIdentity::generate();
        original.save(&path).expect("save");

        let loaded = HostIdentity::load(&path).expect("load");
        assert_eq!(loaded.public_key(), original.public_key());
        assert_eq!(loaded.host_id(), original.host_id());
    }

    #[test]
    fn saved_file_mode_is_0600() {
        let td = TempDir::new().expect("tempdir");
        let path = key_path(&td);
        HostIdentity::generate().save(&path).expect("save");

        let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, HOST_KEY_FILE_MODE);
    }

    #[test]
    fn parent_directory_mode_is_0700() {
        let td = TempDir::new().expect("tempdir");
        let path = key_path(&td);
        HostIdentity::generate().save(&path).expect("save");

        let dir = path.parent().expect("parent");
        let mode = fs::metadata(dir).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, HOST_KEY_DIR_MODE);
    }

    #[test]
    fn load_refuses_a_world_readable_key() {
        let td = TempDir::new().expect("tempdir");
        let path = key_path(&td);
        HostIdentity::generate().save(&path).expect("save");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");

        match HostIdentity::load(&path) {
            Err(HostError::PermissionsTooLoose { found, .. }) => assert_eq!(found, 0o644),
            other => panic!("expected PermissionsTooLoose, got {other:?}"),
        }
    }

    #[test]
    fn load_refuses_a_truncated_key() {
        let td = TempDir::new().expect("tempdir");
        let path = key_path(&td);
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        fs::write(&path, [0u8; 16]).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");

        match HostIdentity::load(&path) {
            Err(HostError::BadLength { got }) => assert_eq!(got, 16),
            other => panic!("expected BadLength, got {other:?}"),
        }
    }

    #[test]
    fn load_or_create_mints_once_and_reuses_afterwards() {
        let td = TempDir::new().expect("tempdir");
        let path = key_path(&td);

        let first = HostIdentity::load_or_create(&path).expect("create");
        let second = HostIdentity::load_or_create(&path).expect("reuse");
        assert_eq!(first.host_id(), second.host_id(), "second call must not mint a new identity");
    }

    #[test]
    fn load_or_create_does_not_replace_a_broken_file() {
        let td = TempDir::new().expect("tempdir");
        let path = key_path(&td);
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        fs::write(&path, [0u8; 8]).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");

        assert!(HostIdentity::load_or_create(&path).is_err(), "must fail rather than silently re-key");
        assert_eq!(fs::read(&path).expect("still there").len(), 8);
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        let identity = HostIdentity::from_secret_bytes(&[9u8; 32]);
        assert_eq!(format!("{identity:?}"), "HostIdentity { host_id: \"<redacted>\" }");
    }
}
