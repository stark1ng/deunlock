//! The pairing QR payload: everything a phone needs to reach and verify this
//! desktop, delivered out of band.
//!
//! AUDIT-001 **D-07** is the reason this exists. The BLE first-pair flow
//! authenticates with a four-word "OOB code" read off the screen; a nearby
//! attacker who can run a second pairing session at the same time has a
//! realistic chance of getting a user to compare the wrong words, and the code
//! alone does not carry the desktop's TLS identity. A QR code is scanned from
//! the screen the user is actually looking at, carries a 256-bit secret, and can
//! carry the certificate pin at the same time — so the phone learns, in one
//! gesture, both *which* desktop this is and *what* proves it.
//!
//! ## Payload
//!
//! ```text
//! "DLQR1" ‖ base64url( version:1 ‖ host_id[32] ‖ host_pubkey[32]
//!                      ‖ u8 host_len ‖ host[host_len]
//!                      ‖ u16be port
//!                      ‖ tls_fingerprint[32]
//!                      ‖ pairing_secret[32]
//!                      ‖ u64be expires_at )
//! ```
//!
//! `base64url` is padded-free URL-safe base64 so the string survives being
//! pasted into a URL, a QR with mixed-case alphanumerics only, or a shell.
//!
//! Nothing in this structure is secret **except** [`PairingOffer::secret`] — and
//! that secret is only as private as the screen showing the QR. That is the
//! point: it is trusted because it was seen, not because it was sent.

use std::os::unix::fs::OpenOptionsExt as _;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Prefix that identifies a DeUnlock pairing QR.
pub const QR_PREFIX: &str = "DLQR1";

/// Wire version inside the payload (the prefix changes when this does).
pub const QR_VERSION: u8 = 1;

/// Length of the pairing secret.
pub const PAIRING_SECRET_BYTES: usize = 32;

/// Where `deunlock pair-qr` leaves the offer for the daemon to find.
pub const DEFAULT_PAIRING_OFFER_PATH: &str = "/run/deunlock/pairing.offer";

/// Maximum length of the LAN host name a QR may carry.
pub const MAX_HOST_BYTES: usize = 63;

/// Why a QR payload was refused.
#[derive(Debug, thiserror::Error)]
pub enum QrError {
    /// The string is not a DeUnlock pairing code.
    #[error("not a deunlock pairing code: {reason}")]
    NotOurs {
        /// What was wrong with the prefix or the encoding.
        reason: String,
    },

    /// The version byte names a format this build does not understand.
    #[error("unsupported pairing QR version {version}")]
    UnsupportedVersion {
        /// The version found in the payload.
        version: u8,
    },

    /// The payload decoded but its fields do not make sense.
    #[error("malformed pairing code: {reason}")]
    Malformed {
        /// Which field was wrong.
        reason: String,
    },

    /// The code is older than its expiry.
    #[error("pairing code expired at {expires_at} (now {now})")]
    Expired {
        /// Expiry stamped into the code.
        expires_at: u64,
        /// Time the check ran at.
        now: u64,
    },
}

/// A decoded pairing offer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingOffer {
    /// Desktop identity (`BLAKE3` of its Ed25519 public key).
    pub host_id: [u8; 32],
    /// Desktop's Ed25519 public key, for verifying anything it signs later.
    pub host_pubkey: [u8; 32],
    /// LAN address a phone should try (an IP literal or a `.local` name).
    pub lan_host: String,
    /// LAN port.
    pub lan_port: u16,
    /// `SHA-256(cert DER)` the phone pins.
    pub tls_fingerprint: [u8; 32],
    /// Secret mixed into the bond key at pairing time.
    pub secret: [u8; PAIRING_SECRET_BYTES],
    /// Unix seconds after which the code must be refused.
    pub expires_at: u64,
}

impl PairingOffer {
    /// Encode as a scannable string.
    ///
    /// # Errors
    ///
    /// [`QrError::Malformed`] when the host is empty, longer than
    /// [`MAX_HOST_BYTES`], or contains a byte a QR reader would mangle.
    pub fn encode(&self) -> Result<String, QrError> {
        let host = self.lan_host.as_bytes();
        if host.is_empty() || host.len() > MAX_HOST_BYTES {
            return Err(QrError::Malformed {
                reason: format!("lan_host must be 1..={MAX_HOST_BYTES} bytes, got {}", host.len()),
            });
        }
        if !host
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'))
        {
            return Err(QrError::Malformed {
                reason: "lan_host may only contain letters, digits, '.', '-', '_' and ':'".to_owned(),
            });
        }

        let mut body = Vec::with_capacity(1 + 32 + 32 + 1 + host.len() + 2 + 32 + 32 + 8);
        body.push(QR_VERSION);
        body.extend_from_slice(&self.host_id);
        body.extend_from_slice(&self.host_pubkey);
        body.push(u8::try_from(host.len()).map_err(|_| QrError::Malformed {
            reason: "lan_host length does not fit a byte".to_owned(),
        })?);
        body.extend_from_slice(host);
        body.extend_from_slice(&self.lan_port.to_be_bytes());
        body.extend_from_slice(&self.tls_fingerprint);
        body.extend_from_slice(&self.secret);
        body.extend_from_slice(&self.expires_at.to_be_bytes());

        Ok(format!("{QR_PREFIX}{}", URL_SAFE_NO_PAD.encode(body)))
    }

    /// Decode a scanned string.
    ///
    /// # Errors
    ///
    /// [`QrError::NotOurs`] for a foreign string, [`QrError::UnsupportedVersion`]
    /// for a newer format, [`QrError::Malformed`] for a bad field, and
    /// [`QrError::Expired`] when `now` is past the stamped expiry.
    pub fn decode(text: &str, now: u64) -> Result<Self, QrError> {
        let trimmed = text.trim();
        let body_b64 = trimmed.strip_prefix(QR_PREFIX).ok_or_else(|| QrError::NotOurs {
            reason: "missing DLQR1 prefix".to_owned(),
        })?;
        let body = URL_SAFE_NO_PAD.decode(body_b64).map_err(|e| QrError::NotOurs {
            reason: format!("base64 decode failed: {e}"),
        })?;

        let mut cursor = Cursor::new(&body);
        let version = cursor.byte()?;
        if version != QR_VERSION {
            return Err(QrError::UnsupportedVersion { version });
        }
        let host_id = cursor.array32()?;
        let host_pubkey = cursor.array32()?;
        let host_len = usize::from(cursor.byte()?);
        if host_len == 0 || host_len > MAX_HOST_BYTES {
            return Err(QrError::Malformed {
                reason: format!("lan_host length {host_len} out of range"),
            });
        }
        let host_bytes = cursor.take(host_len)?;
        let lan_host = String::from_utf8(host_bytes.to_vec()).map_err(|_| QrError::Malformed {
            reason: "lan_host is not UTF-8".to_owned(),
        })?;
        let port = u16::from_be_bytes([cursor.byte()?, cursor.byte()?]);
        let tls_fingerprint = cursor.array32()?;
        let mut secret = [0u8; PAIRING_SECRET_BYTES];
        secret.copy_from_slice(cursor.take(PAIRING_SECRET_BYTES)?);
        let mut expiry = [0u8; 8];
        expiry.copy_from_slice(cursor.take(8)?);
        let expires_at = u64::from_be_bytes(expiry);
        if cursor.remaining() != 0 {
            return Err(QrError::Malformed {
                reason: format!("{} trailing bytes", cursor.remaining()),
            });
        }
        if now > expires_at {
            return Err(QrError::Expired { expires_at, now });
        }

        Ok(Self {
            host_id,
            host_pubkey,
            lan_host,
            lan_port: port,
            tls_fingerprint,
            secret,
            expires_at,
        })
    }
}

/// Bounds-checked reader; every accessor refuses rather than panics, because the
/// input comes from a camera pointed at whatever the user was shown.
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], QrError> {
        if self.remaining() < len {
            return Err(QrError::Malformed {
                reason: format!("truncated: wanted {len} bytes, {} left", self.remaining()),
            });
        }
        let out = &self.bytes[self.offset..self.offset + len];
        self.offset += len;
        Ok(out)
    }

    fn byte(&mut self) -> Result<u8, QrError> {
        Ok(self.take(1)?[0])
    }

    fn array32(&mut self) -> Result<[u8; 32], QrError> {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.take(32)?);
        Ok(out)
    }
}


/// The offer a running daemon is currently willing to accept, as written to disk
/// by `deunlock pair-qr` and consumed by the LAN listener.
///
/// It lives in a file rather than in the daemon's memory because the two
/// processes are different: the CLI prints the QR, the daemon answers it. The file
/// is the hand-off, and it is short-lived on purpose.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PendingOffer {
    /// Hex of the 32-byte pairing secret.
    pub secret: String,
    /// Hex of the host id the secret was minted for.
    pub host_id: String,
    /// Unix seconds after which the offer is dead.
    pub expires_at: u64,
}

impl PendingOffer {
    /// Build a file record from an offer.
    #[must_use]
    pub fn from_offer(offer: &PairingOffer) -> Self {
        Self {
            secret: hex_encode(&offer.secret),
            host_id: hex_encode(&offer.host_id),
            expires_at: offer.expires_at,
        }
    }

    /// The secret as bytes.
    ///
    /// # Errors
    ///
    /// [`QrError::Malformed`] when the file was corrupted or edited.
    pub fn secret_bytes(&self) -> Result<[u8; PAIRING_SECRET_BYTES], QrError> {
        let bytes = hex_decode(&self.secret).ok_or_else(|| QrError::Malformed {
            reason: "offer secret is not 32 bytes of hex".to_owned(),
        })?;
        bytes.try_into().map_err(|v: Vec<u8>| QrError::Malformed {
            reason: format!("offer secret is {} bytes, expected {PAIRING_SECRET_BYTES}", v.len()),
        })
    }

    /// The host id as bytes.
    ///
    /// # Errors
    ///
    /// [`QrError::Malformed`] when the file was corrupted or edited.
    pub fn host_id_bytes(&self) -> Result<[u8; 32], QrError> {
        let bytes = hex_decode(&self.host_id).ok_or_else(|| QrError::Malformed {
            reason: "offer host_id is not 32 bytes of hex".to_owned(),
        })?;
        bytes.try_into().map_err(|v: Vec<u8>| QrError::Malformed {
            reason: format!("offer host_id is {} bytes, expected 32", v.len()),
        })
    }

    /// Write the offer where the daemon looks for it, mode `0600`.
    ///
    /// # Errors
    ///
    /// Any I/O or serialization failure, including a directory that cannot be
    /// created.
    pub fn write(&self, path: &std::path::Path) -> std::io::Result<()> {
        use std::io::Write as _;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let body = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        let tmp = path.with_extension("tmp");
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            file.write_all(&body)?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp, path)
    }

    /// Read the offer, refusing one that has expired.
    ///
    /// # Errors
    ///
    /// [`QrError::Malformed`] for an unreadable or corrupt file,
    /// [`QrError::Expired`] when `now` is past the expiry.
    pub fn read(path: &std::path::Path, now: u64) -> Result<Self, QrError> {
        let body = std::fs::read(path).map_err(|e| QrError::Malformed {
            reason: format!("cannot read {}: {e}", path.display()),
        })?;
        let offer: Self = serde_json::from_slice(&body).map_err(|e| QrError::Malformed {
            reason: format!("cannot parse {}: {e}", path.display()),
        })?;
        // Validate now rather than when the bytes are used: a corrupt secret should
        // fail at the boundary, not halfway through a pairing.
        let _ = offer.secret_bytes()?;
        let _ = offer.host_id_bytes()?;
        if now > offer.expires_at {
            return Err(QrError::Expired {
                expires_at: offer.expires_at,
                now,
            });
        }
        Ok(offer)
    }
}

/// Lowercase hex, without pulling in a formatting dependency.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode hex, returning `None` on any non-hex character or odd length.
fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer() -> PairingOffer {
        PairingOffer {
            host_id: [0x11; 32],
            host_pubkey: [0x22; 32],
            lan_host: "192.168.1.42".to_owned(),
            lan_port: 47_823,
            tls_fingerprint: [0x33; 32],
            secret: [0x44; PAIRING_SECRET_BYTES],
            expires_at: 1_800_000_000,
        }
    }

    #[test]
    fn an_offer_survives_the_round_trip() {
        let text = offer().encode().expect("encode");
        assert!(text.starts_with(QR_PREFIX));
        let decoded = PairingOffer::decode(&text, 1_700_000_000).expect("decode");
        assert_eq!(decoded, offer());
    }

    #[test]
    fn the_payload_is_url_safe_and_free_of_padding() {
        let text = offer().encode().expect("encode");
        let body = text.trim_start_matches(QR_PREFIX);
        assert!(!body.contains('='), "no padding");
        assert!(!body.contains('+') && !body.contains('/'), "url-safe alphabet");
        assert!(body.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn an_expired_code_is_refused() {
        let text = offer().encode().expect("encode");
        match PairingOffer::decode(&text, 1_800_000_001) {
            Err(QrError::Expired { expires_at, now }) => {
                assert_eq!(expires_at, 1_800_000_000);
                assert_eq!(now, 1_800_000_001);
            }
            other => panic!("expected Expired, got {other:?}"),
        }
    }

    #[test]
    fn a_foreign_string_is_not_mistaken_for_a_pairing_code() {
        for text in ["", "hello", "DLQR2abc", "https://example.com"] {
            assert!(matches!(PairingOffer::decode(text, 0), Err(QrError::NotOurs { .. })));
        }
    }

    #[test]
    fn a_newer_version_is_refused_rather_than_guessed_at() {
        let mut body = Vec::new();
        body.push(QR_VERSION + 1);
        body.extend_from_slice(&[0u8; 32]);
        body.extend_from_slice(&[0u8; 32]);
        let text = format!("{QR_PREFIX}{}", URL_SAFE_NO_PAD.encode(body));
        assert!(matches!(
            PairingOffer::decode(&text, 0),
            Err(QrError::UnsupportedVersion { version }) if version == QR_VERSION + 1
        ));
    }

    #[test]
    fn truncated_payloads_are_refused_without_panicking() {
        let text = offer().encode().expect("encode");
        let body = text.trim_start_matches(QR_PREFIX);
        for cut in 1..body.len() {
            let partial = format!("{QR_PREFIX}{}", &body[..cut]);
            let _ = PairingOffer::decode(&partial, 0);
        }
    }

    #[test]
    fn a_host_the_phone_could_not_dial_is_refused_at_encode_time() {
        let mut bad = offer();
        bad.lan_host = "example.com/evil?x=1".to_owned();
        assert!(bad.encode().is_err());

        let mut too_long = offer();
        too_long.lan_host = "a".repeat(MAX_HOST_BYTES + 1);
        assert!(too_long.encode().is_err());

        let mut empty = offer();
        empty.lan_host = String::new();
        assert!(empty.encode().is_err());
    }

    #[test]
    fn the_secret_is_not_visible_in_the_printed_form() {
        // A shoulder-surfer reading the QR text should not see the secret as hex;
        // only the scanned payload carries it, and it is base64'd as a whole.
        let text = offer().encode().expect("encode");
        assert!(!text.contains(&"44".repeat(32)), "secret must not appear as hex");
    }
    #[test]
    fn a_pending_offer_round_trips_through_disk() {
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("pairing.offer");
        let offer = offer();
        let pending = PendingOffer::from_offer(&offer);
        pending.write(&path).expect("write");

        let read_back = PendingOffer::read(&path, 1_700_000_000).expect("read");
        assert_eq!(read_back.secret_bytes().expect("secret"), offer.secret);
        assert_eq!(read_back.host_id_bytes().expect("host"), offer.host_id);
    }

    #[test]
    fn a_pending_offer_file_is_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("pairing.offer");
        PendingOffer::from_offer(&offer()).write(&path).expect("write");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "the secret must not be world-readable");
    }

    #[test]
    fn an_expired_pending_offer_is_refused_at_read() {
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("pairing.offer");
        PendingOffer::from_offer(&offer()).write(&path).expect("write");
        assert!(matches!(
            PendingOffer::read(&path, 1_800_000_001),
            Err(QrError::Expired { .. })
        ));
    }

    #[test]
    fn a_corrupt_pending_offer_is_refused() {
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("pairing.offer");
        std::fs::write(&path, br#"{"secret":"zz","host_id":"00","expires_at":99999999999}"#).expect("write");
        assert!(matches!(PendingOffer::read(&path, 0), Err(QrError::Malformed { .. })));
        assert!(PendingOffer::read(&dir.path().join("missing"), 0).is_err());
    }

}
