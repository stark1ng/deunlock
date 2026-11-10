//! The signed/mac'd message a desktop sends to the phone: **who is asking,
//! for what, and when**.
//!
//! ## Why this module exists
//!
//! In v1 the phone signed `version || nonce` and nothing else. It could not
//! tell which desktop was asking, which service the login was for, or which
//! human account it was about, and it never verified the challenge MAC. A
//! rogue BLE peripheral could therefore drive the phone as a signing oracle
//! (AUDIT-001 D-02) and a signature minted for `sudo` was valid for `gdm`
//! within the TTL (D-06).
//!
//! v2 binds the whole request into one canonical, unambiguous byte string:
//!
//! ```text
//! "deunlock-auth-v2"            domain separator, 16 bytes
//! || u16be(2)                   protocol version
//! || host_id[32]                which desktop is asking
//! || u16be(len) || service      "sudo" | "gdm" | "polkit" | "lock"
//! || u16be(len) || user         the human account the decision is about
//! || nonce[16]                  the desktop's per-request nonce
//! || u64be(issued_at)           unix seconds, checked against a clock window
//! ```
//!
//! Length prefixes plus a strictly printable-ASCII field alphabet make the
//! encoding injective: there is no pair of different `(service, user)` values
//! that produce the same bytes, so a MAC can never be "moved" between
//! requests by a separator-injection trick.
//!
//! The MAC is BLAKE3 keyed with a key derived from the bond key
//! ([`crate::kex::derive_auth_mac_key`]), compared in constant time.

use blake3::Hash;
use subtle::ConstantTimeEq;

use crate::kex::{BOND_KEY_V2_BYTES, derive_auth_mac_key};

/// Domain separator for the v2 authentication transcript.
pub const TRANSCRIPT_DOMAIN_V2: &[u8] = b"deunlock-auth-v2";

/// Protocol version carried inside the transcript (and checked on decode).
pub const TRANSCRIPT_VERSION: u16 = 2;

/// Longest accepted `service` or `user` field, in bytes.
pub const MAX_TRANSCRIPT_FIELD_LEN: usize = 64;

/// Length of the transcript MAC tag, in bytes.
pub const TRANSCRIPT_TAG_LEN: usize = 16;

/// Length of the per-request nonce, in bytes.
pub const REQUEST_NONCE_LEN: usize = 16;

/// Errors produced while building a transcript.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TranscriptError {
    /// A required text field was empty.
    #[error("transcript field '{field}' must not be empty")]
    EmptyField {
        /// Which field was empty (`service` or `user`).
        field: &'static str,
    },
    /// A text field exceeded [`MAX_TRANSCRIPT_FIELD_LEN`].
    #[error("transcript field '{field}' is longer than {MAX_TRANSCRIPT_FIELD_LEN} bytes")]
    FieldTooLong {
        /// Which field was too long.
        field: &'static str,
    },
    /// A text field contained a byte outside printable ASCII.
    #[error("transcript field '{field}' must be printable ASCII (0x21..=0x7e)")]
    NonPrintableField {
        /// Which field carried the offending byte.
        field: &'static str,
    },
}

fn validate_field(field: &'static str, value: &str) -> Result<(), TranscriptError> {
    if value.is_empty() {
        return Err(TranscriptError::EmptyField { field });
    }
    if value.len() > MAX_TRANSCRIPT_FIELD_LEN {
        return Err(TranscriptError::FieldTooLong { field });
    }
    // Strictly printable, no space, no control characters: keeps the
    // encoding injective and keeps homoglyph/UTF-8 tricks out of the MAC.
    if !value.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(TranscriptError::NonPrintableField { field });
    }
    Ok(())
}

/// One authentication request, in the exact shape the phone approves and the
/// desktop verifies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthTranscript {
    host_id: [u8; BOND_KEY_V2_BYTES],
    service: String,
    user: String,
    nonce: [u8; REQUEST_NONCE_LEN],
    issued_at: u64,
}

impl AuthTranscript {
    /// Build a transcript, validating both text fields.
    ///
    /// # Errors
    ///
    /// Returns a [`TranscriptError`] when `service` or `user` is empty, too
    /// long, or contains a non-printable byte.
    pub fn new(
        host_id: [u8; BOND_KEY_V2_BYTES],
        service: &str,
        user: &str,
        nonce: [u8; REQUEST_NONCE_LEN],
        issued_at: u64,
    ) -> Result<Self, TranscriptError> {
        validate_field("service", service)?;
        validate_field("user", user)?;
        Ok(Self {
            host_id,
            service: service.to_owned(),
            user: user.to_owned(),
            nonce,
            issued_at,
        })
    }

    /// The desktop identity this request names.
    #[must_use]
    pub fn host_id(&self) -> &[u8; BOND_KEY_V2_BYTES] {
        &self.host_id
    }

    /// The PAM service this request is for (`sudo`, `gdm`, `polkit`, `lock`).
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// The human account the decision is about.
    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }

    /// The desktop's per-request nonce.
    #[must_use]
    pub fn nonce(&self) -> &[u8; REQUEST_NONCE_LEN] {
        &self.nonce
    }

    /// Unix seconds when the desktop issued the request.
    #[must_use]
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    /// Canonical bytes covered by the MAC and, on the phone, by the signature.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(TRANSCRIPT_DOMAIN_V2.len() + 2 + 32 + 2 + self.service.len() + 2 + self.user.len() + 16 + 8);
        out.extend_from_slice(TRANSCRIPT_DOMAIN_V2);
        out.extend_from_slice(&TRANSCRIPT_VERSION.to_be_bytes());
        out.extend_from_slice(&self.host_id);
        // Lengths are bounded by MAX_TRANSCRIPT_FIELD_LEN, so the u16 cast is lossless.
        out.extend_from_slice(&u16::try_from(self.service.len()).unwrap_or(u16::MAX).to_be_bytes());
        out.extend_from_slice(self.service.as_bytes());
        out.extend_from_slice(&u16::try_from(self.user.len()).unwrap_or(u16::MAX).to_be_bytes());
        out.extend_from_slice(self.user.as_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out
    }

    /// Keyed MAC over [`Self::encode`], truncated to [`TRANSCRIPT_TAG_LEN`].
    #[must_use]
    pub fn tag(&self, bond_key: &[u8; BOND_KEY_V2_BYTES]) -> [u8; TRANSCRIPT_TAG_LEN] {
        let mac_key = derive_auth_mac_key(bond_key);
        let digest: Hash = blake3::keyed_hash(&mac_key, &self.encode());
        let mut tag = [0u8; TRANSCRIPT_TAG_LEN];
        tag.copy_from_slice(&digest.as_bytes()[..TRANSCRIPT_TAG_LEN]);
        tag
    }

    /// Constant-time check of `tag` against this transcript.
    #[must_use]
    pub fn verify(&self, bond_key: &[u8; BOND_KEY_V2_BYTES], tag: &[u8; TRANSCRIPT_TAG_LEN]) -> bool {
        let expected = self.tag(bond_key);
        expected.ct_eq(tag).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transcript() -> AuthTranscript {
        AuthTranscript::new([0xAB; 32], "sudo", "roma", [0x5A; REQUEST_NONCE_LEN], 1_760_000_000).expect("valid")
    }

    fn key() -> [u8; 32] {
        [0x42; 32]
    }

    #[test]
    fn tag_roundtrips() {
        let t = transcript();
        let tag = t.tag(&key());
        assert!(t.verify(&key(), &tag));
    }

    #[test]
    fn tag_is_deterministic() {
        assert_eq!(transcript().tag(&key()), transcript().tag(&key()));
    }

    #[test]
    fn every_field_is_covered_by_the_tag() {
        let base = transcript();
        let tag = base.tag(&key());

        let variants = [
            AuthTranscript::new([0xAC; 32], "sudo", "roma", [0x5A; 16], 1_760_000_000).expect("host"),
            AuthTranscript::new([0xAB; 32], "gdm", "roma", [0x5A; 16], 1_760_000_000).expect("service"),
            AuthTranscript::new([0xAB; 32], "sudo", "root", [0x5A; 16], 1_760_000_000).expect("user"),
            AuthTranscript::new([0xAB; 32], "sudo", "roma", [0x5B; 16], 1_760_000_000).expect("nonce"),
            AuthTranscript::new([0xAB; 32], "sudo", "roma", [0x5A; 16], 1_760_000_001).expect("ts"),
        ];
        for (index, other) in variants.iter().enumerate() {
            assert!(!other.verify(&key(), &tag), "variant {index} must not verify");
        }
    }

    #[test]
    fn signature_for_one_service_does_not_cover_another() {
        // D-06 regression: a tag minted for `sudo` must not be accepted for `gdm`.
        let sudo = AuthTranscript::new([0xAB; 32], "sudo", "roma", [1; 16], 42).expect("t");
        let gdm = AuthTranscript::new([0xAB; 32], "gdm", "roma", [1; 16], 42).expect("t");
        assert!(!gdm.verify(&key(), &sudo.tag(&key())));
    }

    #[test]
    fn wrong_bond_key_is_rejected() {
        let t = transcript();
        let tag = t.tag(&key());
        assert!(!t.verify(&[0x43; 32], &tag));
    }

    #[test]
    fn tampered_tag_is_rejected() {
        let t = transcript();
        let mut tag = t.tag(&key());
        tag[0] ^= 0x01;
        assert!(!t.verify(&key(), &tag));
    }

    #[test]
    fn encoding_is_injective_across_the_service_user_boundary() {
        // Without length prefixes, ("ab", "c") and ("a", "bc") could collide.
        let a = AuthTranscript::new([0; 32], "ab", "c", [0; 16], 0).expect("a");
        let b = AuthTranscript::new([0; 32], "a", "bc", [0; 16], 0).expect("b");
        assert_ne!(a.encode(), b.encode());
        assert_ne!(a.tag(&key()), b.tag(&key()));
    }

    #[test]
    fn empty_fields_are_refused() {
        assert_eq!(
            AuthTranscript::new([0; 32], "", "roma", [0; 16], 0).unwrap_err(),
            TranscriptError::EmptyField { field: "service" }
        );
        assert_eq!(
            AuthTranscript::new([0; 32], "sudo", "", [0; 16], 0).unwrap_err(),
            TranscriptError::EmptyField { field: "user" }
        );
    }

    #[test]
    fn overlong_fields_are_refused() {
        let long = "a".repeat(MAX_TRANSCRIPT_FIELD_LEN + 1);
        assert_eq!(
            AuthTranscript::new([0; 32], &long, "roma", [0; 16], 0).unwrap_err(),
            TranscriptError::FieldTooLong { field: "service" }
        );
    }

    #[test]
    fn control_and_space_bytes_are_refused() {
        for bad in ["su do", "sudo\n", "sudo\u{7f}", "юзер"] {
            assert_eq!(
                AuthTranscript::new([0; 32], bad, "roma", [0; 16], 0).unwrap_err(),
                TranscriptError::NonPrintableField { field: "service" },
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn encode_carries_domain_and_version() {
        let encoded = transcript().encode();
        assert!(encoded.starts_with(TRANSCRIPT_DOMAIN_V2));
        assert_eq!(
            &encoded[TRANSCRIPT_DOMAIN_V2.len()..TRANSCRIPT_DOMAIN_V2.len() + 2],
            &TRANSCRIPT_VERSION.to_be_bytes()
        );
    }
}
