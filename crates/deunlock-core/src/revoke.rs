//! Revocation carried over the authenticated unlock channel.
//!
//! `revoke` used to be one-sided: the phone deleted its bond record and the
//! desktop kept challenging a device that no longer held the key, while — because
//! pair mode is exclusive to "no bonds" — it also stopped advertising itself as
//! pairable. The user-visible symptom was "the computer is not in the list" with
//! a perfectly healthy daemon (AUDIT-001 D-14).
//!
//! The phone cannot open a socket to the daemon; its only channel is the GATT
//! response characteristic, which the daemon reads while a challenge is in
//! flight. So revocation is delivered **on the next contact**: instead of a
//! signature the phone answers with this frame, the daemon verifies it under the
//! bond key it already holds, drops the bond, and reports a distinct outcome so
//! PAM can tell the user to re-pair rather than fail silently.
//!
//! Frame (44 bytes):
//!
//! ```text
//! "DLR1" ‖ timestamp_ms: u64 big-endian ‖ tag: [u8; 32]
//! tag = BLAKE3_keyed(derive_auth_mac_key(bond), "deunlock-revoke-v1" ‖ timestamp_be)
//! ```
//!
//! The tag proves possession of the bond key, so a stranger cannot retire
//! somebody else's bond, and a frame captured from one peer cannot be replayed
//! against another (different key). The timestamp only bounds how long a
//! captured frame stays usable: revocation is idempotent, so the residual attack
//! is "delay a re-pair", not "unlock something".

use subtle::ConstantTimeEq as _;

use crate::kex::{derive_auth_mac_key, BOND_KEY_V2_BYTES};
use crate::mac::BOND_KEY_BYTES;

/// Magic prefix of a revocation frame.
pub const REVOKE_MAGIC: &[u8; 4] = b"DLR1";

/// Length of a revocation frame: magic + timestamp + tag.
pub const REVOKE_FRAME_LEN: usize = 4 + 8 + 32;

/// Domain separator for the revocation tag.
pub const REVOKE_DOMAIN: &[u8] = b"deunlock-revoke-v1";

/// How far a revocation timestamp may sit from the desktop's clock.
///
/// Wide enough for phones whose clock is a few minutes off, narrow enough that a
/// captured frame does not stay usable for long.
pub const REVOKE_WINDOW_MS: i64 = 10 * 60 * 1_000;

/// Failures a revocation frame can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeError {
    /// The frame does not start with [`REVOKE_MAGIC`].
    BadMagic,
    /// The frame is not exactly [`REVOKE_FRAME_LEN`] bytes.
    BadLength {
        /// Length actually seen.
        seen: usize,
    },
    /// The tag does not authenticate the frame under this bond.
    BadTag,
    /// The timestamp is outside [`REVOKE_WINDOW_MS`] of the desktop clock.
    StaleTimestamp {
        /// Timestamp carried by the frame.
        frame_ms: u64,
        /// Desktop clock at verification time.
        now_ms: u64,
    },
}

impl core::fmt::Display for RevokeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "not a revocation frame"),
            Self::BadLength { seen } => {
                write!(f, "revocation frame is {seen} bytes, expected {REVOKE_FRAME_LEN}")
            }
            Self::BadTag => write!(f, "revocation tag does not authenticate under this bond"),
            Self::StaleTimestamp { frame_ms, now_ms } => {
                write!(f, "revocation timestamp {frame_ms} is outside the window of {now_ms}")
            }
        }
    }
}

impl std::error::Error for RevokeError {}

/// True when `frame` claims to be a revocation rather than a signature.
///
/// Cheap and allocation-free: the caller uses this to branch before treating the
/// bytes as a 64-byte Ed25519 signature.
#[must_use]
pub fn is_revoke_frame(frame: &[u8]) -> bool {
    frame.len() >= REVOKE_MAGIC.len() && &frame[..REVOKE_MAGIC.len()] == REVOKE_MAGIC
}

fn tag_for(bond_key: &[u8; BOND_KEY_V2_BYTES], timestamp_be: &[u8; 8]) -> [u8; 32] {
    let mac_key = derive_auth_mac_key(bond_key);
    let mut message = Vec::with_capacity(REVOKE_DOMAIN.len() + 8);
    message.extend_from_slice(REVOKE_DOMAIN);
    message.extend_from_slice(timestamp_be);
    *blake3::keyed_hash(&mac_key, &message).as_bytes()
}

/// Build the frame that retires the bond at the other end.
#[must_use]
pub fn encode_revoke(bond_key: &[u8; BOND_KEY_V2_BYTES], timestamp_ms: u64) -> Vec<u8> {
    let timestamp_be = timestamp_ms.to_be_bytes();
    let mut out = Vec::with_capacity(REVOKE_FRAME_LEN);
    out.extend_from_slice(REVOKE_MAGIC);
    out.extend_from_slice(&timestamp_be);
    out.extend_from_slice(&tag_for(bond_key, &timestamp_be));
    out
}

/// Authenticate a revocation frame against `bond_key`, returning its timestamp.
///
/// The tag is compared in constant time; a bad tag and a bad length are the only
/// outcomes that can be attacker-chosen, and both are reported distinctly so the
/// audit log can tell a protocol mistake from an attack.
pub fn decode_revoke(
    bond_key: &[u8; BOND_KEY_V2_BYTES],
    frame: &[u8],
    now_ms: u64,
) -> Result<u64, RevokeError> {
    if !is_revoke_frame(frame) {
        return Err(RevokeError::BadMagic);
    }
    if frame.len() != REVOKE_FRAME_LEN {
        return Err(RevokeError::BadLength { seen: frame.len() });
    }
    let mut timestamp_be = [0u8; 8];
    timestamp_be.copy_from_slice(&frame[4..12]);
    let expected = tag_for(bond_key, &timestamp_be);
    let seen = &frame[12..44];
    if expected.ct_eq(seen).unwrap_u8() != 1 {
        return Err(RevokeError::BadTag);
    }
    let frame_ms = u64::from_be_bytes(timestamp_be);
    let delta = i128::from(frame_ms) - i128::from(now_ms);
    if delta.unsigned_abs() > u128::from(REVOKE_WINDOW_MS.unsigned_abs()) {
        return Err(RevokeError::StaleTimestamp { frame_ms, now_ms });
    }
    Ok(frame_ms)
}

/// Convenience: [`encode_revoke`] for callers that hold the shorter
/// [`BOND_KEY_BYTES`] array from a bond record.
#[must_use]
pub fn encode_revoke_from_record(bond_key: &[u8; BOND_KEY_BYTES], timestamp_ms: u64) -> Vec<u8> {
    encode_revoke(bond_key, timestamp_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_794_400_000_000;

    fn key(seed: u8) -> [u8; BOND_KEY_V2_BYTES] {
        [seed; BOND_KEY_V2_BYTES]
    }

    #[test]
    fn round_trip_authenticates() {
        let bond = key(7);
        let frame = encode_revoke(&bond, NOW);
        assert_eq!(frame.len(), REVOKE_FRAME_LEN);
        assert!(is_revoke_frame(&frame));
        assert_eq!(decode_revoke(&bond, &frame, NOW + 5_000).unwrap(), NOW);
    }

    #[test]
    fn another_bonds_key_does_not_authenticate() {
        let frame = encode_revoke(&key(7), NOW);
        assert_eq!(decode_revoke(&key(9), &frame, NOW), Err(RevokeError::BadTag));
    }

    #[test]
    fn a_flipped_tag_byte_is_rejected() {
        let bond = key(7);
        let mut frame = encode_revoke(&bond, NOW);
        let last = frame.len() - 1;
        frame[last] ^= 0x01;
        assert_eq!(decode_revoke(&bond, &frame, NOW), Err(RevokeError::BadTag));
    }

    #[test]
    fn a_flipped_timestamp_byte_is_rejected() {
        let bond = key(7);
        let mut frame = encode_revoke(&bond, NOW);
        frame[11] ^= 0x01;
        assert_eq!(decode_revoke(&bond, &frame, NOW), Err(RevokeError::BadTag));
    }

    #[test]
    fn a_signature_is_not_a_revoke_frame() {
        assert!(!is_revoke_frame(&[0u8; 64]));
        assert_eq!(
            decode_revoke(&key(7), &[0u8; 64], NOW),
            Err(RevokeError::BadMagic)
        );
    }

    #[test]
    fn truncated_frame_is_rejected() {
        let bond = key(7);
        let frame = encode_revoke(&bond, NOW);
        assert_eq!(
            decode_revoke(&bond, &frame[..20], NOW),
            Err(RevokeError::BadLength { seen: 20 })
        );
    }

    #[test]
    fn a_stale_timestamp_is_rejected_even_with_a_valid_tag() {
        let bond = key(7);
        let frame = encode_revoke(&bond, NOW);
        let err = decode_revoke(&bond, &frame, NOW + (REVOKE_WINDOW_MS as u64) + 1).unwrap_err();
        assert!(matches!(err, RevokeError::StaleTimestamp { .. }));
    }

    #[test]
    fn a_future_timestamp_inside_the_window_is_accepted() {
        let bond = key(7);
        let frame = encode_revoke(&bond, NOW);
        assert!(decode_revoke(&bond, &frame, NOW - 60_000).is_ok());
    }

    #[test]
    fn record_key_helper_matches_the_general_encoder() {
        let bond = key(3);
        assert_eq!(
            encode_revoke_from_record(&bond, NOW),
            encode_revoke(&bond, NOW)
        );
    }
}
