//! Turning a scanned QR into a bond.
//!
//! The QR ([`crate::qr_pair`]) carries a 256-bit `pairing_secret` that the user
//! saw on the desktop's own screen. That secret is high-entropy and out of band,
//! so it is the whole basis of the bond — no ECDH is needed, and nothing the
//! network says can influence the result.
//!
//! ## Conversation
//!
//! Runs on the pinned TLS connection, before any challenge:
//!
//! ```text
//! phone  → "DLP1" ‖ phone_pubkey[65] ‖ tag[32]
//!           tag = BLAKE3_keyed(secret, "deunlock-pair-request-v1" ‖ host_id ‖ phone_pubkey)
//! desktop → "DLP2" ‖ tag[32]
//!           tag = BLAKE3_keyed(secret, "deunlock-pair-accept-v1"  ‖ host_id ‖ phone_pubkey)
//! ```
//!
//! Both tags are checked in constant time. The second one exists so the phone
//! learns that the desktop it just talked to *also* held the secret: without it a
//! phone that had scanned a code could be paired to a machine that merely
//! forwarded the bytes.
//!
//! ## Bond
//!
//! ```text
//! bond = BLAKE3-derive_key("deunlock-bond-qr-v1") ‖ host_id ‖ phone_pubkey ‖ secret
//! ```
//!
//! Note what is **not** in there: the desktop's TLS fingerprint (already proven by
//! the connection) and the phone's own choice of address. The bond depends on the
//! secret and on both identities, so a bond derived by another phone, or against
//! another host, is a different key.

use subtle::ConstantTimeEq as _;

use crate::mac::BOND_KEY_BYTES;

/// Magic of the phone's pairing request.
pub const PAIR_REQUEST_MAGIC: [u8; 4] = *b"DLP1";

/// Magic of the desktop's pairing acceptance.
pub const PAIR_ACCEPT_MAGIC: [u8; 4] = *b"DLP2";

/// Domain separator for the bond derivation.
pub const QR_BOND_INFO: &[u8] = b"deunlock-bond-qr-v1";

/// Domain separator for the phone's request tag.
pub const PAIR_REQUEST_DOMAIN: &[u8] = b"deunlock-pair-request-v1";

/// Domain separator for the desktop's acceptance tag.
pub const PAIR_ACCEPT_DOMAIN: &[u8] = b"deunlock-pair-accept-v1";

/// Length of the phone's Ed25519 public key.
///
/// The phone already owns this key (it is what `peer_id` hashes), so pairing does
/// not have to mint and store a second one.
pub const PHONE_PUBKEY_BYTES: usize = 32;

/// Length of a pairing tag.
pub const PAIR_TAG_BYTES: usize = 32;

/// Total length of a pairing request record.
pub const PAIR_REQUEST_LEN: usize = PAIR_REQUEST_MAGIC.len() + PHONE_PUBKEY_BYTES + PAIR_TAG_BYTES;

/// Total length of a pairing acceptance record.
pub const PAIR_ACCEPT_LEN: usize = PAIR_ACCEPT_MAGIC.len() + PAIR_TAG_BYTES;

/// Why a QR pairing step was refused.
#[derive(Debug, thiserror::Error)]
pub enum PairError {
    /// The record is not the message we expected.
    #[error("malformed pairing record: {reason}")]
    Malformed {
        /// What was wrong with it.
        reason: String,
    },

    /// The tag did not verify: wrong secret, wrong host, wrong phone key, or a
    /// forgery.
    #[error("pairing tag did not verify")]
    TagMismatch,

    /// The phone's public key is the all-zero placeholder.
    #[error("phone public key is empty")]
    EmptyPublicKey,
}

/// Derive the bond both sides will store.
///
/// Pure function of the out-of-band secret and both identities, so the desktop
/// and the phone compute the same key without ever exchanging it.
#[must_use]
pub fn derive_qr_bond_key(
    secret: &[u8; 32],
    host_id: &[u8; 32],
    phone_pubkey: &[u8; PHONE_PUBKEY_BYTES],
) -> [u8; BOND_KEY_BYTES] {
    let mut hasher = blake3::Hasher::new_derive_key(std::str::from_utf8(QR_BOND_INFO).unwrap_or("deunlock-bond-qr-v1"));
    hasher.update(secret);
    hasher.update(host_id);
    hasher.update(phone_pubkey);
    *hasher.finalize().as_bytes()
}

fn tag(mac_key: &[u8; BOND_KEY_BYTES], domain: &[u8], host_id: &[u8; 32], phone_pubkey: &[u8; PHONE_PUBKEY_BYTES]) -> [u8; PAIR_TAG_BYTES] {
    let mut message = Vec::with_capacity(domain.len() + 32 + PHONE_PUBKEY_BYTES);
    message.extend_from_slice(domain);
    message.extend_from_slice(host_id);
    message.extend_from_slice(phone_pubkey);
    *blake3::keyed_hash(mac_key, &message).as_bytes()
}

/// Encode the phone's pairing request.
#[must_use]
pub fn encode_pair_request(
    secret: &[u8; 32],
    host_id: &[u8; 32],
    phone_pubkey: &[u8; PHONE_PUBKEY_BYTES],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(PAIR_REQUEST_LEN);
    out.extend_from_slice(&PAIR_REQUEST_MAGIC);
    out.extend_from_slice(phone_pubkey);
    out.extend_from_slice(&tag(secret, PAIR_REQUEST_DOMAIN, host_id, phone_pubkey));
    out
}

/// Verify a phone's pairing request and return its public key.
///
/// # Errors
///
/// [`PairError::Malformed`] for a bad record, [`PairError::TagMismatch`] when the
/// secret does not match, [`PairError::EmptyPublicKey`] for an all-zero key.
pub fn verify_pair_request(
    bytes: &[u8],
    secret: &[u8; 32],
    host_id: &[u8; 32],
) -> Result<[u8; PHONE_PUBKEY_BYTES], PairError> {
    if bytes.len() != PAIR_REQUEST_LEN {
        return Err(PairError::Malformed {
            reason: format!("request has {} bytes, expected {PAIR_REQUEST_LEN}", bytes.len()),
        });
    }
    if bytes[..4] != PAIR_REQUEST_MAGIC {
        return Err(PairError::Malformed {
            reason: "request magic mismatch".to_owned(),
        });
    }
    let mut phone_pubkey = [0u8; PHONE_PUBKEY_BYTES];
    phone_pubkey.copy_from_slice(&bytes[4..4 + PHONE_PUBKEY_BYTES]);
    let mut got = [0u8; PAIR_TAG_BYTES];
    got.copy_from_slice(&bytes[4 + PHONE_PUBKEY_BYTES..]);
    let expected = tag(secret, PAIR_REQUEST_DOMAIN, host_id, &phone_pubkey);
    if expected.ct_eq(&got).unwrap_u8() != 1 {
        return Err(PairError::TagMismatch);
    }
    if phone_pubkey == [0u8; PHONE_PUBKEY_BYTES] {
        return Err(PairError::EmptyPublicKey);
    }
    Ok(phone_pubkey)
}

/// Encode the desktop's acceptance.
#[must_use]
pub fn encode_pair_accept(
    secret: &[u8; 32],
    host_id: &[u8; 32],
    phone_pubkey: &[u8; PHONE_PUBKEY_BYTES],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(PAIR_ACCEPT_LEN);
    out.extend_from_slice(&PAIR_ACCEPT_MAGIC);
    out.extend_from_slice(&tag(secret, PAIR_ACCEPT_DOMAIN, host_id, phone_pubkey));
    out
}

/// Verify the desktop's acceptance.
///
/// # Errors
///
/// [`PairError::Malformed`] for a bad record, [`PairError::TagMismatch`] when the
/// desktop did not hold the secret we scanned.
pub fn verify_pair_accept(
    bytes: &[u8],
    secret: &[u8; 32],
    host_id: &[u8; 32],
    phone_pubkey: &[u8; PHONE_PUBKEY_BYTES],
) -> Result<(), PairError> {
    if bytes.len() != PAIR_ACCEPT_LEN {
        return Err(PairError::Malformed {
            reason: format!("accept has {} bytes, expected {PAIR_ACCEPT_LEN}", bytes.len()),
        });
    }
    if bytes[..4] != PAIR_ACCEPT_MAGIC {
        return Err(PairError::Malformed {
            reason: "accept magic mismatch".to_owned(),
        });
    }
    let mut got = [0u8; PAIR_TAG_BYTES];
    got.copy_from_slice(&bytes[4..]);
    let expected = tag(secret, PAIR_ACCEPT_DOMAIN, host_id, phone_pubkey);
    if expected.ct_eq(&got).unwrap_u8() != 1 {
        return Err(PairError::TagMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: [u8; 32] = [0x11; 32];
    const SECRET: [u8; 32] = [0x44; 32];

    const PHONE: [u8; PHONE_PUBKEY_BYTES] = [0x22; PHONE_PUBKEY_BYTES];

    fn phone_key() -> [u8; PHONE_PUBKEY_BYTES] {
        PHONE
    }

    #[test]
    fn the_request_round_trips_and_yields_the_phone_key() {
        let phone = phone_key();
        let bytes = encode_pair_request(&SECRET, &HOST, &phone);
        assert_eq!(bytes.len(), PAIR_REQUEST_LEN);
        assert_eq!(verify_pair_request(&bytes, &SECRET, &HOST).expect("verify"), phone);
    }

    #[test]
    fn both_sides_derive_the_same_bond() {
        let phone = phone_key();
        // The desktop derives after verifying; the phone derives locally.
        let verified = verify_pair_request(&encode_pair_request(&SECRET, &HOST, &phone), &SECRET, &HOST).expect("verify");
        let desktop = derive_qr_bond_key(&SECRET, &HOST, &verified);
        let phone_side = derive_qr_bond_key(&SECRET, &HOST, &phone);
        assert_eq!(desktop, phone_side);
    }

    #[test]
    fn the_bond_depends_on_secret_host_and_phone_key() {
        let phone = phone_key();
        let base = derive_qr_bond_key(&SECRET, &HOST, &phone);
        assert_ne!(base, derive_qr_bond_key(&[0x45; 32], &HOST, &phone), "secret");
        assert_ne!(base, derive_qr_bond_key(&SECRET, &[0x12; 32], &phone), "host");
        assert_ne!(base, derive_qr_bond_key(&SECRET, &HOST, &[0x23; PHONE_PUBKEY_BYTES]), "phone key");
    }

    #[test]
    fn a_request_for_another_secret_or_host_is_refused() {
        let phone = phone_key();
        let bytes = encode_pair_request(&SECRET, &HOST, &phone);
        assert!(matches!(
            verify_pair_request(&bytes, &[0x45; 32], &HOST),
            Err(PairError::TagMismatch)
        ));
        assert!(matches!(
            verify_pair_request(&bytes, &SECRET, &[0x12; 32]),
            Err(PairError::TagMismatch)
        ));
    }

    #[test]
    fn the_acceptance_proves_the_desktop_held_the_secret() {
        let phone = phone_key();
        let accept = encode_pair_accept(&SECRET, &HOST, &phone);
        assert!(verify_pair_accept(&accept, &SECRET, &HOST, &phone).is_ok());
        // A desktop that only forwarded the request cannot produce this.
        assert!(matches!(
            verify_pair_accept(&accept, &[0x45; 32], &HOST, &phone),
            Err(PairError::TagMismatch)
        ));
        // Nor can it answer for a different phone key.
        assert!(matches!(
            verify_pair_accept(&accept, &SECRET, &HOST, &[0x23; PHONE_PUBKEY_BYTES]),
            Err(PairError::TagMismatch)
        ));
    }

    #[test]
    fn request_and_accept_tags_are_not_interchangeable() {
        let phone = phone_key();
        let request_tag = &encode_pair_request(&SECRET, &HOST, &phone)[4 + PHONE_PUBKEY_BYTES..];
        let accept_tag = &encode_pair_accept(&SECRET, &HOST, &phone)[4..];
        assert_ne!(request_tag, accept_tag, "domain separation");
    }

    #[test]
    fn garbage_records_are_refused_without_panicking() {
        let phone = phone_key();
        let request = encode_pair_request(&SECRET, &HOST, &phone);
        for cut in 0..request.len() {
            let _ = verify_pair_request(&request[..cut], &SECRET, &HOST);
        }
        assert!(matches!(
            verify_pair_request(&[0u8; PAIR_REQUEST_LEN], &SECRET, &HOST),
            Err(PairError::Malformed { .. })
        ));
        assert!(matches!(
            verify_pair_accept(&[0u8; PAIR_ACCEPT_LEN], &SECRET, &HOST, &phone),
            Err(PairError::Malformed { .. })
        ));
    }

    #[test]
    fn an_all_zero_phone_key_is_refused() {
        let bytes = encode_pair_request(&SECRET, &HOST, &[0u8; PHONE_PUBKEY_BYTES]);
        assert!(matches!(
            verify_pair_request(&bytes, &SECRET, &HOST),
            Err(PairError::EmptyPublicKey)
        ));
    }
}
