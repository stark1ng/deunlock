//! P-256 ECDH key agreement for the v2 pairing flow.
//!
//! ## Why this module exists
//!
//! v1 derived the bond key as `HKDF-SHA256(host_pub || phone_pub)` — two
//! *public* values that travel over the pairing channel and sit in the bond
//! store. Anyone who watched a pairing could recompute the key, so the
//! challenge MAC authenticated nothing and the rotating session UUID was
//! reversible (AUDIT-001 D-01).
//!
//! v2 replaces it with a real elliptic-curve Diffie-Hellman secret:
//!
//! ```text
//! shared     = ECDH(P-256, my_secret, peer_public)          // 32 bytes, secret
//! bond_key   = HKDF-SHA256(salt = pairing_nonce,           // 32 bytes, secret
//!                          ikm  = shared,
//!                          info = "deunlock-bond-v2" || host_id || phone_id,
//!                          len  = 32)
//! mac_key    = HKDF-SHA256(salt = none, ikm = bond_key,
//!                          info = "deunlock-auth-mac-v2", len = 32)
//! ```
//!
//! The identity binding (`host_id || phone_id`) and the fresh
//! `pairing_nonce` prevent a shared secret produced for one pairing from
//! being replayed as the bond key of another. Key separation (`bond_key`
//! vs `mac_key`) keeps the same secret from keying two primitives.
//!
//! ## Curve choice
//!
//! P-256, not X25519: the phone half must be able to hold the private key in
//! the Android Keystore, which supports EC key agreement
//! (`PURPOSE_AGREE_KEY`, API 31+) but not X25519 on every device. P-256 is
//! the intersection that works on the whole supported range (Android 13+).
//!
//! The phone half is *not* required to be hardware-backed for the protocol
//! to hold — a compromised ECDH key still cannot sign a challenge, because
//! the signing key is separate and biometric-gated. Hardware backing the
//! agreement key is defence in depth, not the trust anchor.

use hkdf::Hkdf;
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use rand_core::OsRng;
use sha2::Sha256;
use zeroize::Zeroizing;

/// HKDF `info` prefix for the v2 bond-key derivation.
pub const KEX_INFO_V2: &[u8] = b"deunlock-bond-v2";

/// HKDF `info` for the key-separated challenge-MAC key.
pub const AUTH_MAC_KEY_INFO_V2: &[u8] = b"deunlock-auth-mac-v2";

/// Length of the derived bond key, in bytes.
pub const BOND_KEY_V2_BYTES: usize = 32;

/// Length of the derived challenge-MAC key, in bytes.
pub const AUTH_MAC_KEY_BYTES: usize = 32;

/// Length of a SEC1 **uncompressed** P-256 public key (`0x04 || X || Y`).
pub const SEC1_PUBKEY_LEN: usize = 65;

/// Length of the per-pairing random nonce that salts the derivation.
pub const PAIRING_NONCE_LEN: usize = 32;

/// Length of the raw ECDH shared secret (the X coordinate).
pub const SHARED_SECRET_LEN: usize = 32;

/// Errors from the key-agreement layer.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KexError {
    /// The peer's public key was not the expected 65-byte SEC1 form.
    #[error("peer public key must be an uncompressed SEC1 point ({SEC1_PUBKEY_LEN} bytes)")]
    WrongPeerKeyLength,
    /// The peer's public key was the right length but not a valid curve point.
    #[error("peer public key is not a valid P-256 point")]
    InvalidPeerKey,
    /// HKDF expansion failed (only possible for absurd output lengths).
    #[error("hkdf expand failed")]
    Hkdf,
}

/// A P-256 key agreement secret held by one side of the pairing.
///
/// The secret is zeroized on drop. It is deliberately not `Clone`: a second
/// copy of a long-term agreement key is a footgun, and pairing needs exactly
/// one.
pub struct PairingSecret {
    inner: SecretKey,
}

impl PairingSecret {
    /// Generate a fresh secret with the operating system CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        Self {
            inner: SecretKey::random(&mut OsRng),
        }
    }

    /// Return the matching public key as an uncompressed SEC1 point.
    #[must_use]
    pub fn public_sec1(&self) -> [u8; SEC1_PUBKEY_LEN] {
        let encoded = self.inner.public_key().to_encoded_point(false);
        let mut out = [0u8; SEC1_PUBKEY_LEN];
        out.copy_from_slice(encoded.as_bytes());
        out
    }

    /// Compute the ECDH shared secret against the peer's SEC1 public key.
    ///
    /// # Errors
    ///
    /// Returns [`KexError::WrongPeerKeyLength`] for a wrong-length key and
    /// [`KexError::InvalidPeerKey`] for bytes that are not a curve point.
    pub fn agree(&self, peer_sec1: &[u8]) -> Result<Zeroizing<[u8; SHARED_SECRET_LEN]>, KexError> {
        if peer_sec1.len() != SEC1_PUBKEY_LEN {
            return Err(KexError::WrongPeerKeyLength);
        }
        let peer = PublicKey::from_sec1_bytes(peer_sec1).map_err(|_| KexError::InvalidPeerKey)?;
        let shared = diffie_hellman(self.inner.to_nonzero_scalar(), peer.as_affine());
        let mut out = [0u8; SHARED_SECRET_LEN];
        out.copy_from_slice(shared.raw_secret_bytes().as_slice());
        Ok(Zeroizing::new(out))
    }
}

impl core::fmt::Debug for PairingSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never render key material, not even in a panic message.
        f.write_str("PairingSecret(<redacted>)")
    }
}

/// Derive the 32-byte v2 bond key from an ECDH shared secret.
///
/// Binds the key to both device identities and to the pairing event through
/// `pairing_nonce`.
///
/// # Errors
///
/// [`KexError::Hkdf`] if the expand step fails (not reachable for 32 bytes).
pub fn derive_bond_key_v2(
    shared: &[u8; SHARED_SECRET_LEN],
    pairing_nonce: &[u8; PAIRING_NONCE_LEN],
    host_id: &[u8; BOND_KEY_V2_BYTES],
    phone_id: &[u8; BOND_KEY_V2_BYTES],
) -> Result<[u8; BOND_KEY_V2_BYTES], KexError> {
    let mut info = Vec::with_capacity(KEX_INFO_V2.len() + 2 * BOND_KEY_V2_BYTES);
    info.extend_from_slice(KEX_INFO_V2);
    info.extend_from_slice(host_id);
    info.extend_from_slice(phone_id);
    let hk = Hkdf::<Sha256>::new(Some(pairing_nonce), shared);
    let mut out = [0u8; BOND_KEY_V2_BYTES];
    hk.expand(&info, &mut out).map_err(|_| KexError::Hkdf)?;
    Ok(out)
}

/// Derive the challenge-MAC key from the bond key (key separation).
///
/// # Panics
///
/// Never: the output length is a compile-time constant well inside the HKDF
/// limit, so the only failure the crate reports cannot occur here.
#[must_use]
pub fn derive_auth_mac_key(bond_key: &[u8; BOND_KEY_V2_BYTES]) -> [u8; AUTH_MAC_KEY_BYTES] {
    let hk = Hkdf::<Sha256>::new(None, bond_key);
    let mut out = [0u8; AUTH_MAC_KEY_BYTES];
    if hk.expand(AUTH_MAC_KEY_INFO_V2, &mut out).is_err() {
        // Unreachable for a 32-byte output; keep the type honest without
        // panicking inside an authentication path.
        out = [0u8; AUTH_MAC_KEY_BYTES];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bond::bond_key_from_pubkeys;

    fn ids() -> ([u8; 32], [u8; 32], [u8; 32]) {
        ([0x11u8; 32], [0x22u8; 32], [0x33u8; 32])
    }

    #[test]
    fn both_sides_derive_the_same_bond_key() {
        let host = PairingSecret::generate();
        let phone = PairingSecret::generate();
        let (host_id, phone_id, nonce) = ids();

        let host_shared = host.agree(&phone.public_sec1()).expect("host agree");
        let phone_shared = phone.agree(&host.public_sec1()).expect("phone agree");
        assert_eq!(*host_shared, *phone_shared, "ECDH must agree");

        let a = derive_bond_key_v2(&host_shared, &nonce, &host_id, &phone_id).expect("key");
        let b = derive_bond_key_v2(&phone_shared, &nonce, &host_id, &phone_id).expect("key");
        assert_eq!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn bond_key_is_bound_to_both_identities() {
        let host = PairingSecret::generate();
        let phone = PairingSecret::generate();
        let (host_id, phone_id, nonce) = ids();
        let shared = host.agree(&phone.public_sec1()).expect("agree");

        let base = derive_bond_key_v2(&shared, &nonce, &host_id, &phone_id).expect("key");

        let mut other_host = host_id;
        other_host[0] ^= 0x01;
        assert_ne!(
            base,
            derive_bond_key_v2(&shared, &nonce, &other_host, &phone_id).expect("key"),
            "a different host identity must not reuse the bond key"
        );

        let mut other_phone = phone_id;
        other_phone[0] ^= 0x01;
        assert_ne!(base, derive_bond_key_v2(&shared, &nonce, &host_id, &other_phone).expect("key"));
    }

    #[test]
    fn bond_key_is_bound_to_the_pairing_nonce() {
        let host = PairingSecret::generate();
        let phone = PairingSecret::generate();
        let (host_id, phone_id, nonce) = ids();
        let shared = host.agree(&phone.public_sec1()).expect("agree");

        let mut other_nonce = nonce;
        other_nonce[31] ^= 0x80;
        assert_ne!(
            derive_bond_key_v2(&shared, &nonce, &host_id, &phone_id).expect("key"),
            derive_bond_key_v2(&shared, &other_nonce, &host_id, &phone_id).expect("key"),
            "the pairing nonce must salt the derivation"
        );
    }

    /// A pairing MITM can only complete against a *different* shared secret.
    /// Both legs then derive different bond keys, which the SAS comparison
    /// (4-word / 6-digit code) surfaces to the operator.
    #[test]
    fn man_in_the_middle_legs_diverge() {
        let host = PairingSecret::generate();
        let phone = PairingSecret::generate();
        let mitm = PairingSecret::generate();
        let (host_id, phone_id, nonce) = ids();

        let host_leg = host.agree(&mitm.public_sec1()).expect("host-mitm");
        let mitm_to_phone = mitm.agree(&host.public_sec1()).expect("mitm-host");
        let phone_leg = phone.agree(&mitm.public_sec1()).expect("phone-mitm");
        let mitm_to_host = mitm.agree(&phone.public_sec1()).expect("mitm-phone");

        let host_key = derive_bond_key_v2(&host_leg, &nonce, &host_id, &phone_id).expect("key");
        let host_key_remote = derive_bond_key_v2(&mitm_to_phone, &nonce, &host_id, &phone_id).expect("key");
        let phone_key = derive_bond_key_v2(&phone_leg, &nonce, &host_id, &phone_id).expect("key");
        let phone_key_remote = derive_bond_key_v2(&mitm_to_host, &nonce, &host_id, &phone_id).expect("key");

        // Each side agrees with the MITM, but the two ends disagree.
        assert_eq!(host_key, host_key_remote);
        assert_eq!(phone_key, phone_key_remote);
        assert_ne!(host_key, phone_key, "MITM legs must derive different keys");
    }

    /// Regression for AUDIT-001 D-01: the v2 key must not equal the v1 key,
    /// which was computable from public inputs alone.
    #[test]
    fn v2_key_differs_from_the_public_input_v1_key() {
        let host = PairingSecret::generate();
        let phone = PairingSecret::generate();
        let (host_id, phone_id, nonce) = ids();
        let shared = host.agree(&phone.public_sec1()).expect("agree");

        let v2 = derive_bond_key_v2(&shared, &nonce, &host_id, &phone_id).expect("key");
        let v1 = bond_key_from_pubkeys(
            &host.public_sec1()[1..33].try_into().unwrap(),
            &phone.public_sec1()[1..33].try_into().unwrap(),
        );
        assert_ne!(v2, v1);
    }

    #[test]
    fn wrong_length_peer_key_is_typed() {
        let host = PairingSecret::generate();
        assert_eq!(host.agree(&[0u8; 64]).unwrap_err(), KexError::WrongPeerKeyLength);
    }

    #[test]
    fn non_point_peer_key_is_typed() {
        let host = PairingSecret::generate();
        let bogus = [0xFFu8; SEC1_PUBKEY_LEN];
        assert_eq!(host.agree(&bogus).unwrap_err(), KexError::InvalidPeerKey);
    }

    #[test]
    fn mac_key_is_separated_from_the_bond_key() {
        let host = PairingSecret::generate();
        let phone = PairingSecret::generate();
        let (host_id, phone_id, nonce) = ids();
        let shared = host.agree(&phone.public_sec1()).expect("agree");
        let bond = derive_bond_key_v2(&shared, &nonce, &host_id, &phone_id).expect("key");
        let mac = derive_auth_mac_key(&bond);
        assert_ne!(bond, mac);
        assert_ne!(mac, [0u8; 32]);
    }

    #[test]
    fn debug_never_prints_key_material() {
        let secret = PairingSecret::generate();
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "PairingSecret(<redacted>)");
    }
}
