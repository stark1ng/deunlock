//! The LAN session hello: the phone proving which bond it holds, bound to one
//! live TLS session.
//!
//! This lives in `deunlock-core` rather than in the transport crate because it
//! is a *protocol* message: the desktop writes it in one language and the phone
//! writes it in another, and the two must agree byte for byte. One
//! implementation, with a layout asserted in tests, is the only way to be sure
//! the phone's hello verifies here.
//!
//! ## Why a server nonce and not a TLS exporter
//!
//! The obvious binding is TLS 1.3 keying material exported per session. Android's
//! `SSLSocket` exposes no exporter API (`SSLSession.exportKeyingMaterial` is a
//! JDK 24 addition, absent from Android), so a protocol built on it could not be
//! implemented on the phone at all. Instead the **desktop speaks first** inside
//! the already-authenticated tunnel:
//!
//! ```text
//! desktop → "DLS1" ‖ session_nonce[32]
//! phone   → "DLH1" ‖ host_id[32] ‖ peer_id[32] ‖ session_nonce[32] ‖ tag[32]
//! tag = BLAKE3_keyed(derive_auth_mac_key(bond), "deunlock-lan-hello-v1" ‖ host_id ‖ peer_id ‖ session_nonce)
//! ```
//!
//! The nonce is fresh per connection and unpredictable, so a hello recorded from
//! one session cannot be replayed onto another: the tag stops it before any
//! challenge exists. The phone needs no exporter — only a byte buffer.

use subtle::ConstantTimeEq as _;

use crate::kex::derive_auth_mac_key;
use crate::mac::BOND_KEY_BYTES;

/// Magic of the desktop's session-challenge record.
pub const SESSION_CHALLENGE_MAGIC: [u8; 4] = *b"DLS1";

/// Magic of the phone's hello record.
pub const HELLO_MAGIC: [u8; 4] = *b"DLH1";

/// Domain separator for the hello tag.
pub const HELLO_DOMAIN: &[u8] = b"deunlock-lan-hello-v1";

/// Length of the per-session nonce the desktop sends.
pub const SESSION_NONCE_BYTES: usize = 32;

/// Length of a phone's peer id.
pub const PEER_ID_BYTES: usize = 32;

/// Length of the hello tag.
pub const HELLO_TAG_BYTES: usize = 32;

/// Total length of an encoded hello.
pub const HELLO_LEN: usize = HELLO_MAGIC.len() + 32 + PEER_ID_BYTES + SESSION_NONCE_BYTES + HELLO_TAG_BYTES;

/// Total length of the desktop's session-challenge record.
pub const SESSION_CHALLENGE_LEN: usize = SESSION_CHALLENGE_MAGIC.len() + SESSION_NONCE_BYTES;

/// Byte offsets inside an encoded hello. Asserted in tests so a layout change
/// cannot pass silently while the phone still writes the old one.
pub mod offsets {
    /// Start of `host_id`.
    pub const HOST_ID: usize = 4;
    /// Start of `peer_id`.
    pub const PEER_ID: usize = 36;
    /// Start of `session_nonce`.
    pub const SESSION_NONCE: usize = 68;
    /// Start of the tag.
    pub const TAG: usize = 100;
}

/// Why a hello record was rejected.
#[derive(Debug, thiserror::Error)]
pub enum HelloError {
    /// The record is not a hello: wrong length or magic.
    #[error("malformed hello: {reason}")]
    Malformed {
        /// What was wrong with it.
        reason: String,
    },

    /// The record is well-formed but does not belong to us, this session, or
    /// this bond.
    #[error("hello rejected: {reason}")]
    Mismatch {
        /// Which binding failed.
        reason: String,
    },
}

/// A verified hello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    /// Desktop the phone believes it is talking to.
    pub host_id: [u8; 32],
    /// Peer id of the calling phone.
    pub peer_id: [u8; PEER_ID_BYTES],
    /// Session nonce the tag covered.
    pub session_nonce: [u8; SESSION_NONCE_BYTES],
}

/// Encode the session challenge the desktop sends right after the handshake.
#[must_use]
pub fn encode_session_challenge(nonce: &[u8; SESSION_NONCE_BYTES]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SESSION_CHALLENGE_LEN);
    out.extend_from_slice(&SESSION_CHALLENGE_MAGIC);
    out.extend_from_slice(nonce);
    out
}

/// Parse a session-challenge record.
///
/// # Errors
///
/// [`HelloError::Malformed`] for the wrong length or magic.
pub fn decode_session_challenge(bytes: &[u8]) -> Result<[u8; SESSION_NONCE_BYTES], HelloError> {
    if bytes.len() != SESSION_CHALLENGE_LEN {
        return Err(HelloError::Malformed {
            reason: format!(
                "session challenge has {} bytes, expected {SESSION_CHALLENGE_LEN}",
                bytes.len()
            ),
        });
    }
    if bytes[..4] != SESSION_CHALLENGE_MAGIC {
        return Err(HelloError::Malformed {
            reason: "session challenge magic mismatch".to_owned(),
        });
    }
    let mut nonce = [0u8; SESSION_NONCE_BYTES];
    nonce.copy_from_slice(&bytes[4..]);
    Ok(nonce)
}

/// Compute the hello tag.
///
/// Every field is fixed width, so the concatenation is unambiguous without
/// length prefixes.
#[must_use]
pub fn hello_tag(
    mac_key: &[u8; BOND_KEY_BYTES],
    host_id: &[u8; 32],
    peer_id: &[u8; PEER_ID_BYTES],
    session_nonce: &[u8; SESSION_NONCE_BYTES],
) -> [u8; HELLO_TAG_BYTES] {
    let mut message = Vec::with_capacity(HELLO_DOMAIN.len() + 96);
    message.extend_from_slice(HELLO_DOMAIN);
    message.extend_from_slice(host_id);
    message.extend_from_slice(peer_id);
    message.extend_from_slice(session_nonce);
    // A full 32-byte tag: the hello is the only thing between an open TLS port
    // and the challenge channel, so it gets the whole digest rather than the
    // 16-byte truncation used for frame MACs.
    *blake3::keyed_hash(mac_key, &message).as_bytes()
}

/// Encode the hello a phone sends after receiving the session challenge.
///
/// The bond key is the raw bond (ECDH output); the MAC key is derived here so a
/// caller cannot accidentally tag with the wrong key.
#[must_use]
pub fn encode_hello(
    bond_key: &[u8; BOND_KEY_BYTES],
    host_id: &[u8; 32],
    peer_id: &[u8; PEER_ID_BYTES],
    session_nonce: &[u8; SESSION_NONCE_BYTES],
) -> Vec<u8> {
    let mac_key = derive_auth_mac_key(bond_key);
    let tag = hello_tag(&mac_key, host_id, peer_id, session_nonce);
    let mut out = Vec::with_capacity(HELLO_LEN);
    out.extend_from_slice(&HELLO_MAGIC);
    out.extend_from_slice(host_id);
    out.extend_from_slice(peer_id);
    out.extend_from_slice(session_nonce);
    out.extend_from_slice(&tag);
    out
}

/// Parse an encoded hello without checking the tag.
///
/// # Errors
///
/// [`HelloError::Malformed`] for the wrong length or magic.
pub fn decode_hello(bytes: &[u8]) -> Result<(Hello, [u8; HELLO_TAG_BYTES]), HelloError> {
    if bytes.len() != HELLO_LEN {
        return Err(HelloError::Malformed {
            reason: format!("hello has {} bytes, expected {HELLO_LEN}", bytes.len()),
        });
    }
    if bytes[..4] != HELLO_MAGIC {
        return Err(HelloError::Malformed {
            reason: "hello magic mismatch".to_owned(),
        });
    }
    let mut host_id = [0u8; 32];
    host_id.copy_from_slice(&bytes[offsets::HOST_ID..offsets::PEER_ID]);
    let mut peer_id = [0u8; PEER_ID_BYTES];
    peer_id.copy_from_slice(&bytes[offsets::PEER_ID..offsets::SESSION_NONCE]);
    let mut session_nonce = [0u8; SESSION_NONCE_BYTES];
    session_nonce.copy_from_slice(&bytes[offsets::SESSION_NONCE..offsets::TAG]);
    let mut tag = [0u8; HELLO_TAG_BYTES];
    tag.copy_from_slice(&bytes[offsets::TAG..HELLO_LEN]);
    Ok((
        Hello {
            host_id,
            peer_id,
            session_nonce,
        },
        tag,
    ))
}

/// Verify a hello for a known bond key and the nonce we sent this session.
///
/// # Errors
///
/// [`HelloError::Malformed`] for a bad record, [`HelloError::Mismatch`] for a
/// wrong host id, session nonce, or tag.
pub fn verify_hello(
    bytes: &[u8],
    bond_key: &[u8; BOND_KEY_BYTES],
    host_id: &[u8; 32],
    session_nonce: &[u8; SESSION_NONCE_BYTES],
) -> Result<Hello, HelloError> {
    let (hello, tag) = decode_hello(bytes)?;
    if &hello.host_id != host_id {
        return Err(HelloError::Mismatch {
            reason: "hello is addressed to a different host_id".to_owned(),
        });
    }
    if &hello.session_nonce != session_nonce {
        return Err(HelloError::Mismatch {
            reason: "hello answers a different session nonce".to_owned(),
        });
    }
    let mac_key = derive_auth_mac_key(bond_key);
    let expected = hello_tag(&mac_key, host_id, &hello.peer_id, session_nonce);
    if expected.ct_eq(&tag).unwrap_u8() != 1 {
        return Err(HelloError::Mismatch {
            reason: "hello tag did not verify".to_owned(),
        });
    }
    Ok(hello)
}

/// Hex-encode a peer id, matching the daemon's `<peer_id>.bin` file naming.
#[must_use]
pub fn peer_id_hex(peer_id: &[u8; PEER_ID_BYTES]) -> String {
    peer_id.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: [u8; 32] = [0x11; 32];
    const PEER: [u8; PEER_ID_BYTES] = [0x22; PEER_ID_BYTES];
    const BOND: [u8; BOND_KEY_BYTES] = [0x33; BOND_KEY_BYTES];
    const NONCE: [u8; SESSION_NONCE_BYTES] = [0x44; SESSION_NONCE_BYTES];

    #[test]
    fn the_layout_is_what_the_phone_writes() {
        let bytes = encode_hello(&BOND, &HOST, &PEER, &NONCE);
        assert_eq!(bytes.len(), HELLO_LEN);
        assert_eq!(&bytes[..4], &HELLO_MAGIC);
        assert_eq!(&bytes[offsets::HOST_ID..offsets::PEER_ID], &HOST);
        assert_eq!(&bytes[offsets::PEER_ID..offsets::SESSION_NONCE], &PEER);
        assert_eq!(&bytes[offsets::SESSION_NONCE..offsets::TAG], &NONCE);
    }

    #[test]
    fn a_hello_round_trips_and_verifies() {
        let bytes = encode_hello(&BOND, &HOST, &PEER, &NONCE);
        let hello = verify_hello(&bytes, &BOND, &HOST, &NONCE).expect("verify");
        assert_eq!(hello.peer_id, PEER);
    }

    #[test]
    fn every_bound_field_breaks_the_tag() {
        let bytes = encode_hello(&BOND, &HOST, &PEER, &NONCE);
        assert!(verify_hello(&bytes, &BOND, &[0x12; 32], &NONCE).is_err(), "host");
        assert!(
            verify_hello(&bytes, &BOND, &HOST, &[0x45; SESSION_NONCE_BYTES]).is_err(),
            "session nonce"
        );
        assert!(
            verify_hello(&bytes, &[0x34; BOND_KEY_BYTES], &HOST, &NONCE).is_err(),
            "bond"
        );
    }

    #[test]
    fn the_tag_is_not_a_bare_keyed_hash_of_the_fields() {
        // Guards against someone "simplifying" the tag by dropping the domain
        // separator: two messages that differ only by domain must not collide.
        let bytes = encode_hello(&BOND, &HOST, &PEER, &NONCE);
        let mac_key = derive_auth_mac_key(&BOND);
        let mut naive = Vec::new();
        naive.extend_from_slice(&HOST);
        naive.extend_from_slice(&PEER);
        naive.extend_from_slice(&NONCE);
        let naive_tag = *blake3::keyed_hash(&mac_key, &naive).as_bytes();
        assert_ne!(&bytes[offsets::TAG..], &naive_tag[..], "domain separation must matter");
    }

    #[test]
    fn the_session_challenge_round_trips() {
        let bytes = encode_session_challenge(&NONCE);
        assert_eq!(bytes.len(), SESSION_CHALLENGE_LEN);
        assert_eq!(decode_session_challenge(&bytes).expect("decode"), NONCE);
        assert!(decode_session_challenge(&bytes[..35]).is_err(), "short");
        assert!(
            decode_session_challenge(&[0u8; SESSION_CHALLENGE_LEN]).is_err(),
            "magic"
        );
    }

    #[test]
    fn garbage_is_refused() {
        assert!(decode_hello(&[]).is_err());
        assert!(decode_hello(&[0u8; HELLO_LEN]).is_err(), "wrong magic");
        assert!(decode_hello(&[0u8; HELLO_LEN - 1]).is_err(), "wrong length");
    }
}
