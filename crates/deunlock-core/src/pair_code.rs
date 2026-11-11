//! Pairing over BLE with a code the operator reads off the desktop.
//!
//! The first bond used to be derived from `(host_pubkey, phone_pubkey)` — two
//! public values that both cross the air during pairing. Anyone who watched the
//! exchange (or simply knew both keys, since `peer_id` is public by construction)
//! could compute the same bond key, and the desktop had no way to tell the
//! difference: the pair service was open to any phone, at any time, with no
//! operator in the loop (AUDIT-001 D-08).
//!
//! This module puts a secret that never crosses the air in the middle of it. The
//! operator runs `deunlock pair-code`, reads ten characters, and types them into
//! the phone. The phone then proposes a full 256-bit bond key and proves it was
//! given the code by tagging `(host_pubkey, phone_pubkey, bond)` under a key
//! derived from the code. The desktop verifies, and only then writes the bond.
//!
//! The division of labour matters: the code authenticates the handshake and
//! nothing else. It is fifty bits, enough for a single-use, expiring,
//! attempt-limited gesture and far too little for a long-lived key — so the bond
//! itself is random, generated on the phone, and travels once inside the
//! LESC-encrypted link.
//!
//! Ten characters of Crockford base32 is 50 bits, and the alphabet leaves out
//! `I`, `L`, `O` and `U` so a code read off a screen survives being typed.

use blake3::Hasher;

/// Characters of a readable pairing code.
pub const PAIR_CODE_LEN: usize = 10;

/// Magic prefix on the phone's pair write.
pub const PAIR_CODE_MAGIC: &[u8; 5] = b"DLPB1";

/// Bytes of a bond key.
pub const PAIR_BOND_BYTES: usize = 32;

/// `magic ‖ phone_pubkey[32] ‖ tag[32] ‖ bond[32]`.
pub const PAIR_CODE_FRAME_LEN: usize = 5 + 32 + 32 + PAIR_BOND_BYTES;

/// Crockford base32: no `I`, `L`, `O` or `U`.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// KDF context for the tag key derived from a code.
const TAG_CONTEXT: &str = "deunlock pair code tag v2";

/// Why a pairing code - or the write that presents one - was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PairCodeError {
    /// The code has the wrong length or contains a character outside the
    /// alphabet.
    #[error("malformed pairing code: {reason}")]
    Malformed {
        /// Which part of the code was wrong.
        reason: String,
    },

    /// A pair write arrived in the old 32-byte shape, which carries no proof of a
    /// secret.
    #[error("pair write carries no code proof (legacy 32-byte form is not accepted)")]
    NoCodeProof,

    /// The write did not have the framing this build expects.
    #[error("pair write of {got} bytes does not match the expected {expected}")]
    BadFrameLength {
        /// Bytes expected.
        expected: usize,
        /// Bytes received.
        got: usize,
    },
}

/// Render `bytes` (32) as a pairing code.
///
/// The first 50 bits of the input become ten characters, so the code is a
/// faithful, checkable projection of whatever secret the offer holds.
#[must_use]
pub fn render_code(bytes: &[u8; 32]) -> String {
    let mut bits = 0u64;
    for b in bytes.iter().take(7) {
        bits = (bits << 8) | u64::from(*b);
    }
    // 7 bytes = 56 bits; keep the top 50 so every character has 5 bits.
    let bits = bits >> 6;
    let mut out = String::with_capacity(PAIR_CODE_LEN);
    for i in (0..PAIR_CODE_LEN).rev() {
        let idx = usize::try_from((bits >> (i * 5)) & 0x1f).unwrap_or(0);
        out.push(char::from(ALPHABET[idx]));
    }
    out
}

/// Normalise what a human typed: upper-case, drop separators, apply the
/// Crockford equivalences (`I`/`L` → `1`, `O` → `0`).
///
/// # Errors
///
/// [`PairCodeError::Malformed`] on the wrong length or a character that is not in
/// the alphabet after normalisation.
pub fn normalise_code(input: &str) -> Result<String, PairCodeError> {
    let mut out = String::with_capacity(PAIR_CODE_LEN);
    for ch in input.chars() {
        if ch.is_whitespace() || ch == '-' || ch == '.' {
            continue;
        }
        let up = ch.to_ascii_uppercase();
        let mapped = match up {
            'I' | 'L' => '1',
            'O' => '0',
            other => other,
        };
        if !ALPHABET.contains(&u8::try_from(mapped).unwrap_or(0)) {
            return Err(PairCodeError::Malformed {
                reason: format!("character '{ch}' is not part of a pairing code"),
            });
        }
        out.push(mapped);
    }
    if out.len() != PAIR_CODE_LEN {
        return Err(PairCodeError::Malformed {
            reason: format!("expected {PAIR_CODE_LEN} characters, got {}", out.len()),
        });
    }
    Ok(out)
}

/// The tag a phone sends to prove it was given the code.
///
/// The proposed bond is part of the input, so an attacker who relays a genuine
/// write cannot substitute a bond of their own.
///
/// # Errors
///
/// [`PairCodeError::Malformed`] if `code` is not a pairing code.
pub fn pair_code_tag(
    code: &str,
    host_pubkey: &[u8; 32],
    phone_pubkey: &[u8; 32],
    bond: &[u8; PAIR_BOND_BYTES],
) -> Result<[u8; 32], PairCodeError> {
    let code = normalise_code(code)?;
    let mut hasher = Hasher::new_derive_key(TAG_CONTEXT);
    hasher.update(code.as_bytes());
    hasher.update(host_pubkey);
    hasher.update(phone_pubkey);
    hasher.update(bond);
    Ok(*hasher.finalize().as_bytes())
}

/// Constant-time tag comparison. A plain `==` on 32 bytes is a timing oracle in
/// principle; the cost of doing it properly here is nothing.
#[must_use]
pub fn tags_equal(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// What a phone wrote to the pair characteristic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairWrite {
    /// The phone's Ed25519 public key.
    pub phone_pubkey: [u8; 32],
    /// Proof that the phone was given the operator's code.
    pub tag: [u8; 32],
    /// The bond key the phone proposes.
    pub bond: [u8; PAIR_BOND_BYTES],
}

impl PairWrite {
    /// Encode for the wire.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PAIR_CODE_FRAME_LEN);
        out.extend_from_slice(PAIR_CODE_MAGIC);
        out.extend_from_slice(&self.phone_pubkey);
        out.extend_from_slice(&self.tag);
        out.extend_from_slice(&self.bond);
        out
    }

    /// Decode a phone's write.
    ///
    /// # Errors
    ///
    /// [`PairCodeError::NoCodeProof`] for the legacy 32-byte write, which is the
    /// shape this change exists to refuse; [`PairCodeError::BadFrameLength`] for
    /// anything else that is not [`PAIR_CODE_FRAME_LEN`] bytes starting with the
    /// magic.
    pub fn decode(bytes: &[u8]) -> Result<Self, PairCodeError> {
        if bytes.len() == 32 {
            return Err(PairCodeError::NoCodeProof);
        }
        if bytes.len() != PAIR_CODE_FRAME_LEN || !bytes.starts_with(PAIR_CODE_MAGIC) {
            return Err(PairCodeError::BadFrameLength {
                expected: PAIR_CODE_FRAME_LEN,
                got: bytes.len(),
            });
        }
        let mut phone_pubkey = [0u8; 32];
        phone_pubkey.copy_from_slice(&bytes[5..37]);
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&bytes[37..69]);
        let mut bond = [0u8; PAIR_BOND_BYTES];
        bond.copy_from_slice(&bytes[69..101]);
        Ok(Self {
            phone_pubkey,
            tag,
            bond,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pubkey(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn render_is_ten_chars_of_the_alphabet() {
        let code = render_code(&[0xab; 32]);
        assert_eq!(code.len(), PAIR_CODE_LEN);
        assert!(code.bytes().all(|b| ALPHABET.contains(&b)));
    }

    #[test]
    fn render_is_deterministic_and_distinct() {
        assert_eq!(render_code(&[1u8; 32]), render_code(&[1u8; 32]));
        assert_ne!(render_code(&[1u8; 32]), render_code(&[2u8; 32]));
    }

    #[test]
    fn normalise_accepts_what_a_human_types() {
        let code = render_code(&[0x5a; 32]);
        let spaced = format!("{} {}", &code[..5], &code[5..]).to_lowercase();
        assert_eq!(normalise_code(&spaced).unwrap(), code);
    }

    #[test]
    fn normalise_applies_crockford_equivalences() {
        let code = render_code(&[0x33; 32]);
        for (from, to) in [('I', '1'), ('L', '1'), ('O', '0')] {
            let mut chars: Vec<char> = code.chars().collect();
            chars[0] = from;
            let typed: String = chars.iter().collect();
            let expected: String = std::iter::once(to).chain(code.chars().skip(1)).collect();
            assert_eq!(normalise_code(&typed).unwrap(), expected);
        }
    }

    #[test]
    fn normalise_refuses_short_long_and_foreign() {
        assert!(matches!(
            normalise_code("ABC"),
            Err(PairCodeError::Malformed { .. })
        ));
        assert!(matches!(
            normalise_code("01234567890"),
            Err(PairCodeError::Malformed { .. })
        ));
        // `U` is the one letter Crockford leaves out; `Q` is in the alphabet.
        assert!(matches!(
            normalise_code("012345678U"),
            Err(PairCodeError::Malformed { .. })
        ));
    }

    #[test]
    fn tag_verifies_only_for_the_same_code_keys_and_bond() {
        let code = render_code(&[7u8; 32]);
        let host = pubkey(0x11);
        let phone = pubkey(0x22);
        let bond = [0x55u8; PAIR_BOND_BYTES];
        let tag = pair_code_tag(&code, &host, &phone, &bond).unwrap();
        assert!(tags_equal(
            &tag,
            &pair_code_tag(&code, &host, &phone, &bond).unwrap()
        ));
        let other = render_code(&[8u8; 32]);
        assert!(!tags_equal(
            &tag,
            &pair_code_tag(&other, &host, &phone, &bond).unwrap()
        ));
        assert!(!tags_equal(
            &tag,
            &pair_code_tag(&code, &pubkey(0x33), &phone, &bond).unwrap()
        ));
        assert!(!tags_equal(
            &tag,
            &pair_code_tag(&code, &host, &pubkey(0x44), &bond).unwrap()
        ));
        // A relayed write with a substituted bond must not verify.
        assert!(!tags_equal(
            &tag,
            &pair_code_tag(&code, &host, &phone, &[0x66u8; PAIR_BOND_BYTES]).unwrap()
        ));
    }

    #[test]
    fn pair_write_round_trips() {
        let write = PairWrite {
            phone_pubkey: pubkey(0x5c),
            tag: [0x77; 32],
            bond: [0x88; PAIR_BOND_BYTES],
        };
        let bytes = write.encode();
        assert_eq!(bytes.len(), PAIR_CODE_FRAME_LEN);
        assert_eq!(PairWrite::decode(&bytes).unwrap(), write);
    }

    #[test]
    fn the_legacy_pubkey_only_write_is_refused() {
        assert!(matches!(
            PairWrite::decode(&[0u8; 32]),
            Err(PairCodeError::NoCodeProof)
        ));
    }

    #[test]
    fn truncated_and_foreign_writes_are_refused() {
        let mut bytes = PairWrite {
            phone_pubkey: pubkey(1),
            tag: [2u8; 32],
            bond: [3u8; PAIR_BOND_BYTES],
        }
        .encode();
        bytes.pop();
        assert!(matches!(
            PairWrite::decode(&bytes),
            Err(PairCodeError::BadFrameLength { .. })
        ));
        let mut foreign = PairWrite {
            phone_pubkey: pubkey(1),
            tag: [2u8; 32],
            bond: [3u8; PAIR_BOND_BYTES],
        }
        .encode();
        foreign[0] = b'X';
        assert!(matches!(
            PairWrite::decode(&foreign),
            Err(PairCodeError::BadFrameLength { .. })
        ));
    }
}
