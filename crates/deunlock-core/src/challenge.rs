//! The v2 challenge payload: everything the phone needs to decide *what* it
//! is approving, carried inside a [`crate::frame::Frame`] of version
//! [`crate::frame::DEUNLOCK_WIRE_VERSION_V2`].
//!
//! ## Layout
//!
//! ```text
//! "DLC2"                        magic, 4 bytes
//! || host_id[32]                which desktop is asking
//! || u16be(service_len) || service
//! || u16be(user_len)    || user
//! || nonce[16]                  the per-request nonce
//! || u64be(issued_at)           unix seconds
//! ```
//!
//! The frame's own `tag` field is the transcript MAC from
//! [`crate::transcript::AuthTranscript::tag`] — there is exactly one MAC per
//! challenge, computed over the transcript, not over the frame body. That
//! keeps the thing the phone verifies byte-identical to the thing it signs.
//!
//! ## Why the nonce appears twice
//!
//! It is in the frame header *and* in the payload. The header copy feeds the
//! replay cache (which is version-agnostic); the payload copy is covered by
//! the transcript MAC. [`ChallengeV2::from_frame`] refuses a frame whose two
//! copies differ, so a peer cannot wedge a fresh header nonce onto a stale,
//! validly-signed transcript.

use crate::frame::{DEUNLOCK_WIRE_VERSION_V2, Frame, FrameError, NONCE_LEN};
use crate::transcript::{AuthTranscript, REQUEST_NONCE_LEN, TRANSCRIPT_TAG_LEN, TranscriptError};

/// Magic prefix of a v2 challenge payload.
pub const CHALLENGE_V2_MAGIC: &[u8; 4] = b"DLC2";

/// Smallest possible encoded payload: empty service and user are impossible,
/// so this uses one byte for each field.
pub const MIN_CHALLENGE_V2_PAYLOAD_LEN: usize = CHALLENGE_V2_MAGIC.len() + 32 + 2 + 1 + 2 + 1 + REQUEST_NONCE_LEN + 8;

/// Errors produced while decoding a v2 challenge.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChallengeError {
    /// The frame version byte was not [`DEUNLOCK_WIRE_VERSION_V2`].
    #[error("challenge frame must be wire version 2, got 0x{0:02x}")]
    BadVersion(u8),
    /// The payload did not start with [`CHALLENGE_V2_MAGIC`].
    #[error("challenge payload has a bad magic prefix")]
    BadMagic,
    /// The payload ended in the middle of a field.
    #[error("challenge payload is truncated")]
    Truncated,
    /// The payload carried bytes after the last field.
    #[error("challenge payload has trailing bytes")]
    TrailingBytes,
    /// The frame header nonce and the transcript nonce disagreed.
    #[error("challenge frame nonce does not match the signed transcript nonce")]
    NonceMismatch,
    /// A transcript field failed validation on decode.
    #[error("challenge transcript is invalid: {0}")]
    Transcript(#[from] TranscriptError),
    /// A field was not valid UTF-8.
    #[error("challenge field is not valid utf-8")]
    Utf8,
    /// The frame itself failed to encode or decode.
    #[error("challenge frame error: {0}")]
    Frame(#[from] FrameError),
}

/// A decoded v2 challenge, tied to the frame it arrived in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeV2 {
    transcript: AuthTranscript,
    tag: [u8; TRANSCRIPT_TAG_LEN],
}

impl ChallengeV2 {
    /// Build a challenge and its MAC for `transcript`.
    #[must_use]
    pub fn new(transcript: AuthTranscript, bond_key: &[u8; 32]) -> Self {
        let tag = transcript.tag(bond_key);
        Self { transcript, tag }
    }

    /// The transcript this challenge authorizes.
    #[must_use]
    pub fn transcript(&self) -> &AuthTranscript {
        &self.transcript
    }

    /// The MAC carried by the challenge.
    #[must_use]
    pub fn tag(&self) -> &[u8; TRANSCRIPT_TAG_LEN] {
        &self.tag
    }

    /// Encode the payload (everything except the frame tag).
    #[must_use]
    pub fn encode_payload(&self) -> Vec<u8> {
        let service = self.transcript.service().as_bytes();
        let user = self.transcript.user().as_bytes();
        let mut out = Vec::with_capacity(MIN_CHALLENGE_V2_PAYLOAD_LEN + service.len() + user.len());
        out.extend_from_slice(CHALLENGE_V2_MAGIC);
        out.extend_from_slice(self.transcript.host_id());
        // Field lengths are capped at 64 bytes by the transcript validator.
        out.extend_from_slice(&u16::try_from(service.len()).unwrap_or(u16::MAX).to_be_bytes());
        out.extend_from_slice(service);
        out.extend_from_slice(&u16::try_from(user.len()).unwrap_or(u16::MAX).to_be_bytes());
        out.extend_from_slice(user);
        out.extend_from_slice(self.transcript.nonce());
        out.extend_from_slice(&self.transcript.issued_at().to_be_bytes());
        out
    }

    /// Wrap this challenge in a v2 [`Frame`], with the transcript MAC as the
    /// frame tag.
    ///
    /// # Errors
    ///
    /// [`ChallengeError::Frame`] if the payload exceeds the frame cap.
    pub fn to_frame(&self) -> Result<Frame, ChallengeError> {
        Ok(Frame {
            version: DEUNLOCK_WIRE_VERSION_V2,
            nonce: *self.transcript.nonce(),
            payload: self.encode_payload(),
            tag: self.tag,
        })
    }

    /// Decode and **verify** a v2 challenge frame against `bond_key`.
    ///
    /// # Errors
    ///
    /// [`ChallengeError::BadVersion`] for a v1 frame,
    /// [`ChallengeError::NonceMismatch`] when the header and transcript nonces
    /// disagree, or a parse error. A wrong MAC is *not* an error here — it is
    /// reported through [`Self::verify`] so callers can log it distinctly
    /// from malformed input.
    pub fn from_frame(frame: &Frame) -> Result<Self, ChallengeError> {
        if frame.version != DEUNLOCK_WIRE_VERSION_V2 {
            return Err(ChallengeError::BadVersion(frame.version));
        }
        let payload = frame.payload.as_slice();
        if payload.len() < MIN_CHALLENGE_V2_PAYLOAD_LEN {
            return Err(ChallengeError::Truncated);
        }
        if &payload[..CHALLENGE_V2_MAGIC.len()] != CHALLENGE_V2_MAGIC {
            return Err(ChallengeError::BadMagic);
        }
        let mut cursor = CHALLENGE_V2_MAGIC.len();
        let host_id: [u8; 32] = payload[cursor..cursor + 32].try_into().map_err(|_| ChallengeError::Truncated)?;
        cursor += 32;

        let service_len = read_u16(payload, &mut cursor)? as usize;
        let service_bytes = take(payload, &mut cursor, service_len)?;
        let service = core::str::from_utf8(service_bytes).map_err(|_| ChallengeError::Utf8)?;

        let user_len = read_u16(payload, &mut cursor)? as usize;
        let user_bytes = take(payload, &mut cursor, user_len)?;
        let user = core::str::from_utf8(user_bytes).map_err(|_| ChallengeError::Utf8)?;

        let nonce: [u8; REQUEST_NONCE_LEN] = take(payload, &mut cursor, REQUEST_NONCE_LEN)?.try_into().map_err(|_| ChallengeError::Truncated)?;
        let issued_at = u64::from_be_bytes(take(payload, &mut cursor, 8)?.try_into().map_err(|_| ChallengeError::Truncated)?);

        if cursor != payload.len() {
            return Err(ChallengeError::TrailingBytes);
        }
        if frame.nonce != nonce {
            return Err(ChallengeError::NonceMismatch);
        }

        let transcript = AuthTranscript::new(host_id, service, user, nonce, issued_at)?;
        Ok(Self { transcript, tag: frame.tag })
    }

    /// Constant-time check that the carried MAC matches the transcript under
    /// `bond_key`.
    #[must_use]
    pub fn verify(&self, bond_key: &[u8; 32]) -> bool {
        self.transcript.verify(bond_key, &self.tag)
    }
}

impl From<ChallengeV2> for Frame {
    /// Best-effort conversion; an oversized payload cannot occur because the
    /// transcript bounds every field at 64 bytes.
    fn from(value: ChallengeV2) -> Self {
        Frame {
            version: DEUNLOCK_WIRE_VERSION_V2,
            nonce: *value.transcript.nonce(),
            payload: value.encode_payload(),
            tag: value.tag,
        }
    }
}

fn read_u16(payload: &[u8], cursor: &mut usize) -> Result<u16, ChallengeError> {
    let bytes = take(payload, cursor, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn take<'a>(payload: &'a [u8], cursor: &mut usize, len: usize) -> Result<&'a [u8], ChallengeError> {
    let end = cursor.checked_add(len).ok_or(ChallengeError::Truncated)?;
    let slice = payload.get(*cursor..end).ok_or(ChallengeError::Truncated)?;
    *cursor = end;
    Ok(slice)
}

/// Length of the frame nonce, re-exported so callers do not have to reach
/// into two modules to talk about freshness.
pub const CHALLENGE_FRAME_NONCE_LEN: usize = NONCE_LEN;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{DEUNLOCK_WIRE_VERSION_V1, TAG_LEN};

    /// Deterministic key material so `challenge()` and the assertions that
    /// re-derive it agree. The ECDH path itself is covered by `kex::tests`.
    fn bond_key() -> [u8; 32] {
        [0x33; 32]
    }

    fn challenge() -> ChallengeV2 {
        let transcript = AuthTranscript::new([0x11; 32], "sudo", "roma", [0x22; 16], 1_760_000_000).expect("transcript");
        ChallengeV2::new(transcript, &bond_key())
    }

    #[test]
    fn frame_roundtrip_verifies() {
        let key = bond_key();
        let original = challenge();
        let frame = original.to_frame().expect("frame");
        assert_eq!(frame.version, DEUNLOCK_WIRE_VERSION_V2);

        let decoded = ChallengeV2::from_frame(&frame).expect("decode");
        assert_eq!(decoded, original);
        assert!(decoded.verify(&key));
    }

    #[test]
    fn wrong_key_fails_verification() {
        let frame = challenge().to_frame().expect("frame");
        let decoded = ChallengeV2::from_frame(&frame).expect("decode");
        assert!(!decoded.verify(&[0xEE; 32]));
    }

    #[test]
    fn tampered_service_byte_breaks_the_mac() {
        let key = bond_key();
        let mut frame = challenge().to_frame().expect("frame");
        // Find the "sudo" bytes and swap one: gdm has the same length.
        let position = frame
            .payload
            .windows(4)
            .position(|w| w == b"sudo")
            .expect("service present");
        frame.payload[position] = b'g';
        let decoded = ChallengeV2::from_frame(&frame).expect("decode");
        assert_eq!(decoded.transcript().service(), "gudo");
        assert!(!decoded.verify(&key), "a changed service must fail the MAC");
    }

    #[test]
    fn v1_frame_is_refused() {
        let mut frame = challenge().to_frame().expect("frame");
        frame.version = DEUNLOCK_WIRE_VERSION_V1;
        assert_eq!(
            ChallengeV2::from_frame(&frame).expect_err("v1"),
            ChallengeError::BadVersion(DEUNLOCK_WIRE_VERSION_V1)
        );
    }

    #[test]
    fn nonce_mismatch_between_header_and_transcript_is_refused() {
        let mut frame = challenge().to_frame().expect("frame");
        frame.nonce = [0x99; 16];
        assert_eq!(ChallengeV2::from_frame(&frame).expect_err("nonce"), ChallengeError::NonceMismatch);
    }

    #[test]
    fn bad_magic_is_refused() {
        let mut frame = challenge().to_frame().expect("frame");
        frame.payload[0] = b'X';
        assert_eq!(ChallengeV2::from_frame(&frame).expect_err("magic"), ChallengeError::BadMagic);
    }

    #[test]
    fn truncated_payload_is_refused() {
        let mut frame = challenge().to_frame().expect("frame");
        frame.payload.truncate(MIN_CHALLENGE_V2_PAYLOAD_LEN - 1);
        assert_eq!(ChallengeV2::from_frame(&frame).expect_err("short"), ChallengeError::Truncated);
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut frame = challenge().to_frame().expect("frame");
        frame.payload.push(0x00);
        assert_eq!(ChallengeV2::from_frame(&frame).expect_err("trailing"), ChallengeError::TrailingBytes);
    }

    #[test]
    fn overlong_service_field_is_refused_on_decode() {
        let mut frame = challenge().to_frame().expect("frame");
        // Rebuild with a 65-byte service: magic || host_id || len || service…
        let mut payload = Vec::new();
        payload.extend_from_slice(CHALLENGE_V2_MAGIC);
        payload.extend_from_slice(&[0x11; 32]);
        let long = vec![b'a'; 65];
        payload.extend_from_slice(&(long.len() as u16).to_be_bytes());
        payload.extend_from_slice(&long);
        payload.extend_from_slice(&2u16.to_be_bytes());
        payload.extend_from_slice(b"ab");
        payload.extend_from_slice(&[0x22; 16]);
        payload.extend_from_slice(&0u64.to_be_bytes());
        frame.payload = payload;

        match ChallengeV2::from_frame(&frame) {
            Err(ChallengeError::Transcript(TranscriptError::FieldTooLong { field })) => assert_eq!(field, "service"),
            other => panic!("expected FieldTooLong, got {other:?}"),
        }
    }

    #[test]
    fn frame_tag_size_is_unchanged_by_v2() {
        let frame = challenge().to_frame().expect("frame");
        assert_eq!(frame.tag.len(), TAG_LEN);
        assert_eq!(frame.tag, challenge().tag().to_owned());
    }
}
