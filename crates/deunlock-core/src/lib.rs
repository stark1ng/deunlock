//! `deunlock-core` — the shared protocol core consumed by the PAM module
//! (`deunlock-pam`), the transport (`deunlock-transport`), the CLI
//! (`deunlock-cli`), and the Android companion (`deunlock-mobile`, via UniFFI).
//!
//! Layered as roadmap items land:
//!
//! - **S-002** — v1 wire-format [`Frame`] encoder / decoder.
//! - **S-003** — sliding LRU + TTL replay nonce cache.
//! - **S-004** — Ed25519 signing + BLAKE3-keyed-hash MAC (this commit).
//! - **S-005** — bond store TOML schema.
//! - **S-006** — kernel-keyring / libsecret `KeyStore` abstraction.
//!
//! See `specs/deunlock/SPEC.md` for the protocol design,
//! `specs/journeys/JOURNEY-S-002-protocol-framing.md` for the framing
//! rationale, `specs/journeys/JOURNEY-S-003-replay-defense.md` for the replay
//! cache rationale, `specs/journeys/JOURNEY-S-004-crypto-primitives.md` for
//! the signing/MAC rationale, and
//! `specs/journeys/JOURNEY-S-005-bond-store.md` for the bond-store rationale.

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod bond;
pub mod challenge;
pub mod frame;
pub mod kex;
pub mod mac;
pub mod replay;
pub mod secrets;
pub mod sign;
pub mod transcript;

pub use challenge::{
    CHALLENGE_FRAME_NONCE_LEN, CHALLENGE_V2_MAGIC, ChallengeError, ChallengeV2, MIN_CHALLENGE_V2_PAYLOAD_LEN,
};
pub use kex::{
    AUTH_MAC_KEY_BYTES, AUTH_MAC_KEY_INFO_V2, BOND_KEY_V2_BYTES, KEX_INFO_V2, KexError, PAIRING_NONCE_LEN, PairingSecret, SEC1_PUBKEY_LEN,
    SHARED_SECRET_LEN, derive_auth_mac_key, derive_bond_key_v2,
};
pub use transcript::{
    AuthTranscript, MAX_TRANSCRIPT_FIELD_LEN, REQUEST_NONCE_LEN, TRANSCRIPT_DOMAIN_V2, TRANSCRIPT_TAG_LEN, TRANSCRIPT_VERSION, TranscriptError,
};

pub use bond::{
    BOND_DIR_MODE, BOND_FILE_MODE, BOND_HKDF_INFO_V1, BOND_KEY_DERIVED_BYTES, BOND_SCHEMA_VERSION_LATEST, Bond, BondError, BondStatus,
    BondStore, PEER_ID_BLAKE3_BYTES, bond_key_from_pubkeys, peer_id_from_pubkey,
};
pub use frame::{
    Frame, FrameError, HEADER_LEN, MAX_FRAME_LEN, MAX_PAYLOAD_LEN, MIN_FRAME_LEN, NONCE_LEN, NONCE_OFFSET, PAYLOAD_OFFSET,
    DEUNLOCK_WIRE_VERSION_V1, TAG_LEN, VERSION_LEN, VERSION_OFFSET,
};
pub use mac::{BOND_KEY_BYTES, MAC_TAG_LEN, compute_tag, verify_tag};
pub use replay::{Acceptance, DEFAULT_REPLAY_CAP, DEFAULT_REPLAY_TTL, ReplayCache};
pub use secrets::{
    BackendKind, InMemoryKeyStore, KEYRING_ID_PREFIX, KeyStore, LOG_LINE_KERNEL, LOG_LINE_SECRET_SERVICE, SECRET_SERVICE_ATTR_ID,
    SECRET_SERVICE_ATTR_KIND, SECRET_SERVICE_ATTR_KIND_VALUE, SECRET_SERVICE_COLLECTION, SECRET_SERVICE_CONTENT_TYPE, SecretError, detect,
    detect_with_logger,
};
pub use sign::{SIGNATURE_LEN, SIGNED_MESSAGE_PREFIX_LEN, Signature, SigningKey, VerifyError, VerifyingKey, sign_frame, verify_frame};
