//! Errors for the LAN transport.
//!
//! Every variant is a refusal, never a degradation: a transport that cannot
//! prove who it is talking to must fail, not fall back to plaintext.

use std::path::PathBuf;

/// A LAN-transport failure.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    /// The TLS identity could not be read, created or written.
    #[error("identity io error at {path}: {source}")]
    IdentityIo {
        /// File that failed.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },

    /// A stored TLS identity file is not what we expect.
    #[error("malformed TLS identity at {path}: {reason}")]
    IdentityMalformed {
        /// File that failed.
        path: PathBuf,
        /// What was wrong with it.
        reason: String,
    },

    /// The identity directory (or a key inside it) has permissions that are too
    /// wide for a private key.
    #[error("TLS identity permissions too loose at {path}: expected no group/other access")]
    PermissionsTooLoose {
        /// Offending path.
        path: PathBuf,
    },

    /// Certificate generation failed.
    #[error("certificate generation failed: {0}")]
    Certificate(String),

    /// TLS setup failed (bad key material, provider missing, ...).
    #[error("tls configuration failed: {0}")]
    TlsConfig(String),

    /// The TLS handshake failed.
    #[error("tls handshake failed: {0}")]
    Handshake(String),

    /// The peer presented a certificate whose pin does not match.
    #[error("peer certificate does not match the pinned fingerprint")]
    PinMismatch,

    /// A length-prefixed message exceeded [`crate::framing::MAX_MESSAGE_BYTES`].
    #[error("message of {len} bytes exceeds the {max}-byte limit")]
    MessageTooLarge {
        /// Declared length.
        len: u32,
        /// Limit.
        max: usize,
    },

    /// The stream ended in the middle of a message.
    #[error("stream ended after {read} of {expected} message bytes")]
    Truncated {
        /// Bytes actually read.
        read: usize,
        /// Bytes the length prefix promised.
        expected: usize,
    },

    /// Underlying I/O failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// mDNS advertisement failed.
    #[error("mdns error: {0}")]
    Mdns(String),
}
