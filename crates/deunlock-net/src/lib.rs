//! `deunlock-net` — the LAN transport for DeUnlock.
//!
//! Closes AUDIT-001 **D-05**: the BLE path has neither encryption nor forward
//! secrecy, so a passive observer could read the challenge and a recorded
//! signature could be replayed against a different service. Over Wi-Fi the same
//! exchange runs inside TLS 1.3, which gives confidentiality, integrity and
//! fresh ephemeral keys per session.
//!
//! Three pieces:
//!
//! - [`identity`] — the desktop's self-signed certificate, persisted at `0600`,
//!   and the `SHA-256(cert DER)` fingerprint a phone pins.
//! - [`tls`] — server and pinned-client configurations, ALPN `deunlock/2`.
//! - [`framing`] — `u32be(len) || body` messages with a hard 4 KiB ceiling.
//! - [`mdns`] — `_deunlock._tcp.local.` advertisement carrying `host_id`.
//!
//! The protocol that runs inside the tunnel is unchanged: a v2 challenge frame
//! is MAC'd under the bond key and the phone signs the transcript. TLS is
//! defence in depth, not a replacement for the bond.

pub mod error;
pub mod framing;
pub mod lan;
pub mod identity;
pub mod mdns;
pub mod tls;

pub use error::NetError;
pub use framing::{MAX_MESSAGE_BYTES, read_message, write_message};
pub use lan::{
    BondLookup, DEFAULT_LAN_PORT, connect_pinned, FilePairingOffers, PairingOffers, PairingSink, DEFAULT_NET_CERT_PATH, DEFAULT_NET_KEY_PATH, HELLO_DOMAIN, HELLO_LEN, HELLO_MAGIC, SESSION_CHALLENGE_LEN, SESSION_CHALLENGE_MAGIC, SESSION_NONCE_BYTES, HELLO_TAG_BYTES, Hello, LanPeripheral, LanServer, PEER_ID_BYTES,
    encode_hello, hello_tag, peer_id_hex, verify_hello,
};
pub use identity::{FINGERPRINT_BYTES, IDENTITY_DIR_MODE, IDENTITY_FILE_MODE, LanIdentity};
pub use mdns::{
    LanAdvertiser, SERVICE_TYPE, TXT_FINGERPRINT, TXT_FINGERPRINT_HEX_CHARS, TXT_HOST_ID, TXT_VERSION,
};
pub use tls::{ALPN_PROTOCOL, acceptor, pinned_client_config, server_config};
