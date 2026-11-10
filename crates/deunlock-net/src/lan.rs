//! LAN sessions: an authenticated hello, and `Peripheral` over TLS.
//!
//! The TLS tunnel proves the *desktop* is the one the phone pinned. It says
//! nothing about which phone is calling, and a bare bond-key MAC over a challenge
//! would let anyone who completes a handshake collect challenge frames.
//!
//! So the first message on every session is a hello:
//!
//! ```text
//! "DLH1" ‖ host_id[32] ‖ peer_id[32] ‖ exporter[32] ‖ BLAKE3_keyed(mac_key, …)[32]
//! ```
//!
//! `exporter` is TLS 1.3 keying material exported with label `deunlock-lan-v1`.
//! Because the exporter differs per session, a hello recorded from one
//! connection is worthless on another — the replay dies at the tag, before any
//! challenge is issued. `mac_key` is the bond's MAC key (`derive_auth_mac_key`),
//! so only the paired phone can produce the tag.
//!
//! Once the hello verifies, the session is attached to the peer id and the
//! orchestrator drives it through the ordinary [`Peripheral`] trait: this module
//! is a second backend behind the same seam as BLE, exactly as the threat matrix
//! asks — no protocol code changes.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use deunlock_core::NONCE_LEN;
use deunlock_transport::{BondKey, Peripheral, PeripheralError};
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;

use crate::error::NetError;
use crate::framing::{read_message, write_message};
use crate::identity::{FINGERPRINT_BYTES, LanIdentity};

/// Default port the desktop listens on.
pub const DEFAULT_LAN_PORT: u16 = 47_823;

/// Default certificate path, alongside the host key.
pub const DEFAULT_NET_CERT_PATH: &str = "/etc/deunlock/net.crt";

/// Default private-key path.
pub const DEFAULT_NET_KEY_PATH: &str = "/etc/deunlock/net.key";

// The hello record itself lives in `deunlock-core`: it is a protocol message the
// desktop and the phone must produce byte-for-byte identically, so there is
// exactly one implementation. This module adds the transport-side policy — who
// is bonded, and how a session is attached.
pub use deunlock_core::hello::{
    HELLO_DOMAIN, HELLO_LEN, HELLO_MAGIC, HELLO_TAG_BYTES, Hello, PEER_ID_BYTES, SESSION_CHALLENGE_LEN, SESSION_CHALLENGE_MAGIC,
    SESSION_NONCE_BYTES, decode_hello, decode_session_challenge, encode_hello, encode_session_challenge, hello_tag,
    peer_id_hex,
};

/// Supplies bond keys by peer id; the daemon backs this with its keys directory.
pub trait BondLookup: Send + Sync {
    /// The MAC-capable bond key for `peer_id_hex`, if that peer is bonded.
    fn bond_key(&self, peer_id_hex: &str) -> Option<BondKey>;
}

impl<F> BondLookup for F
where
    F: Fn(&str) -> Option<BondKey> + Send + Sync,
{
    fn bond_key(&self, peer_id_hex: &str) -> Option<BondKey> {
        self(peer_id_hex)
    }
}

/// Verify a hello against our own identity, the session nonce we just sent, and
/// the bond for the claimed peer.
///
/// The tag check itself lives in `deunlock-core::hello`; this adds the lookup
/// that decides *which* key the peer claims.
///
/// # Errors
///
/// [`NetError::Handshake`] for a malformed record, a wrong host id or session
/// nonce, or a tag that does not verify; [`NetError::PinMismatch`] when the peer is not
/// bonded (the phone is talking to a desktop it never paired with, or its bond
/// was revoked).
pub fn verify_hello(
    bytes: &[u8],
    our_host_id: &[u8; 32],
    session_nonce: &[u8; SESSION_NONCE_BYTES],
    bonds: &dyn BondLookup,
) -> Result<Hello, NetError> {
    let (hello, _tag) = deunlock_core::decode_hello(bytes)
        .map_err(|e| NetError::Handshake(format!("hello decode failed: {e}")))?;
    let peer_hex = peer_id_hex(&hello.peer_id);
    let bond = bonds.bond_key(&peer_hex).ok_or(NetError::PinMismatch)?;
    deunlock_core::verify_hello(bytes, &bond, our_host_id, session_nonce)
        .map_err(|e| NetError::Handshake(e.to_string()))
}

/// A live session attached to a peer.
struct Session {
    /// Frames for the phone; the writer task owns the read end.
    outbound: mpsc::UnboundedSender<Vec<u8>>,
    /// Responses from the phone.
    responses: mpsc::UnboundedReceiver<Vec<u8>>,
}

/// The LAN backend behind [`Peripheral`].
pub struct LanPeripheral {
    host_id: [u8; 32],
    peers: Mutex<HashMap<String, BondKey>>,
    sessions: tokio::sync::Mutex<HashMap<String, Session>>,
}

impl std::fmt::Debug for LanPeripheral {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LanPeripheral").field("host_id", &hex(&self.host_id)).finish()
    }
}

impl LanPeripheral {
    /// Create a peripheral for the given desktop identity.
    #[must_use]
    pub fn new(host_id: [u8; 32]) -> Arc<Self> {
        Arc::new(Self {
            host_id,
            peers: Mutex::new(HashMap::new()),
            sessions: tokio::sync::Mutex::new(HashMap::new()),
        })
    }

    /// Attach a verified session to `peer_hex`, replacing any previous one.
    async fn attach(
        &self,
        peer_hex: String,
        outbound: mpsc::UnboundedSender<Vec<u8>>,
        responses: mpsc::UnboundedReceiver<Vec<u8>>,
    ) {
        let mut sessions = self.sessions.lock().await;
        if let Some(old) = sessions.insert(peer_hex.clone(), Session { outbound, responses }) {
            tracing::info!(peer = %peer_hex, "replacing a previous LAN session");
            drop(old.outbound);
        }
    }

    async fn detach(&self, peer_hex: &str) {
        let mut sessions = self.sessions.lock().await;
        if let Some(old) = sessions.remove(peer_hex) {
            drop(old.outbound);
        }
    }

    /// Is `peer_hex` currently connected?
    pub async fn is_connected(&self, peer_hex: &str) -> bool {
        self.sessions.lock().await.contains_key(peer_hex)
    }
}

#[async_trait::async_trait]
impl Peripheral for LanPeripheral {
    async fn check_health(&self) -> Result<(), PeripheralError> {
        Ok(())
    }

    async fn add_peer(&self, peer_id: &str, bond_key: &BondKey) -> Result<(), PeripheralError> {
        let mut peers = self.peers.lock().expect("peers lock");
        if peers.contains_key(peer_id) {
            return Err(PeripheralError::PeerAlreadyAdded {
                peer_id: peer_id.to_owned(),
            });
        }
        peers.insert(peer_id.to_owned(), *bond_key);
        Ok(())
    }

    async fn remove_peer(&self, peer_id: &str) -> Result<(), PeripheralError> {
        // The guard is scoped: a `std::sync::MutexGuard` held across an `.await`
        // makes the future non-Send, and the trait requires Send.
        let known = {
            let mut peers = self.peers.lock().expect("peers lock");
            peers.remove(peer_id).is_some()
        };
        if !known {
            return Err(PeripheralError::UnknownPeer {
                peer_id: peer_id.to_owned(),
            });
        }
        self.detach(peer_id).await;
        Ok(())
    }

    async fn set_session_uuids(&self, _uuids: std::collections::HashSet<uuid::Uuid>) -> Result<(), PeripheralError> {
        // mDNS carries the service record instead of a UUID set; there is
        // nothing to rotate here.
        Ok(())
    }

    async fn notify_challenge(&self, peer_id: &str, frame: &[u8]) -> Result<(), PeripheralError> {
        let sessions = self.sessions.lock().await;
        let Some(session) = sessions.get(peer_id) else {
            return Err(PeripheralError::Backend {
                reason: format!("no live LAN session for peer_id={peer_id}"),
            });
        };
        session
            .outbound
            .send(frame.to_vec())
            .map_err(|_| PeripheralError::Backend {
                reason: format!("LAN session for peer_id={peer_id} is closing"),
            })
    }

    async fn wait_for_response(&self, peer_id: &str, deadline: Duration) -> Result<Vec<u8>, PeripheralError> {
        let mut sessions = self.sessions.lock().await;
        let Some(session) = sessions.get_mut(peer_id) else {
            return Err(PeripheralError::UnknownPeer {
                peer_id: peer_id.to_owned(),
            });
        };
        match tokio::time::timeout(deadline, session.responses.recv()).await {
            Ok(Some(bytes)) => Ok(bytes),
            Ok(None) => Err(PeripheralError::Backend {
                reason: format!("LAN session for peer_id={peer_id} closed while waiting"),
            }),
            Err(_) => Err(PeripheralError::ResponseTimeout {
                peer_id: peer_id.to_owned(),
                deadline_ms: u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX),
            }),
        }
    }
}

/// A bound LAN listener ready to serve.
pub struct LanServer {
    acceptor: TlsAcceptor,
    listener: TcpListener,
    host_id: [u8; 32],
    peripheral: Arc<LanPeripheral>,
    bonds: Arc<dyn BondLookup>,
}

impl LanServer {
    /// Bind the LAN listener and build the peripheral that sessions feed.
    ///
    /// # Errors
    ///
    /// [`NetError::TlsConfig`] for a broken identity, [`NetError::Io`] when the
    /// address cannot be bound.
    pub async fn bind(
        addr: SocketAddr,
        identity: &LanIdentity,
        host_id: [u8; 32],
        bonds: Arc<dyn BondLookup>,
    ) -> Result<Self, NetError> {
        let acceptor = crate::tls::acceptor(identity)?;
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            acceptor,
            listener,
            host_id,
            peripheral: LanPeripheral::new(host_id),
            bonds,
        })
    }

    /// The peripheral the orchestrator should use.
    #[must_use]
    pub fn peripheral(&self) -> Arc<LanPeripheral> {
        Arc::clone(&self.peripheral)
    }

    /// The address actually bound (useful when port 0 was requested).
    ///
    /// # Errors
    ///
    /// [`NetError::Io`] when the local address cannot be read.
    pub fn local_addr(&self) -> Result<SocketAddr, NetError> {
        Ok(self.listener.local_addr()?)
    }

    /// Accept sessions, keeping an mDNS advertisement alive for as long as the
    /// listener runs.
    ///
    /// The advertisement is dropped when this future returns, which deregisters
    /// the service — no `mem::forget`, no record left behind by a dead daemon.
    pub async fn serve_advertised(
        self,
        advertiser: Option<crate::mdns::LanAdvertiser>,
        stop: tokio::sync::watch::Receiver<bool>,
    ) {
        let _keep_advertised = advertiser;
        self.serve(stop).await;
    }

    /// Accept sessions until `shutdown` fires.
    ///
    /// A failing connection is logged and dropped: one broken phone must not
    /// take the listener down.
    pub async fn serve(self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    // `Err` means every sender was dropped: that is a stop signal,
                    // not a reason to spin.
                    if changed.is_err() || *shutdown.borrow() {
                        tracing::info!("LAN listener stopping");
                        return;
                    }
                }
                accepted = self.listener.accept() => {
                    let Ok((tcp, peer_addr)) = accepted else {
                        tracing::warn!("LAN accept failed");
                        continue;
                    };
                    let acceptor = self.acceptor.clone();
                    let host_id = self.host_id;
                    let peripheral = Arc::clone(&self.peripheral);
                    let bonds = Arc::clone(&self.bonds);
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(acceptor, tcp, host_id, peripheral, bonds, peer_addr).await {
                            tracing::warn!(peer = %peer_addr, error = %e, "LAN session rejected");
                        }
                    });
                }
            }
        }
    }
}


/// A fresh 32-byte session nonce from the OS RNG.
///
/// Failure is not recoverable and must not be papered over with a weak value:
/// the nonce is what makes a recorded hello useless on another connection.
fn random_session_nonce() -> [u8; SESSION_NONCE_BYTES] {
    use rand_core::RngCore as _;
    let mut nonce = [0u8; SESSION_NONCE_BYTES];
    rand_core::OsRng.fill_bytes(&mut nonce);
    nonce
}

async fn handle_connection(
    acceptor: TlsAcceptor,
    tcp: tokio::net::TcpStream,
    host_id: [u8; 32],
    peripheral: Arc<LanPeripheral>,
    bonds: Arc<dyn BondLookup>,
    peer_addr: SocketAddr,
) -> Result<(), NetError> {
    let tls = acceptor
        .accept(tcp)
        .await
        .map_err(|e| NetError::Handshake(e.to_string()))?;

    // The desktop speaks first: a fresh nonce the phone must cover in its hello.
    // Android has no TLS-exporter API, so this is how the hello is bound to this
    // specific connection.
    let session_nonce = random_session_nonce();
    let mut tls = tls;
    write_message(&mut tls, &encode_session_challenge(&session_nonce)).await?;

    let (mut reader, mut writer) = tokio::io::split(tls);
    let hello_bytes = read_message(&mut reader).await?;
    let hello = verify_hello(&hello_bytes, &host_id, &session_nonce, bonds.as_ref())?;
    let peer_hex = peer_id_hex(&hello.peer_id);
    tracing::info!(peer = %peer_hex, addr = %peer_addr, "LAN session authenticated");

    let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (responses_tx, responses_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    peripheral.attach(peer_hex.clone(), outbound_tx, responses_rx).await;

    let writer_task = tokio::spawn(async move {
        while let Some(frame) = outbound_rx.recv().await {
            if write_message(&mut writer, &frame).await.is_err() {
                break;
            }
        }
        let _ = writer.shutdown().await;
    });

    // Anything the phone sends after the hello is a response to the challenge the
    // orchestrator just pushed; a broken stream simply ends the session.
    while let Ok(bytes) = read_message(&mut reader).await {
        if responses_tx.send(bytes).is_err() {
            break;
        }
    }

    peripheral.detach(&peer_hex).await;
    writer_task.abort();
    tracing::info!(peer = %peer_hex, "LAN session closed");
    Ok(())
}

/// Hex helper used by `Debug`.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Length of a signature response, re-exported for tests and callers.
pub const SIGNATURE_BYTES: usize = 64;

/// Length of the v2 challenge nonce, re-exported for callers building frames.
pub const V2_NONCE_BYTES: usize = NONCE_LEN;

/// Fingerprint length alias so callers need not import two modules.
pub const LAN_FINGERPRINT_BYTES: usize = FINGERPRINT_BYTES;
