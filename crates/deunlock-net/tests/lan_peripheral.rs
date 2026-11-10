//! LAN sessions: the hello contract and `Peripheral` over TLS.
//!
//! The negative cases matter more than the happy path: an unbonded phone, a
//! hello replayed onto another session, a hello for a different desktop, and a
//! forged tag each have to be refused *before* the challenge channel is open.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use deunlock_core::BOND_KEY_BYTES;
use deunlock_net::lan::{
    HELLO_LEN, LanServer, PEER_ID_BYTES, SESSION_NONCE_BYTES, decode_session_challenge, encode_hello, peer_id_hex,
    verify_hello,
};
use deunlock_net::{LanIdentity, NetError, pinned_client_config};
use deunlock_transport::{BondKey, Peripheral};
use tokio_rustls::rustls::pki_types::ServerName;

const HOST_ID: [u8; 32] = [0x11; 32];
const PEER_ID: [u8; PEER_ID_BYTES] = [0x22; PEER_ID_BYTES];
const OTHER_PEER: [u8; PEER_ID_BYTES] = [0x23; PEER_ID_BYTES];
const BOND: BondKey = [0x33; BOND_KEY_BYTES];

fn bonds_with(peer_hex: &str, bond: BondKey) -> Arc<dyn deunlock_net::BondLookup> {
    let key = peer_hex.to_owned();
    Arc::new(move |asked: &str| if asked == key { Some(bond) } else { None })
}

// ---------------------------------------------------------------------------
// The hello record on its own
// ---------------------------------------------------------------------------

#[test]
fn a_hello_from_the_bonded_phone_verifies_and_names_the_peer() {
    let session_nonce = [0x44u8; SESSION_NONCE_BYTES];
    let bytes = encode_hello(&BOND, &HOST_ID, &PEER_ID, &session_nonce);
    assert_eq!(bytes.len(), HELLO_LEN);
    let bonds = bonds_with(&peer_id_hex(&PEER_ID), BOND);
    let hello = verify_hello(&bytes, &HOST_ID, &session_nonce, bonds.as_ref()).expect("verify");
    assert_eq!(hello.peer_id, PEER_ID);
    assert_eq!(hello.host_id, HOST_ID);
}

#[test]
fn a_hello_is_refused_by_a_desktop_it_was_not_addressed_to() {
    let session_nonce = [0x44u8; SESSION_NONCE_BYTES];
    let bytes = encode_hello(&BOND, &HOST_ID, &PEER_ID, &session_nonce);
    let bonds = bonds_with(&peer_id_hex(&PEER_ID), BOND);
    match verify_hello(&bytes, &[0x12; 32], &session_nonce, bonds.as_ref()) {
        Err(NetError::Handshake(reason)) => assert!(reason.contains("host_id")),
        other => panic!("expected a host_id refusal, got {other:?}"),
    }
}

#[test]
fn a_hello_answering_another_sessions_nonce_is_dead() {
    let recorded_nonce = [0x44u8; SESSION_NONCE_BYTES];
    let fresh_nonce = [0x45u8; SESSION_NONCE_BYTES];
    let bytes = encode_hello(&BOND, &HOST_ID, &PEER_ID, &recorded_nonce);
    let bonds = bonds_with(&peer_id_hex(&PEER_ID), BOND);
    match verify_hello(&bytes, &HOST_ID, &fresh_nonce, bonds.as_ref()) {
        Err(NetError::Handshake(reason)) => assert!(reason.contains("session nonce")),
        other => panic!("expected a cross-session refusal, got {other:?}"),
    }
}

#[test]
fn an_unbonded_phone_is_refused_outright() {
    let session_nonce = [0x44u8; SESSION_NONCE_BYTES];
    let bytes = encode_hello(&BOND, &HOST_ID, &OTHER_PEER, &session_nonce);
    let bonds = bonds_with(&peer_id_hex(&PEER_ID), BOND);
    match verify_hello(&bytes, &HOST_ID, &session_nonce, bonds.as_ref()) {
        Err(NetError::PinMismatch) => {}
        other => panic!("expected PinMismatch, got {other:?}"),
    }
}

#[test]
fn a_phone_that_does_not_hold_the_bond_key_cannot_produce_a_valid_tag() {
    let session_nonce = [0x44u8; SESSION_NONCE_BYTES];
    let attacker_bond = [0x99u8; BOND_KEY_BYTES];
    let bytes = encode_hello(&attacker_bond, &HOST_ID, &PEER_ID, &session_nonce);
    let bonds = bonds_with(&peer_id_hex(&PEER_ID), BOND);
    match verify_hello(&bytes, &HOST_ID, &session_nonce, bonds.as_ref()) {
        Err(NetError::Handshake(reason)) => assert!(reason.contains("tag")),
        other => panic!("expected a tag refusal, got {other:?}"),
    }
}

#[test]
fn a_truncated_or_garbage_hello_is_refused() {
    let bonds = bonds_with(&peer_id_hex(&PEER_ID), BOND);
    let session_nonce = [0x44u8; SESSION_NONCE_BYTES];
    for bad in [&b""[..], &b"DLH1"[..], &[0u8; HELLO_LEN][..]] {
        match verify_hello(bad, &HOST_ID, &session_nonce, bonds.as_ref()) {
            Err(NetError::Handshake(_)) => {}
            other => panic!("expected a refusal for {} bytes, got {other:?}", bad.len()),
        }
    }
}

// ---------------------------------------------------------------------------
// A full session over loopback TLS
// ---------------------------------------------------------------------------

async fn connect_and_hello(
    addr: std::net::SocketAddr,
    identity: &LanIdentity,
    peer_id: [u8; PEER_ID_BYTES],
    bond: &BondKey,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let connector = tokio_rustls::TlsConnector::from(pinned_client_config(identity.fingerprint()));
    let tcp = tokio::net::TcpStream::connect(addr).await.expect("tcp");
    let name = ServerName::try_from("deunlock.local").expect("name");
    let tls = connector.connect(name, tcp).await.expect("handshake");

    // The desktop speaks first on a LAN session: it sends the nonce the hello
    // must cover.
    let mut tls = tls;
    let challenge = deunlock_net::read_message(&mut tls)
        .await
        .expect("session challenge");
    let session_nonce = decode_session_challenge(&challenge).expect("DLS1 record");
    let hello = encode_hello(bond, &HOST_ID, &peer_id, &session_nonce);
    deunlock_net::write_message(&mut tls, &hello).await.expect("hello");
    tls
}

#[tokio::test]
async fn a_verified_session_carries_a_challenge_and_a_signature() {
    let identity = LanIdentity::generate().expect("identity");
    let peer_hex = peer_id_hex(&PEER_ID);
    let bonds = bonds_with(&peer_hex, BOND);
    let server = LanServer::bind(
        std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        &identity,
        HOST_ID,
        bonds,
    )
    .await
    .expect("bind");
    let addr = server.local_addr().expect("addr");
    let peripheral = server.peripheral();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_task = tokio::spawn(async move { server.serve(shutdown_rx).await });

    peripheral
        .add_peer(&peer_hex, &BOND)
        .await
        .expect("add peer");

    let mut client = connect_and_hello(addr, &identity, PEER_ID, &BOND).await;

    // Session attachment happens right after the hello, so give it a moment.
    for _ in 0..50 {
        if peripheral.is_connected(&peer_hex).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(peripheral.is_connected(&peer_hex).await, "session must attach");

    peripheral
        .notify_challenge(&peer_hex, b"v2-challenge-frame")
        .await
        .expect("notify");
    let received = deunlock_net::read_message(&mut client).await.expect("frame");
    assert_eq!(received, b"v2-challenge-frame");

    let signature = vec![0xABu8; 64];
    deunlock_net::write_message(&mut client, &signature).await.expect("signature");
    let response = peripheral
        .wait_for_response(&peer_hex, Duration::from_secs(2))
        .await
        .expect("response");
    assert_eq!(response, signature);

    let _ = shutdown_tx.send(true);
    server_task.abort();
}

#[tokio::test]
async fn a_silent_phone_times_out_rather_than_hanging_the_prompt() {
    let identity = LanIdentity::generate().expect("identity");
    let peer_hex = peer_id_hex(&PEER_ID);
    let bonds = bonds_with(&peer_hex, BOND);
    let server = LanServer::bind(
        std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        &identity,
        HOST_ID,
        bonds,
    )
    .await
    .expect("bind");
    let addr = server.local_addr().expect("addr");
    let peripheral = server.peripheral();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_task = tokio::spawn(async move { server.serve(shutdown_rx).await });

    peripheral.add_peer(&peer_hex, &BOND).await.expect("add peer");
    let _client = connect_and_hello(addr, &identity, PEER_ID, &BOND).await;
    for _ in 0..50 {
        if peripheral.is_connected(&peer_hex).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    match peripheral
        .wait_for_response(&peer_hex, Duration::from_millis(80))
        .await
    {
        Err(deunlock_transport::PeripheralError::ResponseTimeout { .. }) => {}
        other => panic!("expected ResponseTimeout, got {other:?}"),
    }
    server_task.abort();
}

#[tokio::test]
async fn a_challenge_for_a_peer_with_no_session_fails_loudly() {
    let identity = LanIdentity::generate().expect("identity");
    let bonds = bonds_with(&peer_id_hex(&PEER_ID), BOND);
    let server = LanServer::bind(
        std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        &identity,
        HOST_ID,
        bonds,
    )
    .await
    .expect("bind");
    let peripheral = server.peripheral();
    let peer_hex = peer_id_hex(&PEER_ID);
    peripheral.add_peer(&peer_hex, &BOND).await.expect("add peer");
    match peripheral.notify_challenge(&peer_hex, b"frame").await {
        Err(deunlock_transport::PeripheralError::Backend { reason }) => {
            assert!(reason.contains("no live LAN session"));
        }
        other => panic!("expected a Backend error, got {other:?}"),
    }
    assert!(peripheral
        .remove_peer(&peer_hex)
        .await
        .is_ok());
    let empty: HashSet<uuid::Uuid> = HashSet::new();
    assert!(peripheral.set_session_uuids(empty).await.is_ok());
}
