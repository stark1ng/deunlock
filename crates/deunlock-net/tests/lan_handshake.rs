//! End-to-end LAN handshake over a real loopback socket.
//!
//! These tests exercise the contract the phone implements: connect, complete a
//! TLS 1.3 handshake against the pinned certificate, exchange one framed
//! message, hang up. A wrong pin must fail *before* any frame can be written.

use std::net::IpAddr;
use std::sync::Arc;

use deunlock_net::{
    ALPN_PROTOCOL, LanIdentity, NetError, pinned_client_config, read_message, server_config, write_message,
};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::ServerName;

/// Serve exactly one connection: read a message, echo it back uppercased.
async fn serve_once(identity: &LanIdentity) -> (std::net::SocketAddr, tokio::task::JoinHandle<Result<(), NetError>>) {
    let config = server_config(identity).expect("server config");
    let acceptor = TlsAcceptor::from(config);
    let listener = TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0))
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let handle = tokio::spawn(async move {
        let (tcp, _peer) = listener.accept().await?;
        let mut tls = acceptor.accept(tcp).await.map_err(|e| NetError::Handshake(e.to_string()))?;
        let message = read_message(&mut tls).await?;
        let echo = message.to_ascii_uppercase();
        write_message(&mut tls, &echo).await?;
        Ok(())
    });
    (addr, handle)
}

async fn connect(
    addr: std::net::SocketAddr,
    fingerprint: [u8; 32],
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, NetError> {
    let config = pinned_client_config(fingerprint);
    let connector = tokio_rustls::TlsConnector::from(config);
    let tcp = TcpStream::connect(addr).await?;
    let name = ServerName::try_from("deunlock.local").expect("server name");
    connector
        .connect(name, tcp)
        .await
        .map_err(|e| NetError::Handshake(e.to_string()))
}

#[tokio::test]
async fn a_pinned_client_completes_the_handshake_and_exchanges_a_message() {
    let identity = LanIdentity::generate().expect("identity");
    let (addr, server) = serve_once(&identity).await;

    let config = pinned_client_config(identity.fingerprint());
    let connector = tokio_rustls::TlsConnector::from(config);
    let tcp = TcpStream::connect(addr).await.expect("tcp");
    let name = ServerName::try_from("deunlock.local").expect("name");
    let mut tls = connector.connect(name, tcp).await.expect("handshake");

    let (_, session) = tls.get_ref();
    assert_eq!(session.alpn_protocol(), Some(ALPN_PROTOCOL), "ALPN must be deunlock/2");

    write_message(&mut tls, b"dlc2-challenge").await.expect("write");
    let echo = read_message(&mut tls).await.expect("read");
    assert_eq!(echo, b"DLC2-CHALLENGE");

    server.await.expect("join").expect("server");
}

#[tokio::test]
async fn a_client_pinning_the_wrong_certificate_never_reaches_the_protocol() {
    let identity = LanIdentity::generate().expect("identity");
    let other = LanIdentity::generate().expect("other identity");
    let (addr, server) = serve_once(&identity).await;

    let wrong_pin = other.fingerprint();
    assert_ne!(wrong_pin, identity.fingerprint());
    match connect(addr, wrong_pin).await {
        Err(NetError::Handshake(_)) => {}
        Ok(_) => panic!("a wrong pin must fail the handshake"),
        Err(other) => panic!("expected a handshake failure, got {other:?}"),
    }

    // The server side sees the aborted handshake, never a frame.
    let served = server.await.expect("join");
    assert!(served.is_err(), "server must not have completed a session");
}

#[tokio::test]
async fn a_hostile_length_prefix_does_not_get_allocated() {
    let identity = LanIdentity::generate().expect("identity");
    let config = server_config(&identity).expect("server config");
    let acceptor = TlsAcceptor::from(config);
    let listener = TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0)).await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server = tokio::spawn(async move {
        let (tcp, _peer) = listener.accept().await?;
        let mut tls = acceptor.accept(tcp).await.map_err(|e| NetError::Handshake(e.to_string()))?;
        read_message(&mut tls).await
    });

    let config = pinned_client_config(identity.fingerprint());
    let connector = tokio_rustls::TlsConnector::from(config);
    let tcp = TcpStream::connect(addr).await.expect("tcp");
    let name = ServerName::try_from("deunlock.local").expect("name");
    let mut tls = connector.connect(name, tcp).await.expect("handshake");
    {
        use tokio::io::AsyncWriteExt as _;
        tls.write_all(&u32::MAX.to_be_bytes()).await.expect("prefix");
        tls.flush().await.expect("flush");
    }

    match server.await.expect("join") {
        Err(NetError::MessageTooLarge { .. }) => {}
        other => panic!("expected MessageTooLarge, got {other:?}"),
    }
}

#[test]
fn the_identity_round_trips_through_disk_and_keeps_its_pin() {
    let dir = tempfile::tempdir().expect("tmp");
    let cert = dir.path().join("net.crt");
    let key = dir.path().join("net.key");
    let first = LanIdentity::load_or_create(&cert, &key).expect("create");
    let second = LanIdentity::load_or_create(&cert, &key).expect("reload");
    assert_eq!(first.fingerprint(), second.fingerprint());
    assert_eq!(first.fingerprint_hex().len(), 64);
    let _ = Arc::strong_count(&server_config(&first).expect("config"));
}
