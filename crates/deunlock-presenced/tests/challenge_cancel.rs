// W-1, daemon half — an abandoned challenge must not hold the peer for 25 s.
//
// The PAM module cancels a challenge by closing the socket the moment the
// operator types a password instead. Before this test the daemon kept waiting
// for a phone nobody was going to answer, so the *next* authentication for the
// same peer came back `busy` for a full deadline — the operator typed a password
// and the next `sudo` within 25 s got "busy" instead of a prompt.
//
// The test drives two callers through the real socket server:
//
//   1. caller A issues a challenge and hangs up before the phone answers;
//   2. caller B issues a challenge for the same single-slot peer, and the
//      phone's signature is injected for whoever is still waiting.
//
// If A's challenge was abandoned, B's wait is the live one and B sees `ok`.
// If it was not, B hits the per-peer semaphore, waits BUSY_QUEUE_DEADLINE, and
// answers `busy` — which is what the assertion below catches.

use std::{path::PathBuf, sync::Arc, time::Duration};

use deunlock_core::{
    Bond, BondStatus, Frame, SigningKey, bond::PUBKEY_LEN, compute_tag, peer_id_from_pubkey, sign_frame,
};
use deunlock_presenced::{AuditLog, Orchestrator, ServeConfig, read_frame, serve, write_frame};
use deunlock_presenced::{Request, Response};
use deunlock_transport::{BOND_KEY_BYTES, FakePeripheral, Peripheral};
use time::OffsetDateTime;
use tokio::{
    net::UnixStream,
    sync::oneshot,
    time::{Instant, sleep, timeout},
};

const SIGNING_KEY_SEED: [u8; 32] = [
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
];

const BOND_KEY: [u8; BOND_KEY_BYTES] = [0xCC; BOND_KEY_BYTES];

fn fixture(signing_key: &SigningKey) -> Bond {
    let pubkey_bytes = signing_key.verifying_key().to_bytes();
    let mut pubkey = [0u8; PUBKEY_LEN];
    pubkey.copy_from_slice(&pubkey_bytes);
    Bond {
        peer_id: peer_id_from_pubkey(&pubkey),
        pubkey,
        name: "cancel-test".to_owned(),
        created_at: OffsetDateTime::UNIX_EPOCH,
        status: BondStatus::Bonded,
    }
}

async fn build_orchestrator(fake: Arc<FakePeripheral>, bond: &Bond, audit_log: AuditLog, state_dir: &std::path::Path) -> Arc<Orchestrator> {
    let peripheral: Arc<dyn Peripheral + Send + Sync> = fake.clone();
    let start = Instant::now() + Duration::from_secs(deunlock_presenced::SECONDS_PER_MINUTE);
    let orchestrator = Arc::new(Orchestrator::with_peers_and_audit(
        peripheral,
        vec![(bond.clone(), BOND_KEY)],
        // Presence bookkeeping (`last_seen`) is written beside the bond store:
        // point it at the tempdir so the test never touches the repo tree.
        state_dir.join("bonds.toml"),
        state_dir.join("keys"),
        start,
        Some(audit_log),
    ));
    fake.add_peer(&bond.peer_id, &BOND_KEY).await.expect("fake add_peer");
    orchestrator
}

/// Sign the challenge the orchestrator notified, as the phone would.
fn sign_notified(notify_bytes: &[u8], signing_key: &SigningKey) -> Vec<u8> {
    let frame = Frame::decode(notify_bytes).expect("decode notify");
    let body = frame.body_bytes().expect("body_bytes");
    assert_eq!(frame.tag, compute_tag(&BOND_KEY, &body));
    sign_frame(signing_key, &frame).expect("sign frame").to_bytes().to_vec()
}

/// Wait for the fake's `index`-th challenge notification.
async fn wait_for_notify(fake: &Arc<FakePeripheral>, index: usize) -> Vec<u8> {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if let Some((_, bytes)) = fake.notify_calls().get(index) {
            return bytes.clone();
        }
        sleep(Duration::from_millis(5)).await;
    }
    panic!("challenge notification #{index} never fired");
}

async fn issue(socket: &PathBuf, peer_id: &str) -> UnixStream {
    let mut stream = UnixStream::connect(socket).await.expect("connect to daemon");
    let request = Request::Challenge {
        peer_id: peer_id.to_owned(),
        nonce: vec![0x5A; deunlock_core::NONCE_LEN],
        service: "sudo".to_owned(),
        user: "romatest".to_owned(),
    };
    write_frame(&mut stream, &request).await.expect("write challenge");
    stream
}

#[tokio::test]
async fn an_abandoned_challenge_frees_the_peer_slot() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let socket = tmp.path().join("auth.sock");
    let signing_key = SigningKey::from_bytes(&SIGNING_KEY_SEED);
    let bond = fixture(&signing_key);
    let fake: Arc<FakePeripheral> = FakePeripheral::new();
    let audit = AuditLog::open(&tmp.path().join("last.log")).expect("audit log");
    let orchestrator = build_orchestrator(Arc::clone(&fake), &bond, audit, tmp.path()).await;

    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let config = ServeConfig {
        socket_path: socket.clone(),
        expected_uid: None,
        reload_tx: None,
        orchestrator: Some(orchestrator),
        host_id: None,
        test_fixed_nonce: None,
        started_at: None,
    };
    let server = tokio::spawn(async move {
        serve(config, async move {
            let _ = stop_rx.await;
        })
        .await
    });
    // Wait for the socket to appear.
    let bind_deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        assert!(std::time::Instant::now() < bind_deadline, "daemon never bound its socket");
        sleep(Duration::from_millis(5)).await;
    }

    // 1. Caller A asks, the phone is asked, then A disappears.
    let caller_a = issue(&socket, &bond.peer_id).await;
    let _first_notify = wait_for_notify(&fake, 0).await;
    drop(caller_a);
    // Let the accept loop notice the hang-up and drop the in-flight challenge.
    sleep(Duration::from_millis(150)).await;

    // 2. Caller B asks for the same single-slot peer and gets the phone's
    //    signature. It must be answered, not queued into `busy`.
    let mut caller_b = issue(&socket, &bond.peer_id).await;
    let second_notify = wait_for_notify(&fake, 1).await;
    fake.inject_response(&bond.peer_id, sign_notified(&second_notify, &signing_key));

    let response = timeout(Duration::from_secs(5), read_frame::<_, Response>(&mut caller_b))
        .await
        .expect("caller B must be answered, not left hanging")
        .expect("decode caller B's response");
    let Response::Challenge { ok, reason, .. } = response else {
        panic!("expected a challenge response, got {response:?}");
    };
    assert_eq!(
        reason,
        deunlock_presenced::OUTCOME_REASON_OK,
        "the abandoned challenge must release the peer slot; caller B was answered with {reason:?}"
    );
    assert!(ok, "the injected signature is valid, so B must be granted");

    let _ = stop_tx.send(());
    let _ = timeout(Duration::from_secs(5), server).await;
}
