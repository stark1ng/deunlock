// D-28 — an answer to a challenge that is no longer open must not poison the
// next one.
//
// W-1 cancels a challenge the moment the operator types a password: the PAM
// module closes the socket, the daemon abandons the wait. The phone, however,
// has already been notified and keeps showing its prompt (that withdrawal is
// still open, AUDIT-001 D-27). When the operator then touches the sensor, the
// answer arrives *during* the next challenge — and since the answer is 64 bytes
// with no reference to the question, it was consumed as if it were the answer to
// the new one and rejected as a bad signature.
//
// Measured live before this test existed:
//
//   12:24:37 notify_challenge …               (attempt 1, cancelled at :38)
//   12:24:40 notify_challenge …               (attempt 2)
//   12:24:45 WARN bad signature: …            (the answer to attempt 1)
//
// The daemon now keeps the last few issued challenges and, on a verification
// failure, asks whether the signature belongs to one of those. If it does, it is
// a late answer to a withdrawn prompt, not an attack: ignore it and keep waiting
// for the answer to the challenge that is actually open.

use std::{sync::Arc, time::Duration};

use deunlock_core::{
    Bond, BondStatus, Frame, NONCE_LEN, SigningKey, bond::PUBKEY_LEN, peer_id_from_pubkey, sign_frame,
};
use deunlock_presenced::{AuditLog, ChallengeOutcome, Orchestrator};
use deunlock_transport::{BOND_KEY_BYTES, FakePeripheral, Peripheral};
use time::OffsetDateTime;
use tokio::time::Instant;

const SIGNING_KEY_SEED: [u8; 32] = [
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80,
];

const BOND_KEY: [u8; BOND_KEY_BYTES] = [0xDD; BOND_KEY_BYTES];

fn fixture(signing_key: &SigningKey) -> Bond {
    let pubkey_bytes = signing_key.verifying_key().to_bytes();
    let mut pubkey = [0u8; PUBKEY_LEN];
    pubkey.copy_from_slice(&pubkey_bytes);
    Bond {
        peer_id: peer_id_from_pubkey(&pubkey),
        pubkey,
        name: "stale-answer".to_owned(),
        created_at: OffsetDateTime::UNIX_EPOCH,
        status: BondStatus::Bonded,
    }
}

async fn build(fake: Arc<FakePeripheral>, bond: &Bond, state_dir: &std::path::Path) -> Arc<Orchestrator> {
    let peripheral: Arc<dyn Peripheral + Send + Sync> = fake.clone();
    let audit = AuditLog::open(&state_dir.join("last.log")).expect("audit log");
    let start = Instant::now() + Duration::from_secs(deunlock_presenced::SECONDS_PER_MINUTE);
    let orchestrator = Arc::new(Orchestrator::with_peers_and_audit(
        peripheral,
        vec![(bond.clone(), BOND_KEY)],
        state_dir.join("bonds.toml"),
        state_dir.join("keys"),
        start,
        Some(audit),
    ));
    fake.add_peer(&bond.peer_id, &BOND_KEY).await.expect("fake add_peer");
    orchestrator
}

/// Sign the frame the orchestrator notified, as the phone would.
fn sign_notified(notify_bytes: &[u8], signing_key: &SigningKey) -> Vec<u8> {
    let frame = Frame::decode(notify_bytes).expect("decode notify");
    sign_frame(signing_key, &frame).expect("sign frame").to_bytes().to_vec()
}

async fn wait_for_notify(fake: &Arc<FakePeripheral>, index: usize) -> Vec<u8> {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if let Some((_, bytes)) = fake.notify_calls().get(index) {
            return bytes.clone();
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("challenge notification #{index} never fired");
}

#[tokio::test]
async fn an_answer_to_an_abandoned_challenge_is_ignored_not_denied() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let signing_key = SigningKey::from_bytes(&SIGNING_KEY_SEED);
    let bond = fixture(&signing_key);
    let fake: Arc<FakePeripheral> = FakePeripheral::new();
    let orchestrator = build(Arc::clone(&fake), &bond, tmp.path()).await;

    // 1. First attempt, cancelled the way the PAM module cancels it: the future
    //    is dropped after the phone has been notified.
    let nonce_a = [0xA1u8; NONCE_LEN];
    let abandoned = orchestrator.issue_challenge_with_nonce(&bond.peer_id, nonce_a, Duration::from_secs(5));
    assert!(
        tokio::time::timeout(Duration::from_millis(120), abandoned).await.is_err(),
        "the abandoned challenge must not complete on its own"
    );
    let notify_a = wait_for_notify(&fake, 0).await;
    let signature_a = sign_notified(&notify_a, &signing_key);

    // 2. Second attempt. The operator touches the sensor for the *withdrawn*
    //    prompt, so the phone's answer to (1) arrives first.
    let nonce_b = [0xB2u8; NONCE_LEN];
    let second = tokio::spawn({
        let orchestrator = Arc::clone(&orchestrator);
        let peer_id = bond.peer_id.clone();
        async move { orchestrator.issue_challenge_with_nonce(&peer_id, nonce_b, Duration::from_secs(5)).await }
    });
    let notify_b = wait_for_notify(&fake, 1).await;
    let signature_b = sign_notified(&notify_b, &signing_key);

    fake.inject_response(&bond.peer_id, signature_a);
    fake.inject_response(&bond.peer_id, signature_b);

    let outcome = second.await.expect("second challenge joined");
    match outcome {
        ChallengeOutcome::Ok { .. } => {}
        other => panic!("a late answer to the abandoned challenge must be ignored, not deny the next one; got {other:?}"),
    }
}

#[tokio::test]
async fn a_late_answer_never_turns_into_a_timeout_free_success() {
    // The ignore path must not become an accept path: an answer to the abandoned
    // challenge, with nothing else arriving, ends in TimedOut — never Ok.
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let signing_key = SigningKey::from_bytes(&SIGNING_KEY_SEED);
    let bond = fixture(&signing_key);
    let fake: Arc<FakePeripheral> = FakePeripheral::new();
    let orchestrator = build(Arc::clone(&fake), &bond, tmp.path()).await;

    let nonce_a = [0xC3u8; NONCE_LEN];
    let abandoned = orchestrator.issue_challenge_with_nonce(&bond.peer_id, nonce_a, Duration::from_secs(5));
    assert!(tokio::time::timeout(Duration::from_millis(120), abandoned).await.is_err());
    let notify_a = wait_for_notify(&fake, 0).await;
    let signature_a = sign_notified(&notify_a, &signing_key);

    let nonce_b = [0xD4u8; NONCE_LEN];
    let second = tokio::spawn({
        let orchestrator = Arc::clone(&orchestrator);
        let peer_id = bond.peer_id.clone();
        async move {
            orchestrator
                .issue_challenge_with_nonce(&peer_id, nonce_b, Duration::from_millis(400))
                .await
        }
    });
    let _notify_b = wait_for_notify(&fake, 1).await;
    fake.inject_response(&bond.peer_id, signature_a);

    let outcome = second.await.expect("second challenge joined");
    assert!(
        matches!(outcome, ChallengeOutcome::TimedOut),
        "a stale answer must leave the challenge unanswered; got {outcome:?}"
    );
}

#[tokio::test]
async fn a_signature_that_belongs_to_no_challenge_still_fails_closed() {
    // The tightened path must keep the attack-shaped verdict: a signature that
    // verifies against nothing we issued is BadSignature, not "keep waiting".
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let signing_key = SigningKey::from_bytes(&SIGNING_KEY_SEED);
    let bond = fixture(&signing_key);
    let fake: Arc<FakePeripheral> = FakePeripheral::new();
    let orchestrator = build(Arc::clone(&fake), &bond, tmp.path()).await;

    let nonce = [0xE5u8; NONCE_LEN];
    let challenge = tokio::spawn({
        let orchestrator = Arc::clone(&orchestrator);
        let peer_id = bond.peer_id.clone();
        async move { orchestrator.issue_challenge_with_nonce(&peer_id, nonce, Duration::from_secs(5)).await }
    });
    let _notify = wait_for_notify(&fake, 0).await;

    // A valid signature — over bytes nobody asked for.
    let forged = {
        let mut frame = Frame {
            version: deunlock_core::DEUNLOCK_WIRE_VERSION_V1,
            nonce: [0x99u8; NONCE_LEN],
            payload: Vec::new(),
            tag: [0u8; deunlock_core::TAG_LEN],
        };
        frame.tag = deunlock_core::compute_tag(&BOND_KEY, &frame.body_bytes().expect("body"));
        sign_frame(&signing_key, &frame).expect("sign").to_bytes().to_vec()
    };
    fake.inject_response(&bond.peer_id, forged);

    let outcome = challenge.await.expect("challenge joined");
    assert!(
        matches!(outcome, ChallengeOutcome::BadSignature),
        "a signature for no issued challenge must fail closed; got {outcome:?}"
    );
}
