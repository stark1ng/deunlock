//! A bond outlives the phone. When it does, the desktop must not pay the
//! human-scale deadline on every authentication — `pam_deunlock.so` installs as
//! `sufficient`, so the wait happens *before* the password prompt, every time,
//! forever. These tests pin both halves of the rule: a peer that has not
//! answered for a day gets a short deadline, and a peer that answers keeps the
//! full one (its clock restarts).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant};

use deunlock_core::{Bond, BondStatus, BondStore, SigningKey};
use deunlock_presenced::{ChallengeOutcome, Orchestrator, PresenceStore, STALE_AFTER_MS, STALE_DEADLINE_MS};
use deunlock_transport::{BOND_KEY_BYTES, FakePeripheral, Peripheral};
use tempfile::TempDir;
use time::OffsetDateTime;
use tokio::time::Instant;

const BOND_KEY: [u8; BOND_KEY_BYTES] = [0x31; BOND_KEY_BYTES];

fn fixture_bond(peer_id: &str) -> Bond {
    let signing_key = SigningKey::from_bytes(&[0x11u8; 32]);
    let bytes = signing_key.verifying_key().to_bytes();
    let mut pubkey = [0u8; deunlock_core::bond::PUBKEY_LEN];
    pubkey.copy_from_slice(&bytes);
    Bond {
        peer_id: peer_id.to_owned(),
        pubkey,
        name: "presence-test".to_owned(),
        created_at: OffsetDateTime::UNIX_EPOCH,
        status: BondStatus::Bonded,
    }
}

fn seed(dir: &TempDir, bond: &Bond) -> (PathBuf, PathBuf) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("tighten tempdir");
    }
    let bonds_file = dir.path().join("bonds.toml");
    let keys_dir = dir.path().join("keys");
    std::fs::create_dir_all(&keys_dir).expect("keys dir");
    let mut store = BondStore::empty();
    store.add(bond.clone()).expect("add bond");
    store.save(&bonds_file).expect("save store");
    std::fs::write(keys_dir.join(format!("{}.bin", bond.peer_id)), BOND_KEY).expect("key file");
    (bonds_file, keys_dir)
}

async fn build(
    fake: Arc<FakePeripheral>,
    bond: &Bond,
    bonds_file: PathBuf,
    keys_dir: PathBuf,
) -> Arc<Orchestrator> {
    let peripheral: Arc<dyn Peripheral + Send + Sync> = fake.clone();
    let start = Instant::now() + Duration::from_secs(deunlock_presenced::SECONDS_PER_MINUTE);
    let orchestrator = Arc::new(Orchestrator::with_peers_and_audit(
        peripheral,
        vec![(bond.clone(), BOND_KEY)],
        bonds_file,
        keys_dir,
        start,
        None,
    ));
    fake.add_peer(&bond.peer_id, &BOND_KEY)
        .await
        .expect("add_peer");
    orchestrator
}

fn write_last_seen(bonds_file: &std::path::Path, peer_id: &str, at_ms: u64) {
    let path = bonds_file.parent().expect("parent").join("last_seen");
    std::fs::write(path, format!("{peer_id}={at_ms}\n")).expect("write last_seen");
}

#[tokio::test]
async fn a_peer_unseen_for_a_day_gets_a_short_deadline() {
    let bond = fixture_bond("peer-stale");
    let td = TempDir::new().expect("tempdir");
    let (bonds_file, keys_dir) = seed(&td, &bond);
    let now = deunlock_presenced::presence::now_ms();
    write_last_seen(&bonds_file, &bond.peer_id, now - STALE_AFTER_MS - 60_000);
    let fake = FakePeripheral::new();
    let orchestrator = build(fake, &bond, bonds_file, keys_dir).await;

    assert_eq!(
        orchestrator
            .effective_deadline_for_test(&bond.peer_id, Duration::from_secs(25))
            .await,
        Duration::from_millis(STALE_DEADLINE_MS)
    );

    // And the shortening is live, not just arithmetic: the call returns in the
    // short deadline instead of sitting on the 25 s one.
    let started = StdInstant::now();
    let outcome = orchestrator
        .issue_challenge(&bond.peer_id, Duration::from_secs(25))
        .await;
    let elapsed = started.elapsed();
    assert!(
        matches!(outcome, ChallengeOutcome::TimedOut),
        "expected TimedOut, got {outcome:?}"
    );
    assert!(
        elapsed < Duration::from_secs(6),
        "a stale peer must not hold sudo for the full deadline, waited {elapsed:?}"
    );
}

#[tokio::test]
async fn a_peer_seen_recently_keeps_the_requested_deadline() {
    let bond = fixture_bond("peer-fresh");
    let td = TempDir::new().expect("tempdir");
    let (bonds_file, keys_dir) = seed(&td, &bond);
    write_last_seen(&bonds_file, &bond.peer_id, deunlock_presenced::presence::now_ms());
    let fake = FakePeripheral::new();
    let orchestrator = build(fake, &bond, bonds_file, keys_dir).await;

    assert_eq!(
        orchestrator
            .effective_deadline_for_test(&bond.peer_id, Duration::from_secs(25))
            .await,
        Duration::from_secs(25)
    );
}

#[tokio::test]
async fn a_peer_never_seen_keeps_the_requested_deadline() {
    // Never-seen is indistinguishable from "paired, then the daemon restarted":
    // shortening it would break the first legitimate unlock after a reboot.
    let bond = fixture_bond("peer-unknown-presence");
    let td = TempDir::new().expect("tempdir");
    let (bonds_file, keys_dir) = seed(&td, &bond);
    let fake = FakePeripheral::new();
    let orchestrator = build(fake, &bond, bonds_file, keys_dir).await;

    assert_eq!(
        orchestrator
            .effective_deadline_for_test(&bond.peer_id, Duration::from_secs(25))
            .await,
        Duration::from_secs(25)
    );
}

#[tokio::test]
async fn a_shorter_request_is_never_stretched() {
    let bond = fixture_bond("peer-stale-short-request");
    let td = TempDir::new().expect("tempdir");
    let (bonds_file, keys_dir) = seed(&td, &bond);
    let now = deunlock_presenced::presence::now_ms();
    write_last_seen(&bonds_file, &bond.peer_id, now - STALE_AFTER_MS - 60_000);
    let fake = FakePeripheral::new();
    let orchestrator = build(fake, &bond, bonds_file, keys_dir).await;

    assert_eq!(
        orchestrator
            .effective_deadline_for_test(&bond.peer_id, Duration::from_millis(800))
            .await,
        Duration::from_millis(800)
    );
}

#[tokio::test]
async fn a_denial_still_proves_the_phone_is_there() {
    let bond = fixture_bond("peer-denies");
    let td = TempDir::new().expect("tempdir");
    let (bonds_file, keys_dir) = seed(&td, &bond);
    let fake = FakePeripheral::new();
    let orchestrator = build(fake.clone(), &bond, bonds_file.clone(), keys_dir).await;

    // An all-zero signature is the phone saying "the operator declined".
    fake.inject_response(&bond.peer_id, vec![0u8; deunlock_core::SIGNATURE_LEN]);
    let outcome = orchestrator
        .issue_challenge(&bond.peer_id, Duration::from_secs(5))
        .await;
    assert!(
        matches!(outcome, ChallengeOutcome::UserDeclined),
        "expected UserDeclined, got {outcome:?}"
    );

    let state_dir = bonds_file.parent().expect("parent");
    let presence = PresenceStore::load(state_dir);
    assert_eq!(
        presence.len(),
        1,
        "any answer must restart the presence clock, including a refusal"
    );
    assert!(!presence.is_stale(&bond.peer_id, deunlock_presenced::presence::now_ms()));
    assert!(
        presence.last_seen_ms_ago(&bond.peer_id, deunlock_presenced::presence::now_ms()).is_some(),
        "the answer must be visible in `deunlock status`"
    );
}
