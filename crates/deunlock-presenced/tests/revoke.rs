//! AUDIT-001 D-14: `revoke` used to be one-sided — the phone forgot the bond,
//! the desktop kept challenging a device that no longer held the key, and
//! because pair mode is exclusive to "no bonds" it also stopped advertising
//! itself as pairable. The user-visible symptom was "the computer is not in the
//! list" with a perfectly healthy daemon.
//!
//! These tests pin the other half: a revocation frame arriving on the response
//! characteristic retires the bond record, the key file and the live peer, and
//! is reported as its own outcome so PAM can say "re-pair" instead of "that
//! fingerprint did not match".

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use deunlock_core::{bond::PUBKEY_LEN, encode_revoke, Bond, BondStatus, BondStore, SigningKey};
use deunlock_presenced::{AuditLog, ChallengeOutcome, Orchestrator, OUTCOME_REASON_BOND_REVOKED};
use deunlock_transport::{BOND_KEY_BYTES, FakePeripheral, Peripheral};
use tempfile::TempDir;
use time::OffsetDateTime;
use tokio::time::Instant;

const BOND_KEY: [u8; BOND_KEY_BYTES] = [0x5C; BOND_KEY_BYTES];
const SIGNING_KEY_SEED: [u8; 32] = [0x42; 32];

fn fixture_bond(signing_key: &SigningKey) -> Bond {
    let bytes = signing_key.verifying_key().to_bytes();
    let mut pubkey = [0u8; PUBKEY_LEN];
    pubkey.copy_from_slice(&bytes);
    Bond {
        peer_id: deunlock_core::peer_id_from_pubkey(&pubkey),
        pubkey,
        name: "revoke-test".to_owned(),
        created_at: OffsetDateTime::UNIX_EPOCH,
        status: BondStatus::Bonded,
    }
}

/// Lay down a bond store and key file so `drop_bond` has something real to
/// delete — the whole point of this test is that the *stored* state changes, not
/// just the in-memory peer map.
fn seed_store(dir: &TempDir, bond: &Bond) -> (PathBuf, PathBuf) {
    // BondStore refuses to write into a group/world-readable parent: a bond
    // file is only as private as the directory holding it.
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
    audit_log: AuditLog,
) -> Arc<Orchestrator> {
    let peripheral: Arc<dyn Peripheral + Send + Sync> = fake.clone();
    let start = Instant::now() + Duration::from_secs(deunlock_presenced::SECONDS_PER_MINUTE);
    let orchestrator = Arc::new(Orchestrator::with_peers_and_audit(
        peripheral,
        vec![(bond.clone(), BOND_KEY)],
        bonds_file,
        keys_dir,
        start,
        Some(audit_log),
    ));
    fake.add_peer(&bond.peer_id, &BOND_KEY)
        .await
        .expect("fake add_peer");
    orchestrator
}

fn audit_reasons(path: &std::path::Path) -> Vec<String> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    text.lines()
        .filter_map(|line| line.split(',').nth(5))
        .map(str::to_owned)
        .collect()
}

#[tokio::test]
async fn a_revocation_frame_retires_the_bond_on_the_desktop() {
    let signing_key = SigningKey::from_bytes(&SIGNING_KEY_SEED);
    let bond = fixture_bond(&signing_key);
    let td = TempDir::new().expect("tempdir");
    let (bonds_file, keys_dir) = seed_store(&td, &bond);
    let audit_path = td.path().join("last.log");
    let audit_log = AuditLog::open(&audit_path).expect("audit");
    let fake = FakePeripheral::new();
    let orchestrator = build(fake.clone(), &bond, bonds_file.clone(), keys_dir.clone(), audit_log).await;

    let now_ms = u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
        .expect("clock");
    fake.inject_response(&bond.peer_id, encode_revoke(&BOND_KEY, now_ms));

    let outcome = orchestrator
        .issue_challenge(&bond.peer_id, Duration::from_millis(500))
        .await;
    assert!(
        matches!(outcome, ChallengeOutcome::BondRevoked),
        "expected BondRevoked, got {outcome:?}"
    );

    let stored = std::fs::read_to_string(&bonds_file).expect("bonds file");
    assert!(
        !stored.contains(&bond.peer_id),
        "bond record must be gone from bonds.toml, got:\n{stored}"
    );
    assert!(
        !keys_dir.join(format!("{}.bin", bond.peer_id)).exists(),
        "per-peer key file must be deleted"
    );
    assert_eq!(audit_reasons(&audit_path), vec![OUTCOME_REASON_BOND_REVOKED.to_owned()]);
    assert!(
        orchestrator.peers_snapshot().await.is_empty(),
        "the live peer set must drop the revoked peer"
    );
}

#[tokio::test]
async fn a_revocation_under_the_wrong_key_changes_nothing() {
    let signing_key = SigningKey::from_bytes(&SIGNING_KEY_SEED);
    let bond = fixture_bond(&signing_key);
    let td = TempDir::new().expect("tempdir");
    let (bonds_file, keys_dir) = seed_store(&td, &bond);
    let audit_path = td.path().join("last.log");
    let audit_log = AuditLog::open(&audit_path).expect("audit");
    let fake = FakePeripheral::new();
    let orchestrator = build(fake.clone(), &bond, bonds_file.clone(), keys_dir.clone(), audit_log).await;

    // A stranger's bond key: the tag will not verify, so the frame must fail
    // closed as a bad signature rather than acting as a remote revoke gadget.
    let now_ms = u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
        .expect("clock");
    fake.inject_response(&bond.peer_id, encode_revoke(&[0x77; BOND_KEY_BYTES], now_ms));

    let outcome = orchestrator
        .issue_challenge(&bond.peer_id, Duration::from_millis(500))
        .await;
    assert!(
        matches!(outcome, ChallengeOutcome::BadSignature),
        "expected BadSignature, got {outcome:?}"
    );

    let stored = std::fs::read_to_string(&bonds_file).expect("bonds file");
    assert!(stored.contains(&bond.peer_id), "bond must survive a forged revoke");
    assert!(keys_dir.join(format!("{}.bin", bond.peer_id)).exists());
}
