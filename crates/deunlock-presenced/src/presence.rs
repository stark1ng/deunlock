//! Who has actually answered lately.
//!
//! A bond can outlive the phone: it is revoked on the device, lost, or wiped.
//! The desktop then keeps a peer it will never hear from again, and — because
//! `pam_deunlock.so` installs as `sufficient` — every `sudo` spends the full
//! human-scale deadline waiting before falling through to the password. Measured
//! on the real phone, the approved round-trip is ~4 s and the deadline is 25 s,
//! so a dead bond costs twenty seconds per authentication, indefinitely.
//!
//! Liveness inside the daemon is `Instant`-based and resets when it restarts, so
//! it cannot answer "has this phone been seen since Tuesday". This store
//! persists the last *contact* per peer — contact meaning the phone answered,
//! not that a challenge was attempted — and the orchestrator shortens the
//! deadline for peers whose last answer is old.
//!
//! Deliberately not a timer that deletes bonds: silently discarding key material
//! is a security decision, and the daemon is not the right place to make one
//! unattended. It only stops paying for a peer that is not there.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// A peer that has not answered for this long counts as stale.
///
/// A day: long enough that a weekend away does not shorten anything, short
/// enough that a bond to a phone that is gone stops costing time quickly.
pub const STALE_AFTER_MS: u64 = 24 * 60 * 60 * 1_000;

/// Deadline applied to a stale peer, regardless of what the caller asked for.
///
/// Long enough that a phone which *is* there but slow — waking, prompting,
/// waiting for a fingerprint — still lands most attempts, short enough that a
/// phone which is not there costs three seconds instead of twenty-five.
pub const STALE_DEADLINE_MS: u64 = 3_000;

/// Milliseconds since the Unix epoch, saturating at `u64::MAX`.
#[must_use]
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(u64::MAX, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Persisted "last answer" per peer id.
///
/// The file is a flat `peer_id=unix_ms` map, not TOML: it is machine state, it
/// is rewritten on every unlock attempt, and it must never be mistaken for the
/// operator-editable bond store next to it. A missing or unreadable file is not
/// an error — it means "nothing known", which reads as "not stale" so a fresh
/// install keeps the human-scale deadline.
#[derive(Debug)]
pub struct PresenceStore {
    path: PathBuf,
    seen: BTreeMap<String, u64>,
}

impl PresenceStore {
    /// Load the store beside the bond file, or start empty.
    #[must_use]
    pub fn load(state_dir: &Path) -> Self {
        let path = state_dir.join("last_seen");
        let seen = std::fs::read_to_string(&path)
            .map(|text| parse_seen(&text))
            .unwrap_or_default();
        Self { path, seen }
    }

    /// Build a store that is never written to disk (tests, and callers that want
    /// no state at all).
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            path: PathBuf::new(),
            seen: BTreeMap::new(),
        }
    }

    /// Record that `peer_id` answered at `at_ms`.
    pub fn mark(&mut self, peer_id: &str, at_ms: u64) {
        self.seen.insert(peer_id.to_owned(), at_ms);
    }

    /// Record that `peer_id` answered now, and persist.
    ///
    /// Persisting on the write path rather than on a timer keeps the file honest
    /// across a crash or a reboot, and it costs one small rewrite per unlock
    /// attempt — a handful per day.
    pub fn mark_now(&mut self, peer_id: &str) -> u64 {
        let at = now_ms();
        self.mark(peer_id, at);
        self.save();
        at
    }

    /// Milliseconds since `peer_id` last answered, or `None` if never.
    #[must_use]
    pub fn last_seen_ms_ago(&self, peer_id: &str, now: u64) -> Option<u64> {
        let at = *self.seen.get(peer_id)?;
        Some(now.saturating_sub(at))
    }

    /// True when the peer has answered, but not for [`STALE_AFTER_MS`].
    ///
    /// A peer with no record is *not* stale: never-seen is indistinguishable
    /// from "freshly paired and the daemon just restarted", and shortening the
    /// deadline there would break the first legitimate unlock after a reboot.
    #[must_use]
    pub fn is_stale(&self, peer_id: &str, now: u64) -> bool {
        self.last_seen_ms_ago(peer_id, now)
            .is_some_and(|ago| ago > STALE_AFTER_MS)
    }

    /// Forget a peer (bond revoked or removed).
    pub fn forget(&mut self, peer_id: &str) {
        if self.seen.remove(peer_id).is_some() {
            self.save();
        }
    }

    /// Persist. Missing directory or a permissions problem is logged and
    /// swallowed: presence is an optimisation, never a reason to fail an unlock.
    pub fn save(&self) {
        if self.path.as_os_str().is_empty() {
            return;
        }
        let mut body = String::with_capacity(self.seen.len() * 24);
        for (peer, at) in &self.seen {
            body.push_str(peer);
            body.push('=');
            body.push_str(&at.to_string());
            body.push('\n');
        }
        let tmp = self.path.with_extension("tmp");
        let write = std::fs::File::create(&tmp).and_then(|mut file| {
            file.write_all(body.as_bytes())?;
            file.sync_all()
        });
        if let Err(err) = write.and_then(|()| std::fs::rename(&tmp, &self.path)) {
            tracing::warn!(path = %self.path.display(), error = %err, "presence store write failed");
        }
    }

    /// Number of peers with a recorded answer (tests and `doctor`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// True when nothing has been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

fn parse_seen(text: &str) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let Some((peer, at)) = line.split_once('=') else {
            continue;
        };
        let peer = peer.trim();
        if peer.is_empty() {
            continue;
        }
        if let Ok(at) = at.trim().parse::<u64>() {
            out.insert(peer.to_owned(), at);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_peer_is_not_stale() {
        let store = PresenceStore::in_memory();
        assert!(!store.is_stale("peer", now_ms()));
    }

    #[test]
    fn a_recent_answer_is_not_stale() {
        let mut store = PresenceStore::in_memory();
        store.mark("peer", 1_000);
        assert!(!store.is_stale("peer", 1_000 + STALE_AFTER_MS));
    }

    #[test]
    fn an_old_answer_is_stale() {
        let mut store = PresenceStore::in_memory();
        store.mark("peer", 1_000);
        assert!(store.is_stale("peer", 1_000 + STALE_AFTER_MS + 1));
    }

    #[test]
    fn a_peer_marks_independently_of_its_neighbour() {
        let mut store = PresenceStore::in_memory();
        store.mark("old", 1_000);
        store.mark("fresh", 1_000 + STALE_AFTER_MS);
        let now = 1_000 + STALE_AFTER_MS + 2;
        assert!(store.is_stale("old", now));
        assert!(!store.is_stale("fresh", now));
    }

    #[test]
    fn the_store_round_trips_through_disk() {
        let td = tempfile::TempDir::new().expect("tempdir");
        let mut store = PresenceStore::load(td.path());
        store.mark("peer-a", 111);
        store.mark("peer-b", 222);
        store.save();

        let reloaded = PresenceStore::load(td.path());
        assert_eq!(reloaded.len(), 2);
        assert_eq!(reloaded.last_seen_ms_ago("peer-a", 500), Some(389));
        assert_eq!(reloaded.last_seen_ms_ago("peer-b", 500), Some(278));
    }

    #[test]
    fn a_corrupt_file_reads_as_nothing_known() {
        let td = tempfile::TempDir::new().expect("tempdir");
        std::fs::write(td.path().join("last_seen"), "garbage\n\n=42\npeer=nope\n").expect("write");
        let store = PresenceStore::load(td.path());
        assert!(store.is_empty(), "unparseable lines must be skipped, not guessed");
    }

    #[test]
    fn forgetting_a_peer_drops_the_record_from_disk() {
        let td = tempfile::TempDir::new().expect("tempdir");
        let mut store = PresenceStore::load(td.path());
        store.mark("peer", 5);
        store.save();
        store.forget("peer");
        assert!(PresenceStore::load(td.path()).is_empty());
    }

    #[test]
    fn a_clock_that_went_backwards_does_not_report_huge_ages() {
        let mut store = PresenceStore::in_memory();
        store.mark("peer", 10_000);
        assert_eq!(store.last_seen_ms_ago("peer", 5_000), Some(0));
        assert!(!store.is_stale("peer", 5_000));
    }
}
