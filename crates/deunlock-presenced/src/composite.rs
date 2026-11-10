//! One `Peripheral` made of several backends.
//!
//! The orchestrator owns a single `Arc<dyn Peripheral>`. With two transports
//! (BLE and LAN) that is a problem: the daemon must not know which one the phone
//! is on, and a phone that walks out of Bluetooth range must still be reachable
//! over Wi-Fi.
//!
//! `CompositePeripheral` fans a challenge out to every backend and takes the
//! first response that arrives. A backend that has no live session answers with
//! an error immediately — which is exactly what "the phone is not on this
//! transport" should look like.
//!
//! Failure policy: a challenge fails only when *every* backend failed, and the
//! reported error prefers a timeout over a "no session" so the caller's log says
//! "the phone did not answer" rather than "the phone was never there".

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use deunlock_transport::{BondKey, Peripheral, PeripheralError};
use uuid::Uuid;
use futures::stream::{FuturesUnordered, StreamExt as _};

/// A peripheral that speaks through several transports at once.
pub struct CompositePeripheral {
    backends: Vec<(&'static str, Arc<dyn Peripheral + Send + Sync>)>,
}

impl std::fmt::Debug for CompositePeripheral {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompositePeripheral")
            .field("backends", &self.backends.iter().map(|(n, _)| *n).collect::<Vec<_>>())
            .finish()
    }
}

impl CompositePeripheral {
    /// Build a composite over `backends`. A single backend is legal and makes
    /// the daemon's code path identical whether or not the LAN is enabled.
    #[must_use]
    pub fn new(backends: Vec<(&'static str, Arc<dyn Peripheral + Send + Sync>)>) -> Arc<Self> {
        Arc::new(Self { backends })
    }

    /// Names of the wired backends, for the startup log line.
    #[must_use]
    pub fn backend_names(&self) -> Vec<&'static str> {
        self.backends.iter().map(|(name, _)| *name).collect()
    }
}

#[async_trait::async_trait]
impl Peripheral for CompositePeripheral {
    async fn check_health(&self) -> Result<(), PeripheralError> {
        let mut last: Option<PeripheralError> = None;
        for (name, backend) in &self.backends {
            match backend.check_health().await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    tracing::warn!(backend = %name, error = %e, "backend health check failed");
                    last = Some(e);
                }
            }
        }
        Err(last.unwrap_or(PeripheralError::Backend {
            reason: "no transport backends configured".to_owned(),
        }))
    }

    async fn add_peer(&self, peer_id: &str, bond_key: &BondKey) -> Result<(), PeripheralError> {
        let mut first_error: Option<PeripheralError> = None;
        let mut added_anywhere = false;
        for (name, backend) in &self.backends {
            match backend.add_peer(peer_id, bond_key).await {
                Ok(()) => added_anywhere = true,
                // A backend that already knows the peer is not a failure: the
                // other one may still be registering it for the first time.
                Err(PeripheralError::PeerAlreadyAdded { .. }) => added_anywhere = true,
                Err(e) => {
                    tracing::warn!(backend = %name, error = %e, "add_peer failed on a backend");
                    first_error.get_or_insert(e);
                }
            }
        }
        if added_anywhere {
            return Ok(());
        }
        Err(first_error.unwrap_or(PeripheralError::Backend {
            reason: "no transport backends configured".to_owned(),
        }))
    }

    async fn remove_peer(&self, peer_id: &str) -> Result<(), PeripheralError> {
        let mut known = false;
        let mut first_error: Option<PeripheralError> = None;
        for (name, backend) in &self.backends {
            match backend.remove_peer(peer_id).await {
                Ok(()) => known = true,
                Err(PeripheralError::UnknownPeer { .. }) => {}
                Err(e) => {
                    tracing::warn!(backend = %name, error = %e, "remove_peer failed on a backend");
                    first_error.get_or_insert(e);
                }
            }
        }
        if known {
            return Ok(());
        }
        Err(first_error.unwrap_or(PeripheralError::UnknownPeer {
            peer_id: peer_id.to_owned(),
        }))
    }

    async fn set_session_uuids(&self, uuids: HashSet<Uuid>) -> Result<(), PeripheralError> {
        for (name, backend) in &self.backends {
            if let Err(e) = backend.set_session_uuids(uuids.clone()).await {
                // BLE rotates the advertised UUID set; LAN has nothing to rotate
                // and ignores it. A failure here must not stop the daemon.
                tracing::warn!(backend = %name, error = %e, "set_session_uuids failed");
            }
        }
        Ok(())
    }

    async fn notify_challenge(&self, peer_id: &str, frame: &[u8]) -> Result<(), PeripheralError> {
        let mut delivered = 0usize;
        let mut first_error: Option<PeripheralError> = None;
        for (name, backend) in &self.backends {
            match backend.notify_challenge(peer_id, frame).await {
                Ok(()) => delivered += 1,
                Err(e) => {
                    tracing::debug!(backend = %name, error = %e, "challenge not deliverable here");
                    first_error.get_or_insert(e);
                }
            }
        }
        if delivered > 0 {
            return Ok(());
        }
        Err(first_error.unwrap_or(PeripheralError::Backend {
            reason: "no transport backends configured".to_owned(),
        }))
    }

    async fn wait_for_response(&self, peer_id: &str, deadline: Duration) -> Result<Vec<u8>, PeripheralError> {
        let mut pending = FuturesUnordered::new();
        for (name, backend) in &self.backends {
            let backend = Arc::clone(backend);
            let peer = peer_id.to_owned();
            pending.push(async move {
                let outcome = backend.wait_for_response(&peer, deadline).await;
                (*name, outcome)
            });
        }

        let mut errors: Vec<(&'static str, PeripheralError)> = Vec::new();
        while let Some((name, outcome)) = pending.next().await {
            match outcome {
                Ok(bytes) => return Ok(bytes),
                Err(e) => errors.push((name, e)),
            }
        }

        // Keep a timeout if any backend produced one: "the phone did not answer"
        // is more informative than "this transport has no session".
        let mut timeout_seen: Option<PeripheralError> = None;
        let mut other_seen: Option<PeripheralError> = None;
        for (_, e) in errors {
            if matches!(e, PeripheralError::ResponseTimeout { .. }) {
                timeout_seen.get_or_insert(e);
            } else {
                other_seen.get_or_insert(e);
            }
        }
        Err(timeout_seen
            .or(other_seen)
            .unwrap_or(PeripheralError::Backend {
                reason: "no transport backends configured".to_owned(),
            }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// What a scripted backend does when asked for a response.
    #[derive(Clone)]
    enum Outcome {
        /// No live session: `notify_challenge` fails, `wait` is unknown-peer.
        NoSession,
        /// A session that answers immediately with these bytes.
        Signature(Vec<u8>),
        /// A session that never answers.
        Timeout,
    }

    /// A backend with a scripted response.
    struct Scripted {
        name: &'static str,
        outcome: Outcome,
        challenges: AtomicUsize,
    }

    impl Scripted {
        fn new(name: &'static str, outcome: Outcome) -> Arc<Self> {
            Arc::new(Self {
                name,
                outcome,
                challenges: AtomicUsize::new(0),
            })
        }
    }

    #[async_trait::async_trait]
    impl Peripheral for Scripted {
        async fn add_peer(&self, _peer_id: &str, _bond_key: &BondKey) -> Result<(), PeripheralError> {
            Ok(())
        }
        async fn remove_peer(&self, _peer_id: &str) -> Result<(), PeripheralError> {
            Ok(())
        }
        async fn set_session_uuids(&self, _uuids: HashSet<Uuid>) -> Result<(), PeripheralError> {
            Ok(())
        }
        async fn notify_challenge(&self, _peer_id: &str, _frame: &[u8]) -> Result<(), PeripheralError> {
            match self.outcome {
                Outcome::Signature(_) | Outcome::Timeout => {
                    self.challenges.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
                Outcome::NoSession => Err(PeripheralError::Backend {
                    reason: format!("{}: no live session", self.name),
                }),
            }
        }
        async fn wait_for_response(&self, peer_id: &str, _deadline: Duration) -> Result<Vec<u8>, PeripheralError> {
            match self.outcome.clone() {
                Outcome::Signature(bytes) => Ok(bytes),
                Outcome::Timeout => Err(PeripheralError::ResponseTimeout {
                    peer_id: peer_id.to_owned(),
                    deadline_ms: 30,
                }),
                Outcome::NoSession => Err(PeripheralError::UnknownPeer {
                    peer_id: peer_id.to_owned(),
                }),
            }
        }
    }

    #[tokio::test]
    async fn a_response_from_whichever_transport_answers_wins() {
        let ble = Scripted::new("ble", Outcome::NoSession);
        let lan = Scripted::new("lan", Outcome::Signature(b"signature".to_vec()));
        let composite = CompositePeripheral::new(vec![
            ("ble", Arc::clone(&ble) as Arc<dyn Peripheral + Send + Sync>),
            ("lan", Arc::clone(&lan) as Arc<dyn Peripheral + Send + Sync>),
        ]);

        composite
            .notify_challenge("peer", b"frame")
            .await
            .expect("delivered somewhere");
        assert_eq!(ble.challenges.load(Ordering::SeqCst), 0, "no session on BLE");
        assert_eq!(lan.challenges.load(Ordering::SeqCst), 1);

        let signature = composite
            .wait_for_response("peer", Duration::from_millis(50))
            .await
            .expect("response");
        assert_eq!(signature, b"signature");
    }

    #[tokio::test]
    async fn a_challenge_nobody_can_carry_fails_with_the_transport_reason() {
        let ble = Scripted::new("ble", Outcome::NoSession);
        let lan = Scripted::new("lan", Outcome::NoSession);
        let composite = CompositePeripheral::new(vec![
            ("ble", Arc::clone(&ble) as Arc<dyn Peripheral + Send + Sync>),
            ("lan", Arc::clone(&lan) as Arc<dyn Peripheral + Send + Sync>),
        ]);
        match composite.notify_challenge("peer", b"frame").await {
            Err(PeripheralError::Backend { reason }) => {
                assert!(reason.contains("no live session"), "reason: {reason}");
            }
            other => panic!("expected a Backend error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_timeout_is_reported_in_preference_to_a_missing_session() {
        let ble = Scripted::new("ble", Outcome::NoSession);
        let lan = Scripted::new(
            "lan",
            Outcome::Timeout,
        );
        let composite = CompositePeripheral::new(vec![
            ("ble", Arc::clone(&ble) as Arc<dyn Peripheral + Send + Sync>),
            ("lan", Arc::clone(&lan) as Arc<dyn Peripheral + Send + Sync>),
        ]);
        match composite.wait_for_response("peer", Duration::from_millis(30)).await {
            Err(PeripheralError::ResponseTimeout { .. }) => {}
            other => panic!("expected ResponseTimeout, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn peer_registration_survives_a_backend_that_already_knows_the_peer() {
        struct AlreadyThere;
        #[async_trait::async_trait]
        impl Peripheral for AlreadyThere {
            async fn add_peer(&self, peer_id: &str, _bond_key: &BondKey) -> Result<(), PeripheralError> {
                Err(PeripheralError::PeerAlreadyAdded {
                    peer_id: peer_id.to_owned(),
                })
            }
            async fn remove_peer(&self, _peer_id: &str) -> Result<(), PeripheralError> {
                Ok(())
            }
            async fn set_session_uuids(&self, _uuids: HashSet<Uuid>) -> Result<(), PeripheralError> {
                Ok(())
            }
            async fn notify_challenge(&self, _peer_id: &str, _frame: &[u8]) -> Result<(), PeripheralError> {
                Ok(())
            }
            async fn wait_for_response(&self, _peer_id: &str, _deadline: Duration) -> Result<Vec<u8>, PeripheralError> {
                Ok(Vec::new())
            }
        }

        let composite = CompositePeripheral::new(vec![
            ("ble", Arc::new(AlreadyThere) as Arc<dyn Peripheral + Send + Sync>),
            ("lan", Arc::new(AlreadyThere) as Arc<dyn Peripheral + Send + Sync>),
        ]);
        assert!(composite.add_peer("peer", &[0u8; 32]).await.is_ok());
        assert_eq!(composite.backend_names(), vec!["ble", "lan"]);
    }
}
