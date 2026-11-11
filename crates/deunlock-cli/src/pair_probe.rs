//! `deunlock pair-probe` — stand in for the phone and walk the whole pairing
//! path against a running daemon.
//!
//! Without a phone, the desktop half of QR pairing has no honest way to be
//! exercised: the unit tests hand the listener an offer object, but nothing proves
//! that `pair-qr`'s file, the listener's TLS identity, the bond sink and the daemon
//! configuration agree. This command does exactly what the phone would do — pin the
//! certificate, read the session nonce, send `DLP1`, check `DLP2` — and is the only
//! end-to-end check available until a device is attached.
//!
//! It is deliberately *not* a pairing shortcut: it proves the phone-side bytes work,
//! and the bond it creates is real. Run `deunlock pair-qr` first.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result};
use clap::Args;
use deunlock_core::{PHONE_PUBKEY_BYTES, PairingOffer};

#[derive(Debug, Args)]
pub struct PairProbeOpts {
    /// The pairing payload printed by `deunlock pair-qr`.
    #[arg(long, value_name = "DLQR1...")]
    pub payload: String,
    /// Fail if the desktop does not answer within this many seconds.
    #[arg(long, value_name = "SECONDS", default_value_t = 10)]
    pub timeout: u64,
}

/// Run the probe.
///
/// # Errors
///
/// Any mismatch along the path, with a message naming the step that failed.
pub async fn run(opts: &PairProbeOpts) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let offer = PairingOffer::decode(&opts.payload, now).context("payload rejected")?;
    println!("offer:   {}:{} (pin {})", offer.lan_host, offer.lan_port, hex(&offer.tls_fingerprint[..8]));

    let phone_pubkey = random_public_key()?;
    println!("phone:   {}…", hex(&phone_pubkey[..8]));

    let bond = async {
        let endpoint = format!("{}:{}", offer.lan_host, offer.lan_port);
        let mut tls = deunlock_net::lan::connect_pinned(&endpoint, &offer.tls_fingerprint, Duration::from_secs(opts.timeout))
            .await
            .context("TLS connect")?;

        let challenge = deunlock_net::read_message(&mut tls).await.context("session challenge")?;
        let session_nonce = deunlock_core::decode_session_challenge(&challenge).context("DLS1 record")?;
        println!("step 1:  session nonce received");

        let request = deunlock_core::encode_pair_request(&offer.secret, &offer.host_id, &phone_pubkey);
        deunlock_net::write_message(&mut tls, &request).await.context("send DLP1")?;
        println!("step 2:  pairing request sent");

        let accept = deunlock_net::read_message(&mut tls).await.context("read DLP2")?;
        deunlock_core::verify_pair_accept(&accept, &offer.secret, &offer.host_id, &phone_pubkey)
            .context("acceptance did not verify")?;
        println!("step 3:  acceptance verified");

        let _ = session_nonce;
        Ok::<_, anyhow::Error>(deunlock_core::derive_qr_bond_key(
            &offer.secret,
            &offer.host_id,
            &phone_pubkey,
        ))
    }
    .await?;

    println!("bond:    {}…", hex(&bond[..8]));
    println!("pairing: ok — the desktop answered with a key derived from the scanned secret");
    Ok(())
}

/// A random Ed25519 public key, standing in for the phone's identity.
fn random_public_key() -> Result<[u8; PHONE_PUBKEY_BYTES]> {
    use rand_core::RngCore as _;
    let mut seed = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut seed);
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    Ok(signing.verifying_key().to_bytes())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
