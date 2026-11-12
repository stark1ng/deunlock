//! `deunlock pair-qr` — print a pairing QR for the current desktop.
//!
//! This is the desktop half of AUDIT-001 **D-07**: instead of the four-word OOB
//! code the BLE flow compares by eye, the phone scans one code that carries the
//! host identity, the LAN endpoint, the TLS pin and a 256-bit pairing secret.
//!
//! What this command does **not** do yet: create a bond. It mints the offer, so
//! the desktop side is inspectable and testable; the phone-side half (scan, store
//! the pin, derive the bond from the secret) is the next step, and until it lands
//! `deunlock pair` over BLE remains the working path.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail};
use clap::Args;
use deunlock_core::{PAIRING_SECRET_BYTES, PairingOffer};

/// How long a printed code stays valid, in seconds.
pub const DEFAULT_QR_TTL_SECONDS: u64 = 600;

#[derive(Debug, Args)]
pub struct PairQrOpts {
    /// LAN address a phone should try (`192.168.1.42` or `desktop.local`).
    #[arg(long, value_name = "HOST")]
    pub lan_host: String,
    /// LAN port the desktop's listener is bound to.
    #[arg(long, value_name = "PORT", default_value_t = 47_823)]
    pub port: u16,
    /// Seconds until the code expires.
    #[arg(long, value_name = "SECONDS", default_value_t = DEFAULT_QR_TTL_SECONDS)]
    pub ttl: u64,
    /// Also write a PNG here (requires the `qrencode` binary).
    #[arg(long, value_name = "PATH")]
    pub png: Option<PathBuf>,
    /// Where to leave the offer for the daemon (default: the path the daemon
    /// watches, `/run/deunlock/pairing.offer`).
    #[arg(long, value_name = "PATH")]
    pub offer_path: Option<PathBuf>,
    /// Print only the payload, for piping into another tool.
    #[arg(long)]
    pub quiet: bool,
}

/// Build the offer for this desktop.
///
/// # Errors
///
/// Any failure to read the host key or the TLS identity: a code built without
/// them would pair a phone to nothing.
pub fn build_offer(
    host_key_path: &Path,
    cert_path: &Path,
    key_path: &Path,
    lan_host: &str,
    port: u16,
    ttl: u64,
    now: u64,
) -> Result<PairingOffer> {
    let identity = deunlock_core::HostIdentity::load(host_key_path)
        .with_context(|| format!("host identity missing at {} (run `deunlock pair --host-key`)", host_key_path.display()))?;
    let lan = deunlock_net::LanIdentity::load_or_create(cert_path, key_path)
        .with_context(|| format!("no LAN identity at {}", cert_path.display()))?;

    let mut secret = [0u8; PAIRING_SECRET_BYTES];
    fill_random(&mut secret)?;

    Ok(PairingOffer {
        host_id: identity.host_id(),
        host_pubkey: identity.public_key(),
        lan_host: lan_host.to_owned(),
        lan_port: port,
        tls_fingerprint: lan.fingerprint(),
        secret,
        expires_at: now.saturating_add(ttl),
    })
}

/// Run the command.
///
/// # Errors
///
/// Identity problems, an invalid host string, or a failed `qrencode` run.
pub fn run(opts: &PairQrOpts, host_key_path: &Path, cert_path: &Path, key_path: &Path) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let offer = build_offer(host_key_path, cert_path, key_path, &opts.lan_host, opts.port, opts.ttl, now)?;
    let payload = offer.encode()?;

    // Hand the secret to the daemon. Without this file the listener refuses every
    // pairing request, which is the safe default: no offer, no pairing.
    let offer_path = opts
        .offer_path
        .clone()
        .or_else(|| std::env::var_os("DEUNLOCK_PAIRING_OFFER").map(PathBuf::from))
        .unwrap_or_else(|| deunlock_core::default_pairing_offer_path());
    let wrote_offer = match deunlock_core::PendingOffer::from_offer(&offer).write(&offer_path) {
        Ok(()) => true,
        Err(err) => {
            eprintln!(
                "warning: could not write the offer to {}: {err}",
                offer_path.display()
            );
            eprintln!("         the daemon will refuse this code; pass --offer-path to somewhere it reads");
            false
        }
    };

    if let Some(png) = &opts.png {
        write_png(png, &payload)?;
    }
    if opts.quiet {
        println!("{payload}");
        return Ok(());
    }

    println!("payload: {payload}");
    println!("host:    {}:{}", offer.lan_host, offer.lan_port);
    println!("pin:     {}", hex(&offer.tls_fingerprint));
    println!("expires: {} (in {}s)", offer.expires_at, offer.expires_at.saturating_sub(now));
    println!(
        "offer:   {} ({})",
        offer_path.display(),
        if wrote_offer { "armed for one attempt" } else { "NOT written" }
    );
    println!();
    println!("Scan this with the DeUnlock app. The code contains a one-time pairing secret —");
    println!("treat a screenshot of it like a password.");
    Ok(())
}

/// Render the payload to a PNG via `qrencode`, when it is installed.
fn write_png(path: &Path, payload: &str) -> Result<()> {
    let status = std::process::Command::new("qrencode")
        .arg("-o")
        .arg(path)
        .arg("-t")
        .arg("PNG")
        .arg("-m")
        .arg("2")
        .arg(payload)
        .status();
    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => bail!("qrencode exited with {s}"),
        Err(e) => bail!("qrencode is not available ({e}); install it or use --quiet and render the payload elsewhere"),
    }
}

/// Fill `out` with OS randomness.
///
/// A predictable pairing secret would let anyone forge the bond, so failure is an
/// error rather than a fallback to a timestamp-derived value.
fn fill_random(out: &mut [u8]) -> Result<()> {
    use rand_core::RngCore as _;
    rand_core::OsRng.fill_bytes(out);
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identities() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().expect("tmp");
        let host_key = dir.path().join("host.key");
        let cert = dir.path().join("net.crt");
        let key = dir.path().join("net.key");
        deunlock_core::HostIdentity::load_or_create(&host_key).expect("host identity");
        deunlock_net::LanIdentity::load_or_create(&cert, &key).expect("lan identity");
        (dir, host_key, cert, key)
    }

    #[test]
    fn a_built_offer_carries_the_real_identity_and_pin() {
        let (_dir, host_key, cert, key) = identities();
        let offer = build_offer(&host_key, &cert, &key, "192.168.1.42", 47_823, 600, 1_700_000_000).expect("offer");

        let identity = deunlock_core::HostIdentity::load(&host_key).expect("reload");
        let lan = deunlock_net::LanIdentity::load_or_create(&cert, &key).expect("reload lan");
        assert_eq!(offer.host_id, identity.host_id());
        assert_eq!(offer.host_pubkey, identity.public_key());
        assert_eq!(offer.tls_fingerprint, lan.fingerprint());
        assert_eq!(offer.lan_port, 47_823);
        assert_eq!(offer.expires_at, 1_700_000_600);
        assert_ne!(offer.secret, [0u8; PAIRING_SECRET_BYTES], "secret must be random");
    }

    #[test]
    fn two_offers_never_share_a_secret() {
        let (_dir, host_key, cert, key) = identities();
        let first = build_offer(&host_key, &cert, &key, "h", 1, 60, 0).expect("first");
        let second = build_offer(&host_key, &cert, &key, "h", 1, 60, 0).expect("second");
        assert_ne!(first.secret, second.secret);
    }

    #[test]
    fn the_printed_payload_scans_back_into_the_same_offer() {
        let (_dir, host_key, cert, key) = identities();
        let offer = build_offer(&host_key, &cert, &key, "desktop.local", 47_823, 600, 1_700_000_000).expect("offer");
        let payload = offer.encode().expect("encode");
        let decoded = deunlock_core::PairingOffer::decode(&payload, 1_700_000_100).expect("decode");
        assert_eq!(decoded, offer);
    }

    #[test]
    fn a_missing_host_identity_is_an_error_not_a_blank_code() {
        let dir = tempfile::tempdir().expect("tmp");
        let missing = dir.path().join("nope.key");
        let cert = dir.path().join("net.crt");
        let key = dir.path().join("net.key");
        deunlock_net::LanIdentity::load_or_create(&cert, &key).expect("lan identity");
        let outcome = build_offer(&missing, &cert, &key, "h", 1, 60, 0);
        assert!(outcome.is_err(), "no code may be minted without a host identity");
    }
}
