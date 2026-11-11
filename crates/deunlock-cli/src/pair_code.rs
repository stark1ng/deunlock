//! `deunlock pair-code` — mint a ten-character code for pairing a phone over BLE.
//!
//! The BLE first-bond used to need nothing but a nearby phone: the desktop
//! derived the bond from two public keys and accepted whichever phone wrote to the
//! pair characteristic first (AUDIT-001 D-08). This command is the operator in the
//! loop — it mints a single-use, expiring code that must be typed into the phone,
//! and the daemon refuses any pairing write that cannot prove it.
//!
//! The code is a projection of a fresh 32-byte secret, so the same offer file
//! still serves the QR path: `pair-code` and `pair-qr` are two renderings of one
//! arming, and the daemon reads whichever the phone presents.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result};
use clap::Args;
use deunlock_core::{PendingOffer, render_code, PAIRING_SECRET_BYTES};

/// How long a code stays valid, in seconds.
///
/// Short on purpose: the code is read off the screen by a human standing next to
/// the machine, and a code that outlives the gesture is a password in the shell
/// history instead of a pairing step.
pub const DEFAULT_CODE_TTL_SECONDS: u64 = 300;

#[derive(Debug, Args)]
pub struct PairCodeOpts {
    /// Seconds until the code expires.
    #[arg(long, value_name = "SECONDS", default_value_t = DEFAULT_CODE_TTL_SECONDS)]
    pub ttl: u64,
    /// Where to leave the offer for the daemon (default: the path the daemon
    /// watches, `/run/deunlock/pairing.offer`).
    #[arg(long, value_name = "PATH")]
    pub offer_path: Option<PathBuf>,
    /// Print only the code, for scripts.
    #[arg(long)]
    pub quiet: bool,
}

/// Where the daemon looks for an armed offer.
///
/// # Errors
///
/// Nothing: the default is compiled in, and the environment override is a path.
#[must_use]
pub fn default_offer_path() -> PathBuf {
    std::env::var_os("DEUNLOCK_PAIRING_OFFER").map_or_else(
        || PathBuf::from(deunlock_core::DEFAULT_PAIRING_OFFER_PATH),
        PathBuf::from,
    )
}

/// Run the command.
///
/// # Errors
///
/// A missing host identity (nothing to arm an offer for) or an unwritable offer
/// path.
pub fn run(opts: &PairCodeOpts) -> Result<()> {
    let offer_path = opts.offer_path.clone().unwrap_or_else(default_offer_path);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let code = mint_code(&offer_path, now, opts.ttl)?;
    if opts.quiet {
        println!("{code}");
        return Ok(());
    }

    let minutes = opts.ttl.div_ceil(60);
    println!("Pair this computer with a phone. The code is good for {minutes} min and works once:\n");
    println!("    {} {}\n", &code[..5], &code[5..]);
    println!("On the phone: DeUnlock -> Pair with computer -> type the code.");
    println!("Offer file: {}", offer_path.display());
    Ok(())
}

/// Mint a code and arm the offer the daemon verifies against.
///
/// # Errors
///
/// A missing host identity, or a failure to write the offer file.
pub fn mint_code(offer_path: &Path, now: u64, ttl: u64) -> Result<String> {
    let host_key_path = std::env::var_os("DEUNLOCK_HOST_KEY").map_or_else(
        || PathBuf::from(deunlock_core::DEFAULT_HOST_KEY_PATH),
        PathBuf::from,
    );
    let identity = deunlock_core::HostIdentity::load(&host_key_path).with_context(|| {
        format!(
            "host identity missing at {} (run `deunlock pair --host-key`)",
            host_key_path.display()
        )
    })?;

    let mut secret = [0u8; PAIRING_SECRET_BYTES];
    fill_random(&mut secret)?;
    let code = render_code(&secret);

    let offer = PendingOffer {
        secret: secret.iter().map(|b| format!("{b:02x}")).collect(),
        host_id: identity
            .host_id()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        expires_at: now.saturating_add(ttl),
        code: Some(code.clone()),
        attempts: 0,
    };
    offer
        .write(offer_path)
        .with_context(|| format!("cannot arm pairing at {}", offer_path.display()))?;
    Ok(code)
}

/// Fill `buf` from the OS CSPRNG.
fn fill_random(buf: &mut [u8]) -> Result<()> {
    use std::io::Read as _;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(buf))
        .context("cannot read /dev/urandom")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_ttl_is_a_gesture_not_a_password() {
        let ttl: u64 = DEFAULT_CODE_TTL_SECONDS;
        assert!(ttl <= 600, "a code that outlives the gesture is a password");
    }

    #[test]
    fn minted_codes_are_ten_chars_and_differ() {
        let dir = std::env::temp_dir().join(format!("deunlock-pair-code-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tempdir");
        let path = dir.join("offer.json");
        let mut secret = [0u8; PAIRING_SECRET_BYTES];
        fill_random(&mut secret).expect("random");
        let a = render_code(&secret);
        fill_random(&mut secret).expect("random");
        let b = render_code(&secret);
        assert_eq!(a.len(), deunlock_core::PAIR_CODE_LEN);
        assert_ne!(a, b, "fresh secrets must not repeat a code");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = path;
    }
}
