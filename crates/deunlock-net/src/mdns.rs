//! mDNS advertisement so a phone on the same LAN can find the desktop.
//!
//! Advertised as `_deunlock._tcp.local.` with three TXT properties:
//!
//! | key  | meaning                                              |
//! |------|------------------------------------------------------|
//! | `v`  | transport version (`2`)                              |
//! | `id` | desktop `host_id`, lowercase hex (64 chars)          |
//! | `fp` | first 16 hex chars of the cert fingerprint            |
//!
//! None of it is secret: the `host_id` is a public identity and the fingerprint
//! prefix only tells the phone *which* paired desktop is answering. The pin that
//! actually decides trust is the full 32-byte fingerprint stored at pairing time
//! — a wrong `fp` here produces a handshake failure, not a silent downgrade.

use std::collections::HashMap;
use std::net::IpAddr;

use mdns_sd::{ServiceDaemon, ServiceInfo};

use crate::error::NetError;

/// mDNS service type used by the LAN transport.
pub const SERVICE_TYPE: &str = "_deunlock._tcp.local.";

/// TXT key carrying the transport version.
pub const TXT_VERSION: &str = "v";

/// TXT key carrying the desktop `host_id` in hex.
pub const TXT_HOST_ID: &str = "id";

/// TXT key carrying the fingerprint prefix.
pub const TXT_FINGERPRINT: &str = "fp";

/// How many hex characters of the fingerprint go into TXT.
pub const TXT_FINGERPRINT_HEX_CHARS: usize = 16;

/// Build the `ServiceInfo` a phone will see.
///
/// Split out from [`LanAdvertiser::start`] so the record can be asserted in
/// tests without mutating the host's mDNS state.
///
/// # Errors
///
/// [`NetError::Mdns`] when mdns-sd rejects the record (a name that is too long,
/// an empty instance name, ...).
pub fn service_info(
    instance: &str,
    host_id_hex: &str,
    fingerprint_hex: &str,
    ip: IpAddr,
    port: u16,
) -> Result<ServiceInfo, NetError> {
    let mut props = HashMap::new();
    props.insert(TXT_VERSION.to_owned(), "2".to_owned());
    props.insert(TXT_HOST_ID.to_owned(), host_id_hex.to_owned());
    let fp_prefix: String = fingerprint_hex.chars().take(TXT_FINGERPRINT_HEX_CHARS).collect();
    props.insert(TXT_FINGERPRINT.to_owned(), fp_prefix);

    ServiceInfo::new(SERVICE_TYPE, instance, "deunlock.local.", ip, port, props)
        .map_err(|e| NetError::Mdns(e.to_string()))
}

/// A live mDNS advertisement; dropping it deregisters the service.
pub struct LanAdvertiser {
    daemon: ServiceDaemon,
    fullname: String,
}

impl std::fmt::Debug for LanAdvertiser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LanAdvertiser")
            .field("fullname", &self.fullname)
            .finish()
    }
}

impl LanAdvertiser {
    /// Register the desktop on the local network.
    ///
    /// # Errors
    ///
    /// [`NetError::Mdns`] when the daemon cannot start or the record is refused.
    pub fn start(
        instance: &str,
        host_id_hex: &str,
        fingerprint_hex: &str,
        ip: IpAddr,
        port: u16,
    ) -> Result<Self, NetError> {
        let info = service_info(instance, host_id_hex, fingerprint_hex, ip, port)?;
        let fullname = info.get_fullname().to_owned();
        let daemon = ServiceDaemon::new().map_err(|e| NetError::Mdns(e.to_string()))?;
        daemon
            .register(info)
            .map_err(|e| NetError::Mdns(e.to_string()))?;
        tracing::info!(service = %fullname, port, "advertising deunlock on the LAN");
        Ok(Self { daemon, fullname })
    }

    /// The fully-qualified service name, e.g. `deunlock-1a2b._deunlock._tcp.local.`
    #[must_use]
    pub fn fullname(&self) -> &str {
        &self.fullname
    }

    /// Stop advertising.
    ///
    /// Errors are logged rather than returned: a failed deregistration must not
    /// keep the daemon alive or abort shutdown.
    pub fn shutdown(&self) {
        if let Err(e) = self.daemon.unregister(&self.fullname) {
            tracing::warn!(service = %self.fullname, error = %e, "mdns unregister failed");
        }
        if let Err(e) = self.daemon.shutdown() {
            tracing::warn!(error = %e, "mdns daemon shutdown failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> ServiceInfo {
        service_info(
            "deunlock-1a2b",
            &"ab".repeat(32),
            &"cd".repeat(32),
            IpAddr::from([192, 168, 1, 42]),
            47_123,
        )
        .expect("service info")
    }

    #[test]
    fn the_record_advertises_version_identity_and_fingerprint_prefix() {
        let info = info();
        assert!(info.get_fullname().contains(SERVICE_TYPE));
        assert_eq!(info.get_property_val_str(TXT_VERSION), Some("2"));
        assert_eq!(
            info.get_property_val_str(TXT_HOST_ID),
            Some("ab".repeat(32).as_str())
        );
        let fp = info.get_property_val_str(TXT_FINGERPRINT).expect("fp").to_owned();
        assert_eq!(fp.len(), TXT_FINGERPRINT_HEX_CHARS, "only a prefix, not the whole pin");
        assert_eq!(fp, "cd".repeat(TXT_FINGERPRINT_HEX_CHARS / 2));
        assert_eq!(info.get_port(), 47_123);
    }

    #[test]
    fn a_short_fingerprint_is_taken_verbatim_rather_than_padded() {
        let info = service_info(
            "deunlock-dead",
            "00",
            "ef01",
            IpAddr::from([127, 0, 0, 1]),
            1234,
        )
        .expect("service info");
        assert_eq!(info.get_property_val_str(TXT_FINGERPRINT), Some("ef01"));
    }
}
