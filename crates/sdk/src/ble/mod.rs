//! BLE connector for app and CLI clients.
//!
//! netprov's client role is a pure GATT *central*: scan, connect, read
//! `Info`/`Challenge`, write `AuthResponse`/`Request`, and consume
//! notifications on `Request`. That surface is available on every desktop OS,
//! so this module carries two interchangeable backends behind one API:
//!
//! | Target        | Backend            | Module              |
//! | ------------- | ------------------ | ------------------- |
//! | Linux         | `bluer` (BlueZ)    | [`backend_bluez`]   |
//! | macOS / other | `btleplug`         | [`backend_btleplug`]|
//!
//! Exactly one is compiled per target. Linux keeps using `bluer` unchanged;
//! `--features ble-btleplug` forces the portable backend there too, which is
//! how CI gets Linux-side compile and behaviour coverage of the macOS path.
//!
//! The server (`netprovd`) is a GATT *peripheral* and stays Linux/`bluer`
//! only — no mature Rust crate does the BLE peripheral role on macOS, and the
//! daemon targets the headless Linux device regardless.
//!
//! Android and iOS should add further transport adapters behind the same
//! [`crate::ProvisioningClient`] surface.

use crate::ops::SdkError;
use netprov_protocol::MAX_FRAME_LEN;
use std::fmt;

// Exactly one backend compiles per target. `ble-btleplug` overrides the Linux
// default; keep the two predicates exact complements of each other.
#[cfg(all(target_os = "linux", not(feature = "ble-btleplug")))]
mod backend_bluez;
#[cfg(any(not(target_os = "linux"), feature = "ble-btleplug"))]
mod backend_btleplug;

#[cfg(all(target_os = "linux", not(feature = "ble-btleplug")))]
pub use backend_bluez::{BleClient, PEER_ID_HINT, parse_peer_id};
#[cfg(any(not(target_os = "linux"), feature = "ble-btleplug"))]
pub use backend_btleplug::{BleClient, PEER_ID_HINT, parse_peer_id};

/// Opaque handle for a BLE peer, in whatever form the active backend
/// understands.
///
/// This deliberately is **not** a MAC address. BlueZ identifies a peer by its
/// BD_ADDR (`AA:BB:CC:DD:EE:FF`), but CoreBluetooth never exposes one: it
/// hands out a per-host `CBPeripheral` UUID that is stable for this Mac and
/// meaningless on any other host. Callers (CLI `--ble-peer`, the app's peer
/// field) must therefore treat the string as opaque — take whatever a scan
/// printed and hand it back verbatim on connect.
///
/// Use [`parse_peer_id`] to build one from user input; it applies the active
/// backend's validation rules.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId(String);

impl PeerId {
    /// Wraps an already-validated backend handle.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for PeerId {
    type Err = SdkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_peer_id(s)
    }
}

/// A netprov peer seen during a scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BleDevice {
    /// Handle to pass back to `BleClient::connect`.
    pub id: PeerId,
    /// Advertised name, when the peer published one.
    pub name: Option<String>,
    /// BD_ADDR, when the platform discloses it. Always `None` on macOS —
    /// CoreBluetooth does not expose peer MAC addresses to applications.
    pub address: Option<String>,
    pub rssi: Option<i16>,
}

impl BleDevice {
    /// Human-facing label: the advertised name if there is one, else the
    /// backend handle.
    pub fn label(&self) -> &str {
        match self.name.as_deref() {
            Some(name) if !name.is_empty() => name,
            _ => self.id.as_str(),
        }
    }

    /// Secondary line for a device picker: the MAC where the platform has
    /// one, otherwise the opaque handle.
    pub fn detail(&self) -> &str {
        self.address.as_deref().unwrap_or_else(|| self.id.as_str())
    }
}

/// ATT overhead on a single notify/write value: 1 opcode byte + 2 handle
/// bytes. A connection's usable value length is `ATT_MTU - ATT_HEADER_LEN`.
pub(crate) const ATT_HEADER_LEN: usize = 3;

/// Smallest value length any BLE connection must support, from the mandatory
/// 23-byte ATT MTU. Backends that cannot report a negotiated MTU fall back to
/// this floor: correct everywhere, just more fragments per message.
pub const MIN_MAX_FRAGMENT: usize = 23 - ATT_HEADER_LEN;

/// Overrides the per-frame BLE value length used when writing requests.
///
/// The btleplug backend cannot read a negotiated MTU on every platform (on
/// CoreBluetooth it always reports the 23-byte floor), so it fragments
/// conservatively. Raise this if a peer is known to negotiate a larger MTU
/// and the extra round trips matter. Values are clamped to
/// `[MIN_MAX_FRAGMENT, MAX_FRAME_LEN]`; anything unparseable is ignored.
pub const MAX_FRAGMENT_ENV: &str = "NETPROV_BLE_MAX_FRAGMENT";

/// Clamps a backend-reported BLE *value* length (already net of ATT
/// overhead) into the range `fragment()` can safely use.
pub(crate) fn clamp_max_fragment(value_len: usize) -> usize {
    value_len.clamp(MIN_MAX_FRAGMENT, MAX_FRAME_LEN)
}

/// Reads [`MAX_FRAGMENT_ENV`], clamped. `None` when unset or unparseable, so
/// a typo silently keeps the safe default rather than breaking the link.
pub(crate) fn max_fragment_override() -> Option<usize> {
    let raw = std::env::var(MAX_FRAGMENT_ENV).ok()?;
    let parsed = raw.trim().parse::<usize>().ok()?;
    Some(clamp_max_fragment(parsed))
}

/// Resolves the per-frame value length: the env override when set, else the
/// backend's negotiated value length clamped to a usable range.
pub(crate) fn resolve_max_fragment(value_len: usize) -> usize {
    max_fragment_override().unwrap_or_else(|| clamp_max_fragment(value_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_holds_the_att_floor() {
        // A backend reporting the bare 23-byte ATT MTU (CoreBluetooth always
        // does) must still yield a legal, non-zero fragment size.
        assert_eq!(clamp_max_fragment(20), 20);
        assert_eq!(clamp_max_fragment(0), MIN_MAX_FRAGMENT);
        assert_eq!(clamp_max_fragment(3), MIN_MAX_FRAGMENT);
    }

    #[test]
    fn clamp_holds_the_frame_ceiling() {
        assert_eq!(clamp_max_fragment(247), 247);
        assert_eq!(clamp_max_fragment(MAX_FRAME_LEN), MAX_FRAME_LEN);
        assert_eq!(clamp_max_fragment(4096), MAX_FRAME_LEN);
    }

    #[test]
    fn peer_id_roundtrips_as_an_opaque_string() {
        let id = PeerId::new("6E4A1B0C-9E3F-4A21-B0D4-7C2F1A8E55D9");
        assert_eq!(id.as_str(), "6E4A1B0C-9E3F-4A21-B0D4-7C2F1A8E55D9");
        assert_eq!(id.to_string(), id.as_str());
        assert_eq!(id.clone().into_string(), id.as_str());
    }

    #[test]
    fn label_prefers_name_and_falls_back_to_handle() {
        let named = BleDevice {
            id: PeerId::new("handle-1"),
            name: Some("netprovd".into()),
            address: None,
            rssi: None,
        };
        assert_eq!(named.label(), "netprovd");
        // A blank advertised name must not produce a blank row.
        let blank = BleDevice {
            name: Some(String::new()),
            ..named.clone()
        };
        assert_eq!(blank.label(), "handle-1");
        let anonymous = BleDevice {
            name: None,
            ..named
        };
        assert_eq!(anonymous.label(), "handle-1");
    }

    #[test]
    fn detail_shows_mac_when_the_platform_has_one() {
        let device = BleDevice {
            id: PeerId::new("handle-1"),
            name: None,
            address: Some("AA:BB:CC:DD:EE:FF".into()),
            rssi: None,
        };
        assert_eq!(device.detail(), "AA:BB:CC:DD:EE:FF");
        // macOS: no MAC is ever available, so the handle is the detail line.
        let macos = BleDevice {
            address: None,
            ..device
        };
        assert_eq!(macos.detail(), "handle-1");
    }
}
