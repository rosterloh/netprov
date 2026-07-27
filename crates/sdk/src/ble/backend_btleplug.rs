//! Portable BLE central backend, over `btleplug`.
//!
//! Used on every target except Linux (where `bluer` remains the default), and
//! on Linux when the `ble-btleplug` feature forces it. `btleplug` maps onto
//! CoreBluetooth on macOS, WinRT on Windows and BlueZ on Linux, which covers
//! the whole of netprov's central-only surface: scan, connect, read, write,
//! subscribe.
//!
//! Three things differ from the BlueZ backend and shape the code below:
//!
//! 1. **No BD_ADDR on macOS.** CoreBluetooth hands out an opaque per-host
//!    `CBPeripheral` UUID and reports the peer MAC as all-zero, so
//!    [`PeerId`] carries whatever handle a scan printed and
//!    [`peer_matches`] accepts a handle, a MAC (where disclosed) or the
//!    advertised name.
//! 2. **Notifications arrive as a stream**, not an `AsyncRead` socket, so
//!    reassembly is driven by [`read_response`] rather than a read loop.
//! 3. **No portable MTU.** `Peripheral::mtu()` reports the negotiated value
//!    on BlueZ but is pinned to the 23-byte ATT floor on CoreBluetooth, so
//!    fragmentation falls back to a conservative 20-byte value length unless
//!    [`super::MAX_FRAGMENT_ENV`] says otherwise.

use super::{ATT_HEADER_LEN, BleDevice, PeerId, resolve_max_fragment};
use crate::ops::{CLIENT_TIMEOUT, ProvisioningClient, SdkError};
use async_trait::async_trait;
use btleplug::api::{
    BDAddr, Central, CharPropFlags, Characteristic, Manager as _, Peripheral as _, ScanFilter,
    ValueNotification, WriteType,
};
use btleplug::platform::{Adapter, Manager, Peripheral};
use futures_util::{Stream, StreamExt};
use netprov_protocol::{
    MAX_MESSAGE_SIZE, NONCE_LEN, Op, OpResult, Psk, Reassembler, Request, Response,
    decode_response, encode_request, fragment, hmac_compute, parse_frame, uuids as proto_uuids,
};
use std::pin::Pin;
use std::time::Duration;
use uuid::Uuid;

const SERVICE_UUID: Uuid = Uuid::from_u128(proto_uuids::SERVICE_UUID);
const INFO_UUID: Uuid = Uuid::from_u128(proto_uuids::INFO_UUID);
const CHALLENGE_UUID: Uuid = Uuid::from_u128(proto_uuids::CHALLENGE_UUID);
const AUTH_RESPONSE_UUID: Uuid = Uuid::from_u128(proto_uuids::AUTH_RESPONSE_UUID);
const REQUEST_UUID: Uuid = Uuid::from_u128(proto_uuids::REQUEST_UUID);

/// How long `connect` keeps scanning for the requested peer before giving up.
const PEER_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);
/// How often `connect` re-checks the discovered set while waiting.
const PEER_DISCOVERY_POLL: Duration = Duration::from_millis(200);
/// Bound on the link-up and service-discovery steps individually, so a peer
/// that accepts a connection but never completes discovery still fails fast.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// Placeholder/help text for peer input on this backend.
pub const PEER_ID_HINT: &str = "device name, or the handle printed by a scan";

/// Validates user input as a portable peer handle.
///
/// Unlike the BlueZ backend there is nothing to validate against: the handle
/// may be a CoreBluetooth UUID, a BlueZ object path, a MAC or an advertised
/// name depending on platform and on what the user copied out of a scan. Only
/// emptiness is rejected; the real check is whether a scan turns it up.
pub fn parse_peer_id(s: &str) -> Result<PeerId, SdkError> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(SdkError::Ble("peer identifier is empty".into()));
    }
    Ok(PeerId::new(trimmed))
}

pub struct BleClient {
    peripheral: Peripheral,
    info: Characteristic,
    challenge: Characteristic,
    auth: Characteristic,
    request: Characteristic,
    /// Taken once in `connect`, before subscribing, so no response fragment
    /// can be dropped between subscription and the first read.
    notifications: Pin<Box<dyn Stream<Item = ValueNotification> + Send>>,
    next_id: u16,
}

impl BleClient {
    pub async fn scan_devices(timeout: Duration) -> Result<Vec<BleDevice>, SdkError> {
        let adapter = default_adapter().await?;
        adapter.start_scan(netprov_scan_filter()).await?;
        tokio::time::sleep(timeout).await;
        let peripherals = adapter.peripherals().await;
        // Stop scanning even if enumeration failed; leaving the radio
        // scanning would keep draining power after the call returns.
        let _ = adapter.stop_scan().await;

        let mut found = Vec::new();
        for peripheral in peripherals? {
            // A peripheral that vanishes mid-enumeration (or whose properties
            // the OS declines to hand over) must not sink the whole scan —
            // the other devices in range are still perfectly usable.
            if let Ok(Some(device)) = describe(&peripheral).await {
                found.push(device);
            }
        }
        Ok(found)
    }

    pub async fn connect(peer: &PeerId) -> Result<Self, SdkError> {
        let adapter = default_adapter().await?;
        adapter.start_scan(netprov_scan_filter()).await?;
        let peripheral = find_peer(&adapter, peer).await;
        let _ = adapter.stop_scan().await;
        let peripheral = peripheral?;

        peripheral
            .connect_with_timeout(CONNECT_TIMEOUT)
            .await
            .map_err(|e| match e {
                btleplug::Error::TimedOut(_) => SdkError::Timeout(CONNECT_TIMEOUT),
                other => SdkError::from(other),
            })?;
        peripheral
            .discover_services_with_timeout(CONNECT_TIMEOUT)
            .await
            .map_err(|e| match e {
                btleplug::Error::TimedOut(_) => SdkError::Timeout(CONNECT_TIMEOUT),
                other => SdkError::from(other),
            })?;

        let chars = peripheral.characteristics();
        let find = |uuid: Uuid| {
            chars
                .iter()
                .find(|c| c.uuid == uuid && c.service_uuid == SERVICE_UUID)
                .cloned()
        };
        let request = find(REQUEST_UUID)
            .ok_or_else(|| SdkError::Ble("REQUEST characteristic missing".into()))?;

        // Take the notification stream *before* subscribing: btleplug keeps
        // the stream valid across connections, and grabbing it first means a
        // fragment cannot land in the gap between subscribe and first read.
        let notifications = peripheral.notifications().await?;
        // Subscribing up front also makes the server mint a PeerSession
        // before authentication begins, matching the BlueZ backend.
        peripheral.subscribe(&request).await?;

        Ok(Self {
            info: find(INFO_UUID)
                .ok_or_else(|| SdkError::Ble("INFO characteristic missing".into()))?,
            challenge: find(CHALLENGE_UUID)
                .ok_or_else(|| SdkError::Ble("CHALLENGE characteristic missing".into()))?,
            auth: find(AUTH_RESPONSE_UUID)
                .ok_or_else(|| SdkError::Ble("AUTH_RESPONSE characteristic missing".into()))?,
            request,
            peripheral,
            notifications,
            next_id: 1,
        })
    }

    pub async fn authenticate(&mut self, psk: Psk) -> Result<(), SdkError> {
        <Self as ProvisioningClient>::authenticate(self, psk).await
    }

    pub async fn request(&mut self, op: Op) -> Result<OpResult, SdkError> {
        <Self as ProvisioningClient>::request(self, op).await
    }

    /// Per-frame BLE value length for request writes.
    fn max_fragment(&self) -> usize {
        resolve_max_fragment((self.peripheral.mtu() as usize).saturating_sub(ATT_HEADER_LEN))
    }
}

#[async_trait]
impl ProvisioningClient for BleClient {
    async fn authenticate(&mut self, psk: Psk) -> Result<(), SdkError> {
        // The reads below can block indefinitely on an unresponsive peer, so
        // bound the whole exchange with the client deadline.
        tokio::time::timeout(CLIENT_TIMEOUT, async {
            // Read Info first to confirm the service is responsive. Protocol
            // compatibility checks can be added here once the UI exposes
            // versions.
            let _info = self.peripheral.read(&self.info).await?;

            let nonce = self.peripheral.read(&self.challenge).await?;
            if nonce.len() != NONCE_LEN {
                return Err(SdkError::UnexpectedMessage("nonce length"));
            }
            let mut n = [0u8; NONCE_LEN];
            n.copy_from_slice(&nonce);
            let tag = hmac_compute(&psk, &n);
            // Must be a write *with response* — that is the only way the
            // server's NotAuthorized rejection reaches us at all.
            self.peripheral
                .write(&self.auth, &tag, WriteType::WithResponse)
                .await
                .map_err(map_auth_write_err)?;
            Ok(())
        })
        .await
        .map_err(|_| SdkError::Timeout(CLIENT_TIMEOUT))?
    }

    async fn request(&mut self, op: Op) -> Result<OpResult, SdkError> {
        // The notification loop has no natural deadline (a dropped response or
        // silent disconnect never wakes it), so bound the round trip.
        tokio::time::timeout(CLIENT_TIMEOUT, async {
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1);
            let bytes = encode_request(&Request { request_id: id, op })?;

            let max_fragment = self.max_fragment();
            let write_type = write_type_for(&self.request);
            for f in fragment(id, &bytes, max_fragment) {
                self.peripheral.write(&self.request, &f, write_type).await?;
            }

            read_response(&mut self.notifications, id).await
        })
        .await
        .map_err(|_| SdkError::Timeout(CLIENT_TIMEOUT))?
    }
}

/// Drives reassembly from a notification stream until the response for
/// `request_id` is complete.
///
/// Split out from `request` so it can be exercised against a synthetic stream
/// of fragments without a radio.
async fn read_response<S>(notifications: &mut S, request_id: u16) -> Result<OpResult, SdkError>
where
    S: Stream<Item = ValueNotification> + Unpin + ?Sized,
{
    let mut reassembler = Reassembler::new(MAX_MESSAGE_SIZE);
    loop {
        let Some(notification) = notifications.next().await else {
            // btleplug ends the stream when the peripheral goes away.
            return Err(SdkError::Ble("notify stream closed".into()));
        };
        // The stream carries every subscribed characteristic on the
        // peripheral; only Request/Response frames are ours.
        if notification.uuid != REQUEST_UUID {
            continue;
        }
        let parsed = parse_frame(&notification.value)?;
        if let Some(msg) = reassembler.push(parsed)? {
            let resp: Response = decode_response(&msg)?;
            if resp.request_id != request_id {
                return Err(SdkError::IdMismatch {
                    expected: request_id,
                    got: resp.request_id,
                });
            }
            return resp.result.map_err(Into::into);
        }
    }
}

/// Prefer write-with-response: it is flow-controlled, so back-to-back
/// fragments cannot overrun the controller's buffer and vanish. Fall back to
/// write-without-response only when the peer offers nothing else.
fn write_type_for(characteristic: &Characteristic) -> WriteType {
    if characteristic.properties.contains(CharPropFlags::WRITE) {
        WriteType::WithResponse
    } else {
        WriteType::WithoutResponse
    }
}

/// Maps an auth-characteristic write failure to an `SdkError`.
///
/// The server rejects a bad tag with `ReqError::NotAuthorized`, i.e. ATT
/// error 0x08. Unlike bluer, btleplug has no typed variant for it: BlueZ
/// surfaces the D-Bus name and CoreBluetooth an `NSError` description, both
/// as free text. Sniffing that text is best-effort, so anything unrecognised
/// still passes through as a transport failure rather than being reported as
/// a wrong PSK.
fn map_auth_write_err(e: btleplug::Error) -> SdkError {
    let authorization_denied = match &e {
        btleplug::Error::PermissionDenied => true,
        btleplug::Error::RuntimeError(msg) | btleplug::Error::NotSupported(msg) => {
            looks_like_auth_rejection(msg)
        }
        other => looks_like_auth_rejection(&other.to_string()),
    };
    if authorization_denied {
        SdkError::AuthFailed
    } else {
        SdkError::from(e)
    }
}

fn looks_like_auth_rejection(message: &str) -> bool {
    let lowered = message.to_ascii_lowercase();
    lowered.contains("authoriz") || lowered.contains("authentic")
}

/// Scan only for peers advertising the netprov service. macOS *requires* a
/// service filter to return anything useful, and it keeps the picker clean
/// elsewhere.
fn netprov_scan_filter() -> ScanFilter {
    ScanFilter {
        services: vec![SERVICE_UUID],
    }
}

async fn default_adapter() -> Result<Adapter, SdkError> {
    let manager = Manager::new().await?;
    manager
        .adapters()
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| SdkError::Ble("no Bluetooth adapter available".into()))
}

/// Polls the discovered set until `peer` shows up or the timeout expires.
///
/// There is no portable way to construct a `PeripheralId` from a string and
/// dial it directly — CoreBluetooth in particular can only hand back
/// peripherals it discovered in this session — so matching happens over scan
/// results.
async fn find_peer(adapter: &Adapter, peer: &PeerId) -> Result<Peripheral, SdkError> {
    let deadline = tokio::time::Instant::now() + PEER_DISCOVERY_TIMEOUT;
    loop {
        for peripheral in adapter.peripherals().await? {
            let id = peripheral.id().to_string();
            // Fall back to the bare handle if properties are unavailable
            // rather than abandoning the search: the handle alone is enough
            // to match a peer the user picked out of a previous scan.
            let (address, name) = match peripheral.properties().await {
                Ok(Some(props)) => (
                    disclosed_address(props.address),
                    props.local_name.or(props.advertisement_name),
                ),
                _ => (disclosed_address(peripheral.address()), None),
            };
            if peer_matches(peer, &id, address.as_deref(), name.as_deref()) {
                return Ok(peripheral);
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(SdkError::Ble(format!(
                "peer {peer} not seen within {PEER_DISCOVERY_TIMEOUT:?}"
            )));
        }
        tokio::time::sleep(PEER_DISCOVERY_POLL).await;
    }
}

/// Whether a scan result answers to the identifier the user supplied.
///
/// Accepts the backend handle, the BD_ADDR where the platform discloses one,
/// or the advertised name — so a MAC still works on Linux/Windows while macOS
/// users can use the CoreBluetooth UUID or just the device name.
fn peer_matches(peer: &PeerId, id: &str, address: Option<&str>, name: Option<&str>) -> bool {
    let wanted = peer.as_str();
    let eq = |candidate: &str| candidate.eq_ignore_ascii_case(wanted);
    eq(id) || address.is_some_and(eq) || name.is_some_and(|n| !n.is_empty() && eq(n))
}

/// CoreBluetooth reports an all-zero MAC because it never discloses the real
/// one; treat that as "no address" rather than showing users `00:00:...`.
fn disclosed_address(address: BDAddr) -> Option<String> {
    if address == BDAddr::default() {
        None
    } else {
        Some(address.to_string())
    }
}

async fn describe(peripheral: &Peripheral) -> Result<Option<BleDevice>, SdkError> {
    let Some(props) = peripheral.properties().await? else {
        return Ok(None);
    };
    // The scan filter is applied by the platform, but not every backend
    // reports the advertised service list back to us. Only exclude a peer we
    // can positively identify as advertising something else.
    if !props.services.is_empty() && !props.services.contains(&SERVICE_UUID) {
        return Ok(None);
    }

    Ok(Some(BleDevice {
        id: PeerId::new(peripheral.id().to_string()),
        name: props
            .local_name
            .or(props.advertisement_name)
            .filter(|value| !value.is_empty()),
        address: disclosed_address(props.address),
        rssi: props.rssi,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use netprov_protocol::{IfaceState, IfaceType, Interface, encode_response};

    fn notification(value: Vec<u8>) -> ValueNotification {
        ValueNotification {
            uuid: REQUEST_UUID,
            service_uuid: SERVICE_UUID,
            value,
        }
    }

    fn interfaces_response(request_id: u16) -> Vec<u8> {
        encode_response(&Response {
            request_id,
            result: Ok(OpResult::Interfaces(vec![Interface {
                name: "wlan0".into(),
                iface_type: IfaceType::Wifi,
                mac: Some("AA:BB:CC:DD:EE:FF".into()),
                state: IfaceState::Up,
            }])),
        })
        .unwrap()
    }

    #[tokio::test]
    async fn reassembles_a_fragmented_response_from_the_stream() {
        // The whole point of the btleplug port: reassembly driven by a
        // notification stream instead of an AsyncRead socket. Use the 20-byte
        // ATT floor so the response genuinely spans many fragments.
        let body = interfaces_response(7);
        let frames = fragment(7, &body, super::super::MIN_MAX_FRAGMENT);
        assert!(frames.len() > 1, "expected a multi-fragment response");

        let mut stream = futures_util::stream::iter(frames.into_iter().map(notification)).boxed();
        let result = read_response(&mut stream, 7).await.unwrap();
        match result {
            OpResult::Interfaces(ifs) => assert_eq!(ifs[0].name, "wlan0"),
            other => panic!("unexpected result {other:?}"),
        }
    }

    #[tokio::test]
    async fn ignores_notifications_from_other_characteristics() {
        let body = interfaces_response(3);
        let mut values: Vec<ValueNotification> = fragment(3, &body, super::super::MIN_MAX_FRAGMENT)
            .into_iter()
            .map(notification)
            .collect();
        // Interleave chatter on an unrelated characteristic; feeding it to
        // parse_frame would corrupt reassembly.
        values.insert(
            1,
            ValueNotification {
                uuid: INFO_UUID,
                service_uuid: SERVICE_UUID,
                value: b"not a frame".to_vec(),
            },
        );

        let mut stream = futures_util::stream::iter(values).boxed();
        assert!(matches!(
            read_response(&mut stream, 3).await.unwrap(),
            OpResult::Interfaces(_)
        ));
    }

    #[tokio::test]
    async fn mismatched_request_id_is_rejected() {
        let body = interfaces_response(9);
        let frames = fragment(9, &body, 512);
        let mut stream = futures_util::stream::iter(frames.into_iter().map(notification)).boxed();
        let err = read_response(&mut stream, 8).await.unwrap_err();
        assert!(matches!(
            err,
            SdkError::IdMismatch {
                expected: 8,
                got: 9
            }
        ));
    }

    #[tokio::test]
    async fn exhausted_stream_reports_a_closed_link() {
        let mut stream = futures_util::stream::iter(Vec::<ValueNotification>::new()).boxed();
        let err = read_response(&mut stream, 1).await.unwrap_err();
        assert!(matches!(err, SdkError::Ble(msg) if msg.contains("notify stream closed")));
    }

    #[test]
    fn peer_matches_handle_address_or_name() {
        let by_handle = PeerId::new("6E4A1B0C-9E3F-4A21-B0D4-7C2F1A8E55D9");
        assert!(peer_matches(
            &by_handle,
            "6e4a1b0c-9e3f-4a21-b0d4-7c2f1a8e55d9",
            None,
            Some("netprovd"),
        ));

        // A MAC still works wherever the platform discloses one.
        let by_mac = PeerId::new("AA:BB:CC:DD:EE:FF");
        assert!(peer_matches(
            &by_mac,
            "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF",
            Some("AA:BB:CC:DD:EE:FF"),
            None,
        ));

        // ...and so does the advertised name, which is the only human-usable
        // identifier on macOS.
        let by_name = PeerId::new("netprovd");
        assert!(peer_matches(
            &by_name,
            "some-handle",
            None,
            Some("netprovd")
        ));

        assert!(!peer_matches(&by_name, "some-handle", None, Some("other")));
        assert!(!peer_matches(&by_name, "some-handle", None, None));
    }

    #[test]
    fn empty_advertised_name_never_matches() {
        // Several peers can advertise no name at once; an empty PeerId is
        // already rejected by parse_peer_id, but guard the match too.
        let peer = PeerId::new("");
        assert!(!peer_matches(&peer, "handle", None, Some("")));
    }

    #[test]
    fn all_zero_address_is_treated_as_undisclosed() {
        assert_eq!(disclosed_address(BDAddr::default()), None);
        let real = BDAddr::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(
            disclosed_address(real).as_deref(),
            Some("AA:BB:CC:DD:EE:FF")
        );
    }

    #[test]
    fn empty_peer_id_is_rejected() {
        assert!(parse_peer_id("   ").is_err());
        assert_eq!(parse_peer_id(" netprovd ").unwrap().as_str(), "netprovd");
    }

    #[test]
    fn auth_rejection_is_recognised_across_platform_wordings() {
        // BlueZ (D-Bus name) and CoreBluetooth (NSError description) phrase
        // ATT error 0x08 differently; both must land on AuthFailed.
        for message in [
            "org.bluez.Error.NotAuthorized",
            "Insufficient Authorization",
            "The attribute requires authentication before it can be written.",
        ] {
            assert!(
                matches!(
                    map_auth_write_err(btleplug::Error::RuntimeError(message.into())),
                    SdkError::AuthFailed
                ),
                "not recognised: {message}"
            );
        }
        assert!(matches!(
            map_auth_write_err(btleplug::Error::PermissionDenied),
            SdkError::AuthFailed
        ));
    }

    #[test]
    fn unrelated_write_errors_stay_transport_errors() {
        // Misreporting a dropped link as a bad PSK would send users chasing
        // the wrong problem.
        assert!(matches!(
            map_auth_write_err(btleplug::Error::NotConnected),
            SdkError::Ble(_)
        ));
    }

    #[test]
    fn write_type_prefers_flow_controlled_writes() {
        let mut characteristic = Characteristic {
            uuid: REQUEST_UUID,
            service_uuid: SERVICE_UUID,
            properties: CharPropFlags::WRITE | CharPropFlags::WRITE_WITHOUT_RESPONSE,
            descriptors: Default::default(),
        };
        assert_eq!(write_type_for(&characteristic), WriteType::WithResponse);

        characteristic.properties = CharPropFlags::WRITE_WITHOUT_RESPONSE;
        assert_eq!(write_type_for(&characteristic), WriteType::WithoutResponse);
    }
}
