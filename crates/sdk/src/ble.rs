//! BLE connector for app and CLI clients.
//!
//! This module is Linux/BlueZ today through `bluer`. Android and iOS should
//! add separate transport adapters behind the same SDK operation surface.

use crate::ops::{ProvisioningClient, SdkError};
use async_trait::async_trait;
use bluer::{
    Adapter, AdapterEvent, Address, DiscoveryFilter, DiscoveryTransport,
    gatt::remote::Characteristic,
};
use futures_util::StreamExt;
use netprov_protocol::{
    FRAME_HEADER_LEN, MAX_MESSAGE_SIZE, MAX_PAYLOAD_PER_FRAME, NONCE_LEN, Op, OpResult, Psk,
    Reassembler, Request, Response, decode_response, encode_request, fragment, hmac_compute,
    parse_frame,
};
use std::collections::HashSet;
use std::time::Duration;

// Must match crates/server/src/ble/uuids.rs.
const SERVICE_UUID: bluer::Uuid = bluer::Uuid::from_u128(0x0eebc1ba_773d_4625_babf_5c6cafe82b30);
const INFO_UUID: bluer::Uuid = bluer::Uuid::from_u128(0xc4c47504_92f6_45d0_97b2_24c965499cf8);
const CHALLENGE_UUID: bluer::Uuid = bluer::Uuid::from_u128(0x0107c3c5_a56b_4283_925b_7dd4ec0aafb6);
const AUTH_RESPONSE_UUID: bluer::Uuid =
    bluer::Uuid::from_u128(0xb78f3640_d56a_487b_b10e_f5dea9facf3c);
const REQUEST_UUID: bluer::Uuid = bluer::Uuid::from_u128(0x6d29f399_aad4_494e_8b0b_b85b9a7fef9e);
const BLE_FRAME_MAX_LEN: usize = MAX_PAYLOAD_PER_FRAME + FRAME_HEADER_LEN;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BleDevice {
    pub address: Address,
    pub name: Option<String>,
    pub rssi: Option<i16>,
}

pub struct BleClient {
    _device: bluer::Device,
    info: Characteristic,
    challenge: Characteristic,
    auth: Characteristic,
    request: Characteristic,
    next_id: u16,
}

impl BleClient {
    pub async fn scan_devices(timeout: Duration) -> Result<Vec<BleDevice>, SdkError> {
        let session = bluer::Session::new().await?;
        let adapter = session.default_adapter().await?;
        adapter.set_powered(true).await?;

        let mut uuids = HashSet::new();
        uuids.insert(SERVICE_UUID);
        adapter
            .set_discovery_filter(DiscoveryFilter {
                uuids,
                transport: DiscoveryTransport::Le,
                ..Default::default()
            })
            .await?;

        let mut events = adapter.discover_devices_with_changes().await?;
        let deadline = tokio::time::Instant::now() + timeout;
        let mut found = Vec::new();

        loop {
            tokio::select! {
                ev = events.next() => match ev {
                    Some(AdapterEvent::DeviceAdded(addr)) => {
                        if let Ok(Some(device)) = query_netprov_device(&adapter, addr).await {
                            upsert_device(&mut found, device);
                        }
                    }
                    Some(_) => continue,
                    None => return Err(SdkError::Ble("discovery stream ended".into())),
                },
                _ = tokio::time::sleep_until(deadline) => break,
            }
        }

        Ok(found)
    }

    pub async fn connect(peer: Address) -> Result<Self, SdkError> {
        let session = bluer::Session::new().await?;
        let adapter = session.default_adapter().await?;
        adapter.set_powered(true).await?;

        let mut events = adapter.discover_devices().await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            tokio::select! {
                ev = events.next() => match ev {
                    Some(AdapterEvent::DeviceAdded(a)) if a == peer => break,
                    Some(_) => continue,
                    None => return Err(SdkError::Ble("discovery stream ended".into())),
                },
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(SdkError::Ble("peer not seen within 10s".into()));
                }
            }
        }
        drop(events);

        let device = adapter.device(peer)?;
        device.connect().await?;

        let services = device.services().await?;
        let mut svc = None;
        for s in services {
            if s.uuid().await? == SERVICE_UUID {
                svc = Some(s);
                break;
            }
        }
        let svc =
            svc.ok_or_else(|| SdkError::Ble(format!("netprov service not found on {peer}")))?;

        let chars = svc.characteristics().await?;
        let mut info = None;
        let mut challenge = None;
        let mut auth = None;
        let mut request = None;
        for c in chars {
            let u = c.uuid().await?;
            if u == INFO_UUID {
                info = Some(c);
            } else if u == CHALLENGE_UUID {
                challenge = Some(c);
            } else if u == AUTH_RESPONSE_UUID {
                auth = Some(c);
            } else if u == REQUEST_UUID {
                request = Some(c);
            }
        }

        Ok(Self {
            _device: device,
            info: info.ok_or_else(|| SdkError::Ble("INFO characteristic missing".into()))?,
            challenge: challenge
                .ok_or_else(|| SdkError::Ble("CHALLENGE characteristic missing".into()))?,
            auth: auth
                .ok_or_else(|| SdkError::Ble("AUTH_RESPONSE characteristic missing".into()))?,
            request: request
                .ok_or_else(|| SdkError::Ble("REQUEST characteristic missing".into()))?,
            next_id: 1,
        })
    }

    pub async fn authenticate(&mut self, psk: Psk) -> Result<(), SdkError> {
        <Self as ProvisioningClient>::authenticate(self, psk).await
    }

    pub async fn request(&mut self, op: Op) -> Result<OpResult, SdkError> {
        <Self as ProvisioningClient>::request(self, op).await
    }
}

#[async_trait]
impl ProvisioningClient for BleClient {
    async fn authenticate(&mut self, psk: Psk) -> Result<(), SdkError> {
        // Read Info first to confirm the service is responsive. Protocol
        // compatibility checks can be added here once the UI exposes versions.
        let _info = self.info.read().await?;

        let nonce = self.challenge.read().await?;
        if nonce.len() != NONCE_LEN {
            return Err(SdkError::UnexpectedMessage("nonce length"));
        }
        let mut n = [0u8; NONCE_LEN];
        n.copy_from_slice(&nonce);
        let tag = hmac_compute(&psk, &n);
        self.auth.write(&tag).await?;
        Ok(())
    }

    async fn request(&mut self, op: Op) -> Result<OpResult, SdkError> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let bytes = encode_request(&Request { request_id: id, op })?;

        // Subscribe before sending so early response fragments cannot be lost.
        let mut notify = self.request.notify_io().await?;

        // fragment() takes the total BLE value length; the payload constant
        // excludes the 5-byte netprov frame header.
        for f in fragment(id, &bytes, BLE_FRAME_MAX_LEN) {
            self.request.write(&f).await?;
        }

        let mut buf = vec![0u8; MAX_MESSAGE_SIZE];
        let mut reassembler = Reassembler::new(MAX_MESSAGE_SIZE);
        loop {
            let n = tokio::io::AsyncReadExt::read(&mut notify, &mut buf).await?;
            if n == 0 {
                return Err(SdkError::Ble("notify stream closed".into()));
            }
            let parsed = parse_frame(&buf[..n])?;
            if let Some(msg) = reassembler.push(parsed)? {
                let resp: Response = decode_response(&msg)?;
                if resp.request_id != id {
                    return Err(SdkError::IdMismatch {
                        expected: id,
                        got: resp.request_id,
                    });
                }
                return resp.result.map_err(Into::into);
            }
        }
    }
}

pub fn parse_peer_address(s: &str) -> Result<Address, SdkError> {
    s.parse()
        .map_err(|e| SdkError::Ble(format!("invalid BD_ADDR {s}: {e}")))
}

async fn query_netprov_device(
    adapter: &Adapter,
    addr: Address,
) -> Result<Option<BleDevice>, SdkError> {
    let device = adapter.device(addr)?;
    let uuids = device.uuids().await?.unwrap_or_default();
    if !uuids.contains(&SERVICE_UUID) {
        return Ok(None);
    }

    let name = device
        .alias()
        .await
        .ok()
        .filter(|value| !value.is_empty())
        .or(device.name().await?.filter(|value| !value.is_empty()));
    let rssi = device.rssi().await?;

    Ok(Some(BleDevice {
        address: addr,
        name,
        rssi,
    }))
}

fn upsert_device(devices: &mut Vec<BleDevice>, device: BleDevice) {
    if let Some(existing) = devices
        .iter_mut()
        .find(|existing| existing.address == device.address)
    {
        *existing = device;
    } else {
        devices.push(device);
    }
}
