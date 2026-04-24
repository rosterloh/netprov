//! BLE connector for the netprov CLI.
//!
//! Only compiled with --features ble.

use anyhow::{anyhow, bail, Context, Result};
use bluer::{gatt::remote::Characteristic, AdapterEvent, Address};
use futures_util::StreamExt;
use netprov_protocol::{
    decode_response, encode_request, fragment, hmac_compute, parse_frame, Reassembler, Request,
    Response, MAX_MESSAGE_SIZE, MAX_PAYLOAD_PER_FRAME, NONCE_LEN, PSK_LEN,
};
use std::time::Duration;

// Redefine UUIDs here with the same values as in netprov-server's uuids.rs.
// The client cannot depend on the server crate (that would create a cycle via
// netprov-protocol). The server's uuids.rs is the canonical source — these
// must track it exactly.
const SERVICE_UUID: bluer::Uuid = bluer::Uuid::from_u128(0x0eebc1ba_773d_4625_babf_5c6cafe82b30);
const INFO_UUID: bluer::Uuid = bluer::Uuid::from_u128(0xc4c47504_92f6_45d0_97b2_24c965499cf8);
const CHALLENGE_UUID: bluer::Uuid = bluer::Uuid::from_u128(0x0107c3c5_a56b_4283_925b_7dd4ec0aafb6);
const AUTH_RESPONSE_UUID: bluer::Uuid =
    bluer::Uuid::from_u128(0xb78f3640_d56a_487b_b10e_f5dea9facf3c);
const REQUEST_UUID: bluer::Uuid = bluer::Uuid::from_u128(0x6d29f399_aad4_494e_8b0b_b85b9a7fef9e);

pub struct BleClient {
    _device: bluer::Device,
    info: Characteristic,
    challenge: Characteristic,
    auth: Characteristic,
    request: Characteristic,
    next_id: u16,
    psk: [u8; PSK_LEN],
}

impl BleClient {
    pub async fn connect(peer: Address, psk: [u8; PSK_LEN]) -> Result<Self> {
        let session = bluer::Session::new().await?;
        let adapter = session.default_adapter().await?;
        adapter.set_powered(true).await?;

        // Scan until we see the peer.
        let mut events = adapter.discover_devices().await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            tokio::select! {
                ev = events.next() => match ev {
                    Some(AdapterEvent::DeviceAdded(a)) if a == peer => break,
                    Some(_) => continue,
                    None => bail!("discovery stream ended"),
                },
                _ = tokio::time::sleep_until(deadline) => bail!("peer not seen within 10s"),
            }
        }
        drop(events);

        let device = adapter.device(peer)?;
        device.connect().await?;

        // Find our service — uuid() is async in bluer 0.17.4.
        let services = device.services().await?;
        let mut svc = None;
        for s in services {
            if s.uuid().await? == SERVICE_UUID {
                svc = Some(s);
                break;
            }
        }
        let svc = svc.ok_or_else(|| anyhow!("netprov service not found on {peer}"))?;

        // Find all four characteristics by UUID.
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
        let info = info.ok_or_else(|| anyhow!("INFO characteristic missing"))?;
        let challenge = challenge.ok_or_else(|| anyhow!("CHALLENGE characteristic missing"))?;
        let auth = auth.ok_or_else(|| anyhow!("AUTH_RESPONSE characteristic missing"))?;
        let request = request.ok_or_else(|| anyhow!("REQUEST characteristic missing"))?;

        Ok(Self {
            _device: device,
            info,
            challenge,
            auth,
            request,
            next_id: 1,
            psk,
        })
    }

    pub async fn authenticate(&self) -> Result<()> {
        // Read Info first — confirms we're talking to a real netprov server.
        let _info = self.info.read().await?;

        let nonce = self.challenge.read().await?;
        if nonce.len() != NONCE_LEN {
            bail!("bad nonce length: {}", nonce.len());
        }
        let mut n = [0u8; NONCE_LEN];
        n.copy_from_slice(&nonce);
        let tag = hmac_compute(&self.psk, &n);
        self.auth.write(&tag).await.context("auth write")?;
        Ok(())
    }

    pub async fn request(
        &mut self,
        op: netprov_protocol::Op,
    ) -> Result<netprov_protocol::OpResult> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let bytes = encode_request(&Request { request_id: id, op })?;

        // Subscribe BEFORE sending so we don't lose early response fragments.
        let mut notify = self.request.notify_io().await?;

        // MAX_PAYLOAD_PER_FRAME = 507; +5 = 512 (max MTU / Web Bluetooth ceiling).
        for f in fragment(id, &bytes, MAX_PAYLOAD_PER_FRAME + 5) {
            self.request.write(&f).await?;
        }

        let mut buf = vec![0u8; MAX_MESSAGE_SIZE];
        let mut reassembler = Reassembler::new(MAX_MESSAGE_SIZE);
        loop {
            let n = tokio::io::AsyncReadExt::read(&mut notify, &mut buf).await?;
            if n == 0 {
                bail!("notify stream closed");
            }
            let parsed = parse_frame(&buf[..n])?;
            if let Some(msg) = reassembler.push(parsed)? {
                let resp: Response = decode_response(&msg)?;
                if resp.request_id != id {
                    bail!("id mismatch: expected {id}, got {}", resp.request_id);
                }
                return resp.result.map_err(|e| anyhow!("{e}"));
            }
        }
    }
}

pub fn parse_peer_address(s: &str) -> Result<Address> {
    s.parse().map_err(|e| anyhow!("invalid BD_ADDR {s}: {e}"))
}
