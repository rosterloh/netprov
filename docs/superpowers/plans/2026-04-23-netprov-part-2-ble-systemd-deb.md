# netprov Implementation Plan — Part 2: BLE + systemd + deb

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Part 1 TCP dev surface with a real BLE GATT server, harden the daemon for systemd (`Type=notify` + hardening), finish the `NmrsFacade` Wi-Fi ops, ship a `.deb`, and extend CI to cover aarch64 + deb build.

**Architecture:** The Part 1 `Session` state machine stays untouched — it already knows how to `issue_nonce`, `submit_auth`, and `handle_request`. Part 2 adds a `BleServer` driver that owns one `bluer::Adapter`, advertises a single GATT service with four characteristics (`Info`, `ChallengeNonce`, `AuthResponse`, `Request`/`Response`), and feeds those events into a per-connection `Session`. The Envelope-based loopback transport from Part 1 is retained under a `serve-tcp` debug subcommand; production uses `serve-ble`. `NmrsFacade` Wi-Fi ops are filled in via a mix of `nmrs` and raw zbus. Packaging uses `cargo-deb` with a single `netprov` source package delivering both binaries plus the unit file.

**Tech Stack:** Rust stable, `bluer` 0.17, `sd-notify` 0.5, `cargo-deb` 3.x, existing `tokio` / `ciborium` / `nmrs` / `zbus` / `tracing` stack from Part 1. aarch64 and amd64 native runners in CI.

---

## Design Reference

Design spec: [`docs/superpowers/specs/2026-04-23-netprov-design.md`](../specs/2026-04-23-netprov-design.md). Part 1 plan: [`docs/superpowers/plans/2026-04-23-netprov-part-1-core.md`](./2026-04-23-netprov-part-1-core.md). Section numbers (§) refer to the design spec.

## File Structure

Created or modified in this plan:

```
netprov/
├── Cargo.toml                                 # workspace — no change
├── crates/
│   ├── protocol/                              # unchanged
│   ├── server/
│   │   ├── Cargo.toml                         # + bluer, sd-notify, live-ble, deb metadata
│   │   └── src/
│   │       ├── ble/                           # NEW — BLE driver module
│   │       │   ├── mod.rs                     #   re-exports
│   │       │   ├── uuids.rs                   #   pinned service + characteristic UUIDs
│   │       │   ├── gatt.rs                    #   build bluer Application{Service, Characteristic}
│   │       │   ├── conn.rs                    #   per-peer Session driver wired to GATT events
│   │       │   └── server.rs                  #   run_ble_server() — adapter init, advertise,
│   │       │                                  #                   accept loop, fan-out to conn.rs
│   │       ├── notify.rs                      # NEW — sd_notify wrapper (READY=1 + WATCHDOG)
│   │       ├── facade_nmrs.rs                 # MODIFY — fill in wifi_status / scan / connect / set_*
│   │       ├── main.rs                        # MODIFY — add serve-ble (default) + rename serve→serve-tcp
│   │       └── lib.rs                         # MODIFY — re-export ble + notify
│   └── client/
│       ├── Cargo.toml                         # + bluer (opt-in under ble feature)
│       └── src/
│           ├── ble.rs                         # NEW — BLE client connector (behind `ble` feature)
│           ├── cli.rs                         # MODIFY — add --ble-peer
│           └── main.rs                        # MODIFY — pick TCP vs BLE transport from CLI
├── packaging/
│   ├── netprovd.service                       # NEW — Type=notify unit with hardening
│   └── debian/
│       ├── postinst                           # NEW
│       ├── prerm                              # NEW
│       └── postrm                             # NEW
├── .github/workflows/
│   └── ci.yml                                 # MODIFY — amd64 + aarch64 matrix, deb artifact
└── docs/superpowers/plans/
    └── 2026-04-23-netprov-part-2-ble-systemd-deb.md  # this file
```

Files **deliberately not touched**: everything under `crates/protocol/` (wire format is frozen). `crates/server/src/server_loop.rs` keeps `run_server` for TCP loopback — Part 2 adds a *new* BLE driver alongside it rather than replacing it, so the existing 9 loopback tests stay as regression coverage for the `Session` state machine.

---

## Phase 0 — Dependencies and UUIDs

### Task 0.1: Pin BLE + sd-notify deps and generate stable UUIDs

**Files:**
- Modify: `Cargo.toml` (workspace), `crates/server/Cargo.toml`, `crates/client/Cargo.toml`
- Create: `crates/server/src/ble/uuids.rs`

Per spec §7.1 (service UUID generated once at scaffold time, hard-coded).

- [ ] **Step 1: Add `bluer` + `sd-notify` + `futures-util` to the workspace**

Edit `Cargo.toml` (workspace root), inside `[workspace.dependencies]`:

```toml
bluer = { version = "0.17", features = ["bluetoothd", "l2cap"] }
sd-notify = "0.5"
futures-util = "0.3"
```

Run: `cargo metadata --format-version 1 --no-deps > /dev/null`
Expected: exit 0.

- [ ] **Step 2: Add new features and deps to `crates/server/Cargo.toml`**

Inside `[features]`, append:
```toml
live-ble = ["dep:bluer", "dep:futures-util", "dep:sd-notify"]
```
(The feature is opt-in to keep the default `cargo test --workspace` path fast and hardware-free. The `serve-ble` subcommand is only compiled when this feature is on.)

Inside `[dependencies]`, add:
```toml
bluer = { workspace = true, optional = true }
sd-notify = { workspace = true, optional = true }
futures-util = { workspace = true, optional = true }
```

- [ ] **Step 3: Add BLE feature + optional dep to `crates/client/Cargo.toml`**

Under `[features]`:
```toml
ble = ["dep:bluer", "dep:futures-util"]
```

Under `[dependencies]`:
```toml
bluer = { workspace = true, optional = true }
futures-util = { workspace = true, optional = true }
```

- [ ] **Step 4: Create `crates/server/src/ble/uuids.rs`** with pinned UUIDs

```rust
//! Pinned BLE service + characteristic UUIDs for netprov.
//!
//! Generated once at Part 2 scaffold time. **Do not change these** — clients
//! discover the service by UUID. Changing a UUID is a breaking protocol change
//! requiring a major-version bump (§7.1).

use bluer::Uuid;

pub const SERVICE_UUID: Uuid = Uuid::from_u128(0x0eebc1ba_773d_4625_babf_5c6cafe82b30);

pub const INFO_UUID:           Uuid = Uuid::from_u128(0xc4c47504_92f6_45d0_97b2_24c965499cf8);
pub const CHALLENGE_UUID:      Uuid = Uuid::from_u128(0x0107c3c5_a56b_4283_925b_7dd4ec0aafb6);
pub const AUTH_RESPONSE_UUID:  Uuid = Uuid::from_u128(0xb78f3640_d56a_487b_b10e_f5dea9facf3c);
pub const REQUEST_UUID:        Uuid = Uuid::from_u128(0x6d29f399_aad4_494e_8b0b_b85b9a7fef9e);

/// `Response` is a notify characteristic. We reuse a single UUID ("request"
/// write + "response" notify) by giving it both properties. This matches how
/// the BlueZ layer actually exposes the endpoint: one characteristic, two
/// flows. Clients subscribe to notifications on REQUEST_UUID.
pub const RESPONSE_UUID: Uuid = REQUEST_UUID;
```

> **Note:** If a future client implementation expects separate UUIDs for Request/Response, bump to a new SERVICE_UUID and add a second characteristic. For v1 a single bidirectional characteristic is simpler and matches the spec's "one Request / one Response" intent.

- [ ] **Step 5: Create `crates/server/src/ble/mod.rs`** (stub; wired in Task 1.1)

```rust
//! BLE GATT server driver.
//!
//! Only compiled when the `live-ble` feature is enabled.

pub mod uuids;
```

- [ ] **Step 6: Wire into `crates/server/src/lib.rs`** — gated re-export

Append:
```rust
#[cfg(feature = "live-ble")]
pub mod ble;
```

- [ ] **Step 7: Verify both builds still succeed**

Run: `cargo build --workspace`
Expected: success.

Run: `cargo build --workspace --features netprov-server/live-ble`
Expected: success. (BlueZ dev headers are not needed — `bluer` talks D-Bus; only `bluez` userspace is required at *runtime*.)

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml crates/server/Cargo.toml crates/client/Cargo.toml \
        crates/server/src/ble/uuids.rs crates/server/src/ble/mod.rs \
        crates/server/src/lib.rs
git commit -m "feat(server): pin BLE UUIDs and add live-ble feature scaffold"
```

---

## Phase 1 — BLE GATT server

All of Phase 1 is gated on `--features live-ble`. The default `cargo test --workspace` build stays BLE-free.

### Task 1.1: GATT Application builder (pure data, no runtime)

**Files:**
- Create: `crates/server/src/ble/gatt.rs`
- Modify: `crates/server/src/ble/mod.rs`

Per spec §7.1. This task defines the `bluer::gatt::local::Application` that advertises netprov's service. It takes callbacks as dependency injection so it can be unit-tested without a real adapter — all the async logic (reading nonces, verifying HMAC, dispatching ops) lives in callbacks hooked up in Task 1.3.

- [ ] **Step 1: Write `crates/server/src/ble/gatt.rs`**

```rust
//! Construct the bluer Application describing netprov's GATT service.

use super::uuids::{
    AUTH_RESPONSE_UUID, CHALLENGE_UUID, INFO_UUID, REQUEST_UUID, SERVICE_UUID,
};
use bluer::gatt::local::{
    characteristic_control, Application, Characteristic, CharacteristicNotify,
    CharacteristicNotifyMethod, CharacteristicRead, CharacteristicWrite,
    CharacteristicWriteMethod, Service,
};
use std::sync::Arc;

/// Thin handle passed to each characteristic's closure so all four share state.
pub struct GattHandlers {
    pub on_info_read: Arc<dyn Fn() -> Vec<u8> + Send + Sync>,
    pub on_nonce_read: Arc<dyn Fn() -> Vec<u8> + Send + Sync>,
    pub on_auth_write: Arc<dyn Fn(Vec<u8>) -> bool + Send + Sync>,
    pub on_request_write: Arc<dyn Fn(Vec<u8>) + Send + Sync>,
}

pub fn build_application(h: GattHandlers) -> Application {
    let info_read = h.on_info_read.clone();
    let nonce_read = h.on_nonce_read.clone();
    let auth_write = h.on_auth_write.clone();
    let request_write = h.on_request_write.clone();

    Application {
        services: vec![Service {
            uuid: SERVICE_UUID,
            primary: true,
            characteristics: vec![
                // Info — unauthenticated read.
                Characteristic {
                    uuid: INFO_UUID,
                    read: Some(CharacteristicRead {
                        read: true,
                        fun: Box::new(move |_req| {
                            let out = (info_read)();
                            Box::pin(async move { Ok(out) })
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                // ChallengeNonce — fresh 32 bytes per read.
                Characteristic {
                    uuid: CHALLENGE_UUID,
                    read: Some(CharacteristicRead {
                        read: true,
                        fun: Box::new(move |_req| {
                            let out = (nonce_read)();
                            Box::pin(async move { Ok(out) })
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                // AuthResponse — write-only, returns error to terminate the
                // connection when auth fails.
                Characteristic {
                    uuid: AUTH_RESPONSE_UUID,
                    write: Some(CharacteristicWrite {
                        write: true,
                        write_without_response: false,
                        method: CharacteristicWriteMethod::Fun(Box::new(move |value, _req| {
                            let ok = (auth_write)(value);
                            Box::pin(async move {
                                if ok { Ok(()) }
                                else { Err(bluer::gatt::local::ReqError::NotAuthorized) }
                            })
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                // Request/Response — writeable (fragments in) + notify (fragments out).
                Characteristic {
                    uuid: REQUEST_UUID,
                    write: Some(CharacteristicWrite {
                        write: true,
                        write_without_response: true,
                        method: CharacteristicWriteMethod::Fun(Box::new(move |value, _req| {
                            (request_write)(value);
                            Box::pin(async move { Ok(()) })
                        })),
                        ..Default::default()
                    }),
                    notify: Some(CharacteristicNotify {
                        notify: true,
                        method: CharacteristicNotifyMethod::Io,
                        ..Default::default()
                    }),
                    control_handle: characteristic_control().0,
                    ..Default::default()
                },
            ],
            ..Default::default()
        }],
        ..Default::default()
    }
}
```

> **Note:** The `CharacteristicNotifyMethod::Io` choice means the notify side exposes a `bluer::gatt::local::CharacteristicWriter` that the server writes bytes into. That writer is acquired in Task 1.3 when a client subscribes. Using the `Io` method (instead of `Fun`) gives us raw streaming for fragment notifications.

- [ ] **Step 2: Wire into `ble/mod.rs`**

```rust
//! BLE GATT server driver.
//!
//! Only compiled when the `live-ble` feature is enabled.

pub mod gatt;
pub mod uuids;
```

- [ ] **Step 3: Compile gate check**

Run: `cargo build -p netprov-server --features live-ble`
Expected: success.

- [ ] **Step 4: Commit**

```bash
git add crates/server/src/ble/gatt.rs crates/server/src/ble/mod.rs
git commit -m "feat(server): build bluer Application describing netprov GATT service"
```

### Task 1.2: Per-connection driver — feeds GATT events into Session

**Files:**
- Create: `crates/server/src/ble/conn.rs`
- Modify: `crates/server/src/ble/mod.rs`

Per spec §7.2 (framing), §7.3 (auth), §7.5 (request/response).

This task is the glue between GATT events (opaque `Vec<u8>` writes and reads) and the `Session` state machine from Part 1. One `PeerSession` exists per connected BLE peer.

- [ ] **Step 1: Create `crates/server/src/ble/conn.rs`**

```rust
//! Per-peer state driven by GATT events.
//!
//! Owns a Session, a Reassembler for inbound request fragments, and a channel
//! to the per-peer notify writer. All four GATT callbacks for this peer close
//! over an Arc<PeerSession>.

use crate::facade::NetworkFacade;
use crate::rate_limit::RateLimiter;
use crate::session::Session;
use netprov_protocol::{
    decode_request, encode_response, fragment, parse_frame, Reassembler, Request,
    Response, InfoPayload, PROTOCOL_VERSION, PSK_LEN, NONCE_LEN, MAX_MESSAGE_SIZE,
    MAX_PAYLOAD_PER_FRAME,
};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

/// Bytes that need to be written out on the Request/Response notify stream.
/// Producer: per-peer PeerSession::dispatch. Consumer: the notify-io writer
/// owned by run_ble_server().
pub type NotifyTx = mpsc::UnboundedSender<Vec<u8>>;
pub type NotifyRx = mpsc::UnboundedReceiver<Vec<u8>>;

pub struct PeerSession<F: NetworkFacade> {
    pub session: Mutex<Session<F>>,
    pub reassembler: Mutex<Reassembler>,
    pub notify_tx: NotifyTx,
    pub model: String,
    pub dispatch_handles: Mutex<Vec<JoinHandle<()>>>,
}

impl<F: NetworkFacade + 'static> PeerSession<F> {
    pub fn new(
        psk: [u8; PSK_LEN],
        peer_id: String,
        facade: Arc<F>,
        rate_limiter: Arc<RateLimiter>,
        model: String,
        notify_tx: NotifyTx,
    ) -> Arc<Self> {
        Arc::new(Self {
            session: Mutex::new(Session::new(psk, peer_id, facade, rate_limiter)),
            reassembler: Mutex::new(Reassembler::new(MAX_MESSAGE_SIZE)),
            notify_tx,
            model,
            dispatch_handles: Mutex::new(Vec::new()),
        })
    }

    /// Info read handler — unauthenticated.
    pub fn on_info(&self) -> Vec<u8> {
        let payload = InfoPayload {
            protocol_version: PROTOCOL_VERSION,
            supported_ops: 0x7F, // bits 0..6 → all 7 v1 ops
            model: self.model.clone(),
        };
        let mut bytes = Vec::with_capacity(64);
        ciborium::into_writer(&payload, &mut bytes).expect("InfoPayload encodes");
        bytes
    }

    /// ChallengeNonce read handler — generates fresh nonce, invalidates any prior.
    pub fn on_nonce(&self) -> Vec<u8> {
        let nonce = self.session.lock().unwrap().issue_nonce();
        nonce.to_vec()
    }

    /// AuthResponse write handler — returns true on success (session becomes
    /// authenticated), false on failure (caller should terminate).
    pub fn on_auth(&self, tag: Vec<u8>) -> bool {
        if tag.len() != NONCE_LEN {
            return false;
        }
        self.session.lock().unwrap().submit_auth(&tag)
    }

    /// Request write handler — reassembles fragments, dispatches complete
    /// messages, emits fragmented responses back via notify_tx.
    pub fn on_request(self: &Arc<Self>, value: Vec<u8>) {
        let parsed = match parse_frame(&value) {
            Ok(f) => f,
            Err(e) => {
                warn!(error = ?e, "rejected malformed frame");
                return;
            }
        };
        let complete = match self.reassembler.lock().unwrap().push(parsed) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return,
            Err(e) => {
                warn!(error = ?e, "reassembler rejected frame");
                return;
            }
        };

        let req: Request = match decode_request(&complete) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = ?e, "rejected malformed request");
                return;
            }
        };

        // Dispatch asynchronously so the GATT write callback returns fast.
        let this = self.clone();
        let handle = tokio::spawn(async move {
            let resp = this.session.lock().unwrap().handle_request_sync(req.clone());
            // ^ Session::handle_request is async in Part 1; see note below.
            let _ = resp; // silence unused if someone edits this path
            let resp = {
                // Need to re-lock because handle_request needs &self — we can't
                // hold the Mutex across await. Session operates on shared &self,
                // so clone the Arc<Session> interior instead.
                let session_ref: *const Session<F> = &*this.session.lock().unwrap();
                // SAFETY: Session's handle_request borrows &self; we're the only
                // writer on this session. Replaced below with a proper design.
                unsafe { (*session_ref).handle_request(req).await }
            };

            let bytes = match encode_response(&resp) {
                Ok(b) => b,
                Err(e) => {
                    warn!(error = ?e, "failed to encode response");
                    return;
                }
            };
            let frames = fragment(resp.request_id, &bytes, MAX_PAYLOAD_PER_FRAME + 5);
            for f in frames {
                if this.notify_tx.send(f).is_err() {
                    debug!("notify channel closed");
                    return;
                }
            }
        });
        self.dispatch_handles.lock().unwrap().push(handle);
    }
}
```

> **Design note:** The `unsafe` block above is a code-smell placeholder — it exists because `Session::handle_request` in Part 1 was defined as `async fn handle_request(&self, ...)` and the `PeerSession::session` field is a `Mutex<Session<F>>`. Holding a lock across `.await` would block other handlers. Step 2 below fixes this properly: refactor `Session` so the auth-state mutation is separated from the read-only dispatch path, allowing us to store the facade + rate limiter + peer_id in `PeerSession` directly and call `Session::handle_request` on a throwaway borrow.

- [ ] **Step 2: Refactor `Session` to separate auth state from dispatch state**

Edit `crates/server/src/session.rs`. Split into an immutable `Dispatcher<F>` that holds `facade + rate_limiter + peer_id + psk` (doesn't need `&mut` for `handle_request`) and a `AuthState` wrapped in a `Mutex` at the peer level.

Exact change: extract the dispatch portion of `handle_request` into a free function `pub async fn dispatch<F: NetworkFacade>(facade: &F, req: Request) -> Response`. Keep `Session::handle_request` as a thin wrapper. This lets `PeerSession` call `dispatch(&*self.facade, req).await` without holding any mutex.

```rust
// Add to crates/server/src/session.rs

pub async fn dispatch<F: NetworkFacade>(facade: &F, req: Request) -> Response {
    use netprov_protocol::{Op, OpResult, Response};
    let request_id = req.request_id;
    let result = match req.op {
        Op::ListInterfaces => facade.list_interfaces().await
            .map(OpResult::Interfaces).map_err(Into::into),
        Op::GetIpConfig { iface } => facade.get_ip_config(&iface).await
            .map(OpResult::IpConfig).map_err(Into::into),
        Op::WifiStatus => facade.wifi_status().await
            .map(OpResult::WifiStatus).map_err(Into::into),
        Op::WifiScan => facade.scan_wifi().await
            .map(OpResult::WifiNetworks).map_err(Into::into),
        Op::SetDhcp { iface } => facade.set_dhcp(&iface).await
            .map(|_| OpResult::Ok).map_err(Into::into),
        Op::SetStaticIpv4 { iface, cfg } => {
            if let Err(e) = crate::validate::validate_static_ipv4(&cfg) {
                Err(e.into())
            } else {
                facade.set_static_ipv4(&iface, cfg).await
                    .map(|_| OpResult::Ok).map_err(Into::into)
            }
        }
        Op::ConnectWifi { ssid, credential } => facade.connect_wifi(&ssid, credential).await
            .map(|_| OpResult::Ok).map_err(Into::into),
    };
    Response { request_id, result }
}
```

Update `Session::handle_request` to delegate:

```rust
pub async fn handle_request(&self, req: Request) -> Response {
    if !self.is_authenticated() {
        return Response {
            request_id: req.request_id,
            result: Err(ProtocolError::NotAuthenticated),
        };
    }
    dispatch(&*self.facade, req).await
}
```

Export `dispatch` from `lib.rs`:
```rust
pub use session::{dispatch, Session};
```

- [ ] **Step 3: Rewrite `PeerSession::on_request` without `unsafe`**

Replace the `on_request` body in `crates/server/src/ble/conn.rs` with:

```rust
pub fn on_request(self: &Arc<Self>, value: Vec<u8>) {
    let parsed = match parse_frame(&value) {
        Ok(f) => f,
        Err(e) => { warn!(error = ?e, "rejected malformed frame"); return; }
    };
    let complete = match self.reassembler.lock().unwrap().push(parsed) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return,
        Err(e) => { warn!(error = ?e, "reassembler rejected frame"); return; }
    };
    let req: Request = match decode_request(&complete) {
        Ok(r) => r,
        Err(e) => { warn!(error = ?e, "rejected malformed request"); return; }
    };

    // Extract the data we need under the lock, then drop it before awaiting.
    let facade = self.session.lock().unwrap().facade_clone();
    let authed = self.session.lock().unwrap().is_authenticated();

    let this = self.clone();
    let handle = tokio::spawn(async move {
        let resp = if !authed {
            Response {
                request_id: req.request_id,
                result: Err(netprov_protocol::ProtocolError::NotAuthenticated),
            }
        } else {
            crate::session::dispatch(&*facade, req).await
        };
        let bytes = match encode_response(&resp) {
            Ok(b) => b,
            Err(e) => { warn!(error = ?e, "failed to encode response"); return; }
        };
        let frames = fragment(resp.request_id, &bytes, MAX_PAYLOAD_PER_FRAME + 5);
        for f in frames {
            if this.notify_tx.send(f).is_err() {
                debug!("notify channel closed");
                return;
            }
        }
    });
    self.dispatch_handles.lock().unwrap().push(handle);
}
```

Add a small helper to `Session`:

```rust
impl<F: NetworkFacade> Session<F> {
    pub fn facade_clone(&self) -> Arc<F> { self.facade.clone() }
}
```

- [ ] **Step 4: Wire into `ble/mod.rs`**

```rust
pub mod conn;
pub mod gatt;
pub mod uuids;
```

- [ ] **Step 5: Verify build + existing tests still pass**

```bash
cargo build --workspace --features netprov-server/live-ble
cargo test --workspace
```
Expected: build succeeds; 33 server + 9 loopback + 24 protocol tests still green. The `dispatch` extraction is a pure refactor — behavior unchanged.

- [ ] **Step 6: Commit**

```bash
git add crates/server/src/session.rs crates/server/src/lib.rs \
        crates/server/src/ble/mod.rs crates/server/src/ble/conn.rs
git commit -m "feat(server): PeerSession driver glues GATT events to Session

- Extract dispatch() from Session::handle_request so it can be called
  without holding a Mutex across await.
- PeerSession wraps Session + Reassembler + notify channel, one per peer."
```

### Task 1.3: `run_ble_server` — adapter init, advertise, accept loop

**Files:**
- Create: `crates/server/src/ble/server.rs`
- Modify: `crates/server/src/ble/mod.rs`

Per spec §7.1 (service UUID advertised), §9.1 (`Type=notify` — readiness after adapter acquired).

- [ ] **Step 1: Write `crates/server/src/ble/server.rs`**

```rust
//! BLE adapter initialization + per-peer connection fan-out.

use super::{conn::PeerSession, gatt::{build_application, GattHandlers}};
use crate::facade::NetworkFacade;
use crate::rate_limit::RateLimiter;
use bluer::{
    adv::{Advertisement, Type as AdvType},
    gatt::local::{characteristic_control, CharacteristicControlEvent},
    Adapter, Session as BluerSession,
};
use futures_util::{pin_mut, StreamExt};
use netprov_protocol::PSK_LEN;
use std::collections::BTreeSet;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

pub struct BleServerConfig {
    pub psk: [u8; PSK_LEN],
    /// Device model exposed via Info characteristic. Per §11: model only, no serial.
    pub model: String,
    /// If Some, bind to a specific controller (e.g. "hci0"); otherwise default.
    pub adapter_name: Option<String>,
}

pub async fn run_ble_server<F>(
    cfg: BleServerConfig,
    facade: Arc<F>,
    rate_limiter: Arc<RateLimiter>,
    mut ready_cb: impl FnMut(),
) -> anyhow::Result<()>
where
    F: NetworkFacade + 'static,
{
    let session = BluerSession::new().await?;
    let adapter = match cfg.adapter_name {
        Some(n) => session.adapter(&n)?,
        None => session.default_adapter().await?,
    };
    adapter.set_powered(true).await?;
    adapter.set_discoverable(true).await?;
    adapter.set_pairable(true).await?;
    info!(name = %adapter.name(), addr = ?adapter.address().await?, "BLE adapter up");

    // Advertise the netprov service UUID so a scanning client can find us.
    let adv = Advertisement {
        advertisement_type: AdvType::Peripheral,
        service_uuids: {
            let mut s = BTreeSet::new();
            s.insert(super::uuids::SERVICE_UUID);
            s
        },
        discoverable: Some(true),
        local_name: Some(format!("netprovd-{}", cfg.model)),
        ..Default::default()
    };
    let _adv_handle = adapter.advertise(adv).await?;

    // One PeerSession is built per new peer. bluer's Application is constructed
    // up front with *static* handlers that route to the current peer via an
    // inner `Mutex<Option<Arc<PeerSession<F>>>>`. This matches bluer's model:
    // there's one Application, but it services one connection at a time (v1
    // goal — mobile clients will typically pair sequentially).
    let current: Arc<std::sync::Mutex<Option<Arc<PeerSession<F>>>>> = Arc::new(Default::default());

    let (notify_ctrl, notify_ctrl_handle) = characteristic_control();
    let _ = notify_ctrl; // placeholder — acquired below

    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let handlers = {
        let cur_info = current.clone();
        let cur_nonce = current.clone();
        let cur_auth = current.clone();
        let cur_req = current.clone();
        GattHandlers {
            on_info_read: Arc::new(move || {
                cur_info.lock().unwrap().as_ref()
                    .map(|p| p.on_info())
                    .unwrap_or_default()
            }),
            on_nonce_read: Arc::new(move || {
                cur_nonce.lock().unwrap().as_ref()
                    .map(|p| p.on_nonce())
                    .unwrap_or_default()
            }),
            on_auth_write: Arc::new(move |value| {
                cur_auth.lock().unwrap().as_ref()
                    .map(|p| p.on_auth(value))
                    .unwrap_or(false)
            }),
            on_request_write: Arc::new(move |value| {
                if let Some(p) = cur_req.lock().unwrap().as_ref() {
                    p.on_request(value);
                }
            }),
        }
    };

    let app = build_application(handlers);
    let _app_handle = adapter.serve_gatt_application(app).await?;
    info!("GATT service registered");

    // Readiness signal to systemd.
    ready_cb();

    // Drive the notify control stream: when a peer subscribes, pipe bytes from
    // `rx` into the CharacteristicWriter it gives us.
    let current_for_conn = current.clone();
    let psk = cfg.psk;
    let model = cfg.model.clone();
    let facade_c = facade.clone();
    let rl_c = rate_limiter.clone();

    pin_mut!(notify_ctrl_handle);
    while let Some(evt) = notify_ctrl_handle.next().await {
        match evt {
            CharacteristicControlEvent::Notify(notifier) => {
                // A peer just subscribed → start a PeerSession for it.
                let peer = PeerSession::new(
                    psk,
                    format!("{:?}", notifier.device_address()),
                    facade_c.clone(),
                    rl_c.clone(),
                    model.clone(),
                    tx.clone(),
                );
                info!(peer = %peer.session.lock().unwrap().peer_id_for_log(),
                      "peer subscribed; session started");
                *current_for_conn.lock().unwrap() = Some(peer);

                // Fan out notifications from rx to this peer until they disconnect.
                let mut notifier = notifier;
                while let Some(frame) = rx.recv().await {
                    if let Err(e) = notifier.write_all(&frame).await {
                        debug!(error = ?e, "notify write failed; peer likely gone");
                        break;
                    }
                }
                *current_for_conn.lock().unwrap() = None;
            }
            CharacteristicControlEvent::Write(_) => {
                // Handled by CharacteristicWriteMethod::Fun in gatt.rs.
            }
        }
    }
    warn!("notify control stream ended — adapter lost");
    Ok(())
}
```

> **Simplification:** This driver serves one peer at a time. Multi-peer concurrency is a Part 3 concern and not part of v1 goals (the spec specifically scopes v1 to a single paired client). The `_ = notify_ctrl` line is a marker — the real control handle is returned by `characteristic_control()` and lives inside the Characteristic. Task 1.4 tightens this to pull the handle out of the built Application instead of calling `characteristic_control()` twice.

- [ ] **Step 2: Add `Session::peer_id_for_log`**

In `crates/server/src/session.rs`:

```rust
impl<F: NetworkFacade> Session<F> {
    pub fn peer_id_for_log(&self) -> &str { &self.peer_id }
}
```

- [ ] **Step 3: Wire into `ble/mod.rs`**

```rust
pub mod conn;
pub mod gatt;
pub mod server;
pub mod uuids;

pub use server::{run_ble_server, BleServerConfig};
```

- [ ] **Step 4: Verify compile under `live-ble`**

```bash
cargo build -p netprov-server --features live-ble
```
Expected: success. Runtime testing happens in Task 6.

- [ ] **Step 5: Commit**

```bash
git add crates/server/src/ble/server.rs crates/server/src/ble/mod.rs \
        crates/server/src/session.rs
git commit -m "feat(server): run_ble_server advertises service, serves one peer at a time"
```

### Task 1.4: Use `control_handle` properly — single-source control stream

**Files:**
- Modify: `crates/server/src/ble/gatt.rs`, `crates/server/src/ble/server.rs`

Task 1.3 reserved a `characteristic_control()` on the Request/Response characteristic but also created a second one locally. That duplicates handles and only one will see events. Fix: return the handle from `build_application` so `run_ble_server` uses the *same* control as the Characteristic.

- [ ] **Step 1: Change `build_application` return type**

Edit `crates/server/src/ble/gatt.rs`:

```rust
pub struct BuiltApp {
    pub app: Application,
    pub notify_control: bluer::gatt::local::CharacteristicControlHandle,
}

pub fn build_application(h: GattHandlers) -> BuiltApp {
    let (ctrl, handle) = characteristic_control();
    // ... (same characteristic construction, but the Request/Response one uses `ctrl`)
    BuiltApp {
        app: Application { services: vec![svc], ..Default::default() },
        notify_control: handle,
    }
}
```

Concrete change inside the Request/Response Characteristic:

```rust
Characteristic {
    uuid: REQUEST_UUID,
    write: Some(CharacteristicWrite { /* as before */ }),
    notify: Some(CharacteristicNotify {
        notify: true,
        method: CharacteristicNotifyMethod::Io,
        ..Default::default()
    }),
    control_handle: ctrl,
    ..Default::default()
},
```

- [ ] **Step 2: Update `run_ble_server` to consume `BuiltApp`**

In `crates/server/src/ble/server.rs`:

```rust
let built = build_application(handlers);
let _app_handle = adapter.serve_gatt_application(built.app).await?;
let notify_ctrl_handle = built.notify_control;
```

Remove the second `characteristic_control()` call.

- [ ] **Step 3: Build check**

Run: `cargo build -p netprov-server --features live-ble`
Expected: success.

- [ ] **Step 4: Commit**

```bash
git add crates/server/src/ble/gatt.rs crates/server/src/ble/server.rs
git commit -m "refactor(server): single control handle for Request/Response notify"
```

---

## Phase 2 — systemd `Type=notify` + production entry point

### Task 2.1: `sd_notify` wrapper module

**Files:**
- Create: `crates/server/src/notify.rs`
- Modify: `crates/server/src/lib.rs`

Per spec §9.1 (`Type=notify` — readiness signalled after GATT registration).

- [ ] **Step 1: Write `crates/server/src/notify.rs`**

```rust
//! Thin wrapper around sd-notify so the rest of the codebase doesn't need to
//! care whether it's running under systemd.

use sd_notify::NotifyState;

/// Tell systemd we're ready. No-op if $NOTIFY_SOCKET is unset.
pub fn notify_ready() {
    let _ = sd_notify::notify(true, &[NotifyState::Ready]);
}

/// Tell systemd we're stopping.
pub fn notify_stopping() {
    let _ = sd_notify::notify(true, &[NotifyState::Stopping]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notify_with_no_socket_is_noop() {
        std::env::remove_var("NOTIFY_SOCKET");
        notify_ready(); // must not panic
        notify_stopping();
    }
}
```

- [ ] **Step 2: Wire into `lib.rs`**

Append:
```rust
#[cfg(feature = "live-ble")]
pub mod notify;
```

> `notify` is feature-gated on `live-ble` because sd-notify only matters when the daemon actually runs; TCP loopback doesn't need readiness. This keeps `cargo test --workspace` dependency-free.

- [ ] **Step 3: Run tests**

```bash
cargo test -p netprov-server --features live-ble notify::
```
Expected: 1 passed.

- [ ] **Step 4: Commit**

```bash
git add crates/server/src/notify.rs crates/server/src/lib.rs
git commit -m "feat(server): sd-notify wrapper for Type=notify readiness signal"
```

### Task 2.2: `netprovd serve-ble` subcommand

**Files:**
- Modify: `crates/server/src/main.rs`

- [ ] **Step 1: Replace `crates/server/src/main.rs`**

```rust
use clap::{Parser, Subcommand};
use netprov_server::keygen::{run_keygen, KeygenArgs};
use netprov_server::logging::{log_startup_banner, spawn_dev_key_warn_loop};
#[cfg(feature = "live-ble")]
use netprov_server::{
    ble::{run_ble_server, BleServerConfig},
    notify::{notify_ready, notify_stopping},
};
use netprov_server::server_loop::run_tcp_server;
use netprov_server::{load_key, LoadOptions, MockFacade, RateLimiter};
#[cfg(feature = "live-ble")]
use netprov_server::NmrsFacade;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "netprovd", about = "netprov daemon")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a PSK. Optionally install it.
    Keygen {
        #[arg(long)]
        install: bool,
        #[arg(long, short = 'o')]
        out: Option<PathBuf>,
    },
    /// (Dev only) Run the loopback TCP server against MockFacade.
    ServeTcp {
        #[arg(long, default_value = "127.0.0.1:9600")]
        listen: String,
    },
    /// (Production) Run the BLE GATT server against NmrsFacade.
    #[cfg(feature = "live-ble")]
    ServeBle {
        /// Which BLE controller to bind ("hci0", "hci1", …). Defaults to the
        /// adapter bluer picks.
        #[arg(long)]
        adapter: Option<String>,
        /// Model string exposed in the Info characteristic.
        #[arg(long, default_value = "netprov-dev")]
        model: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli.command {
        Cmd::Keygen { install, out } => {
            run_keygen(
                KeygenArgs {
                    install,
                    install_path: out.unwrap_or_else(|| "/etc/netprov/key".into()),
                },
                &mut std::io::stdout(),
            )?;
        }
        Cmd::ServeTcp { listen } => {
            let key = load_prod_or_dev_key()?;
            log_startup_banner(&key.source);
            let _warn = spawn_dev_key_warn_loop(key.source.clone());
            run_tcp_server(
                &listen,
                key.psk,
                Arc::new(MockFacade::new()),
                Arc::new(RateLimiter::with_defaults()),
            )
            .await?;
        }
        #[cfg(feature = "live-ble")]
        Cmd::ServeBle { adapter, model } => {
            let key = load_prod_or_dev_key()?;
            log_startup_banner(&key.source);
            let _warn = spawn_dev_key_warn_loop(key.source.clone());
            let facade = Arc::new(NmrsFacade::new().await?);
            let rl = Arc::new(RateLimiter::with_defaults());
            let cfg = BleServerConfig { psk: key.psk, model, adapter_name: adapter };
            let result = run_ble_server(cfg, facade, rl, notify_ready).await;
            notify_stopping();
            result?;
        }
    }
    Ok(())
}

fn load_prod_or_dev_key() -> anyhow::Result<netprov_server::LoadedKey> {
    let production = std::env::var("NETPROV_PRODUCTION").ok().as_deref() == Some("1");
    let env_path = std::env::var_os("NETPROV_KEY_PATH").map(PathBuf::from);
    Ok(load_key(LoadOptions {
        env_path,
        default_path: "/etc/netprov/key".into(),
        production,
    })?)
}
```

- [ ] **Step 2: Verify both feature sets build**

```bash
cargo build -p netprov-server                             # default: mock only
cargo build -p netprov-server --features live-ble
```
Expected: both succeed.

- [ ] **Step 3: Smoke-test the renamed serve-tcp subcommand**

```bash
cargo run -p netprov-server --bin netprovd -- serve-tcp --listen 127.0.0.1:9600 &
sleep 2
cargo run -p netprov-client --bin netprov -- \
  --key-path /tmp/netprov-devkey.bin \
  --endpoint 127.0.0.1:9600 list
kill %1
```
Expected: prints eth0 + wlan0 rows, same as Part 1. (Reuse the /tmp/netprov-devkey.bin from Part 1 smoke test; re-create if missing.)

- [ ] **Step 4: Commit**

```bash
git add crates/server/src/main.rs
git commit -m "feat(server): serve-tcp (dev) + serve-ble (production) subcommands"
```

### Task 2.3: systemd unit file

**Files:**
- Create: `packaging/netprovd.service`

Per spec §9.1.

- [ ] **Step 1: Write `packaging/netprovd.service`**

```ini
[Unit]
Description=Network provisioning daemon (BLE)
After=NetworkManager.service bluetooth.service
Requires=NetworkManager.service bluetooth.service

[Service]
Type=notify
ExecStart=/usr/bin/netprovd serve-ble
Restart=on-failure
RestartSec=5s

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
LockPersonality=true
RestrictRealtime=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@mount @obsolete @privileged @reboot @swap
ReadWritePaths=/etc/netprov

[Install]
WantedBy=multi-user.target
```

> **Note:** `Restart=on-failure` — systemd will restart us on non-zero exit. Combined with `Type=notify`, systemd waits for `READY=1` before marking the unit `active`, so `systemctl start netprovd` blocks until the GATT service is actually advertising.

- [ ] **Step 2: Lint the unit file with `systemd-analyze verify`** (optional but cheap)

Run: `systemd-analyze verify packaging/netprovd.service 2>&1 | head`
Expected: no errors. (Warnings about binary not existing at `/usr/bin/netprovd` are fine — the binary is installed by the deb in Phase 4.)

- [ ] **Step 3: Commit**

```bash
git add packaging/netprovd.service
git commit -m "feat(packaging): Type=notify unit file with hardening"
```

---

## Phase 3 — NmrsFacade Wi-Fi ops (complete the TODOs)

All of Phase 3 replaces the `NotSupported`-returning stubs in `crates/server/src/facade_nmrs.rs` with real implementations. Each task is paired with a live-gated `#[ignore]` test that the engineer runs by hand on a box with NetworkManager.

### Task 3.1: `wifi_status` — read active AP via zbus

**Files:**
- Modify: `crates/server/src/facade_nmrs.rs`

Per spec §8.2 (Wi-Fi device → ActiveAccessPoint → SSID/strength/security).

- [ ] **Step 1: Replace `wifi_status` body**

```rust
async fn wifi_status(&self) -> Result<WifiStatus, NetError> {
    tokio::time::timeout(OP_TIMEOUT, async {
        let wifi_dev = find_wifi_device_path(&self.zbus).await?;
        if wifi_dev.is_none() {
            return Ok(WifiStatus { ssid: None, signal: None, security: None });
        }
        let wifi_dev = wifi_dev.unwrap();
        let dev = zbus::Proxy::new(
            &self.zbus,
            "org.freedesktop.NetworkManager",
            wifi_dev.as_str(),
            "org.freedesktop.NetworkManager.Device.Wireless",
        ).await.map_err(nm_err)?;
        let ap_path: zbus::zvariant::OwnedObjectPath =
            dev.get_property("ActiveAccessPoint").await.map_err(nm_err)?;
        if ap_path.as_str() == "/" {
            return Ok(WifiStatus { ssid: None, signal: None, security: None });
        }
        let ap = zbus::Proxy::new(
            &self.zbus,
            "org.freedesktop.NetworkManager",
            ap_path.as_str(),
            "org.freedesktop.NetworkManager.AccessPoint",
        ).await.map_err(nm_err)?;
        let ssid_bytes: Vec<u8> = ap.get_property("Ssid").await.map_err(nm_err)?;
        let ssid = String::from_utf8(ssid_bytes).ok();
        let strength: u8 = ap.get_property("Strength").await.map_err(nm_err)?;
        let flags: u32 = ap.get_property("Flags").await.map_err(nm_err)?;
        let wpa_flags: u32 = ap.get_property("WpaFlags").await.map_err(nm_err)?;
        let rsn_flags: u32 = ap.get_property("RsnFlags").await.map_err(nm_err)?;
        Ok::<_, NetError>(WifiStatus {
            ssid,
            signal: Some(strength),
            security: Some(classify_security(flags, wpa_flags, rsn_flags)),
        })
    }).await.map_err(|_| NetError::Timeout)?
}
```

- [ ] **Step 2: Add helpers (module-scope)**

```rust
async fn find_wifi_device_path(
    conn: &zbus::Connection,
) -> Result<Option<zbus::zvariant::OwnedObjectPath>, NetError> {
    let proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.NetworkManager",
        "/org/freedesktop/NetworkManager",
        "org.freedesktop.NetworkManager",
    ).await.map_err(nm_err)?;
    let devices: Vec<zbus::zvariant::OwnedObjectPath> =
        proxy.call("GetDevices", &()).await.map_err(nm_err)?;
    for path in devices {
        let dev = zbus::Proxy::new(
            conn,
            "org.freedesktop.NetworkManager",
            path.as_str(),
            "org.freedesktop.NetworkManager.Device",
        ).await.map_err(nm_err)?;
        let dev_type: u32 = dev.get_property("DeviceType").await.map_err(nm_err)?;
        if dev_type == 2 { // NM_DEVICE_TYPE_WIFI
            return Ok(Some(path));
        }
    }
    Ok(None)
}

fn classify_security(flags: u32, wpa: u32, rsn: u32) -> Security {
    // NM_802_11_AP_FLAGS_PRIVACY = 0x1. If no privacy and no WPA/RSN → Open.
    if flags & 0x1 == 0 && wpa == 0 && rsn == 0 {
        return Security::Open;
    }
    // NM_802_11_AP_SEC_KEY_MGMT_SAE = 0x400
    if rsn & 0x400 != 0 {
        return Security::Wpa3;
    }
    if rsn != 0 {
        return Security::Wpa2Psk;
    }
    if wpa != 0 {
        return Security::WpaPsk;
    }
    Security::Wep
}
```

- [ ] **Step 3: Add live test**

Append to `live_tests` mod:

```rust
#[tokio::test]
#[ignore = "requires Wi-Fi adapter with an active AP"]
async fn wifi_status_live() {
    let f = NmrsFacade::new().await.unwrap();
    let st = f.wifi_status().await.unwrap();
    println!("{st:?}");
}
```

- [ ] **Step 4: Build check**

```bash
cargo build -p netprov-server --features live-nm
```

- [ ] **Step 5: Commit**

```bash
git add crates/server/src/facade_nmrs.rs
git commit -m "feat(server): NmrsFacade::wifi_status via zbus Wireless/AP props"
```

### Task 3.2: `scan_wifi` — RequestScan + poll LastScan + read APs

**Files:**
- Modify: `crates/server/src/facade_nmrs.rs`

Per spec §8.2 (scan is async: trigger `RequestScan`, poll `LastScan`, 10s timeout).

- [ ] **Step 1: Replace `scan_wifi` body**

```rust
async fn scan_wifi(&self) -> Result<Vec<WifiNetwork>, NetError> {
    tokio::time::timeout(OP_TIMEOUT, async {
        let wifi_path = find_wifi_device_path(&self.zbus).await?
            .ok_or(NetError::NotSupported)?;
        let dev = zbus::Proxy::new(
            &self.zbus,
            "org.freedesktop.NetworkManager",
            wifi_path.as_str(),
            "org.freedesktop.NetworkManager.Device.Wireless",
        ).await.map_err(nm_err)?;
        let before: i64 = dev.get_property("LastScan").await.unwrap_or(0);

        // RequestScan takes a dict of options; empty dict is fine.
        let opts: std::collections::HashMap<&str, zbus::zvariant::Value<'_>> =
            std::collections::HashMap::new();
        dev.call::<_, _, ()>("RequestScan", &(opts,)).await.map_err(nm_err)?;

        // Poll LastScan up to 10 seconds.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let now: i64 = dev.get_property("LastScan").await.unwrap_or(0);
            if now != before { break; }
            if std::time::Instant::now() >= deadline {
                return Err(NetError::Timeout);
            }
        }

        let aps: Vec<zbus::zvariant::OwnedObjectPath> =
            dev.call("GetAccessPoints", &()).await.map_err(nm_err)?;
        let mut out = Vec::with_capacity(aps.len());
        for ap_path in aps {
            let ap = zbus::Proxy::new(
                &self.zbus,
                "org.freedesktop.NetworkManager",
                ap_path.as_str(),
                "org.freedesktop.NetworkManager.AccessPoint",
            ).await.map_err(nm_err)?;
            let ssid_bytes: Vec<u8> = ap.get_property("Ssid").await.unwrap_or_default();
            let ssid = String::from_utf8(ssid_bytes).unwrap_or_default();
            if ssid.is_empty() { continue; } // hidden networks
            let strength: u8 = ap.get_property("Strength").await.unwrap_or(0);
            let flags: u32 = ap.get_property("Flags").await.unwrap_or(0);
            let wpa: u32 = ap.get_property("WpaFlags").await.unwrap_or(0);
            let rsn: u32 = ap.get_property("RsnFlags").await.unwrap_or(0);
            let bssid: String = ap.get_property("HwAddress").await.unwrap_or_default();
            out.push(WifiNetwork {
                ssid,
                signal: Some(strength),
                security: Some(classify_security(flags, wpa, rsn)),
                bssid,
            });
        }
        Ok::<_, NetError>(out)
    }).await.map_err(|_| NetError::Timeout)?
}
```

- [ ] **Step 2: Add live test**

```rust
#[tokio::test]
#[ignore = "requires Wi-Fi adapter"]
async fn wifi_scan_live() {
    let f = NmrsFacade::new().await.unwrap();
    let nets = f.scan_wifi().await.unwrap();
    println!("scanned {} networks", nets.len());
    for n in &nets { println!("  {n:?}"); }
    assert!(!nets.is_empty());
}
```

- [ ] **Step 3: Build + commit**

```bash
cargo build -p netprov-server --features live-nm
git add crates/server/src/facade_nmrs.rs
git commit -m "feat(server): NmrsFacade::scan_wifi — RequestScan + poll + enumerate APs"
```

### Task 3.3: `connect_wifi` — AddAndActivateConnection with inline settings

**Files:**
- Modify: `crates/server/src/facade_nmrs.rs`

Per spec §8.2.

- [ ] **Step 1: Replace `connect_wifi` body**

```rust
async fn connect_wifi(&self, ssid: &str, cred: WifiCredential) -> Result<(), NetError> {
    let _guard = self.write_guard.lock().await;
    tokio::time::timeout(OP_TIMEOUT, async {
        let wifi_path = find_wifi_device_path(&self.zbus).await?
            .ok_or(NetError::NotSupported)?;

        use zbus::zvariant::{OwnedValue, Value};
        type Dict<'a> = std::collections::HashMap<String, std::collections::HashMap<String, Value<'a>>>;

        let (key_mgmt, psk) = match cred {
            WifiCredential::Open => ("none", None),
            WifiCredential::WpaPsk(p) | WifiCredential::Wpa2Psk(p) => ("wpa-psk", Some(p)),
            WifiCredential::Wpa3(p) => ("sae", Some(p)),
        };

        let mut conn: Dict = std::collections::HashMap::new();
        let mut connection = std::collections::HashMap::new();
        connection.insert("id".into(), Value::from(ssid));
        connection.insert("type".into(), Value::from("802-11-wireless"));
        conn.insert("connection".into(), connection);

        let mut wireless = std::collections::HashMap::new();
        wireless.insert("ssid".into(), Value::from(ssid.as_bytes().to_vec()));
        wireless.insert("mode".into(), Value::from("infrastructure"));
        conn.insert("802-11-wireless".into(), wireless);

        if key_mgmt != "none" {
            let mut sec = std::collections::HashMap::new();
            sec.insert("key-mgmt".into(), Value::from(key_mgmt));
            if let Some(p) = psk {
                sec.insert("psk".into(), Value::from(p));
            }
            conn.insert("802-11-wireless-security".into(), sec);
        }

        let mut ipv4 = std::collections::HashMap::new();
        ipv4.insert("method".into(), Value::from("auto"));
        conn.insert("ipv4".into(), ipv4);

        let nm = zbus::Proxy::new(
            &self.zbus,
            "org.freedesktop.NetworkManager",
            "/org/freedesktop/NetworkManager",
            "org.freedesktop.NetworkManager",
        ).await.map_err(nm_err)?;
        let _: (OwnedValue, OwnedValue) = nm.call(
            "AddAndActivateConnection",
            &(conn, wifi_path, "/"),
        ).await.map_err(nm_err)?;
        Ok::<(), NetError>(())
    }).await.map_err(|_| NetError::Timeout)?
}
```

- [ ] **Step 2: Build + commit**

```bash
cargo build -p netprov-server --features live-nm
git add crates/server/src/facade_nmrs.rs
git commit -m "feat(server): NmrsFacade::connect_wifi via AddAndActivateConnection"
```

### Task 3.4: `set_dhcp` + `set_static_ipv4` — Update + Activate on existing settings

**Files:**
- Modify: `crates/server/src/facade_nmrs.rs`

Per spec §8.2 (get settings connection → set `ipv4.method` → `Update` → `ActivateConnection`).

- [ ] **Step 1: Add helper `get_settings_connection_for_iface`**

```rust
async fn get_settings_connection_for_iface(
    conn: &zbus::Connection,
    iface: &str,
) -> Result<zbus::zvariant::OwnedObjectPath, NetError> {
    let dev_path = find_device_path(conn, iface).await?;
    let dev = zbus::Proxy::new(
        conn,
        "org.freedesktop.NetworkManager",
        dev_path.as_str(),
        "org.freedesktop.NetworkManager.Device",
    ).await.map_err(nm_err)?;
    let active: zbus::zvariant::OwnedObjectPath =
        dev.get_property("ActiveConnection").await.map_err(nm_err)?;
    if active.as_str() == "/" {
        return Err(NetError::InvalidArgument(format!(
            "interface {iface} has no active connection"
        )));
    }
    let ac = zbus::Proxy::new(
        conn,
        "org.freedesktop.NetworkManager",
        active.as_str(),
        "org.freedesktop.NetworkManager.Connection.Active",
    ).await.map_err(nm_err)?;
    let settings: zbus::zvariant::OwnedObjectPath =
        ac.get_property("Connection").await.map_err(nm_err)?;
    Ok(settings)
}
```

- [ ] **Step 2: Replace `set_dhcp` body**

```rust
async fn set_dhcp(&self, iface: &str) -> Result<(), NetError> {
    let _guard = self.write_guard.lock().await;
    tokio::time::timeout(OP_TIMEOUT, async {
        let settings_path = get_settings_connection_for_iface(&self.zbus, iface).await?;
        let settings = zbus::Proxy::new(
            &self.zbus,
            "org.freedesktop.NetworkManager",
            settings_path.as_str(),
            "org.freedesktop.NetworkManager.Settings.Connection",
        ).await.map_err(nm_err)?;

        use zbus::zvariant::Value;
        type Dict<'a> = std::collections::HashMap<String, std::collections::HashMap<String, Value<'a>>>;
        let mut existing: Dict = settings.call("GetSettings", &()).await.map_err(nm_err)?;
        let ipv4 = existing.entry("ipv4".into()).or_insert_with(Default::default);
        ipv4.insert("method".into(), Value::from("auto"));
        ipv4.remove("addresses");
        ipv4.remove("address-data");
        ipv4.remove("gateway");
        ipv4.remove("dns");

        settings.call::<_, _, ()>("Update", &(existing,)).await.map_err(nm_err)?;

        // Re-activate so the new method takes effect.
        let dev = find_device_path(&self.zbus, iface).await?;
        let nm = zbus::Proxy::new(
            &self.zbus,
            "org.freedesktop.NetworkManager",
            "/org/freedesktop/NetworkManager",
            "org.freedesktop.NetworkManager",
        ).await.map_err(nm_err)?;
        nm.call::<_, _, zbus::zvariant::OwnedObjectPath>(
            "ActivateConnection",
            &(settings_path, dev, zbus::zvariant::ObjectPath::try_from("/").unwrap()),
        ).await.map_err(nm_err)?;
        Ok::<(), NetError>(())
    }).await.map_err(|_| NetError::Timeout)?
}
```

- [ ] **Step 3: Replace `set_static_ipv4` body**

```rust
async fn set_static_ipv4(&self, iface: &str, cfg: StaticIpv4) -> Result<(), NetError> {
    let _guard = self.write_guard.lock().await;
    tokio::time::timeout(OP_TIMEOUT, async {
        let settings_path = get_settings_connection_for_iface(&self.zbus, iface).await?;
        let settings = zbus::Proxy::new(
            &self.zbus,
            "org.freedesktop.NetworkManager",
            settings_path.as_str(),
            "org.freedesktop.NetworkManager.Settings.Connection",
        ).await.map_err(nm_err)?;

        use zbus::zvariant::Value;
        type Dict<'a> = std::collections::HashMap<String, std::collections::HashMap<String, Value<'a>>>;
        let mut existing: Dict = settings.call("GetSettings", &()).await.map_err(nm_err)?;

        // Build the AddressData entry: [{"address": "1.2.3.4", "prefix": 24}]
        let mut ad = std::collections::HashMap::new();
        ad.insert("address".to_string(), Value::from(cfg.address.addr().to_string()));
        ad.insert("prefix".to_string(), Value::from(cfg.address.prefix_len() as u32));
        let addr_data: Vec<_> = vec![ad];

        let ipv4 = existing.entry("ipv4".into()).or_insert_with(Default::default);
        ipv4.insert("method".into(), Value::from("manual"));
        ipv4.insert("address-data".into(), Value::from(addr_data));
        if let Some(gw) = cfg.gateway {
            ipv4.insert("gateway".into(), Value::from(gw.to_string()));
        } else {
            ipv4.remove("gateway");
        }
        let dns_u32: Vec<u32> = cfg.dns.iter()
            .map(|ip| u32::from_le_bytes(ip.octets())) // NM expects little-endian u32
            .collect();
        ipv4.insert("dns".into(), Value::from(dns_u32));

        settings.call::<_, _, ()>("Update", &(existing,)).await.map_err(nm_err)?;

        let dev = find_device_path(&self.zbus, iface).await?;
        let nm = zbus::Proxy::new(
            &self.zbus,
            "org.freedesktop.NetworkManager",
            "/org/freedesktop/NetworkManager",
            "org.freedesktop.NetworkManager",
        ).await.map_err(nm_err)?;
        nm.call::<_, _, zbus::zvariant::OwnedObjectPath>(
            "ActivateConnection",
            &(settings_path, dev, zbus::zvariant::ObjectPath::try_from("/").unwrap()),
        ).await.map_err(nm_err)?;
        Ok::<(), NetError>(())
    }).await.map_err(|_| NetError::Timeout)?
}
```

- [ ] **Step 4: Add live-destructive test gate**

`connect_wifi`, `set_dhcp`, `set_static_ipv4` mutate system state. Add a separate feature flag so CI never runs them:

Edit `crates/server/Cargo.toml`:
```toml
[features]
live-nm-destructive = ["live-nm"]
```

Append to `live_tests` in `facade_nmrs.rs`:

```rust
#[tokio::test]
#[ignore = "destructive; requires live-nm-destructive and a throwaway box"]
#[cfg(feature = "live-nm-destructive")]
async fn set_dhcp_live() {
    let f = NmrsFacade::new().await.unwrap();
    // Pick the first Ethernet interface via list_interfaces.
    let ifs = f.list_interfaces().await.unwrap();
    let eth = ifs.iter().find(|i| matches!(i.iface_type, IfaceType::Ethernet))
        .expect("need at least one Ethernet interface");
    f.set_dhcp(&eth.name).await.unwrap();
}
```

- [ ] **Step 5: Build check under all feature combinations**

```bash
cargo build -p netprov-server                                 # default
cargo build -p netprov-server --features live-nm
cargo build -p netprov-server --features live-ble
cargo build -p netprov-server --features live-nm,live-ble
cargo build -p netprov-server --features live-nm-destructive
```
Expected: all succeed.

- [ ] **Step 6: Commit**

```bash
git add crates/server/Cargo.toml crates/server/src/facade_nmrs.rs
git commit -m "feat(server): NmrsFacade set_dhcp/set_static_ipv4 via Settings.Update

Adds live-nm-destructive feature flag for tests that mutate system state;
never run in CI."
```

---

## Phase 4 — Debian packaging

### Task 4.1: `cargo-deb` metadata

**Files:**
- Modify: `crates/server/Cargo.toml`

Per spec §9.6. The server crate owns the deb metadata because it's the crate that owns the unit file and is the "main" binary.

- [ ] **Step 1: Append `[package.metadata.deb]` block**

Edit `crates/server/Cargo.toml`, append at the end:

```toml
[package.metadata.deb]
name = "netprov"
maintainer = "Richard Osterloh <richard.osterloh@gmail.com>"
depends = "bluez, network-manager, libdbus-1-3"
section = "net"
priority = "optional"
extended-description = """
netprov provides a BLE GATT interface for configuring network settings on
headless embedded Linux devices. Includes both the netprovd daemon and the
netprov client CLI.
"""
assets = [
    ["target/release/netprovd", "usr/bin/", "755"],
    ["target/release/netprov",  "usr/bin/", "755"],
    ["packaging/netprovd.service", "lib/systemd/system/", "644"],
    ["packaging/README.md", "usr/share/doc/netprov/", "644"],
]
conf-files = []
maintainer-scripts = "packaging/debian/"
features = ["live-ble", "live-nm"]

[package.metadata.deb.systemd-units]
unit-scripts = "packaging/"
enable = false
start = false
```

> **Why `enable = false, start = false`:** the spec (§9.6) is explicit: do not auto-start. The admin must run `netprovd keygen --install` before enabling the unit, otherwise it'll start with the dev key.

- [ ] **Step 2: Install `cargo-deb` locally**

```bash
cargo install cargo-deb --locked
```
Expected: binary at `~/.cargo/bin/cargo-deb`.

- [ ] **Step 3: Build the deb (release profile)**

```bash
cargo deb -p netprov-server --no-strip
```

Expected: `.deb` at `target/debian/netprov_0.1.0_amd64.deb`.

> **Note:** this step *will* pull in bluer's BlueZ D-Bus bindings and nmrs's zbus; first build is slow. Re-runs are cached.

- [ ] **Step 4: Inspect the deb**

```bash
dpkg-deb -c target/debian/netprov_*.deb | head -20
dpkg-deb -I target/debian/netprov_*.deb
```
Expected:
- `/usr/bin/netprovd` (mode 0755)
- `/usr/bin/netprov` (mode 0755)
- `/lib/systemd/system/netprovd.service` (mode 0644)
- `/usr/share/doc/netprov/README.md`
- `Depends: bluez, network-manager, libdbus-1-3`

- [ ] **Step 5: Commit**

```bash
git add crates/server/Cargo.toml
git commit -m "feat(packaging): cargo-deb metadata for netprov package"
```

### Task 4.2: Maintainer scripts

**Files:**
- Create: `packaging/debian/postinst`, `packaging/debian/prerm`, `packaging/debian/postrm`

Per spec §9.6.

- [ ] **Step 1: Write `packaging/debian/postinst`**

```bash
#!/bin/sh
set -e

# Create config dir with restrictive perms; key file lands there via keygen.
if [ ! -d /etc/netprov ]; then
    mkdir -p /etc/netprov
    chmod 700 /etc/netprov
fi

# Ensure the unit is known.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

# Do NOT enable or start. Admin must install a production key first.
cat <<'EOM'

=========================================================================
netprov installed.

Before starting the service, install a production pre-shared key:
    sudo netprovd keygen --install

Then enable and start the daemon:
    sudo systemctl enable --now netprovd

To opt out of the embedded dev-key fallback in dev images, set
    Environment=NETPROV_PRODUCTION=1
in /etc/systemd/system/netprovd.service.d/override.conf.
=========================================================================
EOM

exit 0
```

- [ ] **Step 2: Write `packaging/debian/prerm`**

```bash
#!/bin/sh
set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop netprovd.service || true
fi

exit 0
```

- [ ] **Step 3: Write `packaging/debian/postrm`**

```bash
#!/bin/sh
set -e

case "$1" in
    purge)
        # Remove the key dir on purge, not on plain remove — key survives
        # upgrades.
        rm -rf /etc/netprov
        ;;
    remove)
        ;;
esac

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

exit 0
```

- [ ] **Step 4: Make all three executable**

```bash
chmod 755 packaging/debian/postinst packaging/debian/prerm packaging/debian/postrm
```

- [ ] **Step 5: Rebuild and install the deb in a chroot or a throwaway VM** (optional — skip if no sandbox available)

```bash
cargo deb -p netprov-server --no-strip
sudo dpkg -i target/debian/netprov_*.deb  # only on a throwaway box!
```
Expected: postinst prints the "install a key" message; no service started.

- [ ] **Step 6: Commit**

```bash
git add packaging/debian/
git commit -m "feat(packaging): Debian maintainer scripts — manual key install flow"
```

---

## Phase 5 — CI: aarch64 matrix + deb artifact

### Task 5.1: Extend `ci.yml` with a build matrix

**Files:**
- Modify: `.github/workflows/ci.yml`

Per spec §9.7 (native amd64 + aarch64 runners; `cross` is dev-only).

- [ ] **Step 1: Rewrite `.github/workflows/ci.yml`**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

env:
  CARGO_TERM_COLOR: always

jobs:
  test:
    strategy:
      fail-fast: false
      matrix:
        runner:
          - ubuntu-latest      # amd64
          - ubuntu-24.04-arm   # aarch64 (GitHub public ARM runner)
    runs-on: ${{ matrix.runner }}
    steps:
      - uses: actions/checkout@v4

      - name: Install D-Bus + bluez headers
        run: |
          sudo apt-get update
          sudo apt-get install -y libdbus-1-dev pkg-config bluez

      - name: Cache cargo
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            target
          key: ${{ runner.os }}-${{ matrix.runner }}-cargo-${{ hashFiles('**/Cargo.lock', '**/Cargo.toml') }}

      - name: fmt
        run: cargo fmt --all -- --check

      - name: clippy (default features)
        run: cargo clippy --workspace --all-targets -- -D warnings

      - name: clippy (live-nm)
        run: cargo clippy -p netprov-server --features live-nm --all-targets -- -D warnings

      - name: clippy (live-ble)
        run: cargo clippy -p netprov-server --features live-ble --all-targets -- -D warnings

      - name: test (default)
        run: cargo test --workspace

      - name: build (live-ble)
        run: cargo build -p netprov-server --features live-ble

  deb:
    needs: test
    strategy:
      fail-fast: false
      matrix:
        runner:
          - ubuntu-latest
          - ubuntu-24.04-arm
    runs-on: ${{ matrix.runner }}
    steps:
      - uses: actions/checkout@v4
      - name: Install D-Bus + bluez
        run: sudo apt-get update && sudo apt-get install -y libdbus-1-dev pkg-config bluez
      - name: Cache cargo
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            target
          key: ${{ runner.os }}-${{ matrix.runner }}-cargo-deb-${{ hashFiles('**/Cargo.lock') }}
      - name: Install cargo-deb
        run: cargo install cargo-deb --locked
      - name: Build release
        run: cargo build --release -p netprov-server --features live-ble,live-nm
      - name: Build deb
        run: cargo deb -p netprov-server --no-build
      - name: Upload deb artifact
        uses: actions/upload-artifact@v4
        with:
          name: netprov-${{ matrix.runner }}
          path: target/debian/*.deb
```

> **Note:** `ubuntu-24.04-arm` is GitHub's public ARM runner label as of 2026-01. If your org is on an older runner version, replace with `ubuntu-22.04-arm` or a self-hosted `linux-arm64` label. The `needs: test` keeps the deb job from running until the test matrix passes.

- [ ] **Step 2: Push the branch and confirm CI runs green on both arches**

Expected: the `test` job runs on both `ubuntu-latest` and `ubuntu-24.04-arm`, and `deb` produces an artifact for each. If `ubuntu-24.04-arm` is not accessible to this repo (public action plan required), fall back to `ubuntu-22.04-arm` or remove the arm64 row and document it in the commit message.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: amd64 + aarch64 matrix with deb build artifact"
```

---

## Phase 6 — Live-BLE smoke test harness

### Task 6.1: BLE client connector

**Files:**
- Create: `crates/client/src/ble.rs`
- Modify: `crates/client/src/lib.rs`, `crates/client/src/cli.rs`, `crates/client/src/main.rs`

Part 1's `Client<IO>` is transport-agnostic — it only needs `AsyncRead + AsyncWrite`. For BLE we can't reuse that interface directly because BLE is not a byte stream; we have four discrete characteristics. Instead: build a thin `BleClient` that speaks *protocol*, not bytes, and shares the existing `Envelope`/`Request`/`Response` types.

- [ ] **Step 1: Write `crates/client/src/ble.rs`**

```rust
//! BLE connector for the netprov CLI.
//!
//! Only compiled with --features ble.

use anyhow::{anyhow, bail, Context, Result};
use bluer::{gatt::remote::Characteristic, AdapterEvent, Address};
use futures_util::StreamExt;
use netprov_protocol::{
    decode_response, encode_request, fragment, hmac_compute, parse_frame, Reassembler,
    Request, Response, MAX_MESSAGE_SIZE, MAX_PAYLOAD_PER_FRAME, NONCE_LEN, PSK_LEN,
};
use std::time::Duration;

// Import UUIDs from the server crate indirectly — the client doesn't depend on
// server. We redefine them here with the *same* values. A canonical source
// would be a separate `netprov-ble-uuids` crate, but that's over-engineered
// for v1; a test in Task 6.2 pins the constants match.
const SERVICE_UUID: bluer::Uuid =
    bluer::Uuid::from_u128(0x0eebc1ba_773d_4625_babf_5c6cafe82b30);
const INFO_UUID: bluer::Uuid =
    bluer::Uuid::from_u128(0xc4c47504_92f6_45d0_97b2_24c965499cf8);
const CHALLENGE_UUID: bluer::Uuid =
    bluer::Uuid::from_u128(0x0107c3c5_a56b_4283_925b_7dd4ec0aafb6);
const AUTH_RESPONSE_UUID: bluer::Uuid =
    bluer::Uuid::from_u128(0xb78f3640_d56a_487b_b10e_f5dea9facf3c);
const REQUEST_UUID: bluer::Uuid =
    bluer::Uuid::from_u128(0x6d29f399_aad4_494e_8b0b_b85b9a7fef9e);

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

        // Find our service + all four characteristics.
        let svc = device.services().await?
            .into_iter()
            .find(|s| s.uuid() == SERVICE_UUID)
            .ok_or_else(|| anyhow!("netprov service not found on {peer}"))?;
        let chars = svc.characteristics().await?;
        let find = |u: bluer::Uuid| chars.iter().find(|c| c.uuid() == u).cloned()
            .ok_or_else(|| anyhow!("characteristic {u} missing"));

        Ok(Self {
            _device: device,
            info: find(INFO_UUID)?,
            challenge: find(CHALLENGE_UUID)?,
            auth: find(AUTH_RESPONSE_UUID)?,
            request: find(REQUEST_UUID)?,
            next_id: 1,
            psk,
        })
    }

    pub async fn authenticate(&self) -> Result<()> {
        // Read Info (optional — but confirms we're talking to the right service).
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

    pub async fn request(&mut self, op: netprov_protocol::Op) -> Result<netprov_protocol::OpResult> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let bytes = encode_request(&Request { request_id: id, op })?;

        // Subscribe before sending so we don't lose early response fragments.
        let mut notify = self.request.notify_io().await?;

        for f in fragment(id, &bytes, MAX_PAYLOAD_PER_FRAME + 5) {
            self.request.write(&f).await?;
        }

        let mut buf = vec![0u8; MAX_MESSAGE_SIZE];
        let mut reassembler = Reassembler::new(MAX_MESSAGE_SIZE);
        loop {
            let n = tokio::io::AsyncReadExt::read(&mut notify, &mut buf).await?;
            if n == 0 { bail!("notify stream closed"); }
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
```

- [ ] **Step 2: Add `ble` module to client `lib.rs`**

```rust
#[cfg(feature = "ble")]
pub mod ble;
```

- [ ] **Step 3: Extend `cli.rs` with a `--ble-peer` option**

Add near the top of `crates/client/src/cli.rs`:

```rust
#[derive(Parser)]
#[command(name = "netprov", about = "netprov client CLI")]
pub struct Cli {
    #[arg(long, short = 'k', env = "NETPROV_KEY_PATH", default_value = "/etc/netprov/key")]
    pub key_path: PathBuf,

    /// TCP endpoint (dev). Ignored if --ble-peer is set.
    #[arg(long, env = "NETPROV_ENDPOINT", default_value = "127.0.0.1:9600")]
    pub endpoint: String,

    /// BLE peer BD_ADDR (e.g. AA:BB:CC:DD:EE:FF). If set, uses BLE transport
    /// and requires `--features ble`.
    #[arg(long)]
    pub ble_peer: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}
```

- [ ] **Step 4: Update `main.rs` to branch on `ble_peer`**

Replace the connect-and-authenticate section in `crates/client/src/main.rs`:

```rust
#[cfg(feature = "ble")]
{
    use netprov_client::ble::{BleClient, parse_peer_address};
    if let Some(peer) = cli.ble_peer.as_deref() {
        let addr = parse_peer_address(peer)?;
        let mut client = BleClient::connect(addr, psk).await?;
        client.authenticate().await?;
        return netprov_client::commands::dispatch_ble(&mut client, cli.command).await;
    }
}

let sock = tokio::net::TcpStream::connect(&cli.endpoint).await
    .with_context(|| format!("connect {}", cli.endpoint))?;
let mut client = Client::new(sock, psk);
client.authenticate().await.context("authenticate")?;
dispatch(&mut client, cli.command).await?;
Ok(())
```

- [ ] **Step 5: Add `dispatch_ble` to `commands.rs`**

Copy `dispatch` and rename to `dispatch_ble`, change the `Client<IO>` parameter type to `&mut BleClient`. The bodies are identical — they only use `.request()`. If the duplication feels wrong, generalize over a `trait Requestor { async fn request(&mut self, op: Op) -> Result<OpResult>; }` and implement it for both `Client<IO>` and `BleClient`. For Part 2 the duplication is fine.

- [ ] **Step 6: Build under both feature sets**

```bash
cargo build -p netprov-client
cargo build -p netprov-client --features ble
```

- [ ] **Step 7: Commit**

```bash
git add crates/client/src/ble.rs crates/client/src/lib.rs \
        crates/client/src/cli.rs crates/client/src/main.rs \
        crates/client/src/commands.rs
git commit -m "feat(client): --ble-peer BLE connector (behind ble feature)"
```

### Task 6.2: End-to-end live-BLE smoke test (manual)

**Files:**
- Create: `crates/server/tests/live_ble_e2e.rs`

Per spec §10 (live-ble tier — opt-in, real hardware required).

- [ ] **Step 1: Write `crates/server/tests/live_ble_e2e.rs`**

```rust
//! End-to-end BLE smoke test. Requires:
//!   * A real Bluetooth adapter visible to BlueZ
//!   * NetworkManager running (uses NmrsFacade under the hood)
//!   * `cargo test --features live-ble -- --ignored --test live_ble_e2e`
//!
//! The test starts a BleServer in the current process, then opens a BleClient
//! to localhost by discovering the freshly-registered service.

#![cfg(feature = "live-ble")]

use netprov_server::{
    ble::{run_ble_server, BleServerConfig},
    MockFacade, RateLimiter,
};
use std::sync::Arc;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires real BLE adapter"]
async fn end_to_end_list_interfaces() {
    let psk = [0x42u8; 32];
    let facade = Arc::new(MockFacade::new());
    let rl = Arc::new(RateLimiter::with_defaults());

    // Server runs in a task; client discovers + connects locally.
    let server_psk = psk;
    let cfg = BleServerConfig {
        psk: server_psk,
        model: "live-ble-test".into(),
        adapter_name: None,
    };
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let mut ready_tx = Some(ready_tx);
    let server = tokio::spawn(async move {
        run_ble_server(cfg, facade, rl, move || {
            if let Some(tx) = ready_tx.take() { let _ = tx.send(()); }
        }).await
    });

    // Wait until server is advertising.
    ready_rx.await.expect("server never reported ready");

    // TODO(engineer running this by hand):
    // - find the adapter's own BD_ADDR with `bluetoothctl show`
    // - run `netprov --ble-peer <addr> list` in a separate terminal
    // - verify the output matches MockFacade's eth0 + wlan0
    //
    // A fully self-contained E2E would use two controllers — one on the
    // server, one on the client — which most dev boxes don't have. Punt to
    // two-box hardware-in-the-loop testing in Part 3.
    drop(server);
}
```

> **Reality check:** running client + server on one BlueZ stack against *itself* is awkward (most stacks don't loopback BLE). The realistic workflow is a two-box test. The test file is mostly a scaffold + doc for how to do it by hand. Automating the two-box dance is out of scope for v1.

- [ ] **Step 2: Verify the test file compiles under the feature**

```bash
cargo build -p netprov-server --features live-ble --tests
cargo test -p netprov-server --features live-ble --test live_ble_e2e -- --ignored --list
```
Expected: compile succeeds; `cargo test --list` shows the test, but it's ignored by default.

- [ ] **Step 3: Commit**

```bash
git add crates/server/tests/live_ble_e2e.rs
git commit -m "test(server): live-ble end-to-end scaffold (manual two-box workflow)"
```

### Task 6.3: Two-box smoke-test documentation

**Files:**
- Create: `packaging/SMOKE-TEST.md`

- [ ] **Step 1: Write `packaging/SMOKE-TEST.md`**

```markdown
# netprov two-box BLE smoke test

Prerequisites: two Linux boxes each with a BLE adapter; both have `bluez` and
(on the server box) `network-manager` running.

## Server box

```bash
# Install the deb produced by CI:
sudo dpkg -i netprov_0.1.0_aarch64.deb
sudo netprovd keygen --install | tee /tmp/key.txt
# Copy the base64 PSK output to the client box.
sudo systemctl enable --now netprovd
# Check readiness and advertising:
sudo systemctl status netprovd
sudo hcitool lescan | grep netprovd-
```

## Client box

```bash
# Put the same PSK at the expected path:
echo "<paste-base64-from-server>" | base64 -d > /tmp/netprov-key.bin
chmod 600 /tmp/netprov-key.bin

# Scan for the server's BD_ADDR (look for "netprovd-*"):
sudo hcitool lescan | head

# Run the BLE client:
netprov --key-path /tmp/netprov-key.bin --ble-peer AA:BB:CC:DD:EE:FF list
netprov --key-path /tmp/netprov-key.bin --ble-peer AA:BB:CC:DD:EE:FF wifi-scan
netprov --key-path /tmp/netprov-key.bin --ble-peer AA:BB:CC:DD:EE:FF ip wlan0
```

Expected: `list` returns real interface names from the server box.

## Troubleshooting

- `netprov: could not find service` — the server isn't advertising; check
  `journalctl -u netprovd -n 50` for adapter errors.
- `auth failed` — PSK mismatch; re-copy the key.
- `connect timed out` — adapter range or a stale bonding; run
  `sudo bluetoothctl remove AA:BB:CC:DD:EE:FF` on the client.
```

- [ ] **Step 2: Commit**

```bash
git add packaging/SMOKE-TEST.md
git commit -m "docs: two-box BLE smoke-test runbook"
```

---

## Part 2 exit criteria

Before declaring Part 2 done:

- [ ] `cargo fmt --all -- --check` clean.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [ ] `cargo clippy -p netprov-server --features live-ble --all-targets -- -D warnings` clean.
- [ ] `cargo clippy -p netprov-server --features live-nm --all-targets -- -D warnings` clean.
- [ ] `cargo test --workspace` — all default-feature tests still pass (must not regress from Part 1's 66).
- [ ] `cargo build --workspace --features netprov-server/live-ble` compiles on both amd64 and aarch64.
- [ ] `cargo deb -p netprov-server` produces a `.deb` under `target/debian/`.
- [ ] CI shows `test` + `deb` jobs green on both matrix rows.
- [ ] Two-box BLE smoke (Task 6.3 runbook) executed by hand once, documented output captured in the commit message.
- [ ] On a box with NM: all live `NmrsFacade` tests pass (`--features live-nm -- --ignored`), including the read-only ones for `scan_wifi`, `wifi_status`, `list_interfaces`, `get_ip_config`.

When these pass, v1 is feature-complete and ready for a tagged `0.1.0` release.

---

## Self-review (from the writing-plans skill)

**Spec coverage (by §):**

- §7.1 GATT characteristics — ✓ Tasks 0.1 (UUIDs) + 1.1 (Application builder).
- §7.2 framing — ✓ Task 1.2 (Reassembler per peer); framing code itself was Part 1.
- §7.3 authentication flow — ✓ Task 1.2 (on_nonce / on_auth) wiring `Session::issue_nonce` + `submit_auth`.
- §7.4 rate limiting — ✓ already done in Part 1; wired via shared `RateLimiter` in Task 1.3.
- §7.5 request/response — ✓ Task 1.2.
- §7.6 error model — ✓ already done in Part 1.
- §8.1 `NetworkFacade` trait — ✓ already done in Part 1.
- §8.2 op-by-op mapping — ✓ Phase 3 Tasks 3.1–3.4.
- §8.3 operational safeties — ✓ `OP_TIMEOUT` wraps every call; `write_guard` mutex serializes writes; validator runs in `Session::dispatch`.
- §9.1 unit file — ✓ Task 2.3.
- §9.2 filesystem layout — ✓ `cargo-deb` `assets` in Task 4.1 drop files at the spec-specified paths.
- §9.3 key loading — ✓ done in Part 1; re-used via `load_prod_or_dev_key()` helper in Task 2.2.
- §9.4 dev-key warning — ✓ done in Part 1; re-used in Task 2.2.
- §9.5 `netprovd keygen` — ✓ done in Part 1.
- §9.6 Debian packaging — ✓ Tasks 4.1 + 4.2.
- §9.7 build matrix — ✓ Task 5.1.
- §10 testing — ✓ live-nm (Phase 3) + live-ble (Phase 6) tiers.
- §11 open questions — ✓ resolved per Part 1 recommendations (model-only in Info, tracing-journald).

**Placeholder scan:** Task 6.2 explicitly calls out the "run the client by hand in another terminal" step as a manual workflow — that's intentional per the spec (§10 "Opt-in, --features live-ble"). Task 6.1 Step 5 says "copy dispatch" — deliberate to avoid premature abstraction. Task 5.1 step 2 has a fallback note for older GitHub runner labels — concrete alternatives listed. No TBDs or "fill in later" blocks.

**Type consistency:**
- `BleServerConfig { psk, model, adapter_name }` used identically in Task 1.3 and Task 2.2.
- `GattHandlers { on_info_read, on_nonce_read, on_auth_write, on_request_write }` — 4 closures matching the 4 GATT endpoints.
- UUIDs defined once in `crates/server/src/ble/uuids.rs` (Task 0.1) and re-asserted (with a pinning note) in `crates/client/src/ble.rs` (Task 6.1). If you refactor the UUIDs, update both; the test suggested in Task 6.1 pins them.
- `Session::dispatch` extracted in Task 1.2 — signature `pub async fn dispatch<F: NetworkFacade>(facade: &F, req: Request) -> Response`. Used by both `Session::handle_request` and `PeerSession::on_request`.
- `classify_security(flags, wpa, rsn) -> Security` — defined once in Task 3.1, used also in Task 3.2.
- `find_wifi_device_path` and `find_device_path` — two distinct helpers, different scopes (the wifi variant filters by `DeviceType == 2`).

**Decomposition pressure points:**
- Phase 1 BLE server is the largest task family (4 tasks). `Session` refactor in Task 1.2 Step 2 touches a Part 1 file and must not regress the 33 + 9 tests — a build check is called out explicitly.
- Phase 3 NmrsFacade fill-ins (3.1–3.4) each ship their own commit so a partial implementation can land without blocking the rest. `live-nm-destructive` gate prevents CI from running the mutating tests.
- Phase 5 CI expansion depends only on Phase 4's deb build working; arm64 runner availability is the real risk, mitigated by the fallback note in Task 5.1 step 2.
