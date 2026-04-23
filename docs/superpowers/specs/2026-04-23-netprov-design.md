# netprov — BLE network provisioning daemon

**Status:** draft
**Date:** 2026-04-23
**Owner:** rio

## 1. Summary

A Rust systemd service that exposes a BLE GATT server for remote network configuration on headless embedded Linux devices. A paired client can list interfaces, read IP configuration, scan for Wi-Fi, and set DHCP / static IPv4 / Wi-Fi credentials. The v1 client is a Linux CLI; mobile and desktop clients are explicit follow-ons.

## 2. Goals and non-goals

### Goals (v1)

- Always-on BLE GATT server running as a systemd service on Linux (aarch64 primary, amd64 secondary).
- Integrates with NetworkManager via D-Bus (using `nmrs` where it fits, `zbus` directly otherwise).
- Application-layer authentication via a per-device pre-shared key, defeating active MitM on top of BLE "Just Works" pairing.
- A Linux CLI client with feature parity to the GATT protocol.
- Ships as a single Debian package containing both binaries plus the systemd unit.

### Non-goals (v1)

- IPv6 configuration.
- Enterprise Wi-Fi (WPA2-EAP / 802.1X).
- Destructive operations: reboot, interface disable, forget connection.
- Mobile/desktop clients.
- RPM packaging.
- Non-Linux server platforms.

### Deferred to v2+

- Apply-with-rollback for write operations (stage change, wait for BLE heartbeat, roll back if unreachable).
- Dropping from root to a dedicated user with `CAP_NET_ADMIN` + `bluetooth` group + polkit rules.
- Splitting the deb into `netprov` (client) and `netprovd` (server).
- `cargo-fuzz` on the `protocol` crate.

## 3. Threat model

The device is physically remote, has no UI, and advertises BLE continuously. The realistic attacker is within BLE range and attempts to either eavesdrop on or hijack network configuration.

- **Eavesdropping on Wi-Fi PSK in transit.** Defeated by BLE LE Secure Connections link encryption.
- **Active MitM during pairing.** BLE "Just Works" is vulnerable here; defeated by the application-layer HMAC challenge/response, which requires possession of the per-device PSK.
- **Unauthorized write operations.** A session cannot issue writes until it completes HMAC authentication. No write op executes without an authenticated session.
- **Replay of a captured `AuthResponse`.** Defeated by per-connection random nonces. Each nonce is consumed by the first `AuthResponse` write.
- **Brute-force of the PSK over BLE.** Rate-limited: N failed auth attempts per peer MAC in a window triggers lockout.
- **Physical key extraction.** Out of scope for v1. Key lives in `/etc/netprov/key` at mode 0600. TPM/secure-element storage is a later hardening concern.

## 4. Architecture

Three layers, separated by explicit traits so each is independently testable.

```
  BLE client (linux CLI v1 → mobile/desktop later)
            │
            ▼  GATT over LE (bonded + app-layer HMAC auth)
  ┌──────────────────────────────────────────────┐
  │  netprovd  (systemd service, runs as root)   │
  │                                              │
  │   ┌─────────┐   ┌──────────┐   ┌──────────┐  │
  │   │  BLE    │──▶│  Auth &  │──▶│ Network  │  │
  │   │ GATT    │   │ Session  │   │  Facade  │  │
  │   │ Server  │   │          │   │          │  │
  │   └─────────┘   └──────────┘   └────┬─────┘  │
  └─────────────────────────────────────┼────────┘
                                        │ D-Bus
                                        ▼
                             NetworkManager (system)
```

- **BLE layer** — owns GATT characteristics, framing, connection lifecycle. Knows nothing about network state.
- **Session layer** — per-connection HMAC challenge/response, authentication state, request/response routing. Knows nothing about BLE internals beyond "frames in, frames out."
- **Network facade** — `NetworkFacade` trait with one async method per operation. Production impl wraps `nmrs` + `zbus`; tests use `MockFacade`.

## 5. Crate layout

Cargo workspace:

```
netprov/
├── Cargo.toml                   # workspace
├── crates/
│   ├── protocol/                # wire format: request/response enums,
│   │                            # CBOR codec, framing, DTOs, auth messages
│   ├── server/                  # netprovd binary + keygen subcommand
│   │                            # BLE layer, session layer, NmrsFacade
│   └── client/                  # netprov CLI binary
└── packaging/
    ├── netprovd.service         # systemd unit
    ├── dev-key.bin              # committed dev PSK (with big scary README)
    └── debian/
        ├── postinst
        ├── prerm
        └── postrm
```

DTOs (`Interface`, `IpConfig`, `WifiStatus`, `WifiNetwork`, `StaticIpv4`, `WifiCredential`, `Security`, `NetError`) live once in `protocol`, imported by both `server` and `client`. One source of truth, no translation layer in v1. If wire format later needs to evolve independently of internal API, we split then.

## 6. Library choices

| Area | Crate | Rationale |
|---|---|---|
| BLE GATT server and client | `bluer` | Linux-only (matches scope), BlueZ-based, async, actively maintained |
| NetworkManager | `nmrs` | Async-first, zbus-based, covers Wi-Fi cleanly |
| D-Bus escape hatch | `zbus` | nmrs sits on it; lets us reach unexposed NM APIs |
| Async runtime | `tokio` | Required by both `nmrs` and `bluer` |
| Wire format | `ciborium` (CBOR) | Compact, serde-compatible, easy to consume from future mobile/JS clients |
| Logging | `tracing` + `tracing-journald` | Structured logs into the journal |
| HMAC | `hmac` + `sha2` (RustCrypto) | Lightweight, no `ring` dependency |
| QR rendering | `qrcode` | For `keygen` output (mobile client enrollment) |
| CLI parsing | `clap` | Standard |

## 7. BLE GATT protocol

### 7.1 Service and characteristics

One primary service with a custom UUID (generated once and hard-coded at scaffold time).

| Characteristic | Properties | Purpose |
|---|---|---|
| `Info` | Read | Unauthenticated. Returns protocol version, supported-ops bitmap, device model string. Allows handshake without the PSK. |
| `ChallengeNonce` | Read | Returns 32 fresh random bytes on every read. Per-connection. |
| `AuthResponse` | Write | Client writes `HMAC-SHA256(PSK, nonce)` (32 bytes). Session becomes authenticated on exact match. |
| `Request` | Write | Write rejected until auth'd. Accepts framed CBOR request fragments. |
| `Response` | Notify | Framed CBOR response fragments. Client must enable notifications. |

Notifications (not indications) are used for responses: lower latency, no ack overhead. Reliability is adequate for this payload size.

### 7.2 Framing

A single GATT write is capped by the ATT MTU (commonly 185–244, up to 512). Requests and responses may exceed one frame. Header per fragment:

```
[u16 request_id] [u16 seq] [u8 flags] [payload bytes...]
  flags: bit0 = FIN (last fragment in this message)
```

Receiver reassembles by `request_id` and frees the buffer after `FIN`. Maximum message size is 4 KiB, enforced at both ends. Larger messages return `InvalidArgument`. 4 KiB is comfortably sufficient for a Wi-Fi scan with dozens of SSIDs.

### 7.3 Authentication flow

```
1. Client initiates a GATT connection.
2. BLE LE Secure Connections "Just Works" pairing is offered; accepted
   if the client supports it (gives link encryption) but not required.
3. Client reads Info → learns protocol version.
4. Client reads ChallengeNonce → receives 32 fresh random bytes.
5. Client computes HMAC-SHA256(PSK, nonce) and writes it to AuthResponse.
6. Server constant-time-compares. On match: session marked authenticated,
   subsequent Request writes accepted. On mismatch: connection dropped,
   failure counted toward rate-limit.
7. Server notifies Response frames correlated by request_id.
8. On disconnect, all session state is discarded. The nonce cannot be reused.
```

A nonce is single-use: it is consumed by the first `AuthResponse` write on that connection, regardless of outcome. Subsequent `AuthResponse` writes without a new `ChallengeNonce` read are rejected.

### 7.4 Rate limiting

Per-peer-MAC state. Defaults:

- **Window:** 60 seconds.
- **Threshold:** 5 failed auth attempts within the window.
- **Lockout:** 10 minutes of dropped connections from that MAC.

Values configurable. MAC-scoped state survives across connections within the process; reset on service restart (acceptable — restarts are rare and observable).

### 7.5 Request / response semantics

- Every request carries a `request_id: u16` chosen by the client.
- Server echoes `request_id` on the matching response.
- v1 client is strictly sequential (one in-flight request). Server MUST handle pipelining correctly anyway, to keep the protocol future-compatible.

### 7.6 Error model

Response payload is `Result<T, ProtocolError>`. `ProtocolError`:

```rust
enum ProtocolError {
    NotAuthenticated,
    RateLimited { retry_after_seconds: u32 },
    NotSupported,
    InvalidArgument { reason: BoundedString },
    NetworkManagerError { message: BoundedString },
    Internal { message: BoundedString },
}
```

`BoundedString` is capped at 512 bytes at encode time so errors cannot blow the 4 KiB frame budget.

## 8. NetworkManager facade

### 8.1 Trait

```rust
#[async_trait]
pub trait NetworkFacade: Send + Sync {
    async fn list_interfaces(&self) -> Result<Vec<Interface>, NetError>;
    async fn get_ip_config(&self, iface: &str) -> Result<IpConfig, NetError>;
    async fn wifi_status(&self) -> Result<WifiStatus, NetError>;
    async fn scan_wifi(&self) -> Result<Vec<WifiNetwork>, NetError>;
    async fn set_dhcp(&self, iface: &str) -> Result<(), NetError>;
    async fn set_static_ipv4(&self, iface: &str, cfg: StaticIpv4) -> Result<(), NetError>;
    async fn connect_wifi(&self, ssid: &str, cred: WifiCredential) -> Result<(), NetError>;
}
```

Two implementations:

- **`NmrsFacade`** — production. Owns a shared `zbus::Connection` and an `nmrs::NetworkManager` built on top of it.
- **`MockFacade`** — in-memory state machine. Used by all session-layer and client-server tests.

### 8.2 Op-by-op mapping

| Op | Approach | Gotchas |
|---|---|---|
| `list_interfaces` | Raw zbus: `GetDevices` on `org.freedesktop.NetworkManager`, then per-device `Interface`, `DeviceType`, `HwAddress`, `State`. | Filter out `loopback`. |
| `get_ip_config` | Device's `Ip4Config` → `AddressData`, `Gateway`, `Nameservers`. Plus settings connection's `ipv4.method` for Auto vs Manual. | Two D-Bus hops. Device may have no active config — return empty. |
| `wifi_status` | `nmrs` if exposed; else Wi-Fi device → `ActiveAccessPoint` → SSID, strength, flags. | v1 assumes one Wi-Fi device. |
| `scan_wifi` | `nmrs.list_networks()` with explicit `RequestScan`; poll `LastScan` property until updated, 10 s timeout. | Scan is async. |
| `set_dhcp` | Get settings connection for iface → set `ipv4.method = "auto"`, clear `addresses`/`gateway`/`dns` → `Update` → `ActivateConnection`. | Must re-activate; `Update` alone does not apply. |
| `set_static_ipv4` | Same flow, `method = "manual"`, populate fields. | Same re-activation requirement. Validate inputs in the facade. |
| `connect_wifi` | `nmrs.connect(ssid, WifiSecurity::WpaPsk { psk })`. | NM may create a new profile or reuse one — both acceptable. Wrap in a 30 s timeout so a wrong PSK fails the request cleanly. |

### 8.3 Operational safeties

- Every write op runs under a 30 s tokio timeout. NM hangs fail the request, not the service.
- A global `tokio::sync::Mutex` serializes write ops at the facade boundary.
- Static-IP validator rejects before touching NM: address ∉ multicast/broadcast/loopback, prefix ∈ 1..=30, gateway in same subnet if provided.
- Every write op logs old config and new config at INFO before applying, for recovery via serial/SSH if the operator makes a mistake.

Apply-with-rollback (stage → apply → heartbeat-or-revert) is deferred to v2.

## 9. Systemd packaging

### 9.1 Unit file

```ini
[Unit]
Description=Network provisioning daemon (BLE)
After=NetworkManager.service bluetooth.service
Requires=NetworkManager.service bluetooth.service

[Service]
Type=notify
ExecStart=/usr/bin/netprovd
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

- **Runs as root** for v1. Privilege drop to a dedicated user with `CAP_NET_ADMIN` + `bluetooth` group + polkit is deferred; cross-distro setup is significantly more complex.
- **`Type=notify`.** Readiness is reported *after* the BLE adapter is acquired and the GATT service is registered, not at process start. Implemented by writing to `$NOTIFY_SOCKET` directly (avoids pulling in `libsystemd`).
- **No `/dev/hci*` exposure** — bluer uses BlueZ's D-Bus API.

### 9.2 Filesystem layout

```
/usr/bin/netprovd                         # server binary
/usr/bin/netprov                          # client CLI
/etc/netprov/key                          # production PSK, 0600 root:root
/lib/systemd/system/netprovd.service      # unit file (Debian-standard path)
```

### 9.3 Key loading

Priority at startup:

1. `$NETPROV_KEY_PATH` — load from that path. Fail hard if missing or unreadable.
2. `/etc/netprov/key` — load if present. **Refuse if any group or world permission bit is set** (`mode & 0o077 != 0`). Owner-only modes like 0400 or 0600 are accepted; anything looser causes a startup error. Misconfigured permissions must not silently fall through to the dev key.
3. Embedded dev key — last resort, emits a loud warning loop.

Override: `$NETPROV_PRODUCTION=1` disables step 3. The service refuses to start without a real key. Intended for staging images where "dev key in use" should be a hard error.

### 9.4 Dev-key warning

- INFO on startup: one-line banner showing which source the key came from.
- If the dev key is active: WARN every 60 seconds with a stable, greppable marker:
  `netprov: INSECURE: development key in use; run 'netprovd keygen --install' to install a production key`.

Periodic rather than once, so it cannot be lost in journal scrollback.

### 9.5 `netprovd keygen`

```
netprovd keygen                    # generate random key, print base64 + QR to stdout
netprovd keygen --install          # + write to /etc/netprov/key, mode 0600 root:root
netprovd keygen --install -o PATH  # custom install path
```

QR code rendered to stdout as ANSI. This is load-bearing for mobile client enrollment later: factory flow is "keygen, print sticker, scan at activation."

### 9.6 Debian packaging

Built with `cargo-deb`. Metadata in `crates/server/Cargo.toml`:

```toml
[package.metadata.deb]
name = "netprov"
maintainer = "..."
depends = "bluez, network-manager, libdbus-1-3"
section = "net"
assets = [
    ["target/release/netprovd", "usr/bin/", "755"],
    ["target/release/netprov",  "usr/bin/", "755"],
    ["packaging/netprovd.service", "lib/systemd/system/", "644"],
]
conf-files = ["/etc/netprov/"]
maintainer-scripts = "packaging/debian/"
```

Maintainer scripts:

- **`postinst`** — `mkdir -p /etc/netprov && chmod 700 /etc/netprov`, `systemctl daemon-reload`, **do not auto-start**. Print explicit next steps: run `sudo netprovd keygen --install`, then `sudo systemctl enable --now netprovd`.
- **`prerm`** — stop the service if running.
- **`postrm`** — on `purge`, remove `/etc/netprov/`; on plain `remove`, leave it so keys survive upgrades.

One package for v1 ships both binaries. Splitting into separate `netprov` / `netprovd` packages is a later concern.

### 9.7 Build matrix

- **amd64:** native build on a standard amd64 runner.
- **aarch64:** native build on an arm64 runner (GitHub Actions ARM64 Linux runners, or self-hosted).
- `cross` is documented as a local-dev fallback, not used in CI.

## 10. Testing strategy

The architecture is arranged so most tests run with no root, no BLE hardware, and no NetworkManager.

| Tier | In CI? | What it covers |
|---|---|---|
| Unit tests | Yes | `protocol` crate: CBOR round-trips, framing fragment/reassemble, HMAC verification, bounded-string enforcement, error enum serialization. |
| Session-layer integration | Yes | Session state machine driven by fake BLE frames against `MockFacade`. Covers auth success/reject, rate limiting, pipelined requests, malformed frames, oversized payloads. |
| Client↔server loopback | Yes | `client` and `server` wired via `tokio::io::duplex`, skipping BLE. Tests the full request/response surface. |
| Facade contract tests | Yes (mock only) | A shared test suite `fn facade_contract<F: NetworkFacade>(f: F)` documents and enforces trait behavior. Real impl runs the same suite under `--features live-nm`. |
| Real-NM integration | Opt-in, `#[ignore]` | `NmrsFacade` against real NetworkManager. Run by hand on a dev machine. |
| Real-BLE end-to-end | Opt-in, `--features live-ble` | `netprovd` on one box, `netprov` CLI on another, over real BLE. Smoke test. |

**`MockFacade`** is central: an in-memory state machine with configurable interfaces, a fake scan list, per-op fault injection, a deterministic clock. Every non-hardware test uses it.

**Property tests** (`proptest`) for: framing round-trip (`fragment ∘ reassemble = id`), CBOR codec symmetry, static-IP validator.

**Not in CI:** D-Bus mocking (reinvents nmrs), BLE stack behavior (same). These are validated by the opt-in live tiers on real hardware.

**CI matrix:**

- `cargo fmt --check`
- `cargo clippy -- -D warnings`
- `cargo test --workspace`
- Build `.deb` and release binaries

All three stages run on both amd64 and aarch64.

## 11. Open questions

- Exact BLE service UUID values — generate at scaffold time, document in this spec.
- Should `Info` include the device serial or only the model? Serial leaks a device identifier to any passerby; model alone is fine for client version negotiation. **Recommendation:** model only. Confirm during implementation.
- `tracing-journald` integration vs. stderr-with-journald-capture: both work. `tracing-journald` preserves structured fields. **Recommendation:** `tracing-journald`.
