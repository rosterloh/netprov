# Changelog

All notable changes to this project are documented in this file. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.1.1] — 2026-08-09

### Added

- `netprovd` exposes the standard Bluetooth SIG Current Time Service
  (0x1805/0x2A2B), so an already-authenticated client can set a clockless
  device's system clock (and, via `timedated`, its RTC). Reads are
  unauthenticated; writes require an authenticated session and are clamped to
  a plausible window. `netprov-sdk`'s `BleClient::set_time` and the desktop
  app's automatic post-auth sync make this transparent; `netprov set-time`
  exposes it from the CLI. (#32)

### Fixed

- `connect_wifi` no longer accumulates duplicate `802-11-wireless` profiles
  when retrying a mistyped password: an existing profile for the SSID is now
  looked up and updated/reactivated instead of always calling
  `AddAndActivateConnection`. It also polls the resulting `ActiveConnection`'s
  state until activated/deactivated, so a bad passphrase surfaces as an error
  instead of a premature success. (#46)

### Security

- Further sandboxed `packaging/netprovd.service`: an empty
  `CapabilityBoundingSet`/`AmbientCapabilities` (the daemon only proxies over
  the NetworkManager and BlueZ D-Bus APIs, never opening a raw network or
  Bluetooth socket itself), `RestrictAddressFamilies=AF_UNIX`,
  `MemoryDenyWriteExecute`, `ProtectClock`, `ProtectHostname`,
  `ProtectKernelLogs`, `ProtectProc=invisible`, `RestrictSUIDSGID`, and
  `UMask=0077`. Also switched `Requires=`/`Restart=on-failure` to
  `BindsTo=`/`Restart=always` so a clean stop or restart of
  `NetworkManager.service`/`bluetooth.service` now brings `netprovd` back up
  instead of leaving it down. (#24)

## [1.1.0] — 2026-08-01

Post-release hardening pass over the BLE auth and transport path, found during
a codebase review.

### Added

- macOS (and Windows) BLE support for the client and desktop app, via a second
  SDK transport backend built on `btleplug`. `netprov-sdk`'s `ble` feature now
  picks `bluer` on Linux and `btleplug` (CoreBluetooth / WinRT) elsewhere, so
  `cargo build -p netprov-app --features desktop` works on a Mac. `netprovd`
  is unchanged and remains Linux-only. (#31)
- `netprov ble-scan` — lists nearby netprov devices with the identifier to
  pass to `--ble-peer`. Requires no PSK and no connection.
- `netprov-sdk`/`netprov-client` feature `ble-btleplug`, forcing the portable
  backend on Linux so the macOS code path is covered by Linux CI.
- `NETPROV_BLE_MAX_FRAGMENT` overrides the per-frame BLE value length, for
  platforms that do not report a negotiated ATT MTU.
- CI: a macOS job building and testing the client, SDK and desktop app.

### Changed

- BLE peers are identified by an opaque `PeerId` rather than a BD_ADDR.
  CoreBluetooth never discloses peer MAC addresses, so `--ble-peer` and the
  app's peer field now accept a platform handle or the advertised device name;
  a BD_ADDR still works wherever the platform provides one.
- `netprov_sdk::parse_peer_address` is replaced by `parse_peer_id`, and
  `BleDevice.address: bluer::Address` by `BleDevice.id: PeerId` plus an
  optional `address: Option<String>`.

### Fixed

- macOS: `--ble-peer <name>` stopped resolving after the first connection.
  CoreBluetooth replaces its cached `local_name` with the peer's GATT device
  name (a Pi reports its hostname), so the name `ble-scan` printed no longer
  matched. Scans now prefer the advertised name, and both names resolve.
- macOS: every request timed out after a successful session. CoreBluetooth
  caches a characteristic's notify state across connections and answers
  `subscribe` from that cache without writing the CCCD, so `netprovd` never saw
  a new subscription and dropped each response with `dropping notify frame for
  inactive peer`. The client now clears that state when it connects, which also
  covers sessions the server ended (a rejected PSK drops the link, leaving
  nothing to unsubscribe over).
- A rejected PSK reported `Device disconnected` on macOS. The server errors the
  `AuthResponse` write and drops the link, and CoreBluetooth discards the ATT
  error behind the disconnect, so the client now names the likely cause.
- macOS: `ble-scan` and `connect` intermittently found nothing when run
  shortly after a previous connection. The client never disconnected, and
  CoreBluetooth keeps the peripheral connected in the system daemon past
  process exit; a connected peripheral stops advertising. The CLI now
  disconnects on exit, including on failure.
- A peer refusing an operation for insufficient link security is reported as
  such, instead of surfacing as `Device disconnected` (CoreBluetooth reports
  the ATT error and drops the link ~2s later) or being misreported as a wrong
  PSK.
- BLE session ordering: sensitive characteristics are no longer reachable
  before authentication completes.
- Link-layer encryption enforced on ChallengeNonce, AuthResponse, and
  Request/Response characteristics (`encrypt_read` / `encrypt_write` in
  `crates/server/src/ble/gatt.rs`).
- MTU-aware fragmentation now respects the negotiated BLE MTU instead of a
  fixed size.
- Reassembly is gated on authentication, partial-message buffers are bounded,
  and a peer-session handle leak on disconnect is fixed.
- BLE service/characteristic UUIDs de-duplicated to a single source of truth.

### Changed

- Failed-auth rate limiter moved from a per-peer-only tier to an additional
  global tier, bounding aggregate brute-force attempts across peers.

### Added

- `netprovd` initiates bonding itself when a peer subscribes. The sensitive
  characteristics need an encrypted link, but a central only discovers that by
  failing a read: CoreBluetooth does raise its pairing prompt at that point,
  yet the read has already errored and the link is torn down seconds later,
  and it never retries. Requesting the bond at subscribe puts the prompt up
  before the first encrypted read, so a first-time connection can complete
  instead of having to fail once to provoke pairing.

### Security

- **The BLE auth handshake is now mutual, and the protocol version is 2.**
  Previously only the client proved knowledge of the PSK; the server proved
  nothing, so a peer that merely advertised the netprov service UUID could
  have collected the Wi-Fi credentials a client sent next. `AuthResponse` now
  carries the client's nonce alongside its tag, and the server answers with a
  tag of its own that the client verifies before issuing any request. The two
  tags are domain-separated (`netprov-auth-client-v2` / `-server-v2`) so
  neither can be replayed as the other. v1 peers are not wire-compatible.
- Sensitive characteristics ask for `encrypt_*` rather than
  `encrypt_authenticated_*`. The authenticated variants are BlueZ's
  `BT_SECURITY_HIGH` and require an MITM-protected LTK, which `netprovd`
  cannot negotiate: it runs headless and registers a `NoInputNoOutput` agent,
  so BlueZ can only do Just Works. The mismatch made every read of a sensitive
  characteristic fail with "Encryption is insufficient" and the link drop
  moments later — the BLE transport could not complete authentication on any
  platform without an out-of-band `bluetoothctl` pairing. MITM protection is
  now provided by the mutual handshake above, at the only layer that holds a
  shared secret.
- `Session::submit_auth` consumes the pending nonce before the rate-limit
  check, so a nonce issued just before lockout no longer survives the whole
  lockout window. (#19)

- `packaging/netprovd.service` now sets `Environment=NETPROV_PRODUCTION=1`,
  so the shipped daemon refuses to start on a missing/unreadable
  `/etc/netprov/key` instead of silently falling back to the public embedded
  dev key. `serve-tcp` (dev/loopback) is unaffected. (#10)

## [1.0.0] — 2026-04-24

First tagged release. Implements the v1 goals.

### Added

**Protocol** (`netprov-protocol` crate)

- CBOR wire format with a 4 KiB message ceiling enforced at both ends.
- Request/Response envelope with `request_id` correlation and a `Result`-shaped
  response payload.
- Seven v1 operations: `ListInterfaces`, `GetIpConfig`, `WifiStatus`,
  `WifiScan`, `SetDhcp`, `SetStaticIpv4`, `ConnectWifi`.
- Fragment/reassemble framing for BLE MTUs up to 512 bytes (`[u16 request_id]
  [u16 seq] [u8 flags]` header, FIN bit).
- `BoundedString` (512-byte cap) to keep error payloads within frame limits.
- HMAC-SHA256 helpers with constant-time verification via `subtle`.
- Property test for `fragment ∘ reassemble = id` across arbitrary payloads and
  MTUs.

**Server** (`netprov-server` crate, `netprovd` binary)

- `NetworkFacade` trait with two implementations:
  - `MockFacade` (default `mock` feature) — in-memory state, fault injection,
    used by all session-layer and loopback tests.
  - `NmrsFacade` (`live-nm` feature) — real NetworkManager via `nmrs` + raw
    `zbus`. Implements all seven ops.
- Per-connection `Session` state machine: challenge/response HMAC auth,
  single-use nonces, authenticated dispatch.
- Per-peer failed-auth rate limiter (5 failures / 60s → 10 min lockout,
  configurable; mockable clock).
- BLE GATT server (`live-ble` feature) over `bluer` 0.17: one primary service
  with Info, ChallengeNonce, AuthResponse, and Request/Response (write +
  notify) characteristics. `run_ble_server` handles adapter setup,
  advertising, per-peer `PeerSession`, and fragment fan-out.
- Static-IPv4 validator: prefix range, loopback/multicast/broadcast rejection,
  gateway-in-subnet check, DNS sanity.
- Key loading priority: `$NETPROV_KEY_PATH` → `/etc/netprov/key` (mode
  enforced) → embedded dev key. `$NETPROV_PRODUCTION=1` disables the dev-key
  fallback.
- Startup banner and periodic WARN loop when the embedded dev key is active.
- `netprovd keygen [--install]` subcommand — generates a 32-byte PSK, prints
  base64 + QR code, optionally installs to `/etc/netprov/key` at mode 0600.
- `netprovd serve-tcp` subcommand — loopback TCP transport for dev (drives
  `MockFacade`).
- `netprovd serve-ble` subcommand (`live-ble`) — production BLE GATT server
  (drives `NmrsFacade`) with sd-notify `Type=notify` readiness signalling.
- `tracing-journald` routing when the journald socket is reachable; stderr
  fmt layer as fallback on dev/non-systemd hosts.

**Client** (`netprov-client` crate, `netprov` binary)

- Transport-agnostic `Client<IO>` over any `AsyncRead + AsyncWrite`.
- BLE connector (`ble` feature) that discovers the service by UUID, reads the
  Info + ChallengeNonce characteristics, computes and writes the HMAC tag,
  then fragments and exchanges Request/Response frames over the notify
  stream.
- Full CLI parity with the protocol: `list`, `ip <iface>`, `wifi-status`,
  `wifi-scan`, `wifi-connect`, `set-dhcp`, `set-static`.
- `--endpoint` for TCP transport, `--ble-peer <BD_ADDR>` for BLE.
- `$NETPROV_KEY_PATH` and `$NETPROV_ENDPOINT` env fallbacks.

**Packaging**

- `cargo-deb` metadata producing a single `netprov_1.0.0-1_<arch>.deb`
  containing both binaries, the systemd unit, and the README.
- Debian maintainer scripts: `postinst` (creates `/etc/netprov` at 0700 and
  prints key-install guidance — never auto-starts the service); `prerm`
  (stops the unit); `postrm` (removes `/etc/netprov` on `purge` only).
- `packaging/netprovd.service` — `Type=notify`, `NoNewPrivileges`,
  `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, system-call filter
  restricted to `@system-service` minus `@mount @obsolete @privileged @reboot
  @swap`, `ReadWritePaths=/etc/netprov`.

**CI**

- GitHub Actions matrix across `ubuntu-latest` (amd64) and `ubuntu-24.04-arm`
  (aarch64). Runs fmt, clippy in three feature configurations (default,
  `live-nm`, `live-ble`), the default test suite, and a release build under
  `live-ble`. Separate `deb` job builds and uploads per-arch `.deb` artifacts
  gated on the `test` job passing.

**Documentation**

- Design spec.
- Part 1 (core) and Part 2 (BLE + systemd + deb) implementation plans.
- README with architecture diagram, install and dev quickstarts, build matrix,
  testing tier table.
- Two-box BLE smoke-test runbook, now at
  `docs/src/guides/ble-smoke-test.md`.

### Security

- Application-layer HMAC-SHA256 challenge/response defeats active MitM during
  BLE pairing regardless of Just Works vs. secure pairing at the link layer.
- Per-peer-MAC rate limiter bounds brute-force attempts.
- Single-use nonces — consumed by the first `AuthResponse` write on each
  connection.
- Key file at `/etc/netprov/key` refused if any group or world permission bit
  is set; no silent fallback to the dev key on misconfigured perms.
- Embedded dev key is flagged as INSECURE at startup and every 60 seconds
  thereafter.
- Static-IP input validation runs at the facade boundary before any
  NetworkManager call.

### Non-goals (deferred)

The v1 release deliberately excludes:

- IPv6 configuration.
- Enterprise Wi-Fi (WPA2-EAP / 802.1X).
- Destructive operations (reboot, interface disable, forget connection).
- Mobile and desktop clients.
- Apply-with-rollback for write operations.
- Running as a non-root user with `CAP_NET_ADMIN` + polkit.
- Split `netprov` / `netprovd` packages.

[Unreleased]: https://github.com/rosterloh/netprov/compare/v1.1.1...HEAD
[1.1.1]: https://github.com/rosterloh/netprov/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/rosterloh/netprov/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/rosterloh/netprov/releases/tag/v1.0.0
