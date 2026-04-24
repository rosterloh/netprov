# Changelog

All notable changes to this project are documented in this file. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-04-24

First tagged release. Implements the v1 goals of the
[design spec](docs/superpowers/specs/2026-04-23-netprov-design.md).

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
- Two-box BLE smoke-test runbook in `packaging/SMOKE-TEST.md`.

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

See the [design spec](docs/superpowers/specs/2026-04-23-netprov-design.md)
§2 for the full list.

[1.0.0]: https://github.com/rosterloh/netprov/releases/tag/v1.0.0
