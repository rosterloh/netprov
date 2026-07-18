# netprov Remediation Plan — Code Review Findings (2026-07-16)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Write the failing test first wherever a test is specified.

**Goal:** Fix the defects and hardening gaps found in the 2026-07-16 repo review: a likely-fatal BLE handshake ordering bug, unencrypted Wi-Fi credentials over the air, MTU-unaware notify fragmentation, pre-auth memory exposure, bypassable rate limiting, and assorted CI/docs drift.

**Context:** The review inspected all five crates. The transport-agnostic core (protocol, session, key loading, TCP loopback tiers) is sound and well tested — do not restructure it. All findings are in the BLE adaptation layer, the SDK BLE client, packaging metadata, and CI. Design spec: [`docs/superpowers/specs/2026-04-23-netprov-design.md`](../specs/2026-04-23-netprov-design.md).

**Ordering:** Tasks 1–4 are correctness/security and should land first, in order. Tasks 5–8 are independent and can be parallelized. Task 9 (hardware smoke test) is the final gate.

---

## Task 1 — Fix BLE auth-before-subscribe ordering (likely fatal bug)

**Problem:** The server only creates a `PeerSession` when a peer subscribes to notifications on `REQUEST_UUID` (`CharacteristicControlEvent::Notify`, `crates/server/src/ble/server.rs:135`). Until then, all four GATT handler closures find `None` in the `current` mutex and return empty/false (`crates/server/src/ble/server.rs:60-88`). But the SDK client authenticates *before* it ever subscribes: `BleClient::authenticate()` reads Info, reads the challenge nonce, and writes the HMAC tag (`crates/sdk/src/ble.rs:161-175`), while `notify_io()` is only called later, per-request (`crates/sdk/src/ble.rs:183`). Consequence: on a fresh connection the client reads a zero-length nonce and fails with `SdkError::UnexpectedMessage("nonce length")`. The live e2e test is manual and was punted (`crates/server/tests/live_ble_e2e.rs:47`), so this path likely never ran end-to-end.

**Fix (both sides, belt and braces):**

- [ ] SDK: in `BleClient::connect()` (`crates/sdk/src/ble.rs:84`), after resolving the four characteristics, open the notify stream once (`self.request.notify_io()`) and store it on `BleClient` (add a `notify: CharacteristicReader`-style field). `request()` reuses the stored stream instead of re-subscribing per request. This also fixes a latent race where response fragments could arrive between requests.
- [ ] Server: make session creation independent of notify subscription. In `run_ble_server`, mint the `PeerSession` on first GATT interaction instead of returning empty defaults: change the `on_nonce_read` / `on_info_read` / `on_auth_write` closures so that when `current` is `None`, they create and install a `PeerSession` (peer address is available on the request via `bluer`'s `CharacteristicReadRequest` / `CharacteristicWriteRequest` — the `GattHandlers` closures in `crates/server/src/ble/gatt.rs:12-17` currently discard `_req`; extend their signatures to pass the peer address through).
- [ ] Keep the notify-writer wiring in the control-event loop as-is (it still binds `notify_rx` to the subscribed writer), but have it *reuse* the already-minted `PeerSession` for the same peer address rather than creating a new one (which would discard authenticated state if the client subscribes after authenticating).
- [ ] Add a unit test at the `GattHandlers`/`PeerSession` level (no hardware needed): simulate read-nonce → write-auth → subscribe → write-request in that order and assert the request succeeds. The existing handler closures are plain `Fn`s, so this is testable without BlueZ.

**Verify:** `cargo test --workspace` green; new ordering test passes; `cargo clippy -p netprov-server --features live-ble --all-targets -- -D warnings` green. Full confirmation is Task 9.

## Task 2 — Require link encryption / protect Wi-Fi credentials over the air

**Problem:** README claims "bonded + app-layer HMAC auth", but no characteristic sets any security requirement (`crates/server/src/ble/gatt.rs:41-106` uses default flags) and the daemon only calls `set_pairable(true)`. HMAC authenticates the client but encrypts nothing, so `Op::ConnectWifi { credential }` — the Wi-Fi PSK — crosses the air in plaintext to any sniffer.

- [ ] Set encryption-required flags on the sensitive characteristics in `gatt.rs`: `encrypt_authenticated_read` on CHALLENGE, `encrypt_authenticated_write` on AUTH_RESPONSE and REQUEST, and require the same on the notify side (check `bluer::gatt::local::CharacteristicRead`/`CharacteristicWrite`/`CharacteristicNotify` field names for the current bluer version — 0.17). INFO may stay open (it exposes model + protocol version only, per spec §11).
- [ ] Decide and document the pairing story: with encryption required, BlueZ will trigger pairing/bonding on first access. The daemon runs headless, so use a Just-Works-compatible agent (`bluer::agent::Agent` with no IO capability) registered at startup, and rely on the app-layer HMAC PSK for actual authorization (Just Works gives encryption without MITM protection; the HMAC challenge is what stops an active MITM from issuing commands — an active MITM could still observe credentials, so state this residual risk in the README's security section, or alternatively add app-layer payload encryption keyed from `HMAC(psk, nonce || "enc")`; the maintainer prefers the simpler bonding approach unless it proves unworkable).
- [ ] Update README "Architecture" wording to match what is actually enforced.

**Verify:** build green under `--features live-ble`; manual check in Task 9 that an unpaired central gets access-denied on CHALLENGE read and that `btmon` shows an encrypted link during `wifi-connect`.

## Task 3 — MTU-aware notify fragmentation

**Problem:** Responses are fragmented at a fixed 512-byte ceiling (`fragment(resp.request_id, &bytes, MAX_PAYLOAD_PER_FRAME + 5)` at `crates/server/src/ble/conn.rs:131`) and written whole to the notify socket (`notifier.write_all` at `crates/server/src/ble/server.rs:150`). If the negotiated ATT MTU is below 512 (typical for mobile centrals — the SDK doc comment names Android/iOS as targets), notification writes fail or truncate.

- [ ] Server: after a peer subscribes, read the writer's MTU (`notifier.mtu()` on the `CharacteristicWriter`) and plumb it into the fragmentation call — e.g. store `mtu: AtomicUsize` on `PeerSession` (default 512) and set it in the control-event loop before entering the recv loop; `on_request`'s spawned task reads it when calling `fragment`.
- [ ] SDK: same on the client side for request writes — `Characteristic::write` uses a reliable write which BlueZ can long-write, but cap request fragments at the connection MTU too (available via `notify_io()`'s reader MTU or `device.remote_mtu()`); keep 512 as the upper bound.
- [ ] Export `pub const MAX_FRAME_LEN: usize = 512;` from `crates/protocol/src/framing.rs` and replace both `MAX_PAYLOAD_PER_FRAME + 5` / `MAX_PAYLOAD_PER_FRAME + FRAME_HEADER_LEN` call-site reconstructions (`crates/server/src/ble/conn.rs:130`, `crates/sdk/src/ble.rs:28`) and their explanatory comments.
- [ ] Unit test: `fragment` with a small MTU (e.g. 23-byte ATT minimum → 20-byte value) round-trips through `Reassembler` (extend the existing proptest range down to 23 if not already covered — current proptest floor is 16, so likely just delete this checkbox after confirming).

**Verify:** `cargo test --workspace` green; Task 9 exercises a real MTU negotiation.

## Task 4 — Auth-gate reassembly and bound partial messages

**Problem:** `PeerSession::on_request` parses and buffers fragments *before* any auth check (`crates/server/src/ble/conn.rs:82-105`); auth is only checked at dispatch. An unauthenticated peer can hold up to 65,536 partial messages × `MAX_MESSAGE_SIZE` (4096, `crates/protocol/src/codec.rs:4`) ≈ 256 MiB per connection — a cheap DoS against an embedded target.

- [ ] In `on_request`, check `session.is_authenticated()` first and drop the frame (with a `warn!`) when unauthenticated, before touching the reassembler.
- [ ] Add a cap on concurrent partial messages in `Reassembler` (`crates/protocol/src/framing.rs:52`): new field `max_partials` (default 4 is generous — the client is strictly request/response), new `FramingError::TooManyPartials`, enforced in `push` when inserting a new `request_id` entry.
- [ ] Tests: unauthenticated request frame produces no reassembler state and no response; 5th concurrent partial `request_id` returns `TooManyPartials`.
- [ ] While in `conn.rs`: fix the `dispatch_handles` leak (`crates/server/src/ble/conn.rs:34`) — when pushing a new handle, `retain(|h| !h.is_finished())`; and abort all handles when the peer session is dropped from `run_ble_server`'s control loop (the drain point at `crates/server/src/ble/server.rs:159`).

**Verify:** new tests pass; `cargo test --workspace` green.

## Task 5 — Rate limiter: global tier + pruning

**Problem:** The limiter is keyed per peer id (`crates/server/src/rate_limit.rs:38`). Over TCP the key is `ip:port`, so every reconnect gets a fresh limiter (`crates/server/src/server_loop.rs:100`); over BLE the key is the peer MAC, which a hostile central rotates freely (random resolvable addresses) — bypassing lockout *and* growing the `HashMap` without bound.

- [ ] Add a global (all-peers) failure window to `RateLimiter`: same config shape, higher threshold (e.g. 5× per-peer). `check`/`record_failure` consult both tiers. Keep the injectable `Clock` — the existing `FakeClock` tests extend naturally.
- [ ] Prune: in `record_failure`, drop map entries whose lockout has expired and whose failure list is empty after window filtering; also cap the map (e.g. 1024 entries, evict oldest) as a backstop.
- [ ] Tests: rotating peer ids still hits the global lockout; expired entries are pruned.

**Verify:** `cargo test -p netprov-server` green.

## Task 6 — Move BLE UUIDs into netprov-protocol

**Problem:** The four characteristic UUIDs + service UUID are defined twice and kept in sync by a comment: `crates/server/src/ble/uuids.rs` and `crates/sdk/src/ble.rs:22-27`.

- [ ] Add a `uuid` module (or plain consts as `u128` values to avoid a bluer dependency in the protocol crate) to `netprov-protocol`; both server and SDK construct `bluer::Uuid::from_u128(...)` from those shared consts. Delete the duplicated definitions.
- [ ] Rename the misleading `tag_len_ok` local in `Session::submit_auth` (`crates/server/src/session.rs:111`) to `nonce_pending` (it tracks whether a nonce was pending, not tag length).

**Verify:** `cargo clippy --workspace --all-targets -- -D warnings` green; grep shows a single definition site for each UUID.

## Task 7 — README + packaging drift

- [ ] README says "Three Rust crates" with a 3-row table — the workspace has five (`crates/sdk`, `crates/app` missing). Update the table (sdk: transport-agnostic `ProvisioningClient` trait + BLE/TCP transports; app: Dioxus desktop UI behind `desktop` feature).
- [ ] README install example uses `netprov_0.1.0-1_arm64.deb`; workspace version is 1.0.0 (`Cargo.toml:12`). Use a placeholder like `netprov_<version>_arm64.deb`.
- [ ] Reflect Task 2's actual security posture in the README architecture section.
- [ ] Add a CHANGELOG entry for this remediation batch.

**Verify:** README statements match `Cargo.toml` workspace members and gatt.rs flags.

## Task 8 — CI gaps

File: `.github/workflows/ci.yml`.

- [ ] `netprov-app` is never built: add a clippy/build step with the `desktop` feature on the amd64 runner only, after installing the GTK deps listed in README (`libgtk-3-dev libwebkit2gtk-4.1-dev libayatana-appindicator3-dev libxdo-dev pkg-config`).
- [ ] Clippy the SDK/client BLE features: `cargo clippy -p netprov-client --features ble --all-targets -- -D warnings` (pulls `netprov-sdk/ble`).
- [ ] Add a `cargo-audit` (or `cargo-deny`) step — this is a credential-handling daemon.
- [ ] The release job recompiles `cargo-deb` every run because `~/.cargo/bin` isn't cached: switch to `taiki-e/install-action@cargo-deb` (or add `~/.cargo/bin` to the cache path).

**Verify:** CI green on a PR touching this file; app job actually compiles `netprov-app`.

## Task 9 — Hardware-in-the-loop smoke test (final gate)

- [ ] Run the two-box runbook in `packaging/SMOKE-TEST.md` against the Task 1–4 changes: scan, connect, authenticate, `list`, `wifi-scan`, `wifi-connect`, `set-static`, plus a deliberately wrong PSK (expect `AuthFail` + lockout after 5 tries).
- [ ] Confirm with `btmon` that the link is encrypted before `wifi-connect` (Task 2) and note the negotiated MTU (Task 3).
- [ ] Record results (pass/fail per op, MTU observed) at the bottom of `SMOKE-TEST.md`.

**Verify:** all ops pass on real hardware; encrypted link observed.

---

## Out of scope (noted, not planned)

- `facade_nmrs.rs` (710 lines) was only skimmed in the review — a dedicated NetworkManager-integration review is worthwhile but separate.
- Multi-peer BLE concurrency remains a Part 3 concern per the spec (`crates/server/src/ble/server.rs:49` comment).
- systemd unit further hardening (`RestrictAddressFamilies`, `CapabilityBoundingSet`, dedicated user + polkit) — nice-to-have, current unit is already strong.
