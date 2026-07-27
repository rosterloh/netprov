# CLAUDE.md

Guidance for AI agents (and humans) working in this repository.

## Project

`netprov` is a BLE GATT service for provisioning network settings on headless
Linux devices, plus a client SDK and desktop app. Rust workspace, edition 2024,
MSRV **1.94.1**.

### Crates

| Crate               | What it is                                                        |
| ------------------- | ----------------------------------------------------------------- |
| `crates/protocol`   | Wire format: frames, CBOR request/response, HMAC auth, reassembly. |
| `crates/server`     | `netprovd` daemon — BLE GATT server + NetworkManager facade.       |
| `crates/sdk`        | Client-side transport/session logic.                               |
| `crates/client`     | CLI client built on the SDK.                                       |
| `crates/app`        | Dioxus desktop app.                                                |

### Feature flags that matter

Much of the code is behind features, so a plain `cargo build`/`cargo test` does
**not** compile it. Mirror CI (below) when touching these areas:

- `netprov-server`: `mock` (default), `live-nm` (real NetworkManager),
  `live-ble` (real BlueZ; implies `live-nm`), `live-nm-destructive`.
- `netprov-sdk`: `ble`, `ble-btleplug`, `dev-tcp`.
- `netprov-client`: `ble`, `ble-btleplug`, `dev-tcp`, `loopback`.
- `netprov-app`: `desktop`.

The BLE server code (`crates/server/src/ble/**`) only compiles under
`--features live-ble`, and its tests only run there — editing it and running
`cargo test --workspace` alone will silently skip every BLE test.

### Two BLE client backends

`netprov-sdk`'s `ble` feature picks a backend by target, so callers just ask
for `ble` and get whatever works there:

| Target        | Backend    | Module                                    |
| ------------- | ---------- | ----------------------------------------- |
| Linux         | `bluer`    | `crates/sdk/src/ble/backend_bluez.rs`     |
| macOS / other | `btleplug` | `crates/sdk/src/ble/backend_btleplug.rs`  |

Only one compiles per target, so **on Linux `--features ble` never type-checks
the btleplug backend**. Use `--features ble-btleplug` to force it and cover
that code locally (CI does both). `netprovd` itself is a GATT peripheral and
stays Linux/`bluer` only.

Peers are identified by an opaque `PeerId`, not a MAC: CoreBluetooth never
discloses peer BD_ADDRs, only a per-host `CBPeripheral` UUID. Do not
reintroduce MAC assumptions into the SDK, CLI `--ble-peer`, or the app.

## Before pushing — run the full CI gate locally

CI (`.github/workflows/ci.yml`) runs all of the following with warnings denied.
Run the same commands before you push; a green local run is the contract.

```sh
# One-time system deps (needed for bluer/BlueZ + GTK builds):
sudo apt-get update && sudo apt-get install -y \
  libdbus-1-dev pkg-config bluez \
  libgtk-3-dev libwebkit2gtk-4.1-dev libayatana-appindicator3-dev libxdo-dev

# Format — this is the check most easily missed. ALWAYS run it.
cargo fmt --all -- --check

# Lint (every feature slice CI checks):
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p netprov-server --features live-nm  --all-targets -- -D warnings
cargo clippy -p netprov-server --features live-ble --all-targets -- -D warnings
cargo clippy -p netprov-client --features ble      --all-targets -- -D warnings
cargo clippy -p netprov-client --features ble-btleplug --all-targets -- -D warnings
cargo clippy -p netprov-app    --features desktop  --all-targets -- -D warnings

# Test:
cargo test --workspace
cargo test -p netprov-server --features live-ble
cargo test -p netprov-sdk    --features ble-btleplug

# Build the BLE server (catches feature-gated compile errors clippy may miss):
cargo build -p netprov-server --features live-ble
```

Tips:
- Run `cargo fmt --all` (no `--check`) to auto-fix formatting, then re-run the
  `--check` to confirm. New test code and multi-arg calls are the usual culprits.
- `cargo audit` also runs in CI; a new/updated dependency can trip it.
- If a change only touches one crate/feature, you still need `cargo fmt` and the
  relevant clippy/test slice for that feature — not just the default build.
