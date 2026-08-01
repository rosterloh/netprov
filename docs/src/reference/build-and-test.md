# Build and Test

## Build matrix

```bash
cargo test --workspace
cargo build -p netprov-server --features live-ble
cargo build -p netprov-server --features live-nm
cargo build -p netprov-client --features ble
cargo build -p netprov-client --features ble-btleplug
cargo deb -p netprov-server
```

`live-ble` implies `live-nm`. The `live-nm-destructive` feature gates mutating
NetworkManager integration tests that are unsafe for CI. `ble-btleplug` forces
the portable backend on Linux so the macOS path remains covered by Linux CI and
local builds.

## Test tiers

| Tier | In CI? | Covers |
|---|---|---|
| Unit tests | Yes | Protocol CBOR round trips, framing, HMAC, bounded strings, and property tests. |
| Session layer | Yes | The `Session` state machine against `MockFacade`. |
| Client/server loopback | Yes | The complete request/response surface over `tokio::io::duplex`. |
| Live NetworkManager | Opt-in | `--features live-nm -- --ignored`; requires NetworkManager on the system bus. |
| Live BLE end-to-end | Opt-in | `--features live-ble` and two BLE-equipped hosts. |
