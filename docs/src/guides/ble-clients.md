# BLE Clients

`netprovd` is a GATT peripheral and remains Linux-only. The CLI and desktop app
are GATT centrals: the SDK uses BlueZ through `bluer` on Linux and
[`btleplug`](https://github.com/deviceplug/btleplug) on macOS and Windows.

## Finding a peer

macOS does not expose peer MAC addresses. CoreBluetooth returns an opaque UUID
that is stable for that Mac but meaningless on other hosts. Discover it with
the scan command, which needs neither a PSK nor a connection:

```bash
cargo run -p netprov-client --features ble --bin netprov -- ble-scan
# 6E4A1B0C-9E3F-4A21-B0D4-7C2F1A8E55D9   netprovd-a1b2   -57 dBm

cargo run -p netprov-client --features ble --bin netprov -- \
  --key-path ./netprov-key.bin \
  --ble-peer 6E4A1B0C-9E3F-4A21-B0D4-7C2F1A8E55D9 list
```

The advertised device name also works as `--ble-peer`. Prefer the identifier
printed by `ble-scan`: CoreBluetooth may replace its cached advertised name
with the peer's GATT device name after the first connection. On Linux and
Windows, a Bluetooth device address still works.

## macOS notes

- The first connection raises a system pairing prompt. Accept it; a headless
  peripheral uses Just Works and has no passkey to compare.
- A terminal-launched CLI needs Bluetooth permission for the terminal app in
  System Settings → Privacy & Security → Bluetooth.
- CoreBluetooth does not expose the negotiated ATT MTU, so requests fragment
  at the mandatory 20-byte floor. Set `NETPROV_BLE_MAX_FRAGMENT` to a larger
  value when the peer is known to negotiate it.
