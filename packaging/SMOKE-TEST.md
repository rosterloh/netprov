# netprov two-box BLE smoke test

Prerequisites: a Linux server box with a BLE adapter running `bluez` and
`network-manager`, plus a client machine with a BLE adapter. The client can be
Linux (below) or macOS (see [the macOS client](#macos-client)).

## Server box

```bash
# Install the deb produced by CI:
sudo dpkg -i netprov_1.0.0-1_arm64.deb           # or amd64, depending on arch
sudo netprovd keygen --install | tee /tmp/key.txt
# Copy the base64 PSK output to the client box.
sudo systemctl enable --now netprovd
# Check readiness and advertising:
sudo systemctl status netprovd
sudo timeout 10 bluetoothctl scan on | grep netprovd-
```

## Linux client box

```bash
# Put the same PSK at the expected path:
echo "<paste-base64-from-server>" | base64 -d > /tmp/netprov-key.bin
chmod 600 /tmp/netprov-key.bin

# Scan for the server's BD_ADDR (look for "netprovd-*"):
sudo timeout 10 bluetoothctl scan on | head

# Run the BLE client (built with --features ble):
netprov --key-path /tmp/netprov-key.bin --ble-peer AA:BB:CC:DD:EE:FF list
netprov --key-path /tmp/netprov-key.bin --ble-peer AA:BB:CC:DD:EE:FF wifi-scan
netprov --key-path /tmp/netprov-key.bin --ble-peer AA:BB:CC:DD:EE:FF ip wlan0
```

Expected: `list` returns real interface names from the server box.

## macOS client

The client and app use `btleplug`/CoreBluetooth on macOS. No Homebrew
packages are needed, but macOS does not expose peer MAC addresses — get the
peer identifier from `ble-scan` rather than `bluetoothctl`.

```bash
# Same PSK as the server box:
echo "<paste-base64-from-server>" | base64 -d > /tmp/netprov-key.bin
chmod 600 /tmp/netprov-key.bin

# Discover the peer. Needs no PSK and no connection.
cargo run -p netprov-client --features ble --bin netprov -- ble-scan
# 6E4A1B0C-9E3F-4A21-B0D4-7C2F1A8E55D9   netprovd-a1b2   -57 dBm

# Either the handle or a device name works as --ble-peer. Prefer the handle:
# it is stable, whereas CoreBluetooth swaps its cached name for the peer's GATT
# device name (usually the hostname) after the first connection.
PEER=6E4A1B0C-9E3F-4A21-B0D4-7C2F1A8E55D9
cargo run -p netprov-client --features ble --bin netprov -- \
  --key-path /tmp/netprov-key.bin --ble-peer "$PEER" list
cargo run -p netprov-client --features ble --bin netprov -- \
  --key-path /tmp/netprov-key.bin --ble-peer "$PEER" wifi-status

# Same path through the desktop app: Scan, click the device, Connect.
cargo run -p netprov-app --features desktop
```

Expect a **system pairing prompt** on the first connection — the Challenge,
AuthResponse and Request characteristics all require an encrypted link. Just
accept it; there is no passkey to compare, because a headless peripheral can
only offer Just Works pairing. Man-in-the-middle protection comes from the
mutual PSK handshake instead: the client verifies the server's HMAC tag before
sending anything, so a device that cannot prove it holds the PSK is refused
with `server failed to prove it holds the PSK`.

## Troubleshooting

- `netprov: could not find service` — the server isn't advertising; check
  `journalctl -u netprovd -n 50` for adapter errors.
- `auth failed` — PSK mismatch; re-copy the key.
- `connect timed out` — adapter range or a stale bonding; run
  `sudo bluetoothctl remove AA:BB:CC:DD:EE:FF` on the client.

macOS-specific:

- `no Bluetooth adapter available`, or `ble-scan` returning nothing at all —
  the terminal app needs Bluetooth permission (System Settings → Privacy &
  Security → Bluetooth). macOS only prompts once, so grant it manually if the
  first prompt was dismissed.
- `peer ... not seen within 10s` — the identifier is stale. CoreBluetooth
  UUIDs are per-host and can be reissued; re-run `ble-scan`.
- Repeated `auth failed` after re-copying the key — clear the stale pairing.
  Forget the device on the Mac (System Settings → Bluetooth) *and* run
  `sudo bluetoothctl remove <mac>` on the server box, then reconnect.
- `peer refused the operation because the link is not encrypted enough` — the
  pairing did not complete or was dismissed. Clear it as above and retry. If it
  persists with a freshly built `netprovd`, check `gatt.rs` still asks for
  `encrypt_*` and not `encrypt_authenticated_*`: the latter needs an
  MITM-protected key that a headless box cannot negotiate, so it fails this way
  every time regardless of the prompt.
- `server failed to prove it holds the PSK` — the peer answered the handshake
  with the wrong tag. Either the two sides hold different PSKs, or the device
  is not the one you think it is. This is a hard failure by design; no request
  is sent.
- Slow round trips are expected: CoreBluetooth does not report a negotiated
  MTU, so requests fragment at the 20-byte ATT floor. Set
  `NETPROV_BLE_MAX_FRAGMENT` (e.g. `185`) to raise it.
