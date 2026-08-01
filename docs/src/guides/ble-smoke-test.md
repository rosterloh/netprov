# Two-box BLE Smoke Test

Use a Linux server with a BLE adapter, BlueZ, and NetworkManager. The client can
be Linux or macOS and also needs a BLE adapter.

## Server

```bash
sudo dpkg -i netprov_1.0.0-1_arm64.deb
sudo netprovd keygen --install | tee /tmp/key.txt
# Copy the base64 PSK output to the client.
sudo systemctl enable --now netprovd
sudo systemctl status netprovd
sudo timeout 10 bluetoothctl scan on | grep netprovd-
```

## Linux client

```bash
echo "<paste-base64-from-server>" | base64 -d > /tmp/netprov-key.bin
chmod 600 /tmp/netprov-key.bin

sudo timeout 10 bluetoothctl scan on | head

netprov --key-path /tmp/netprov-key.bin --ble-peer AA:BB:CC:DD:EE:FF list
netprov --key-path /tmp/netprov-key.bin --ble-peer AA:BB:CC:DD:EE:FF wifi-scan
netprov --key-path /tmp/netprov-key.bin --ble-peer AA:BB:CC:DD:EE:FF ip wlan0
```

`list` should return real interface names from the server.

## macOS client

macOS uses CoreBluetooth and needs no Homebrew packages. It does not expose
peer MAC addresses, so use `ble-scan` to get the identifier.

```bash
echo "<paste-base64-from-server>" | base64 -d > /tmp/netprov-key.bin
chmod 600 /tmp/netprov-key.bin

cargo run -p netprov-client --features ble --bin netprov -- ble-scan
# 6E4A1B0C-9E3F-4A21-B0D4-7C2F1A8E55D9   netprovd-a1b2   -57 dBm

PEER=6E4A1B0C-9E3F-4A21-B0D4-7C2F1A8E55D9
cargo run -p netprov-client --features ble --bin netprov -- \
  --key-path /tmp/netprov-key.bin --ble-peer "$PEER" list
cargo run -p netprov-client --features ble --bin netprov -- \
  --key-path /tmp/netprov-key.bin --ble-peer "$PEER" wifi-status

cargo run -p netprov-app --features desktop
```

The first connection raises a system pairing prompt before the first encrypted
read. Accept it while the command is running. Later connections reuse the bond.
The mutual PSK handshake provides MITM protection, and the client sends no
request until the server proves that it holds the PSK.

## Troubleshooting

- `netprov: could not find service`: check
  `journalctl -u netprovd -n 50` for adapter errors.
- `auth failed`: copy the PSK again.
- `connect timed out`: check range or remove a stale bond with
  `sudo bluetoothctl remove AA:BB:CC:DD:EE:FF`.
- `no Bluetooth adapter available`, or an empty macOS scan: grant the terminal
  Bluetooth permission in System Settings → Privacy & Security → Bluetooth.
- `peer ... not seen within 10s`: rerun `ble-scan`; CoreBluetooth identifiers
  are per-host and can be reissued.
- Repeated authentication failures after replacing the key: forget the device
  on the Mac and remove its bond from the server with `bluetoothctl`.
- `peer refused the operation because the link is not encrypted enough`: clear
  the bond and pair again. If it persists, verify `gatt.rs` uses `encrypt_*`,
  not `encrypt_authenticated_*`.
- `server failed to prove it holds the PSK`: the peer has the wrong PSK or is
  not the expected device. No request is sent.
- `peer closed the connection during authentication`: on macOS this usually
  means the PSK is wrong; CoreBluetooth may hide the ATT authorization error
  behind the disconnect.
- Requests timing out while the daemon logs `dropping notify frame for inactive
  peer`: clear stale CoreBluetooth notification state by power-cycling
  Bluetooth when testing an older client.
- Slow macOS round trips are expected at the 20-byte ATT floor. Raise
  `NETPROV_BLE_MAX_FRAGMENT` only when the peer supports a larger value.
