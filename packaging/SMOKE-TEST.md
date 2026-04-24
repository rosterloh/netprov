# netprov two-box BLE smoke test

Prerequisites: two Linux boxes each with a BLE adapter; both have `bluez` and
(on the server box) `network-manager` running.

## Server box

```bash
# Install the deb produced by CI:
sudo dpkg -i netprov_0.1.0-1_arm64.deb           # or amd64, depending on arch
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
