# Installation

CI produces Debian packages for `amd64` and `aarch64`. On the target device:

```bash
sudo dpkg -i netprov_<version>_arm64.deb
sudo netprovd keygen --install
sudo systemctl enable --now netprovd
```

The package does not start the daemon automatically. Install a production PSK
first, then enable the service.

The shipped `netprovd.service` sets `NETPROV_PRODUCTION=1`, so the daemon
refuses to start without a real key at `/etc/netprov/key`. It never silently
falls back to the public development key in production.

For a hardware checkout after installation, follow the
[two-box BLE smoke test](../guides/ble-smoke-test.md).
