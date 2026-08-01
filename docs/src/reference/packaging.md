# Packaging

The `packaging/` directory contains files consumed during build and
installation.

## Development key

`packaging/dev-key.bin` is a 32-byte pre-shared key embedded in development
builds as a fallback. It is committed to the repository and is therefore
public. Use it only for local development and CI loopback tests.

The server logs a recurring warning when this key is active. In production,
install a per-device key with `netprovd keygen --install`. The shipped service
sets `NETPROV_PRODUCTION=1`, which disables the fallback.

## systemd service

`packaging/netprovd.service` runs `netprovd serve-ble` and refuses to start
without a real key at `/etc/netprov/key`.

The Debian package installs this page under `/usr/share/doc/netprov/`.
