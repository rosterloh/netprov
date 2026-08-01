# Development

## Loopback quick start

The complete request/response surface can run over TCP against an in-memory
network facade, without BLE or NetworkManager.

In one terminal:

```bash
cp packaging/dev-key.bin /tmp/netprov-key.bin
chmod 600 /tmp/netprov-key.bin
cargo run -p netprov-server --bin netprovd -- serve-tcp --listen 127.0.0.1:9600
```

In another terminal:

```bash
cargo run -p netprov-client --features dev-tcp --bin netprov -- \
  --key-path /tmp/netprov-key.bin --endpoint 127.0.0.1:9600 list
```

The mock supports `list`, `ip <iface>`, `wifi-status`, `wifi-scan`,
`wifi-connect`, `set-dhcp`, and `set-static`.

The committed key under `packaging/` is public and is only for local
development and CI loopback tests. When it is active, the server logs a warning
every 60 seconds.

See [Build and Test](../reference/build-and-test.md) for the workspace commands.
