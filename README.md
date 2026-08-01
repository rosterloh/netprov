# netprov

BLE-provisioned network configuration for headless embedded Linux.

`netprovd` exposes NetworkManager configuration over an authenticated BLE GATT
service. The `netprov` CLI and desktop app connect from Linux, macOS, or Windows.

## Documentation

The [mdBook documentation](docs/src/introduction.md) covers installation,
development, architecture, and hardware testing. Build it locally with
`mdbook build docs` or run `mdbook serve docs`.

## License

MIT OR Apache-2.0.
