# Desktop App

The Dioxus desktop app is gated behind the `desktop` feature. macOS needs no
additional packages because WebKit and CoreBluetooth are provided by the OS.

On Ubuntu or Debian, install the native development libraries:

```bash
sudo apt-get install -y \
  pkg-config \
  libgtk-3-dev \
  libwebkit2gtk-4.1-dev \
  libayatana-appindicator3-dev \
  libxdo-dev
```

## Running

Run the app through the Dioxus CLI, from the `crates/app` directory:

```bash
cargo install dioxus-cli   # once, provides `dx`
cd crates/app
dx serve --features desktop --platform desktop
```

`dx` resolves the `asset!()` stylesheet and writes the macOS bundle to
`target/dx/netprov-app/debug/macos/NetprovApp.app`, which can be launched
directly once built.

> Running the binary straight out of `cargo build -p netprov-app --features
> desktop` starts an **unstyled** window: `asset!()` paths are resolved by `dx`,
> so a plain Cargo binary loads no stylesheet. Use `dx` (or the bundle it
> produces) for anything you intend to look at.

The app communicates with target devices over BLE. TCP remains a development
and protocol-regression path.

## Startup

The app scans for nearby devices as soon as it opens, so the device list is
populated without any action; "Scan again" repeats the scan.

## Connection settings

The peer identifier and PSK path live under "Advanced connection". Both are
remembered after a **successful** connection and restored on the next launch —
a failed connection is never persisted, so a typo does not become the new
default.

The PSK path may also be given on the command line, which takes precedence over
the stored value:

```bash
dx serve --features desktop --platform desktop -- --key-path ~/.netprov/key
# or, against an already-built bundle:
target/dx/netprov-app/debug/macos/NetprovApp.app/Contents/MacOS/netprov-app \
  --key-path ~/.netprov/key
```

`-k` is accepted as a short form, matching the `netprov` CLI. With neither a
flag nor a stored value the path defaults to `/etc/netprov/key`, where
`netprovd` installs the PSK.

Resolution order for the PSK path is therefore: `--key-path`, then the stored
value, then `/etc/netprov/key`.

### Where the settings live

| Platform | Path |
| -------- | ---- |
| macOS    | `~/Library/Application Support/com.rosterloh.NetprovApp/connection.conf` |
| Other    | `$XDG_CONFIG_HOME/netprov/connection.conf`, else `~/.config/netprov/connection.conf` |

The file is `key = value` lines holding `peer` and `key_path`. It records the
**path** to the PSK, never key bytes, so it is not a secret — the PSK itself
stays wherever that path points. Delete the file to forget the device.

Writes are best-effort: if the directory cannot be created or written, the app
still connects, it just will not remember the values.

## Bundle identifier

`crates/app/Dioxus.toml` sets the bundle identifier to
`com.rosterloh.NetprovApp`. macOS keys both per-app Bluetooth consent and the
Application Support directory by this value, so changing it re-prompts for
Bluetooth permission and orphans any previously stored `connection.conf`. The
constant in `crates/app/src/settings.rs` must be kept in step with it.
