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

Run the BLE-first app with:

```bash
cargo run -p netprov-app --features desktop
```

The app communicates with target devices over BLE. TCP remains a development
and protocol-regression path.
