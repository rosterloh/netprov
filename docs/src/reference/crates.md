# Workspace Crates

| Crate | Role |
|---|---|
| `netprov-protocol` | Transport-independent CBOR messages, framing, and HMAC authentication helpers. |
| `netprov-server` | The `netprovd` daemon, BLE GATT driver, session state machine, and mock or NetworkManager facade. |
| `netprov-sdk` | The transport-independent provisioning client and BLE/TCP implementations shared by the CLI and desktop app. |
| `netprov-client` | The `netprov` CLI, with BLE production transport and a feature-gated TCP development transport. |
| `netprov-app` | The feature-gated Dioxus desktop UI. |
