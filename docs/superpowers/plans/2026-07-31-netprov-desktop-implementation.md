# Netprov Desktop App Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the current read-only Dioxus desktop screen with the approved Open Design interface backed by real BLE discovery, Wi-Fi, and IPv4 operations.

**Architecture:** Keep one authenticated `Netprov<BleClient>` in an `Arc<tokio::sync::Mutex<_>>` for the connected workspace. Dioxus signals own view state and live snapshots; small async functions serialize SDK calls through the retained client, while pure functions validate form input before mutation.

**Tech Stack:** Rust 2024, Dioxus 0.7 desktop, Tokio, `netprov-sdk`, `netprov-protocol`, HTML/CSS via Dioxus assets.

## Global Constraints

- Preserve opaque BLE peer identifiers; never assume a MAC address.
- Use the existing SDK and protocol crates; add no dependencies.
- Use real BLE and network operations; add no fixture devices or networks.
- Keep production changes in `crates/app/src/main.rs` and `crates/app/assets/main.css`.
- Match the supplied `brand-spec.md` and `netprov-desktop-app.html` layout, states, responsive behavior, and accessibility semantics.
- Allow only one connected SDK request at a time through the shared Tokio mutex.
- Validate credentials and static IPv4 input before sending mutating requests.

---

### Task 1: Form conversion and live workspace model

**Files:**
- Modify: `crates/app/src/main.rs`
- Test: `crates/app/src/main.rs` (`#[cfg(test)]` module)

**Interfaces:**
- Consumes: `netprov_protocol::{IpConfig, Security, StaticIpv4, WifiCredential}`.
- Produces: `parse_static_ipv4(&str, &str, &str) -> Result<StaticIpv4, String>` and `wifi_credential(Option<&Security>, &str) -> Result<WifiCredential, String>`.
- Produces: `InterfaceSnapshot { interface: Interface, config: IpConfig }` and `DeviceSnapshot { interfaces: Vec<InterfaceSnapshot>, wifi_status: WifiStatus }`.

- [ ] **Step 1: Add failing static IPv4 conversion tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_static_ipv4_form() {
        let config = parse_static_ipv4(
            "192.168.1.20/24",
            "192.168.1.1",
            "1.1.1.1, 8.8.8.8",
        )
        .unwrap();

        assert_eq!(config.address.to_string(), "192.168.1.20/24");
        assert_eq!(config.gateway.unwrap().to_string(), "192.168.1.1");
        assert_eq!(
            config
                .dns
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["1.1.1.1", "8.8.8.8"]
        );
    }

    #[test]
    fn rejects_invalid_static_ipv4_form() {
        assert!(parse_static_ipv4("192.168.1.20/99", "", "1.1.1.1").is_err());
        assert!(parse_static_ipv4("192.168.1.20/24", "999.1.1.1", "1.1.1.1").is_err());
        assert!(parse_static_ipv4("192.168.1.20/24", "", "").is_err());
    }
}
```

- [ ] **Step 2: Run the focused test and confirm RED**

Run: `cargo test -p netprov-app --features desktop tests::parses_static_ipv4_form`

Expected: compilation fails because `parse_static_ipv4` does not exist.

- [ ] **Step 3: Implement minimal static IPv4 conversion**

```rust
fn parse_static_ipv4(address: &str, gateway: &str, dns: &str) -> Result<StaticIpv4, String> {
    let address = address
        .trim()
        .parse()
        .map_err(|_| "Enter a valid IPv4 address and CIDR prefix.".to_string())?;
    let gateway = match gateway.trim() {
        "" => None,
        value => Some(
            value
                .parse()
                .map_err(|_| "Enter a valid IPv4 gateway.".to_string())?,
        ),
    };
    let dns = dns
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .parse()
                .map_err(|_| "Enter valid comma-separated DNS addresses.".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if dns.is_empty() {
        return Err("Enter at least one DNS address.".into());
    }
    Ok(StaticIpv4 {
        address,
        gateway,
        dns,
    })
}
```

- [ ] **Step 4: Run both static IPv4 tests and confirm GREEN**

Run: `cargo test -p netprov-app --features desktop static_ipv4_form`

Expected: both tests pass.

- [ ] **Step 5: Add failing Wi-Fi credential tests**

```rust
#[test]
fn maps_wifi_security_to_credentials() {
    assert_eq!(
        wifi_credential(Some(&Security::Open), "").unwrap(),
        WifiCredential::Open
    );
    assert_eq!(
        wifi_credential(Some(&Security::Wpa2Psk), "password").unwrap(),
        WifiCredential::Wpa2Psk("password".into())
    );
}

#[test]
fn rejects_unsupported_or_short_wifi_credentials() {
    assert!(wifi_credential(Some(&Security::Wep), "password").is_err());
    assert!(wifi_credential(Some(&Security::Wpa3), "short").is_err());
    assert!(wifi_credential(None, "password").is_err());
}
```

- [ ] **Step 6: Run the credential test and confirm RED**

Run: `cargo test -p netprov-app --features desktop tests::maps_wifi_security_to_credentials`

Expected: compilation fails because `wifi_credential` does not exist.

- [ ] **Step 7: Implement credential conversion and snapshot types**

```rust
fn wifi_credential(
    security: Option<&Security>,
    password: &str,
) -> Result<WifiCredential, String> {
    if matches!(security, Some(Security::Open)) {
        return Ok(WifiCredential::Open);
    }
    if password.len() < 8 {
        return Err("Enter a password with at least 8 characters.".into());
    }
    match security {
        Some(Security::WpaPsk) => Ok(WifiCredential::WpaPsk(password.into())),
        Some(Security::Wpa2Psk) => Ok(WifiCredential::Wpa2Psk(password.into())),
        Some(Security::Wpa3) => Ok(WifiCredential::Wpa3(password.into())),
        Some(Security::Wep) => Err("WEP networks are not supported.".into()),
        Some(Security::Open) => unreachable!(),
        None => Err("This network did not report a supported security mode.".into()),
    }
}

#[derive(Clone, PartialEq)]
struct InterfaceSnapshot {
    interface: Interface,
    config: IpConfig,
}

#[derive(Clone, PartialEq)]
struct DeviceSnapshot {
    interfaces: Vec<InterfaceSnapshot>,
    wifi_status: WifiStatus,
}
```

- [ ] **Step 8: Run app tests and commit**

Run: `cargo test -p netprov-app --features desktop`

Expected: all app tests pass.

```bash
git add crates/app/src/main.rs
git commit -m "feat(app): validate provisioning forms"
```

---

### Task 2: Persistent authenticated BLE session

**Files:**
- Modify: `crates/app/src/main.rs`

**Interfaces:**
- Consumes: Task 1's `InterfaceSnapshot` and `DeviceSnapshot`.
- Produces: `type SharedClient = Arc<Mutex<Netprov<BleClient>>>`.
- Produces: `connect_device(String, String) -> Result<(SharedClient, DeviceSnapshot), String>`, `load_snapshot(&mut Netprov<BleClient>) -> Result<DeviceSnapshot, String>`, and `disconnect_device(SharedClient)`.

- [ ] **Step 1: Replace the one-shot snapshot loader with a retained client**

Add `std::sync::Arc` and `tokio::sync::Mutex`, then implement:

```rust
type SharedClient = Arc<Mutex<Netprov<BleClient>>>;

async fn connect_device(
    peer: String,
    key_path: String,
) -> Result<(SharedClient, DeviceSnapshot), String> {
    if peer.trim().is_empty() {
        return Err("Peer identifier is required".into());
    }
    let key = tokio::fs::read(&key_path)
        .await
        .map_err(|err| format!("read {key_path}: {err}"))?;
    if key.len() != PSK_LEN {
        return Err(format!("key length is {}, expected {PSK_LEN}", key.len()));
    }
    let mut psk = [0; PSK_LEN];
    psk.copy_from_slice(&key);
    let peer_id = parse_peer_id(peer.trim()).map_err(|err| err.to_string())?;
    let client = BleClient::connect(&peer_id)
        .await
        .map_err(|err| err.to_string())?;
    let mut client = Netprov::new(client);
    client.authenticate(psk).await.map_err(|err| err.to_string())?;
    let snapshot = load_snapshot(&mut client).await?;
    Ok((Arc::new(Mutex::new(client)), snapshot))
}

async fn load_snapshot(client: &mut Netprov<BleClient>) -> Result<DeviceSnapshot, String> {
    let interfaces = client
        .list_interfaces()
        .await
        .map_err(|err| err.to_string())?;
    let mut interface_snapshots = Vec::with_capacity(interfaces.len());
    for interface in interfaces {
        let config = client
            .get_ip_config(interface.name.clone())
            .await
            .map_err(|err| err.to_string())?;
        interface_snapshots.push(InterfaceSnapshot { interface, config });
    }
    let wifi_status = client.wifi_status().await.map_err(|err| err.to_string())?;
    Ok(DeviceSnapshot {
        interfaces: interface_snapshots,
        wifi_status,
    })
}

async fn disconnect_device(client: SharedClient) {
    let client = client.lock().await;
    let _ = client.inner().disconnect().await;
}
```

- [ ] **Step 2: Reshape top-level state around discovery and connected views**

In `App`, replace the old connection status and optional one-shot snapshot with signals for `Option<SharedClient>`, `Option<DeviceSnapshot>`, the selected `DeviceSummary`, and connection errors. Render the discovery screen only when no client is retained and render the workspace only when both client and snapshot exist.

On connect, call `connect_device`; store both returned values on success. On disconnect, clear the client and snapshot immediately, then spawn `disconnect_device` with the former client. Keep the existing real `scan_ble_devices` implementation and make device selection populate the peer field.

- [ ] **Step 3: Compile and lint the connected-session slice**

Run: `cargo fmt --all`

Run: `cargo clippy -p netprov-app --features desktop --all-targets -- -D warnings`

Expected: both commands succeed with no warnings.

- [ ] **Step 4: Commit**

```bash
git add crates/app/src/main.rs
git commit -m "feat(app): retain authenticated BLE session"
```

---

### Task 3: Real Wi-Fi and IPv4 operations

**Files:**
- Modify: `crates/app/src/main.rs`
- Test: `crates/app/src/main.rs` (Task 1 tests remain the mutation boundary checks)

**Interfaces:**
- Consumes: `SharedClient`, `DeviceSnapshot`, `parse_static_ipv4`, and `wifi_credential`.
- Produces: `scan_wifi`, `connect_selected_wifi`, `apply_ip_config`, and refresh helpers used by the workspace event handlers.

- [ ] **Step 1: Add serialized Wi-Fi SDK helpers**

```rust
async fn scan_wifi(client: SharedClient) -> Result<Vec<WifiNetwork>, String> {
    client
        .lock()
        .await
        .wifi_scan()
        .await
        .map_err(|err| err.to_string())
}

async fn connect_selected_wifi(
    client: SharedClient,
    network: WifiNetwork,
    password: String,
) -> Result<WifiStatus, String> {
    let credential = wifi_credential(network.security.as_ref(), &password)?;
    let mut client = client.lock().await;
    client
        .connect_wifi(network.ssid, credential)
        .await
        .map_err(|err| err.to_string())?;
    client.wifi_status().await.map_err(|err| err.to_string())
}
```

- [ ] **Step 2: Wire the Wi-Fi tab**

Add Dioxus signals for network results, selected BSSID, password, busy state, error, and success toast. The Scan button calls `scan_wifi`, sorts results by descending `signal.unwrap_or(0)`, and renders actual SSID, security, signal, and current-SSID state. Submit calls `connect_selected_wifi`; on success replace `snapshot.wifi_status`, clear the password, and show `Connected to {ssid}`.

Use the network BSSID—not SSID—as the row selection key so duplicate SSIDs remain selectable.

- [ ] **Step 3: Add serialized IPv4 SDK helpers**

```rust
async fn apply_ip_config(
    client: SharedClient,
    iface: String,
    config: Option<StaticIpv4>,
) -> Result<IpConfig, String> {
    let mut client = client.lock().await;
    match config {
        Some(config) => client
            .set_static_ipv4(iface.clone(), config)
            .await
            .map_err(|err| err.to_string())?,
        None => client
            .set_dhcp(iface.clone())
            .await
            .map_err(|err| err.to_string())?,
    }
    client
        .get_ip_config(iface)
        .await
        .map_err(|err| err.to_string())
}
```

- [ ] **Step 4: Wire the interface editor and confirmation**

Add signals for selected interface name, DHCP/static mode, address, gateway, DNS, busy state, error, and confirmation visibility. Selecting a row copies its live `IpConfig` into the form. Applying DHCP passes `None`; applying static first calls `parse_static_ipv4` and passes `Some(config)`. Only after validation succeeds should the confirmation dialog appear. On success replace that interface's config in `DeviceSnapshot` and show `Network configuration updated`.

- [ ] **Step 5: Verify and commit real operations**

Run: `cargo test -p netprov-app --features desktop`

Run: `cargo clippy -p netprov-app --features desktop --all-targets -- -D warnings`

Expected: tests pass and Clippy reports no warnings.

```bash
git add crates/app/src/main.rs
git commit -m "feat(app): wire Wi-Fi and IPv4 operations"
```

---

### Task 4: Apply the approved desktop interface

**Files:**
- Modify: `crates/app/src/main.rs`
- Modify: `crates/app/assets/main.css`

**Interfaces:**
- Consumes: all state and handlers from Tasks 2 and 3.
- Produces: the final discovery, overview, Wi-Fi, and interfaces user experience.

- [ ] **Step 1: Replace markup with the supplied semantic structure**

Translate the body of the supplied `netprov-desktop-app.html` into RSX without its fixture arrays or JavaScript. Preserve these structural hooks and meanings:

```text
app-header
discovery-card → section-heading, scan-line, device-list, advanced-grid, connect-row
device-header → device-actions, secure status
tabs → overview-panel | wifi-panel | interfaces-panel
workspace-grid → overview panel + setup progress
network-layout → network list + credential form
interface-layout → interface list + IPv4 editor
confirmation overlay/dialog
toast role=status aria-live=polite
```

Use native `button`, `input`, `details`, `summary`, `form`, `fieldset`, and radio controls. Preserve `role="status"`, `role="alert"`, `role="tablist"`, `role="tab"`, `role="tabpanel"`, `aria-selected`, `aria-pressed`, `aria-invalid`, and descriptive labels. Implement tab click behavior in Rust; keyboard focus and arrow-key tab switching may use Dioxus keyboard events without JavaScript.

- [ ] **Step 2: Replace CSS with the supplied brand system**

Start from the exact `<style>` block in the supplied `netprov-desktop-app.html`, located at:

```text
/Users/richard.osterloh/Library/Application Support/Open Design/namespaces/release-stable/data/projects/aefc0531-8a36-48eb-9e37-7467d0930abe/netprov-desktop-app.html
```

Keep its `:root` OKLCH tokens, font stacks, compact panels, header, lists, tabs, forms, dialog/overlay, toast, focus-visible treatment, reduced-motion rule, and `760px` responsive breakpoint. Remove only selectors for HTML IDs or JavaScript-only hidden-state mechanics that the RSX does not emit. Add no CSS framework.

- [ ] **Step 3: Check formatting and all app behavior that does not require hardware**

Run: `cargo fmt --all`

Run: `cargo test -p netprov-app --features desktop`

Run: `cargo clippy -p netprov-app --features desktop --all-targets -- -D warnings`

Run: `cargo build -p netprov-app --features desktop`

Expected: every command succeeds; static/DNS and credential tests remain green.

- [ ] **Step 4: Run the workspace regression gate**

Run: `cargo clippy --workspace --all-targets -- -D warnings`

Run: `cargo test --workspace`

Expected: both commands succeed.

- [ ] **Step 5: Inspect the final diff and commit**

Run: `git diff --check`

Run: `git diff --stat fceb8a8`

Expected: no whitespace errors; production changes are limited to the two app files.

```bash
git add crates/app/src/main.rs crates/app/assets/main.css
git commit -m "feat(app): implement provisioning desktop design"
```

Hardware follow-up: run `cargo run -p netprov-app --features desktop` with a reachable device and valid PSK to verify pairing, Wi-Fi connection, DHCP, static IPv4, and disconnect behavior end to end.
