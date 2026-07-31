use dioxus::prelude::*;
use netprov_protocol::{
    Interface, IpConfig, PSK_LEN, Security, StaticIpv4, WifiCredential, WifiStatus,
};
use netprov_sdk::{BleClient, BleDevice, Netprov, PEER_ID_HINT, parse_peer_id};
use std::time::Duration;

const MAIN_CSS: Asset = asset!("/assets/main.css");

fn main() {
    dioxus::launch(App);
}

#[derive(Clone, PartialEq)]
enum ConnectionState {
    Idle,
    Busy,
    Ready,
    Failed(String),
}

#[derive(Clone, PartialEq)]
enum ScanState {
    Idle,
    Scanning,
    Complete,
    Failed(String),
}

/// One row in the device picker.
///
/// `id` is the opaque backend handle to connect with; `detail` is the
/// human-facing second line — the MAC where the platform discloses one, and
/// the handle itself on macOS, where it never does.
#[derive(Clone, PartialEq)]
struct DeviceSummary {
    id: String,
    label: String,
    detail: String,
    rssi: Option<i16>,
}

#[derive(Clone, PartialEq)]
struct DeviceSnapshot {
    interfaces: Vec<InterfaceSnapshot>,
    wifi_status: WifiStatus,
}

#[derive(Clone, PartialEq)]
struct InterfaceSnapshot {
    interface: Interface,
    config: IpConfig,
}

#[component]
fn App() -> Element {
    let mut peer = use_signal(String::new);
    let mut key_path = use_signal(|| "/etc/netprov/key".to_string());
    let mut state = use_signal(|| ConnectionState::Idle);
    let mut scan_state = use_signal(|| ScanState::Idle);
    let mut devices = use_signal(Vec::<DeviceSummary>::new);
    let mut snapshot = use_signal(|| None::<DeviceSnapshot>);

    let current_peer = peer();
    let current_key_path = key_path();
    let devices_view = devices();
    let scan_state_view = scan_state();
    let snapshot_view = snapshot();
    let state_view = state();
    let is_busy = matches!(state_view, ConnectionState::Busy);
    let is_scanning = matches!(scan_state_view, ScanState::Scanning);
    let can_connect = !is_busy && !current_peer.trim().is_empty();

    let scan = move |_| {
        scan_state.set(ScanState::Scanning);
        devices.set(Vec::new());
        spawn(async move {
            match scan_ble_devices().await {
                Ok(found) => {
                    devices.set(found);
                    scan_state.set(ScanState::Complete);
                }
                Err(err) => scan_state.set(ScanState::Failed(err)),
            }
        });
    };

    let connect = move |_| {
        let peer_value = peer();
        let key_path_value = key_path();
        state.set(ConnectionState::Busy);
        snapshot.set(None);
        spawn(async move {
            match load_snapshot(peer_value, key_path_value).await {
                Ok(next) => {
                    snapshot.set(Some(next));
                    state.set(ConnectionState::Ready);
                }
                Err(err) => state.set(ConnectionState::Failed(err)),
            }
        });
    };

    rsx! {
        document::Stylesheet { href: MAIN_CSS }
        main { class: "app-shell",
            section { class: "topbar",
                div {
                    h1 { "netprov" }
                    p { "BLE network provisioning" }
                }
                StatusPill { state: state_view.clone() }
            }

            section { class: "connection-panel",
                label {
                    span { "Peer" }
                    input {
                        value: "{current_peer}",
                        placeholder: "{PEER_ID_HINT}",
                        oninput: move |event| peer.set(event.value()),
                    }
                }
                label {
                    span { "PSK path" }
                    input {
                        value: "{current_key_path}",
                        oninput: move |event| key_path.set(event.value()),
                    }
                }
                div { class: "connection-actions",
                    button {
                        disabled: is_busy || is_scanning,
                        onclick: scan,
                        "Scan"
                    }
                    button {
                        disabled: !can_connect,
                        onclick: connect,
                        "Connect"
                    }
                }
            }

            section { class: "device-panel",
                div { class: "panel-heading",
                    h2 { "Devices" }
                    ScanStatus { state: scan_state_view.clone(), count: devices_view.len() }
                }
                DeviceList {
                    devices: devices_view,
                    selected_peer: current_peer.clone(),
                    disabled: is_busy,
                    onselect: move |id: String| peer.set(id),
                }
            }

            match state_view {
                ConnectionState::Failed(ref message) => rsx! {
                    div { class: "error-row", "{message}" }
                },
                _ => rsx! {},
            }

            if let Some(snapshot) = snapshot_view {
                Dashboard { snapshot }
            } else {
                EmptyState {}
            }
        }
    }
}

#[component]
fn StatusPill(state: ConnectionState) -> Element {
    let (class, label) = match state {
        ConnectionState::Idle => ("status idle", "Disconnected"),
        ConnectionState::Busy => ("status busy", "Connecting"),
        ConnectionState::Ready => ("status ready", "Ready"),
        ConnectionState::Failed(_) => ("status failed", "Error"),
    };

    rsx! {
        div { class, "{label}" }
    }
}

#[component]
fn EmptyState() -> Element {
    rsx! {
        section { class: "empty-state",
            h2 { "No device connected" }
            p { "Select a BLE peer and connect to load network state." }
        }
    }
}

#[component]
fn ScanStatus(state: ScanState, count: usize) -> Element {
    match state {
        ScanState::Idle => rsx! {
            span { class: "scan-status", "Not scanned" }
        },
        ScanState::Scanning => rsx! {
            span { class: "scan-status", "Scanning..." }
        },
        ScanState::Complete => rsx! {
            span { class: "scan-status", "{count} found" }
        },
        ScanState::Failed(ref message) => rsx! {
            span { class: "scan-status failed", "{message}" }
        },
    }
}

#[component]
fn DeviceList(
    devices: Vec<DeviceSummary>,
    selected_peer: String,
    disabled: bool,
    onselect: EventHandler<String>,
) -> Element {
    if devices.is_empty() {
        return rsx! {
            p { class: "muted", "Scan to discover nearby netprov BLE devices." }
        };
    }

    rsx! {
        div { class: "device-list",
            for device in devices {
                {
                    let selected = device.id == selected_peer;
                    let row_class = if selected {
                        "device-row selected"
                    } else {
                        "device-row"
                    };
                    let signal = device
                        .rssi
                        .map(|rssi| format!("{rssi} dBm"))
                        .unwrap_or_else(|| "RSSI -".to_string());
                    let id = device.id.clone();
                    rsx! {
                        button {
                            class: row_class,
                            disabled,
                            onclick: move |_| onselect.call(id.clone()),
                            div {
                                strong { "{device.label}" }
                                span { "{device.detail}" }
                            }
                            span { class: "device-signal", "{signal}" }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn Dashboard(snapshot: DeviceSnapshot) -> Element {
    rsx! {
        section { class: "dashboard",
            div { class: "panel",
                h2 { "Interfaces" }
                div { class: "interface-list",
                    for snapshot in snapshot.interfaces {
                        {
                            let iface = snapshot.interface;
                            let mac = iface.mac.clone().unwrap_or_else(|| "-".to_string());
                            rsx! {
                        div { class: "interface-row",
                            div {
                                strong { "{iface.name}" }
                                        span { "{mac}" }
                            }
                            div { class: "interface-meta",
                                span { "{iface.iface_type:?}" }
                                span { "{iface.state:?}" }
                            }
                        }
                            }
                        }
                    }
                }
            }

            div { class: "panel",
                h2 { "Wi-Fi" }
                div { class: "metric-grid",
                    Metric {
                        label: "SSID".to_string(),
                        value: snapshot.wifi_status.ssid.unwrap_or_else(|| "-".to_string()),
                    }
                    Metric {
                        label: "Signal".to_string(),
                        value: snapshot.wifi_status.signal
                            .map(|signal| format!("{signal}%"))
                            .unwrap_or_else(|| "-".to_string()),
                    }
                    Metric {
                        label: "Security".to_string(),
                        value: snapshot.wifi_status.security
                            .map(|security| format!("{security:?}"))
                            .unwrap_or_else(|| "-".to_string()),
                    }
                }
            }
        }
    }
}

#[component]
fn Metric(label: String, value: String) -> Element {
    rsx! {
        div { class: "metric",
            span { "{label}" }
            strong { "{value}" }
        }
    }
}

async fn scan_ble_devices() -> Result<Vec<DeviceSummary>, String> {
    let devices = BleClient::scan_devices(Duration::from_secs(8))
        .await
        .map_err(|err| err.to_string())?;
    Ok(devices.into_iter().map(DeviceSummary::from).collect())
}

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

fn wifi_credential(security: Option<&Security>, password: &str) -> Result<WifiCredential, String> {
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

async fn load_snapshot(peer: String, key_path: String) -> Result<DeviceSnapshot, String> {
    if peer.trim().is_empty() {
        return Err("Peer identifier is required".into());
    }

    let key = tokio::fs::read(&key_path)
        .await
        .map_err(|err| format!("read {key_path}: {err}"))?;
    if key.len() != PSK_LEN {
        return Err(format!("key length is {}, expected {PSK_LEN}", key.len()));
    }
    let mut psk = [0u8; PSK_LEN];
    psk.copy_from_slice(&key);

    let peer_id = parse_peer_id(peer.trim()).map_err(|err| err.to_string())?;
    let client = BleClient::connect(&peer_id)
        .await
        .map_err(|err| err.to_string())?;
    let mut netprov = Netprov::new(client);
    netprov
        .authenticate(psk)
        .await
        .map_err(|err| err.to_string())?;
    let interfaces = netprov
        .list_interfaces()
        .await
        .map_err(|err| err.to_string())?;
    let mut interface_snapshots = Vec::with_capacity(interfaces.len());
    for interface in interfaces {
        let config = netprov
            .get_ip_config(interface.name.clone())
            .await
            .map_err(|err| err.to_string())?;
        interface_snapshots.push(InterfaceSnapshot { interface, config });
    }
    let wifi_status = netprov.wifi_status().await.map_err(|err| err.to_string())?;

    Ok(DeviceSnapshot {
        interfaces: interface_snapshots,
        wifi_status,
    })
}

impl From<BleDevice> for DeviceSummary {
    fn from(value: BleDevice) -> Self {
        Self {
            id: value.id.to_string(),
            label: value.label().to_string(),
            detail: value.detail().to_string(),
            rssi: value.rssi,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_static_ipv4_form() {
        let config =
            parse_static_ipv4("192.168.1.20/24", "192.168.1.1", "1.1.1.1, 8.8.8.8").unwrap();

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
}
