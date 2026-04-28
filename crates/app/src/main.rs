use dioxus::prelude::*;
use netprov_protocol::{Interface, PSK_LEN, WifiStatus};
use netprov_sdk::{BleClient, BleDevice, Netprov, parse_peer_address};
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

#[derive(Clone, PartialEq)]
struct DeviceSummary {
    address: String,
    name: Option<String>,
    rssi: Option<i16>,
}

#[derive(Clone, PartialEq)]
struct DeviceSnapshot {
    interfaces: Vec<Interface>,
    wifi_status: WifiStatus,
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
                    span { "Peer address" }
                    input {
                        value: "{current_peer}",
                        placeholder: "AA:BB:CC:DD:EE:FF",
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
                    onselect: move |address: String| peer.set(address),
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
                    let selected = device.address == selected_peer;
                    let row_class = if selected {
                        "device-row selected"
                    } else {
                        "device-row"
                    };
                    let name = device
                        .name
                        .clone()
                        .unwrap_or_else(|| "netprovd".to_string());
                    let signal = device
                        .rssi
                        .map(|rssi| format!("{rssi} dBm"))
                        .unwrap_or_else(|| "RSSI -".to_string());
                    let address = device.address.clone();
                    rsx! {
                        button {
                            class: row_class,
                            disabled,
                            onclick: move |_| onselect.call(address.clone()),
                            div {
                                strong { "{name}" }
                                span { "{device.address}" }
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
                    for iface in snapshot.interfaces {
                        {
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

async fn load_snapshot(peer: String, key_path: String) -> Result<DeviceSnapshot, String> {
    if peer.trim().is_empty() {
        return Err("Peer address is required".into());
    }

    let key = tokio::fs::read(&key_path)
        .await
        .map_err(|err| format!("read {key_path}: {err}"))?;
    if key.len() != PSK_LEN {
        return Err(format!("key length is {}, expected {PSK_LEN}", key.len()));
    }
    let mut psk = [0u8; PSK_LEN];
    psk.copy_from_slice(&key);

    let addr = parse_peer_address(peer.trim()).map_err(|err| err.to_string())?;
    let client = BleClient::connect(addr)
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
    let wifi_status = netprov.wifi_status().await.map_err(|err| err.to_string())?;

    Ok(DeviceSnapshot {
        interfaces,
        wifi_status,
    })
}

impl From<BleDevice> for DeviceSummary {
    fn from(value: BleDevice) -> Self {
        Self {
            address: value.address.to_string(),
            name: value.name,
            rssi: value.rssi,
        }
    }
}
