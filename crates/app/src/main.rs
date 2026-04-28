use dioxus::prelude::*;
use netprov_protocol::{Interface, PSK_LEN, WifiStatus};
use netprov_sdk::{BleClient, Netprov, parse_peer_address};

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
struct DeviceSnapshot {
    interfaces: Vec<Interface>,
    wifi_status: WifiStatus,
}

#[component]
fn App() -> Element {
    let mut peer = use_signal(String::new);
    let mut key_path = use_signal(|| "/etc/netprov/key".to_string());
    let mut state = use_signal(|| ConnectionState::Idle);
    let mut snapshot = use_signal(|| None::<DeviceSnapshot>);

    let current_peer = peer();
    let current_key_path = key_path();
    let snapshot_view = snapshot();
    let state_view = state();
    let is_busy = matches!(state_view, ConnectionState::Busy);

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
                button {
                    disabled: is_busy,
                    onclick: connect,
                    "Connect"
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

async fn load_snapshot(peer: String, key_path: String) -> Result<DeviceSnapshot, String> {
    if peer.trim().is_empty() {
        return Err("Peer address is required".into());
    }

    let key = std::fs::read(&key_path).map_err(|err| format!("read {key_path}: {err}"))?;
    if key.len() != PSK_LEN {
        return Err(format!("key length is {}, expected {PSK_LEN}", key.len()));
    }
    let mut psk = [0u8; PSK_LEN];
    psk.copy_from_slice(&key);

    let addr = parse_peer_address(peer.trim()).map_err(|err| err.to_string())?;
    let client = BleClient::connect(addr, psk)
        .await
        .map_err(|err| err.to_string())?;
    let mut netprov = Netprov::new(client);
    netprov
        .authenticate()
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
