use dioxus::prelude::*;
use netprov_protocol::{
    Interface, IpConfig, PSK_LEN, Security, StaticIpv4, WifiCredential, WifiStatus,
};
use netprov_sdk::{BleClient, BleDevice, Netprov, PEER_ID_HINT, parse_peer_id};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

const MAIN_CSS: Asset = asset!("/assets/main.css");

fn main() {
    dioxus::launch(App);
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

type SharedClient = Arc<Mutex<Netprov<BleClient>>>;

#[component]
fn App() -> Element {
    let mut peer = use_signal(String::new);
    let mut key_path = use_signal(|| "/etc/netprov/key".to_string());
    let mut scan_state = use_signal(|| ScanState::Idle);
    let mut devices = use_signal(Vec::<DeviceSummary>::new);
    let mut client = use_signal(|| None::<SharedClient>);
    let mut snapshot = use_signal(|| None::<DeviceSnapshot>);
    let mut selected_device = use_signal(|| None::<DeviceSummary>);
    let mut connection_error = use_signal(|| None::<String>);
    let mut is_connecting = use_signal(|| false);

    let current_peer = peer();
    let current_key_path = key_path();
    let devices_view = devices();
    let scan_state_view = scan_state();
    let client_view = client();
    let snapshot_view = snapshot();
    let selected_peer = selected_device().map(|device| device.id);
    let connection_error_view = connection_error();
    let is_busy = is_connecting();
    let is_scanning = matches!(scan_state_view, ScanState::Scanning);
    let can_connect = !is_busy && !current_peer.trim().is_empty();

    let scan = move |_| {
        scan_state.set(ScanState::Scanning);
        devices.set(Vec::new());
        selected_device.set(None);
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
        is_connecting.set(true);
        connection_error.set(None);
        spawn(async move {
            match connect_device(peer_value, key_path_value).await {
                Ok((next_client, next_snapshot)) => {
                    snapshot.set(Some(next_snapshot));
                    client.set(Some(next_client));
                }
                Err(err) => connection_error.set(Some(err)),
            }
            is_connecting.set(false);
        });
    };

    let disconnect = move |_| {
        if let Some(former_client) = client() {
            client.set(None);
            snapshot.set(None);
            connection_error.set(None);
            spawn(disconnect_device(former_client));
        }
    };

    rsx! {
        document::Stylesheet { href: MAIN_CSS }
        main { class: "app-shell",
            section { class: "topbar",
                div {
                    h1 { "netprov" }
                    p { "BLE network provisioning" }
                }
                if client_view.is_some() {
                    button { onclick: disconnect, "Disconnect" }
                }
            }

            if client_view.is_none() {
                section { class: "connection-panel",
                    label {
                        span { "Peer" }
                        input {
                            value: "{current_peer}",
                            placeholder: "{PEER_ID_HINT}",
                            oninput: move |event| {
                                peer.set(event.value());
                                selected_device.set(None);
                            },
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
                        selected_peer,
                        disabled: is_busy,
                        onselect: move |device: DeviceSummary| {
                            peer.set(device.id.clone());
                            selected_device.set(Some(device));
                        },
                    }
                }

                if let Some(message) = connection_error_view {
                    div { class: "error-row", "{message}" }
                }
            } else if let Some(snapshot) = snapshot_view {
                Dashboard { snapshot }
            }

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
    selected_peer: Option<String>,
    disabled: bool,
    onselect: EventHandler<DeviceSummary>,
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
                    let selected = selected_peer.as_deref() == Some(&device.id);
                    let row_class = if selected {
                        "device-row selected"
                    } else {
                        "device-row"
                    };
                    let signal = device
                        .rssi
                        .map(|rssi| format!("{rssi} dBm"))
                        .unwrap_or_else(|| "RSSI -".to_string());
                    let selected_device = device.clone();
                    rsx! {
                        button {
                            class: row_class,
                            disabled,
                            onclick: move |_| onselect.call(selected_device.clone()),
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

#[allow(dead_code)] // Used by the provisioning form added in the next app slice.
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

#[allow(dead_code)] // Used by the provisioning form added in the next app slice.
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
    if let Err(err) = client.authenticate(psk).await {
        let error = err.to_string();
        let _ = client.inner().disconnect().await;
        return Err(error);
    }
    let snapshot = match load_snapshot(&mut client).await {
        Ok(snapshot) => snapshot,
        Err(err) => {
            let error = err.to_string();
            let _ = client.inner().disconnect().await;
            return Err(error);
        }
    };
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

    #[tokio::test]
    async fn rejects_empty_peer_before_connecting() {
        let result = connect_device("  ".into(), "/key/is/not/read".into()).await;

        assert!(matches!(result, Err(ref error) if error == "Peer identifier is required"));
    }

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
