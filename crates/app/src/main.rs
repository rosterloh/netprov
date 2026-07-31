use dioxus::prelude::*;
use netprov_protocol::{
    Interface, IpConfig, Ipv4Method, PSK_LEN, Security, StaticIpv4, WifiCredential, WifiNetwork,
    WifiStatus,
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
            } else if snapshot_view.is_some() {
                Dashboard { client, snapshot }
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
fn Dashboard(
    client: Signal<Option<SharedClient>>,
    mut snapshot: Signal<Option<DeviceSnapshot>>,
) -> Element {
    let mut wifi_networks = use_signal(Vec::<WifiNetwork>::new);
    let mut selected_bssid = use_signal(|| None::<String>);
    let mut wifi_password = use_signal(String::new);
    let mut wifi_busy = use_signal(|| false);
    let mut wifi_error = use_signal(|| None::<String>);
    let mut success_message = use_signal(|| None::<String>);
    let mut selected_interface = use_signal(|| None::<String>);
    let mut dhcp_mode = use_signal(|| true);
    let mut address = use_signal(String::new);
    let mut gateway = use_signal(String::new);
    let mut dns = use_signal(String::new);
    let mut ip_busy = use_signal(|| false);
    let mut ip_error = use_signal(|| None::<String>);
    let mut confirm_ip = use_signal(|| false);
    let mut pending_ip_change = use_signal(|| None::<(String, Option<StaticIpv4>)>);

    let snapshot_view = snapshot().expect("dashboard requires a connected device");
    let wifi_networks_view = wifi_networks();
    let selected_bssid_view = selected_bssid();
    let wifi_password_view = wifi_password();
    let wifi_error_view = wifi_error();
    let success_message_view = success_message();
    let selected_interface_view = selected_interface();
    let dhcp_mode_view = dhcp_mode();
    let address_view = address();
    let gateway_view = gateway();
    let dns_view = dns();
    let ip_error_view = ip_error();
    let wifi_is_busy = wifi_busy();
    let ip_is_busy = ip_busy();

    let scan = move |_| {
        let Some(client) = client() else {
            return;
        };
        wifi_busy.set(true);
        wifi_error.set(None);
        success_message.set(None);
        spawn(async move {
            match scan_wifi(client).await {
                Ok(mut networks) => {
                    sort_wifi_networks(&mut networks);
                    wifi_networks.set(networks);
                    selected_bssid.set(None);
                }
                Err(err) => wifi_error.set(Some(err)),
            }
            wifi_busy.set(false);
        });
    };

    let connect_wifi = move |_| {
        let Some(client) = client() else {
            return;
        };
        let Some(bssid) = selected_bssid() else {
            wifi_error.set(Some("Select a Wi-Fi network.".into()));
            return;
        };
        let Some(network) = wifi_networks()
            .into_iter()
            .find(|network| network.bssid == bssid)
        else {
            wifi_error.set(Some(
                "The selected Wi-Fi network is no longer available.".into(),
            ));
            return;
        };
        let ssid = network.ssid.clone();
        let password = wifi_password();
        wifi_busy.set(true);
        wifi_error.set(None);
        success_message.set(None);
        spawn(async move {
            match connect_selected_wifi(client, network, password).await {
                Ok(status) => {
                    snapshot.with_mut(|snapshot| {
                        if let Some(snapshot) = snapshot {
                            snapshot.wifi_status = status;
                        }
                    });
                    wifi_password.set(String::new());
                    success_message.set(Some(format!("Connected to {ssid}")));
                }
                Err(err) => wifi_error.set(Some(err)),
            }
            wifi_busy.set(false);
        });
    };

    let request_ip_change = move |_| match prepare_ip_change(
        selected_interface(),
        dhcp_mode(),
        &address(),
        &gateway(),
        &dns(),
    ) {
        Ok(change) => {
            pending_ip_change.set(Some(change));
            ip_error.set(None);
            confirm_ip.set(true);
        }
        Err(err) => {
            confirm_ip.set(false);
            ip_error.set(Some(err));
        }
    };

    let apply_ip = move |_| {
        let Some(client) = client() else {
            return;
        };
        let Some((iface, config)) = pending_ip_change() else {
            return;
        };
        confirm_ip.set(false);
        ip_busy.set(true);
        ip_error.set(None);
        success_message.set(None);
        spawn(async move {
            match apply_ip_config(client, iface.clone(), config).await {
                Ok(config) => {
                    snapshot.with_mut(|snapshot| {
                        if let Some(snapshot) = snapshot {
                            replace_interface_config(snapshot, &iface, config);
                        }
                    });
                    pending_ip_change.set(None);
                    success_message.set(Some("Network configuration updated".into()));
                }
                Err(err) => ip_error.set(Some(err)),
            }
            ip_busy.set(false);
        });
    };

    rsx! {
        section { class: "dashboard",
            if let Some(message) = success_message_view {
                div { class: "status ready", "{message}" }
            }
            div { class: "panel",
                h2 { "Interfaces" }
                div { class: "interface-list",
                    for interface_snapshot in snapshot_view.interfaces {
                        {
                            let selected = selected_interface_view.as_deref()
                                == Some(interface_snapshot.interface.name.as_str());
                            let row_class = if selected {
                                "device-row selected"
                            } else {
                                "device-row"
                            };
                            let iface = interface_snapshot.interface.clone();
                            let mac = iface.mac.clone().unwrap_or_else(|| "-".to_string());
                            let address_text = interface_snapshot
                                .config
                                .addresses
                                .first()
                                .map(ToString::to_string)
                                .unwrap_or_else(|| "-".to_string());
                            let selected_snapshot = interface_snapshot.clone();
                            rsx! {
                                button {
                                    key: "{iface.name}",
                                    class: row_class,
                                    disabled: ip_is_busy,
                                    onclick: move |_| {
                                        let config = &selected_snapshot.config;
                                        selected_interface.set(Some(
                                            selected_snapshot.interface.name.clone()
                                        ));
                                        dhcp_mode.set(matches!(config.method, Ipv4Method::Auto));
                                        address.set(config.addresses.first()
                                            .map(ToString::to_string)
                                            .unwrap_or_default());
                                        gateway.set(config.gateway
                                            .map(|value| value.to_string())
                                            .unwrap_or_default());
                                        dns.set(config.dns.iter()
                                            .map(ToString::to_string)
                                            .collect::<Vec<_>>()
                                            .join(", "));
                                        ip_error.set(None);
                                    },
                                    div {
                                        strong { "{iface.name}" }
                                        span { "{mac}" }
                                    }
                                    div { class: "interface-meta",
                                        span { "{iface.iface_type:?}" }
                                        span { "{iface.state:?}" }
                                        span { "{interface_snapshot.config.method:?}" }
                                        span { "{address_text}" }
                                    }
                                }
                            }
                        }
                    }
                }

                if let Some(iface) = selected_interface_view {
                    div { class: "metric-grid",
                        strong { "Configure {iface}" }
                        label {
                            input {
                                r#type: "radio",
                                name: "ipv4-mode",
                                checked: dhcp_mode_view,
                                disabled: ip_is_busy,
                                onchange: move |_| dhcp_mode.set(true),
                            }
                            "DHCP"
                        }
                        label {
                            input {
                                r#type: "radio",
                                name: "ipv4-mode",
                                checked: !dhcp_mode_view,
                                disabled: ip_is_busy,
                                onchange: move |_| dhcp_mode.set(false),
                            }
                            "Static"
                        }
                        if !dhcp_mode_view {
                            label {
                                span { "Address / prefix" }
                                input {
                                    value: "{address_view}",
                                    disabled: ip_is_busy,
                                    oninput: move |event| address.set(event.value()),
                                }
                            }
                            label {
                                span { "Gateway" }
                                input {
                                    value: "{gateway_view}",
                                    disabled: ip_is_busy,
                                    oninput: move |event| gateway.set(event.value()),
                                }
                            }
                            label {
                                span { "DNS" }
                                input {
                                    value: "{dns_view}",
                                    disabled: ip_is_busy,
                                    oninput: move |event| dns.set(event.value()),
                                }
                            }
                        }
                        button {
                            disabled: ip_is_busy,
                            onclick: request_ip_change,
                            if ip_is_busy { "Applying..." } else { "Apply" }
                        }
                        if let Some(message) = ip_error_view {
                            div { class: "error-row", "{message}" }
                        }
                    }
                }
            }

            div { class: "panel",
                h2 { "Wi-Fi" }
                div { class: "metric-grid",
                    Metric {
                        label: "SSID".to_string(),
                        value: snapshot_view.wifi_status.ssid.clone()
                            .unwrap_or_else(|| "-".to_string()),
                    }
                    Metric {
                        label: "Signal".to_string(),
                        value: snapshot_view.wifi_status.signal
                            .map(|signal| format!("{signal}%"))
                            .unwrap_or_else(|| "-".to_string()),
                    }
                    Metric {
                        label: "Security".to_string(),
                        value: snapshot_view.wifi_status.security.clone()
                            .map(|security| format!("{security:?}"))
                            .unwrap_or_else(|| "-".to_string()),
                    }
                }
                div { class: "connection-actions",
                    button {
                        disabled: wifi_is_busy,
                        onclick: scan,
                        if wifi_is_busy { "Working..." } else { "Scan" }
                    }
                    button {
                        disabled: wifi_is_busy || selected_bssid_view.is_none(),
                        onclick: connect_wifi,
                        "Connect"
                    }
                }
                div { class: "device-list",
                    for network in wifi_networks_view {
                        {
                            let selected = selected_bssid_view.as_deref()
                                == Some(network.bssid.as_str());
                            let current = snapshot_view.wifi_status.ssid.as_deref()
                                == Some(network.ssid.as_str());
                            let row_class = if selected {
                                "device-row selected"
                            } else {
                                "device-row"
                            };
                            let signal = network.signal
                                .map(|signal| format!("{signal}%"))
                                .unwrap_or_else(|| "-".to_string());
                            let security = network.security.as_ref()
                                .map(|security| format!("{security:?}"))
                                .unwrap_or_else(|| "Unknown".to_string());
                            let selected_network = network.clone();
                            rsx! {
                                button {
                                    key: "{network.bssid}",
                                    class: row_class,
                                    disabled: wifi_is_busy,
                                    onclick: move |_| selected_bssid.set(Some(
                                        selected_network.bssid.clone()
                                    )),
                                    div {
                                        strong { "{network.ssid}" }
                                        span { "{security}" }
                                    }
                                    div {
                                        span { "{signal}" }
                                        if current { span { "Current" } }
                                    }
                                }
                            }
                        }
                    }
                }
                label {
                    span { "Password" }
                    input {
                        r#type: "password",
                        value: "{wifi_password_view}",
                        disabled: wifi_is_busy,
                        oninput: move |event| wifi_password.set(event.value()),
                    }
                }
                if let Some(message) = wifi_error_view {
                    div { class: "error-row", "{message}" }
                }
            }

            if confirm_ip() {
                dialog { open: true,
                    p { "Apply this network configuration?" }
                    div { class: "connection-actions",
                        button {
                            disabled: ip_is_busy,
                            onclick: apply_ip,
                            "Confirm"
                        }
                        button {
                            disabled: ip_is_busy,
                            onclick: move |_| {
                                confirm_ip.set(false);
                                pending_ip_change.set(None);
                            },
                            "Cancel"
                        }
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

fn sort_wifi_networks(networks: &mut [WifiNetwork]) {
    networks.sort_by_key(|network| std::cmp::Reverse(network.signal.unwrap_or(0)));
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

fn prepare_ip_change(
    iface: Option<String>,
    dhcp: bool,
    address: &str,
    gateway: &str,
    dns: &str,
) -> Result<(String, Option<StaticIpv4>), String> {
    let iface = iface.ok_or_else(|| "Select an interface.".to_string())?;
    let config = if dhcp {
        None
    } else {
        Some(parse_static_ipv4(address, gateway, dns)?)
    };
    Ok((iface, config))
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

fn replace_interface_config(snapshot: &mut DeviceSnapshot, iface: &str, config: IpConfig) {
    if let Some(interface) = snapshot
        .interfaces
        .iter_mut()
        .find(|snapshot| snapshot.interface.name == iface)
    {
        interface.config = config;
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
    use netprov_protocol::{IfaceState, IfaceType, Ipv4Method, WifiNetwork};

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

    #[test]
    fn sorts_wifi_by_descending_signal() {
        let mut networks = vec![
            WifiNetwork {
                ssid: "weak".into(),
                signal: Some(20),
                security: Some(Security::Open),
                bssid: "20".into(),
            },
            WifiNetwork {
                ssid: "unknown".into(),
                signal: None,
                security: Some(Security::Open),
                bssid: "none".into(),
            },
            WifiNetwork {
                ssid: "strong".into(),
                signal: Some(80),
                security: Some(Security::Open),
                bssid: "80".into(),
            },
        ];

        sort_wifi_networks(&mut networks);

        assert_eq!(
            networks
                .iter()
                .map(|network| network.bssid.as_str())
                .collect::<Vec<_>>(),
            ["80", "20", "none"]
        );
    }

    #[test]
    fn replaces_only_the_selected_interface_config() {
        let automatic = IpConfig {
            method: Ipv4Method::Auto,
            addresses: vec![],
            gateway: None,
            dns: vec![],
        };
        let manual = IpConfig {
            method: Ipv4Method::Manual,
            addresses: vec!["192.168.2.10/24".parse().unwrap()],
            gateway: Some("192.168.2.1".parse().unwrap()),
            dns: vec!["1.1.1.1".parse().unwrap()],
        };
        let mut snapshot = DeviceSnapshot {
            interfaces: ["eth0", "wlan0"]
                .into_iter()
                .map(|name| InterfaceSnapshot {
                    interface: Interface {
                        name: name.into(),
                        iface_type: IfaceType::Ethernet,
                        mac: None,
                        state: IfaceState::Up,
                    },
                    config: automatic.clone(),
                })
                .collect(),
            wifi_status: WifiStatus {
                ssid: None,
                signal: None,
                security: None,
            },
        };

        replace_interface_config(&mut snapshot, "wlan0", manual.clone());

        assert_eq!(snapshot.interfaces[0].config, automatic);
        assert_eq!(snapshot.interfaces[1].config, manual);
    }

    #[test]
    fn pending_ip_change_owns_its_original_interface() {
        let (iface, config) = prepare_ip_change(
            Some("wlan0".into()),
            false,
            "192.168.2.10/24",
            "192.168.2.1",
            "1.1.1.1",
        )
        .unwrap();

        assert_eq!(iface, "wlan0");
        assert_eq!(config.unwrap().address.to_string(), "192.168.2.10/24");
    }
}
