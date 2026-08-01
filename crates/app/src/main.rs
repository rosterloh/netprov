use dioxus::prelude::*;
use netprov_protocol::{Ipv4Method, Security, StaticIpv4, WifiNetwork};
use netprov_sdk::PEER_ID_HINT;
use std::rc::Rc;

mod operations;

use operations::*;

const MAIN_CSS: Asset = asset!("/assets/main.css");
const MIN_WINDOW_HEIGHT: f64 = 600.0;
const SCREEN_MARGIN: f64 = 80.0;

fn target_window_height(content_height: f64, screen_height: f64) -> f64 {
    content_height.clamp(
        MIN_WINDOW_HEIGHT,
        (screen_height - SCREEN_MARGIN).max(MIN_WINDOW_HEIGHT),
    )
}

fn main() {
    dioxus::LaunchBuilder::desktop()
        .with_cfg(
            dioxus::desktop::Config::new()
                .with_close_behaviour(dioxus::desktop::WindowCloseBehaviour::WindowHides),
        )
        .launch(App);
}

#[derive(Clone, PartialEq)]
enum ScanState {
    Idle,
    Scanning,
    Complete,
    Failed(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActiveTab {
    Overview,
    Wifi,
    Interfaces,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TabDirection {
    Previous,
    Next,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WifiOperation {
    Idle,
    Scanning,
    Connecting,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ConnectionPhase {
    #[default]
    Discovery,
    Connecting,
    Connected,
    Disconnecting,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ConnectedDevice {
    peer_id: String,
    label: String,
    detail: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ConnectionLifecycle {
    phase: ConnectionPhase,
    target: Option<ConnectedDevice>,
    error: Option<String>,
}

impl ConnectionLifecycle {
    fn begin_connect(&mut self, target: ConnectedDevice) {
        self.phase = ConnectionPhase::Connecting;
        self.target = Some(target);
        self.error = None;
    }

    fn connect_succeeded(&mut self) {
        self.phase = ConnectionPhase::Connected;
    }

    fn connect_failed(&mut self, error: String) {
        self.phase = ConnectionPhase::Discovery;
        self.target = None;
        self.error = Some(error);
    }

    fn begin_disconnect(&mut self) -> bool {
        if self.phase != ConnectionPhase::Connected {
            return false;
        }
        self.phase = ConnectionPhase::Disconnecting;
        self.error = None;
        true
    }

    fn finish_disconnect(&mut self, result: Result<(), String>) -> bool {
        match result {
            Ok(()) => {
                self.phase = ConnectionPhase::Discovery;
                self.target = None;
                self.error = None;
                true
            }
            Err(error) => {
                self.phase = ConnectionPhase::Connected;
                self.error = Some(error);
                false
            }
        }
    }

    fn discovery_enabled(&self) -> bool {
        self.phase == ConnectionPhase::Discovery
    }
}

fn capture_connected_device(peer: &str, selected: Option<&DeviceSummary>) -> ConnectedDevice {
    let peer_id = peer.trim().to_string();
    match selected.filter(|device| device.id == peer_id) {
        Some(device) => ConnectedDevice {
            peer_id,
            label: device.label.clone(),
            detail: format!("{} · {}", device.detail, device.id),
        },
        None => ConnectedDevice {
            detail: peer_id.clone(),
            peer_id,
            label: "Netprov device".into(),
        },
    }
}

fn adjacent_tab(tab: ActiveTab, direction: TabDirection) -> ActiveTab {
    match (tab, direction) {
        (ActiveTab::Overview, TabDirection::Previous) => ActiveTab::Interfaces,
        (ActiveTab::Overview, TabDirection::Next) => ActiveTab::Wifi,
        (ActiveTab::Wifi, TabDirection::Previous) => ActiveTab::Overview,
        (ActiveTab::Wifi, TabDirection::Next) => ActiveTab::Interfaces,
        (ActiveTab::Interfaces, TabDirection::Previous) => ActiveTab::Wifi,
        (ActiveTab::Interfaces, TabDirection::Next) => ActiveTab::Overview,
    }
}

fn wifi_status_message(operation: WifiOperation, ssid: Option<&str>, count: usize) -> String {
    match operation {
        WifiOperation::Scanning => "Scanning for Wi-Fi networks…".into(),
        WifiOperation::Connecting => format!("Connecting to {}…", ssid.unwrap_or("Wi-Fi")),
        WifiOperation::Idle if count == 0 => "Scan to find nearby networks.".into(),
        WifiOperation::Idle => format!("{count} networks found"),
    }
}

fn focus_mounted(element: Option<Rc<MountedData>>) {
    if let Some(element) = element {
        spawn(async move {
            let _ = element.set_focus(true).await;
        });
    }
}

fn allow_window_close(window: &dioxus::desktop::DesktopContext) {
    window.set_close_behavior(dioxus::desktop::WindowCloseBehaviour::WindowCloses);
    window.close();
}

fn begin_disconnect(
    mut lifecycle: Signal<ConnectionLifecycle>,
    mut client: Signal<Option<SharedClient>>,
    mut snapshot: Signal<Option<DeviceSnapshot>>,
    mut close_requested: Signal<bool>,
    window: dioxus::desktop::DesktopContext,
) -> bool {
    let Some(active_client) = client() else {
        return false;
    };
    if !lifecycle.with_mut(ConnectionLifecycle::begin_disconnect) {
        return false;
    }

    spawn(async move {
        let result = disconnect_device(active_client).await;
        if result.is_ok() {
            client.set(None);
            snapshot.set(None);
        }
        let disconnected = lifecycle.with_mut(|lifecycle| lifecycle.finish_disconnect(result));
        if close_requested() {
            close_requested.set(false);
            if disconnected {
                allow_window_close(&window);
            } else {
                window.set_visible(true);
            }
        }
    });
    true
}

#[component]
fn App() -> Element {
    let mut peer = use_signal(String::new);
    let mut key_path = use_signal(|| "/etc/netprov/key".to_string());
    let mut scan_state = use_signal(|| ScanState::Idle);
    let mut devices = use_signal(Vec::<DeviceSummary>::new);
    let mut client = use_signal(|| None::<SharedClient>);
    let mut snapshot = use_signal(|| None::<DeviceSnapshot>);
    let mut selected_device = use_signal(|| None::<DeviceSummary>);
    let mut lifecycle = use_signal(ConnectionLifecycle::default);
    let mut close_requested = use_signal(|| false);
    let window = dioxus::desktop::use_window();

    let resize_window = window.clone();
    use_future(move || {
        let resize_window = resize_window.clone();
        async move {
            let mut measurements = document::eval(
                r#"
            const header = document.querySelector('.app-header');
            const app = document.querySelector('#app');
            const report = () => dioxus.send(Math.ceil(
                header.getBoundingClientRect().height + app.scrollHeight
            ));
            const observer = new ResizeObserver(report);
            observer.observe(header);
            observer.observe(app);
            report();
            await new Promise(() => {});
            "#,
            );

            while let Ok(content_height) = measurements.recv::<f64>().await {
                if resize_window.is_maximized() || resize_window.fullscreen().is_some() {
                    continue;
                }
                let scale = resize_window.scale_factor();
                let current = resize_window.inner_size().to_logical::<f64>(scale);
                let screen_height = resize_window
                    .current_monitor()
                    .map(|monitor| monitor.size().to_logical::<f64>(scale).height)
                    .unwrap_or(current.height + SCREEN_MARGIN);
                let height = target_window_height(content_height, screen_height);
                if (current.height - height).abs() >= 1.0 {
                    resize_window.set_inner_size(dioxus::desktop::tao::dpi::LogicalSize::new(
                        current.width,
                        height,
                    ));
                }
            }
        }
    });

    let close_window = window.clone();
    let _close_handler = dioxus::desktop::use_wry_event_handler(move |event, _| {
        if !matches!(
            event,
            dioxus::desktop::tao::event::Event::WindowEvent {
                event: dioxus::desktop::WindowEvent::CloseRequested,
                ..
            }
        ) {
            return;
        }

        match lifecycle().phase {
            ConnectionPhase::Discovery => {
                close_window.set_close_behavior(dioxus::desktop::WindowCloseBehaviour::WindowCloses)
            }
            ConnectionPhase::Connecting => close_requested.set(true),
            ConnectionPhase::Connected => {
                close_requested.set(true);
                if !begin_disconnect(
                    lifecycle,
                    client,
                    snapshot,
                    close_requested,
                    close_window.clone(),
                ) {
                    close_requested.set(false);
                    close_window
                        .set_close_behavior(dioxus::desktop::WindowCloseBehaviour::WindowCloses);
                }
            }
            ConnectionPhase::Disconnecting => close_requested.set(true),
        }
    });

    use_drop(move || {
        if let Some(active_client) = client.peek().as_ref().cloned() {
            dioxus::dioxus_core::spawn_forever(async move {
                let _ = disconnect_device(active_client).await;
            });
        }
    });

    let current_peer = peer();
    let current_key_path = key_path();
    let devices_view = devices();
    let scan_state_view = scan_state();
    let client_view = client();
    let snapshot_view = snapshot();
    let selected_device_view = selected_device();
    let selected_peer = selected_device_view
        .as_ref()
        .map(|device| device.id.clone());
    let lifecycle_view = lifecycle();
    let connection_error_view = lifecycle_view.error.clone();
    let is_connecting = lifecycle_view.phase == ConnectionPhase::Connecting;
    let is_disconnecting = lifecycle_view.phase == ConnectionPhase::Disconnecting;
    let discovery_enabled = lifecycle_view.discovery_enabled();
    let is_scanning = matches!(scan_state_view, ScanState::Scanning);
    let can_connect = discovery_enabled && !current_peer.trim().is_empty();
    let connected_device_name = lifecycle_view
        .target
        .as_ref()
        .map(|target| target.label.clone())
        .unwrap_or_else(|| "Netprov device".to_string());
    let connected_device_detail = lifecycle_view
        .target
        .as_ref()
        .map(|target| target.detail.clone())
        .unwrap_or_default();

    let scan = move |_| {
        if !lifecycle().discovery_enabled() {
            return;
        }
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

    let connect_window = window.clone();
    let connect = move |_| {
        let peer_value = peer();
        let key_path_value = key_path();
        if !lifecycle().discovery_enabled() || peer_value.trim().is_empty() {
            return;
        }
        lifecycle.with_mut(|lifecycle| {
            lifecycle.begin_connect(capture_connected_device(
                &peer_value,
                selected_device().as_ref(),
            ));
        });
        let connect_window = connect_window.clone();
        spawn(async move {
            match connect_device(peer_value, key_path_value).await {
                Ok((next_client, next_snapshot)) => {
                    snapshot.set(Some(next_snapshot));
                    client.set(Some(next_client));
                    lifecycle.with_mut(ConnectionLifecycle::connect_succeeded);
                    if close_requested() {
                        begin_disconnect(
                            lifecycle,
                            client,
                            snapshot,
                            close_requested,
                            connect_window,
                        );
                    }
                }
                Err(err) => {
                    lifecycle.with_mut(|lifecycle| lifecycle.connect_failed(err));
                    if close_requested() {
                        close_requested.set(false);
                        allow_window_close(&connect_window);
                    }
                }
            }
        });
    };

    let disconnect_window = window.clone();
    let disconnect = move |_| {
        begin_disconnect(
            lifecycle,
            client,
            snapshot,
            close_requested,
            disconnect_window.clone(),
        );
    };

    rsx! {
        document::Stylesheet { href: MAIN_CSS }
        document::Title { "Netprov desktop app" }
        header { class: "app-header",
            a { class: "brand", href: "#app", aria_label: "Netprov home", "netprov" }
            span { class: "header-rule", aria_hidden: "true" }
            p { "Secure network setup over Bluetooth" }
        }
        main { id: "app",
            if client_view.is_none() {
                section {
                    id: "discovery-view",
                    class: "discovery-card",
                    aria_labelledby: "discovery-title",
                    div { class: "section-heading",
                        div {
                            p { class: "eyebrow", "Device setup" }
                            h1 { id: "discovery-title", "Find a device" }
                            p { class: "muted", "Choose the nearby device you want to provision." }
                        }
                        button {
                            class: "secondary",
                            r#type: "button",
                            disabled: !discovery_enabled || is_scanning,
                            onclick: scan,
                            "Scan again"
                        }
                    }

                    div {
                        class: if is_scanning { "scan-line scanning" } else { "scan-line" },
                        span { class: "scan-dot", aria_hidden: "true" }
                        ScanStatus { state: scan_state_view.clone(), count: devices_view.len() }
                    }

                    DeviceList {
                        devices: devices_view,
                        selected_peer,
                        disabled: !discovery_enabled,
                        onselect: move |device: DeviceSummary| {
                            peer.set(device.id.clone());
                            selected_device.set(Some(device));
                        },
                    }

                    details {
                        summary { "Advanced connection" }
                        div { class: "advanced-grid",
                            label {
                                span { "Peer identifier" }
                                input {
                                    class: "mono",
                                    autocomplete: "off",
                                    value: "{current_peer}",
                                    placeholder: "{PEER_ID_HINT}",
                                    disabled: !discovery_enabled,
                                    oninput: move |event| {
                                        peer.set(event.value());
                                        selected_device.set(None);
                                    },
                                }
                            }
                            label {
                                span { "PSK path" }
                                input {
                                    class: "mono",
                                    value: "{current_key_path}",
                                    disabled: !discovery_enabled,
                                    oninput: move |event| key_path.set(event.value()),
                                }
                            }
                        }
                    }

                    if let Some(message) = connection_error_view {
                        div { class: "message error", role: "alert", "{message}" }
                    }
                    div { class: "connect-row",
                        button {
                            class: "primary",
                            r#type: "button",
                            disabled: !can_connect,
                            onclick: connect,
                            if is_connecting {
                                "Connecting securely…"
                            } else {
                                "Connect to device"
                            }
                        }
                    }
                }
            } else if snapshot_view.is_some() {
                Dashboard {
                    client,
                    snapshot,
                    device_name: connected_device_name,
                    device_detail: connected_device_detail,
                    disconnecting: is_disconnecting,
                    connection_error: connection_error_view,
                    ondisconnect: disconnect,
                }
            }
        }
    }
}

#[component]
fn ScanStatus(state: ScanState, count: usize) -> Element {
    match state {
        ScanState::Idle => rsx! {
            span { role: "status", "Ready to scan for nearby Netprov devices." }
        },
        ScanState::Scanning => rsx! {
            span { role: "status", "Scanning for nearby Netprov devices…" }
        },
        ScanState::Complete => rsx! {
            span { role: "status", "{count} devices found" }
        },
        ScanState::Failed(ref message) => rsx! {
            span { role: "status", "Scan failed: {message}" }
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
    rsx! {
        div { class: "device-list", aria_label: "Nearby devices",
            if devices.is_empty() {
                p { class: "muted", "Scan to discover nearby Netprov devices." }
            }
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
                            r#type: "button",
                            aria_pressed: selected,
                            disabled,
                            onclick: move |_| onselect.call(selected_device.clone()),
                            span {
                                strong { "{device.label}" }
                                small { "{device.detail}" }
                            }
                            span { class: "mono", "{signal}" }
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
    device_name: String,
    device_detail: String,
    disconnecting: bool,
    connection_error: Option<String>,
    ondisconnect: EventHandler<()>,
) -> Element {
    let mut active_tab = use_signal(|| ActiveTab::Overview);
    let mut wifi_networks = use_signal(Vec::<WifiNetwork>::new);
    let mut selected_bssid = use_signal(|| None::<String>);
    let mut wifi_password = use_signal(String::new);
    let mut wifi_operation = use_signal(|| WifiOperation::Idle);
    let mut wifi_error = use_signal(|| None::<String>);
    let mut success_message = use_signal(|| None::<String>);
    let mut selected_interface = use_signal(|| None::<String>);
    let mut dhcp_mode = use_signal(|| true);
    let mut address = use_signal(String::new);
    let mut gateway = use_signal(String::new);
    let mut dns = use_signal(String::new);
    let mut ip_busy = use_signal(|| false);
    let mut ip_error = use_signal(|| None::<String>);
    let mut ip_invalid = use_signal(StaticIpv4Invalid::default);
    let mut confirm_ip = use_signal(|| false);
    let mut restore_ip_focus = use_signal(|| false);
    let mut pending_ip_change = use_signal(|| None::<(String, Option<StaticIpv4>)>);
    let mut overview_tab_element = use_signal(|| None::<Rc<MountedData>>);
    let mut wifi_tab_element = use_signal(|| None::<Rc<MountedData>>);
    let mut interfaces_tab_element = use_signal(|| None::<Rc<MountedData>>);
    let mut apply_ip_button_element = use_signal(|| None::<Rc<MountedData>>);
    let mut cancel_ip_button_element = use_signal(|| None::<Rc<MountedData>>);
    let mut confirm_ip_button_element = use_signal(|| None::<Rc<MountedData>>);

    let snapshot_view = snapshot().expect("dashboard requires a connected device");
    let active_tab_view = active_tab();
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
    let ip_invalid_view = ip_invalid();
    let confirm_ip_view = confirm_ip();
    let wifi_operation_view = wifi_operation();
    let wifi_is_busy = wifi_operation_view != WifiOperation::Idle;
    let wifi_is_scanning = wifi_operation_view == WifiOperation::Scanning;
    let wifi_is_connecting = wifi_operation_view == WifiOperation::Connecting;
    let ip_is_busy = ip_busy();
    let overview_active = active_tab_view == ActiveTab::Overview;
    let wifi_active = active_tab_view == ActiveTab::Wifi;
    let interfaces_active = active_tab_view == ActiveTab::Interfaces;
    let interfaces_view = snapshot_view.interfaces.clone();
    let overview_interfaces = interfaces_view.clone();
    let current_ssid = snapshot_view.wifi_status.ssid.clone();
    let wifi_ssid = current_ssid
        .clone()
        .unwrap_or_else(|| "Not connected".into());
    let wifi_signal = snapshot_view
        .wifi_status
        .signal
        .map(|signal| format!("{signal}%"))
        .unwrap_or_else(|| "Signal unavailable".into());
    let wifi_security = snapshot_view
        .wifi_status
        .security
        .as_ref()
        .map(|security| format!("{security:?}"))
        .unwrap_or_else(|| "Security unavailable".into());
    let selected_network_view = selected_bssid_view
        .as_deref()
        .and_then(|bssid| {
            wifi_networks_view
                .iter()
                .find(|network| network.bssid == bssid)
        })
        .cloned();
    let wifi_form_title = selected_network_view
        .as_ref()
        .map(|network| network.ssid.clone())
        .unwrap_or_else(|| "Select a network".into());
    let wifi_form_copy = selected_network_view
        .as_ref()
        .map(|network| {
            let security = network
                .security
                .as_ref()
                .map(|security| format!("{security:?}"))
                .unwrap_or_else(|| "Unknown security".into());
            let signal = network
                .signal
                .map(|signal| format!("{signal}%"))
                .unwrap_or_else(|| "unknown".into());
            format!("{security} network · {signal} signal")
        })
        .unwrap_or_else(|| "Choose a network to enter its credentials.".into());
    let needs_wifi_password = selected_network_view
        .as_ref()
        .is_some_and(|network| !matches!(network.security.as_ref(), Some(&Security::Open)));
    let wifi_password_invalid = wifi_error_view
        .as_deref()
        .is_some_and(|error| error.contains("password"));
    let selected_interface_snapshot = selected_interface_view
        .as_deref()
        .and_then(|name| {
            interfaces_view
                .iter()
                .find(|snapshot| snapshot.interface.name == name)
        })
        .cloned();
    let selected_interface_title = selected_interface_snapshot
        .as_ref()
        .map(|snapshot| snapshot.interface.name.clone())
        .unwrap_or_else(|| "Select an interface".into());
    let selected_interface_detail = selected_interface_snapshot
        .as_ref()
        .map(|snapshot| {
            format!(
                "{:?} · {}",
                snapshot.interface.iface_type,
                snapshot
                    .interface
                    .mac
                    .as_deref()
                    .unwrap_or("MAC unavailable")
            )
        })
        .unwrap_or_else(|| "Choose an interface to edit its IPv4 configuration.".into());
    let selected_interface_summary = selected_interface_snapshot
        .as_ref()
        .map(|snapshot| {
            let address = snapshot
                .config
                .addresses
                .first()
                .map(ToString::to_string)
                .unwrap_or_else(|| "No address".into());
            format!("{} · {address}", ipv4_method_label(&snapshot.config.method))
        })
        .unwrap_or_else(|| format!("{} interfaces available", interfaces_view.len()));
    let configured_interfaces = overview_interfaces
        .iter()
        .filter(|snapshot| !snapshot.config.addresses.is_empty())
        .count();
    let wifi_status_text = wifi_status_message(
        wifi_operation_view,
        selected_network_view
            .as_ref()
            .map(|network| network.ssid.as_str()),
        wifi_networks_view.len(),
    );

    use_effect(move || {
        if restore_ip_focus() && !confirm_ip() && !ip_busy() {
            restore_ip_focus.set(false);
            focus_mounted(apply_ip_button_element.cloned());
        }
    });

    let navigate_tabs = move |event: KeyboardEvent| {
        let direction = match event.key() {
            Key::ArrowLeft => TabDirection::Previous,
            Key::ArrowRight => TabDirection::Next,
            _ => return,
        };
        event.prevent_default();
        let next = adjacent_tab(active_tab(), direction);
        active_tab.set(next);
        focus_mounted(match next {
            ActiveTab::Overview => overview_tab_element.cloned(),
            ActiveTab::Wifi => wifi_tab_element.cloned(),
            ActiveTab::Interfaces => interfaces_tab_element.cloned(),
        });
    };

    let scan = move |_| {
        let Some(client) = client() else {
            return;
        };
        wifi_operation.set(WifiOperation::Scanning);
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
            wifi_operation.set(WifiOperation::Idle);
        });
    };

    let connect_wifi = move |event: FormEvent| {
        event.prevent_default();
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
        wifi_operation.set(WifiOperation::Connecting);
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
                Err(err) => wifi_error.set(Some(mutation_failure_message("Wi-Fi connection", err))),
            }
            wifi_operation.set(WifiOperation::Idle);
        });
    };

    let request_ip_change = move |event: FormEvent| {
        event.prevent_default();
        let invalid = if dhcp_mode() {
            StaticIpv4Invalid::default()
        } else {
            static_ipv4_invalid_fields(&address(), &gateway(), &dns())
        };
        ip_invalid.set(invalid);
        match prepare_ip_change(
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
        }
    };

    let mut close_ip_confirmation = move || {
        confirm_ip.set(false);
        pending_ip_change.set(None);
        restore_ip_focus.set(true);
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
                Err(err) => {
                    ip_error.set(Some(mutation_failure_message("Network configuration", err)))
                }
            }
            ip_busy.set(false);
            restore_ip_focus.set(true);
        });
    };

    rsx! {
        section { id: "workspace-view",
        div { inert: confirm_ip_view || disconnecting,
        header { class: "device-header",
            div {
                p { class: "eyebrow", "Connected device" }
                h1 { "{device_name}" }
                p { class: "mono muted", "{device_detail}" }
            }
            div { class: "device-actions",
                span { class: "status success",
                    if disconnecting { "Disconnecting…" } else { "Secure connection" }
                }
                button {
                    class: "secondary",
                    r#type: "button",
                    disabled: disconnecting,
                    onclick: move |_| ondisconnect.call(()),
                    if disconnecting { "Disconnecting…" } else { "Disconnect" }
                }
            }
        }

        if let Some(message) = connection_error {
            div {
                class: "message error",
                role: "alert",
                "Disconnect failed: {message}"
            }
        }

        nav {
            class: "tabs",
            role: "tablist",
            aria_label: "Device configuration",
            button {
                id: "overview-tab",
                r#type: "button",
                role: "tab",
                aria_controls: "overview-panel",
                aria_selected: overview_active,
                "tabindex": if overview_active { "0" } else { "-1" },
                onmounted: move |event| overview_tab_element.set(Some(event.data())),
                onkeydown: navigate_tabs,
                onclick: move |_| active_tab.set(ActiveTab::Overview),
                "Overview"
            }
            button {
                id: "wifi-tab",
                r#type: "button",
                role: "tab",
                aria_controls: "wifi-panel",
                aria_selected: wifi_active,
                "tabindex": if wifi_active { "0" } else { "-1" },
                onmounted: move |event| wifi_tab_element.set(Some(event.data())),
                onkeydown: navigate_tabs,
                onclick: move |_| active_tab.set(ActiveTab::Wifi),
                "Wi-Fi"
            }
            button {
                id: "interfaces-tab",
                r#type: "button",
                role: "tab",
                aria_controls: "interfaces-panel",
                aria_selected: interfaces_active,
                "tabindex": if interfaces_active { "0" } else { "-1" },
                onmounted: move |event| interfaces_tab_element.set(Some(event.data())),
                onkeydown: navigate_tabs,
                onclick: move |_| active_tab.set(ActiveTab::Interfaces),
                "Interfaces"
            }
        }

        section {
            id: "overview-panel",
            role: "tabpanel",
            aria_labelledby: "overview-tab",
            hidden: !overview_active,
            div { class: "workspace-grid",
                div { class: "panel",
                    p { class: "eyebrow", "Current state" }
                    h2 { "Network overview" }
                    div { class: "summary-row",
                        div {
                            h3 { "Wi-Fi" }
                            p { class: "muted", "Active wireless connection" }
                        }
                        div { class: "summary-value",
                            strong { "{wifi_ssid}" }
                            small { "{wifi_security} · {wifi_signal}" }
                        }
                    }
                    for interface_snapshot in overview_interfaces {
                        {
                            let mac = interface_snapshot
                                .interface
                                .mac
                                .as_deref()
                                .unwrap_or("MAC unavailable");
                            let address_text = interface_snapshot
                                .config
                                .addresses
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join(", ");
                            let address_text = if address_text.is_empty() {
                                "No IPv4 address".to_string()
                            } else {
                                address_text
                            };
                            let method = ipv4_method_label(&interface_snapshot.config.method);
                            rsx! {
                                div { class: "summary-row",
                                    div {
                                        h3 { "{interface_snapshot.interface.name}" }
                                        p { class: "muted mono", "{mac}" }
                                    }
                                    div { class: "summary-value mono",
                                        strong { "{address_text}" }
                                        small {
                                            "{method} · {interface_snapshot.interface.state:?}"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                aside { class: "panel",
                    p { class: "eyebrow", "Setup progress" }
                    h2 { "Ready to configure" }
                    ul { class: "checklist",
                        li {
                            span { class: "checkmark", aria_hidden: "true", "✓" }
                            span {
                                strong { "Securely connected" }
                                small {
                                    class: "muted",
                                    "Authenticated with the device PSK"
                                }
                            }
                        }
                        li {
                            span {
                                class: if current_ssid.is_some() {
                                    "checkmark"
                                } else {
                                    "checkmark pending"
                                },
                                aria_hidden: "true",
                                if current_ssid.is_some() { "✓" } else { "–" }
                            }
                            span {
                                strong {
                                    if current_ssid.is_some() {
                                        "Wi-Fi detected"
                                    } else {
                                        "Wi-Fi not connected"
                                    }
                                }
                                small { class: "muted", "{wifi_ssid}" }
                            }
                        }
                        li {
                            span {
                                class: if configured_interfaces > 0 {
                                    "checkmark"
                                } else {
                                    "checkmark pending"
                                },
                                aria_hidden: "true",
                                if configured_interfaces > 0 { "✓" } else { "–" }
                            }
                            span {
                                strong { "IPv4 configuration" }
                                small {
                                    class: "muted",
                                    "{configured_interfaces} interfaces have an address"
                                }
                            }
                        }
                    }
                    button {
                        class: "primary",
                        r#type: "button",
                        onclick: move |_| {
                            active_tab.set(ActiveTab::Wifi);
                            focus_mounted(wifi_tab_element.cloned());
                        },
                        "Continue setup"
                    }
                }
            }
        }

        section {
            id: "wifi-panel",
            role: "tabpanel",
            aria_labelledby: "wifi-tab",
            hidden: !wifi_active,
            div { class: "network-layout",
                div { class: "panel",
                    div { class: "panel-heading",
                        div {
                            p { class: "eyebrow", "Nearby networks" }
                            h2 { "Choose Wi-Fi" }
                        }
                        button {
                            class: "secondary",
                            r#type: "button",
                            disabled: wifi_is_busy,
                            onclick: scan,
                            if wifi_is_scanning { "Scanning…" } else { "Scan" }
                        }
                    }
                    p { class: "muted", role: "status",
                        "{wifi_status_text}"
                    }
                    div {
                        class: "network-list",
                        aria_label: "Nearby Wi-Fi networks",
                        for network in wifi_networks_view {
                            {
                                let selected = selected_bssid_view.as_deref()
                                    == Some(network.bssid.as_str());
                                let current = current_ssid.as_deref()
                                    == Some(network.ssid.as_str());
                                let row_class = if selected {
                                    "network-row selected"
                                } else {
                                    "network-row"
                                };
                                let signal = network
                                    .signal
                                    .map(|signal| format!("{signal}%"))
                                    .unwrap_or_else(|| "-".to_string());
                                let security = network
                                    .security
                                    .as_ref()
                                    .map(|security| format!("{security:?}"))
                                    .unwrap_or_else(|| "Unknown".to_string());
                                let selected_network = network.clone();
                                rsx! {
                                    button {
                                        key: "{network.bssid}",
                                        class: row_class,
                                        r#type: "button",
                                        aria_pressed: selected,
                                        disabled: wifi_is_busy,
                                        onclick: move |_| {
                                            selected_bssid.set(Some(
                                                selected_network.bssid.clone()
                                            ));
                                            wifi_error.set(None);
                                        },
                                        span {
                                            strong { "{network.ssid}" }
                                            small {
                                                "{security}"
                                                if current {
                                                    span {
                                                        class: "current-tag",
                                                        " · Connected"
                                                    }
                                                }
                                            }
                                        }
                                        span { class: "mono signal", "{signal}" }
                                    }
                                }
                            }
                        }
                    }
                }
                form { class: "panel", onsubmit: connect_wifi,
                    p { class: "eyebrow", "Connection" }
                    h2 { "{wifi_form_title}" }
                    p { class: "muted", "{wifi_form_copy}" }
                    div { class: "form-stack",
                        if needs_wifi_password {
                            label {
                                span { "Wi-Fi password" }
                                input {
                                    r#type: "password",
                                    autocomplete: "new-password",
                                    minlength: 8,
                                    value: "{wifi_password_view}",
                                    aria_invalid: wifi_password_invalid,
                                    disabled: wifi_is_busy,
                                    oninput: move |event| wifi_password.set(event.value()),
                                }
                            }
                        }
                        if let Some(message) = wifi_error_view {
                            div {
                                class: "message error",
                                role: "alert",
                                "{message}"
                            }
                        }
                        div { class: "form-actions",
                            button {
                                class: "primary",
                                r#type: "submit",
                                disabled: wifi_is_busy || selected_bssid_view.is_none(),
                                if wifi_is_connecting {
                                    "Connecting to {wifi_form_title}…"
                                } else {
                                    "Connect"
                                }
                            }
                        }
                    }
                }
            }
        }

        section {
            id: "interfaces-panel",
            role: "tabpanel",
            aria_labelledby: "interfaces-tab",
            hidden: !interfaces_active,
            div { class: "interface-layout",
                div { class: "panel",
                    p { class: "eyebrow", "Network hardware" }
                    h2 { "Interfaces" }
                    p { class: "muted mono", "{selected_interface_summary}" }
                    div {
                        class: "interface-list",
                        aria_label: "Network interfaces",
                        for interface_snapshot in interfaces_view {
                            {
                                let selected = selected_interface_view.as_deref()
                                    == Some(interface_snapshot.interface.name.as_str());
                                let row_class = if selected {
                                    "interface-row selected"
                                } else {
                                    "interface-row"
                                };
                                let iface = interface_snapshot.interface.clone();
                                let address_text = interface_snapshot
                                    .config
                                    .addresses
                                    .first()
                                    .map(ToString::to_string)
                                    .unwrap_or_else(|| "No address".into());
                                let selected_snapshot = interface_snapshot.clone();
                                rsx! {
                                    button {
                                        key: "{iface.name}",
                                        class: row_class,
                                        r#type: "button",
                                        aria_pressed: selected,
                                        disabled: ip_is_busy,
                                        onclick: move |_| {
                                            let config = &selected_snapshot.config;
                                            selected_interface.set(Some(
                                                selected_snapshot.interface.name.clone()
                                            ));
                                            dhcp_mode.set(matches!(
                                                config.method,
                                                Ipv4Method::Auto
                                            ));
                                            address.set(
                                                config
                                                    .addresses
                                                    .first()
                                                    .map(ToString::to_string)
                                                    .unwrap_or_default()
                                            );
                                            gateway.set(
                                                config
                                                    .gateway
                                                    .map(|value| value.to_string())
                                                    .unwrap_or_default()
                                            );
                                            dns.set(
                                                config
                                                    .dns
                                                    .iter()
                                                    .map(ToString::to_string)
                                                    .collect::<Vec<_>>()
                                                    .join(", ")
                                            );
                                            ip_error.set(None);
                                            ip_invalid.set(StaticIpv4Invalid::default());
                                        },
                                        span {
                                            strong { "{iface.name}" }
                                            small {
                                                "{iface.iface_type:?} · {iface.state:?}"
                                            }
                                        }
                                        span { class: "mono", "{address_text}" }
                                    }
                                }
                            }
                        }
                    }
                }
                form { class: "panel", onsubmit: request_ip_change,
                    p { class: "eyebrow", "IPv4 configuration" }
                    h2 { "{selected_interface_title}" }
                    p { class: "muted mono", "{selected_interface_detail}" }
                    div { class: "form-stack",
                        fieldset {
                            disabled: selected_interface_view.is_none() || ip_is_busy,
                            legend { "Address assignment" }
                            div { class: "segmented",
                                label {
                                    input {
                                        r#type: "radio",
                                        name: "ipv4-mode",
                                        value: "DHCP",
                                        checked: dhcp_mode_view,
                                        onchange: move |_| dhcp_mode.set(true),
                                    }
                                    span { "DHCP" }
                                }
                                label {
                                    input {
                                        r#type: "radio",
                                        name: "ipv4-mode",
                                        value: "Static",
                                        checked: !dhcp_mode_view,
                                        onchange: move |_| dhcp_mode.set(false),
                                    }
                                    span { "Static" }
                                }
                            }
                        }
                        if !dhcp_mode_view {
                            div { class: "form-stack",
                                label {
                                    span { "Address / CIDR" }
                                    input {
                                        class: "mono",
                                        inputmode: "decimal",
                                        value: "{address_view}",
                                        aria_invalid: ip_invalid_view.address,
                                        disabled: ip_is_busy,
                                        oninput: move |event| address.set(event.value()),
                                    }
                                }
                                label {
                                    span { "Gateway" }
                                    input {
                                        class: "mono",
                                        inputmode: "decimal",
                                        value: "{gateway_view}",
                                        aria_invalid: ip_invalid_view.gateway,
                                        disabled: ip_is_busy,
                                        oninput: move |event| gateway.set(event.value()),
                                    }
                                }
                                label {
                                    span { "DNS addresses" }
                                    input {
                                        class: "mono",
                                        inputmode: "decimal",
                                        value: "{dns_view}",
                                        aria_describedby: "dns-hint",
                                        aria_invalid: ip_invalid_view.dns,
                                        disabled: ip_is_busy,
                                        oninput: move |event| dns.set(event.value()),
                                    }
                                    small {
                                        id: "dns-hint",
                                        class: "muted",
                                        "Separate multiple addresses with commas."
                                    }
                                }
                            }
                        }
                        if let Some(message) = ip_error_view {
                            div {
                                class: "message error",
                                role: "alert",
                                "{message}"
                            }
                        }
                        div { class: "form-actions",
                            button {
                                class: "primary",
                                r#type: "submit",
                                disabled: selected_interface_view.is_none() || ip_is_busy,
                                onmounted: move |event| {
                                    apply_ip_button_element.set(Some(event.data()))
                                },
                                if ip_is_busy {
                                    "Applying…"
                                } else {
                                    "Apply configuration"
                                }
                            }
                        }
                    }
                }
            }
        }
        }

        if confirm_ip_view {
            div { class: "dialog-overlay",
                dialog {
                    id: "ip-confirm-dialog",
                    open: true,
                    aria_labelledby: "ip-confirm-title",
                    aria_modal: "true",
                    onkeydown: move |event: KeyboardEvent| {
                        if event.key() == Key::Escape {
                            event.prevent_default();
                            close_ip_confirmation();
                        }
                    },
                    div { class: "dialog-body",
                        p { class: "eyebrow", "Confirm change" }
                        h2 { id: "ip-confirm-title", "Apply network changes?" }
                        p {
                            class: "muted",
                            "The device may briefly disconnect while its IPv4 configuration changes."
                        }
                        div { class: "dialog-actions",
                            button {
                                class: "secondary",
                                r#type: "button",
                                autofocus: true,
                                disabled: ip_is_busy,
                                onmounted: move |event| {
                                    cancel_ip_button_element.set(Some(event.data()))
                                },
                                onkeydown: move |event: KeyboardEvent| {
                                    if event.key() == Key::Tab {
                                        event.prevent_default();
                                        focus_mounted(confirm_ip_button_element.cloned());
                                    }
                                },
                                onclick: move |_| close_ip_confirmation(),
                                "Cancel"
                            }
                            button {
                                class: "primary",
                                r#type: "button",
                                disabled: ip_is_busy,
                                onmounted: move |event| {
                                    confirm_ip_button_element.set(Some(event.data()))
                                },
                                onkeydown: move |event: KeyboardEvent| {
                                    if event.key() == Key::Tab {
                                        event.prevent_default();
                                        focus_mounted(cancel_ip_button_element.cloned());
                                    }
                                },
                                onclick: apply_ip,
                                "Apply changes"
                            }
                        }
                    }
                }
            }
        }

        if let Some(message) = success_message_view {
            div {
                class: "toast",
                role: "status",
                aria_live: "polite",
                "{message}"
            }
        }
        }
    }
}

fn ipv4_method_label(method: &Ipv4Method) -> &'static str {
    match method {
        Ipv4Method::Auto => "DHCP",
        Ipv4Method::Manual => "Static",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_height_tracks_content_with_screen_bounds() {
        assert_eq!(target_window_height(720.0, 1_080.0), 720.0);
        assert_eq!(target_window_height(520.0, 1_080.0), 600.0);
        assert_eq!(target_window_height(1_200.0, 1_080.0), 1_000.0);
    }

    #[test]
    fn tab_navigation_wraps_in_both_directions() {
        assert_eq!(
            adjacent_tab(ActiveTab::Overview, TabDirection::Previous),
            ActiveTab::Interfaces
        );
        assert_eq!(
            adjacent_tab(ActiveTab::Interfaces, TabDirection::Next),
            ActiveTab::Overview
        );
    }

    #[test]
    fn wifi_operation_status_names_the_active_operation() {
        assert_eq!(
            wifi_status_message(WifiOperation::Scanning, None, 0),
            "Scanning for Wi-Fi networks…"
        );
        assert_eq!(
            wifi_status_message(WifiOperation::Connecting, Some("Workshop"), 3),
            "Connecting to Workshop…"
        );
    }

    #[test]
    fn successful_connection_keeps_the_captured_discovered_identity() {
        let device = DeviceSummary {
            id: "opaque-peer-a".into(),
            label: "Workshop device".into(),
            detail: "AA:BB:CC:DD:EE:FF".into(),
            rssi: Some(-42),
        };
        let mut peer_form = device.id.clone();
        let mut selected_form = Some(device);
        let mut lifecycle = ConnectionLifecycle::default();

        lifecycle.begin_connect(capture_connected_device(&peer_form, selected_form.as_ref()));
        lifecycle.connect_succeeded();
        peer_form = "opaque-peer-b".into();
        selected_form = None;

        let connected = lifecycle.target.as_ref().unwrap();
        assert_eq!(connected.peer_id, "opaque-peer-a");
        assert_eq!(connected.label, "Workshop device");
        assert_eq!(connected.detail, "AA:BB:CC:DD:EE:FF · opaque-peer-a");
        assert_eq!(peer_form, "opaque-peer-b");
        assert!(selected_form.is_none());
    }

    #[test]
    fn manual_connection_captures_the_opaque_peer_with_generic_copy() {
        let mut lifecycle = ConnectionLifecycle::default();

        lifecycle.begin_connect(capture_connected_device("opaque-manual-peer", None));
        lifecycle.connect_succeeded();

        let connected = lifecycle.target.as_ref().unwrap();
        assert_eq!(connected.peer_id, "opaque-manual-peer");
        assert_eq!(connected.label, "Netprov device");
        assert_eq!(connected.detail, "opaque-manual-peer");
    }

    #[test]
    fn disconnect_stays_gated_on_error_and_can_be_retried() {
        let mut lifecycle = ConnectionLifecycle::default();
        lifecycle.begin_connect(capture_connected_device("opaque-peer", None));
        lifecycle.connect_succeeded();

        assert!(lifecycle.begin_disconnect());
        assert_eq!(lifecycle.phase, ConnectionPhase::Disconnecting);
        assert!(!lifecycle.discovery_enabled());
        assert!(!lifecycle.finish_disconnect(Err("link still active".into())));
        assert_eq!(lifecycle.phase, ConnectionPhase::Connected);
        assert_eq!(lifecycle.error.as_deref(), Some("link still active"));
        assert!(lifecycle.target.is_some());
        assert!(!lifecycle.discovery_enabled());

        assert!(lifecycle.begin_disconnect());
        assert!(lifecycle.finish_disconnect(Ok(())));
        assert_eq!(lifecycle.phase, ConnectionPhase::Discovery);
        assert!(lifecycle.target.is_none());
        assert!(lifecycle.error.is_none());
        assert!(lifecycle.discovery_enabled());
    }
}
