use dioxus::prelude::*;
use netprov_sdk::PEER_ID_HINT;

mod dashboard;
mod operations;

use dashboard::Dashboard;
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
