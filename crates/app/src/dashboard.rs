use crate::operations::{
    DeviceSnapshot, InterfaceSnapshot, IpChange, SharedClient, StaticIpv4Form, StaticIpv4Invalid,
    apply_ip_config, connect_selected_wifi, dedupe_wifi_networks, fetch_snapshot,
    mutation_failure_message, prepare_ip_change, replace_interface_config, scan_wifi,
    sort_wifi_networks, static_ipv4_invalid_fields, wifi_password_too_short,
};
use dioxus::prelude::*;
use netprov_protocol::{IfaceState, IfaceType, Ipv4Method, Security, WifiNetwork};
use std::rc::Rc;
use std::time::Duration;

const TOAST_DURATION: Duration = Duration::from_secs(5);

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

/// The pending change lives in the state that needs it, so "confirming with
/// nothing to confirm" and "confirming while applying" cannot be expressed.
#[derive(Clone, Debug, PartialEq)]
enum IpOperation {
    Idle,
    Confirming(IpChange),
    Applying,
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

/// The success toast, shared by the panels that report into it.
#[derive(Clone, Copy, PartialEq)]
struct Toast {
    message: Signal<Option<String>>,
    generation: Signal<u32>,
}

impl Toast {
    fn clear(mut self) {
        // A write notifies readers even when nothing changed.
        if self.message.peek().is_some() {
            self.message.set(None);
        }
    }

    fn show(mut self, text: String) {
        let generation = self.generation.peek().wrapping_add(1);
        self.generation.set(generation);
        self.message.set(Some(text));
        spawn(async move {
            tokio::time::sleep(TOAST_DURATION).await;
            // A newer toast owns the region by now.
            if *self.generation.peek() == generation {
                self.message.set(None);
            }
        });
    }
}

/// Refetches what a mutation's reply does not carry: a new lease, link state.
// shortcut: one refetch as soon as the change converges, so a DHCP lease that
// lands later is still missed; poll until an address appears if that shows up.
async fn refresh_snapshot(
    client: SharedClient,
    mut snapshot: Signal<Option<DeviceSnapshot>>,
) -> Result<(), String> {
    let next = fetch_snapshot(client).await?;
    // A disconnect may have cleared it while this waited for the client.
    if snapshot.peek().is_some() {
        snapshot.set(Some(next));
    }
    Ok(())
}

fn stale_state_message(err: &str) -> String {
    format!("The change was applied, but the device state could not be refreshed: {err}")
}

#[component]
pub(crate) fn Dashboard(
    client: Signal<Option<SharedClient>>,
    snapshot: Signal<Option<DeviceSnapshot>>,
    device_name: String,
    device_detail: String,
    disconnecting: bool,
    connection_error: Option<String>,
    ondisconnect: EventHandler<()>,
) -> Element {
    let mut active_tab = use_signal(|| ActiveTab::Overview);
    // Owned here rather than by the interfaces panel: confirming blocks the
    // whole workspace, not just that panel.
    let ip_operation = use_signal(|| IpOperation::Idle);
    let toast = Toast {
        message: use_signal(|| None),
        generation: use_signal(|| 0),
    };
    let mut overview_tab_element = use_signal(|| None::<Rc<MountedData>>);
    let mut wifi_tab_element = use_signal(|| None::<Rc<MountedData>>);
    let mut interfaces_tab_element = use_signal(|| None::<Rc<MountedData>>);

    // The parent drops this component when the snapshot goes, but both
    // subscribe to it, so do not rely on the parent rendering first.
    let Some(snapshot_view) = snapshot() else {
        return rsx! {};
    };
    let active_tab_view = active_tab();
    let overview_active = active_tab_view == ActiveTab::Overview;
    let wifi_active = active_tab_view == ActiveTab::Wifi;
    let interfaces_active = active_tab_view == ActiveTab::Interfaces;
    let blocked = matches!(*ip_operation.read(), IpOperation::Confirming(_)) || disconnecting;
    let interfaces_view = snapshot_view.interfaces;
    let current_ssid = snapshot_view.wifi_status.ssid;
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
        .map(|security| security_label(security).to_string())
        .unwrap_or_else(|| "Security unavailable".into());
    let configured_interfaces = interfaces_view
        .iter()
        .filter(|snapshot| !snapshot.config.addresses.is_empty())
        .count();
    let toast_text = (toast.message)().unwrap_or_default();

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

    rsx! {
        section { id: "workspace-view",
        // `inert` is not in the interpreter's boolean-attribute list, so a
        // `false` would still be written as `inert="false"`, which makes the
        // element inert. Omit the attribute instead.
        div { inert: if blocked { "true" },
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
                    for interface_snapshot in &interfaces_view {
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
                            let state = iface_state_label(&interface_snapshot.interface.state);
                            rsx! {
                                div { class: "summary-row",
                                    div {
                                        h3 { "{interface_snapshot.interface.name}" }
                                        p { class: "muted mono", "{mac}" }
                                    }
                                    div { class: "summary-value mono",
                                        strong { "{address_text}" }
                                        small {
                                            "{method} · {state}"
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

        WifiPanel {
            client,
            snapshot,
            toast,
            active: wifi_active,
            current_ssid: current_ssid.clone(),
        }
        }

        InterfacesPanel {
            client,
            snapshot,
            toast,
            ip_operation,
            active: interfaces_active,
            blocked,
            interfaces: interfaces_view,
        }

        // One persistent live region whose text changes, as in `ScanStatus`.
        div {
            class: if toast_text.is_empty() { "toast toast-empty" } else { "toast" },
            role: "status",
            aria_live: "polite",
            "{toast_text}"
        }
        }
    }
}

#[component]
fn WifiPanel(
    client: Signal<Option<SharedClient>>,
    mut snapshot: Signal<Option<DeviceSnapshot>>,
    toast: Toast,
    active: bool,
    current_ssid: Option<String>,
) -> Element {
    let mut wifi_networks = use_signal(Vec::<WifiNetwork>::new);
    let mut selected_bssid = use_signal(|| None::<String>);
    let mut wifi_password = use_signal(String::new);
    let mut wifi_operation = use_signal(|| WifiOperation::Idle);
    let mut wifi_error = use_signal(|| None::<String>);
    let mut password_too_short = use_signal(|| false);

    let wifi_networks_view = wifi_networks();
    let selected_bssid_view = selected_bssid();
    let wifi_password_view = wifi_password();
    let wifi_error_view = wifi_error();
    let wifi_password_invalid = password_too_short();
    let wifi_operation_view = wifi_operation();
    let wifi_is_busy = wifi_operation_view != WifiOperation::Idle;
    let wifi_is_scanning = wifi_operation_view == WifiOperation::Scanning;
    let wifi_is_connecting = wifi_operation_view == WifiOperation::Connecting;
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
                .map(|security| security_label(security).to_string())
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
    let wifi_status_text = wifi_status_message(
        wifi_operation_view,
        selected_network_view
            .as_ref()
            .map(|network| network.ssid.as_str()),
        wifi_networks_view.len(),
    );

    let scan = move |_| {
        // `disabled` only lands with the next render; a queued click can beat it.
        if wifi_operation() != WifiOperation::Idle {
            return;
        }
        let Some(client) = client() else {
            return;
        };
        wifi_operation.set(WifiOperation::Scanning);
        wifi_error.set(None);
        password_too_short.set(false);
        toast.clear();
        spawn(async move {
            match scan_wifi(client).await {
                Ok(mut networks) => {
                    sort_wifi_networks(&mut networks);
                    dedupe_wifi_networks(&mut networks);
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
        if wifi_operation() != WifiOperation::Idle {
            return;
        }
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
        password_too_short.set(wifi_password_too_short(
            network.security.as_ref(),
            &password,
        ));
        wifi_operation.set(WifiOperation::Connecting);
        wifi_error.set(None);
        toast.clear();
        spawn(async move {
            match connect_selected_wifi(client.clone(), network, password).await {
                Ok(status) => {
                    snapshot.with_mut(|snapshot| {
                        if let Some(snapshot) = snapshot {
                            snapshot.wifi_status = status;
                        }
                    });
                    if let Err(err) = refresh_snapshot(client, snapshot).await {
                        wifi_error.set(Some(stale_state_message(&err)));
                    }
                    wifi_password.set(String::new());
                    toast.show(format!("Connected to {ssid}"));
                }
                Err(err) => wifi_error.set(Some(mutation_failure_message("Wi-Fi connection", err))),
            }
            wifi_operation.set(WifiOperation::Idle);
        });
    };

    rsx! {
        section {
            id: "wifi-panel",
            role: "tabpanel",
            aria_labelledby: "wifi-tab",
            hidden: !active,
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
                        role: "group",
                        aria_label: "Nearby Wi-Fi networks",
                        for network in wifi_networks_view {
                            Fragment { key: "{network.bssid}",
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
                                    .map(|security| security_label(security).to_string())
                                    .unwrap_or_else(|| "Unknown".to_string());
                                let selected_network = network.clone();
                                rsx! {
                                    button {
                                        class: row_class,
                                        r#type: "button",
                                        aria_pressed: selected,
                                        disabled: wifi_is_busy,
                                        onclick: move |_| {
                                            selected_bssid.set(Some(
                                                selected_network.bssid.clone()
                                            ));
                                            wifi_error.set(None);
                                            password_too_short.set(false);
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
    }
}

#[component]
fn InterfacesPanel(
    client: Signal<Option<SharedClient>>,
    mut snapshot: Signal<Option<DeviceSnapshot>>,
    toast: Toast,
    mut ip_operation: Signal<IpOperation>,
    active: bool,
    blocked: bool,
    interfaces: Vec<InterfaceSnapshot>,
) -> Element {
    let mut selected_interface = use_signal(|| None::<String>);
    let mut dhcp_mode = use_signal(|| true);
    let mut address = use_signal(String::new);
    let mut gateway = use_signal(String::new);
    let mut dns = use_signal(String::new);
    let mut ip_error = use_signal(|| None::<String>);
    let mut ip_invalid = use_signal(StaticIpv4Invalid::default);
    let mut restore_ip_focus = use_signal(|| false);
    let mut apply_ip_button_element = use_signal(|| None::<Rc<MountedData>>);
    let mut cancel_ip_button_element = use_signal(|| None::<Rc<MountedData>>);
    let mut confirm_ip_button_element = use_signal(|| None::<Rc<MountedData>>);

    use_effect(move || {
        if restore_ip_focus() && *ip_operation.read() == IpOperation::Idle {
            restore_ip_focus.set(false);
            focus_mounted(apply_ip_button_element.cloned());
        }
    });

    let interfaces_view = interfaces;
    let selected_interface_view = selected_interface();
    let dhcp_mode_view = dhcp_mode();
    let address_view = address();
    let gateway_view = gateway();
    let dns_view = dns();
    let ip_error_view = ip_error();
    let ip_invalid_view = ip_invalid();
    let confirm_ip_view = matches!(*ip_operation.read(), IpOperation::Confirming(_));
    let ip_is_busy = *ip_operation.read() == IpOperation::Applying;
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
                "{} · {}",
                iface_type_label(&snapshot.interface.iface_type),
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

    let request_ip_change = move |event: FormEvent| {
        event.prevent_default();
        if *ip_operation.read() != IpOperation::Idle {
            return;
        }
        let (address, gateway, dns) = (address(), gateway(), dns());
        let form = StaticIpv4Form {
            address: &address,
            gateway: &gateway,
            dns: &dns,
        };
        let invalid = if dhcp_mode() {
            StaticIpv4Invalid::default()
        } else {
            static_ipv4_invalid_fields(form)
        };
        ip_invalid.set(invalid);
        match prepare_ip_change(selected_interface(), dhcp_mode(), form) {
            Ok(change) => {
                ip_error.set(None);
                ip_operation.set(IpOperation::Confirming(change));
            }
            Err(err) => ip_error.set(Some(err)),
        }
    };

    let mut close_ip_confirmation = move || {
        let confirming = matches!(*ip_operation.peek(), IpOperation::Confirming(_));
        if confirming {
            ip_operation.set(IpOperation::Idle);
            restore_ip_focus.set(true);
        }
    };

    let apply_ip = move |_| {
        let Some(client) = client() else {
            return;
        };
        // `disabled` only lands with the next render; a queued second click
        // finds `Applying` here and stops.
        let IpOperation::Confirming(change) = ip_operation() else {
            return;
        };
        ip_operation.set(IpOperation::Applying);
        ip_error.set(None);
        toast.clear();
        spawn(async move {
            let iface = change.iface.clone();
            match apply_ip_config(client.clone(), change).await {
                Ok(config) => {
                    snapshot.with_mut(|snapshot| {
                        if let Some(snapshot) = snapshot {
                            replace_interface_config(snapshot, &iface, config);
                        }
                    });
                    if let Err(err) = refresh_snapshot(client, snapshot).await {
                        ip_error.set(Some(stale_state_message(&err)));
                    }
                    toast.show("Network configuration updated".into());
                }
                Err(err) => {
                    ip_error.set(Some(mutation_failure_message("Network configuration", err)))
                }
            }
            ip_operation.set(IpOperation::Idle);
            restore_ip_focus.set(true);
        });
    };

    rsx! {
        section {
            id: "interfaces-panel",
            role: "tabpanel",
            aria_labelledby: "interfaces-tab",
            hidden: !active,
            // Outside the workspace wrapper so the dialog below is not inert too.
            inert: if blocked { "true" },
            div { class: "interface-layout",
                div { class: "panel",
                    p { class: "eyebrow", "Network hardware" }
                    h2 { "Interfaces" }
                    p { class: "muted mono", "{selected_interface_summary}" }
                    div {
                        class: "interface-list",
                        role: "group",
                        aria_label: "Network interfaces",
                        for interface_snapshot in interfaces_view {
                            Fragment { key: "{interface_snapshot.interface.name}",
                            {
                                let selected = selected_interface_view.as_deref()
                                    == Some(interface_snapshot.interface.name.as_str());
                                let row_class = if selected {
                                    "interface-row selected"
                                } else {
                                    "interface-row"
                                };
                                let iface = interface_snapshot.interface.clone();
                                let iface_kind = iface_type_label(&iface.iface_type);
                                let iface_state = iface_state_label(&iface.state);
                                let address_text = interface_snapshot
                                    .config
                                    .addresses
                                    .first()
                                    .map(ToString::to_string)
                                    .unwrap_or_else(|| "No address".into());
                                let selected_snapshot = interface_snapshot;
                                rsx! {
                                    button {
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
                                                "{iface_kind} · {iface_state}"
                                            }
                                        }
                                        span { class: "mono", "{address_text}" }
                                    }
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
                                // `autofocus` only fires for the first one in a
                                // document's lifetime, so a reopened dialog
                                // would leave focus behind the inert workspace.
                                onmounted: move |event| {
                                    let element = event.data();
                                    cancel_ip_button_element.set(Some(element.clone()));
                                    focus_mounted(Some(element));
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
    }
}

fn security_label(security: &Security) -> &'static str {
    match security {
        Security::Open => "Open",
        Security::Wep => "WEP",
        Security::WpaPsk => "WPA",
        Security::Wpa2Psk => "WPA2",
        Security::Wpa3 => "WPA3",
    }
}

fn iface_type_label(iface_type: &IfaceType) -> &'static str {
    match iface_type {
        IfaceType::Ethernet => "Ethernet",
        IfaceType::Wifi => "Wi-Fi",
        IfaceType::Loopback => "Loopback",
        IfaceType::Other => "Other",
    }
}

fn iface_state_label(state: &IfaceState) -> &'static str {
    match state {
        IfaceState::Up => "Up",
        IfaceState::Down => "Down",
        IfaceState::Unknown => "Unknown",
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

    /// The `inert` value the workspace wrapper is created with, as written to
    /// the webview.
    fn rendered_inert(disconnecting: bool) -> Vec<dioxus::dioxus_core::AttributeValue> {
        use dioxus::dioxus_core::Mutation;
        use netprov_protocol::WifiStatus;

        #[component]
        fn Root(disconnecting: bool) -> Element {
            let client = use_signal(|| None::<SharedClient>);
            let snapshot = use_signal(|| {
                Some(DeviceSnapshot {
                    interfaces: Vec::new(),
                    wifi_status: WifiStatus {
                        ssid: None,
                        signal: None,
                        security: None,
                    },
                })
            });
            rsx! {
                Dashboard {
                    client,
                    snapshot,
                    device_name: "device",
                    device_detail: "peer",
                    disconnecting,
                    connection_error: None,
                    ondisconnect: |_| {},
                }
            }
        }

        VirtualDom::new_with_props(Root, RootProps { disconnecting })
            .rebuild_to_vec()
            .edits
            .into_iter()
            .filter_map(|edit| match edit {
                Mutation::SetAttribute {
                    name: "inert",
                    value,
                    ..
                } => Some(value),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn workspace_is_only_inert_while_blocked() {
        use dioxus::dioxus_core::AttributeValue;

        // Any value, even "false", makes a boolean attribute true in the DOM.
        assert!(
            rendered_inert(false)
                .iter()
                .all(|value| *value == AttributeValue::None)
        );
        assert!(
            rendered_inert(true)
                .iter()
                .any(|value| *value != AttributeValue::None)
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
}
