use crate::operations::{
    DeviceSnapshot, SharedClient, StaticIpv4Invalid, apply_ip_config, connect_selected_wifi,
    mutation_failure_message, prepare_ip_change, replace_interface_config, scan_wifi,
    sort_wifi_networks, static_ipv4_invalid_fields,
};
use dioxus::prelude::*;
use netprov_protocol::{Ipv4Method, Security, StaticIpv4, WifiNetwork};
use std::rc::Rc;

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
#[component]
pub(crate) fn Dashboard(
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
}
