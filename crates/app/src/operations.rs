use netprov_protocol::{
    Interface, IpConfig, Ipv4Method, PSK_LEN, Security, StaticIpv4, WifiCredential, WifiNetwork,
    WifiStatus,
};
use netprov_sdk::{BleClient, BleDevice, Netprov, parse_peer_id};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

const CONVERGENCE_POLL_INTERVAL: Duration = Duration::from_millis(500);
const CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum MutationFailure {
    Validation(String),
    Request(String),
    Confirmation(String),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct StaticIpv4Invalid {
    pub(crate) address: bool,
    pub(crate) gateway: bool,
    pub(crate) dns: bool,
}

/// One row in the device picker.
///
/// `id` is the opaque backend handle to connect with; `detail` is the
/// human-facing second line — the MAC where the platform discloses one, and
/// the handle itself on macOS, where it never does.
#[derive(Clone, PartialEq)]
pub(crate) struct DeviceSummary {
    pub(crate) id: String,
    pub(crate) label: String,
    pub(crate) detail: String,
    pub(crate) rssi: Option<i16>,
}

#[derive(Clone, PartialEq)]
pub(crate) struct DeviceSnapshot {
    pub(crate) interfaces: Vec<InterfaceSnapshot>,
    pub(crate) wifi_status: WifiStatus,
}

#[derive(Clone, PartialEq)]
pub(crate) struct InterfaceSnapshot {
    pub(crate) interface: Interface,
    pub(crate) config: IpConfig,
}

pub(crate) type SharedClient = Arc<Mutex<Netprov<BleClient>>>;

pub(crate) fn static_ipv4_invalid_fields(
    address: &str,
    gateway: &str,
    dns: &str,
) -> StaticIpv4Invalid {
    let address = address.trim().parse();
    let gateway = gateway.trim();
    let gateway = match gateway {
        "" => Ok(None),
        value => value.parse().map(Some),
    };
    let dns = dns
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let has_dns = dns.clone().next().is_some();
    let dns = dns.map(str::parse).collect::<Result<Vec<_>, _>>();

    let address_invalid = address.as_ref().map_or(true, |address| {
        static_ipv4_invalid(&StaticIpv4 {
            address: *address,
            gateway: None,
            dns: Vec::new(),
        })
        .address
    });
    let gateway_invalid = match (address.as_ref(), gateway.as_ref()) {
        (_, Err(_)) => true,
        (Ok(address), Ok(gateway)) => {
            static_ipv4_invalid(&StaticIpv4 {
                address: *address,
                gateway: *gateway,
                dns: Vec::new(),
            })
            .gateway
        }
        (Err(_), Ok(_)) => false,
    };
    let dns_invalid = !has_dns
        || dns
            .as_ref()
            .map_or(true, |dns| dns.iter().any(invalid_dns_address));

    StaticIpv4Invalid {
        address: address_invalid,
        gateway: gateway_invalid,
        dns: dns_invalid,
    }
}

fn invalid_dns_address(address: &Ipv4Addr) -> bool {
    address.is_unspecified() || address.is_multicast() || address.is_broadcast()
}

fn static_ipv4_invalid(config: &StaticIpv4) -> StaticIpv4Invalid {
    let address = config.address.addr();
    let prefix = config.address.prefix_len();

    StaticIpv4Invalid {
        address: !(1..=30).contains(&prefix)
            || address.is_loopback()
            || address.is_multicast()
            || address.is_broadcast()
            || address.is_unspecified()
            || address == config.address.broadcast()
            || address == config.address.network(),
        gateway: config
            .gateway
            .is_some_and(|gateway| !config.address.contains(&gateway) || gateway == address),
        dns: config.dns.iter().any(invalid_dns_address),
    }
}

fn wifi_converged(status: &WifiStatus, requested_ssid: &str) -> bool {
    status.ssid.as_deref() == Some(requested_ssid)
}

fn ip_config_converged(actual: &IpConfig, requested: Option<&StaticIpv4>) -> bool {
    match requested {
        None => actual.method == Ipv4Method::Auto,
        Some(requested) => {
            let mut actual_dns = actual.dns.clone();
            let mut requested_dns = requested.dns.clone();
            actual_dns.sort_unstable();
            requested_dns.sort_unstable();

            actual.method == Ipv4Method::Manual
                && actual.addresses.len() == 1
                && actual.addresses.first() == Some(&requested.address)
                && actual.gateway == requested.gateway
                && actual_dns == requested_dns
        }
    }
}

pub(crate) fn mutation_failure_message(subject: &str, failure: MutationFailure) -> String {
    match failure {
        MutationFailure::Validation(message) => message,
        MutationFailure::Request(message) => format!("{subject} request failed: {message}"),
        MutationFailure::Confirmation(message) => {
            format!("{subject} request was accepted, but confirmation failed: {message}")
        }
    }
}

pub(crate) async fn scan_ble_devices() -> Result<Vec<DeviceSummary>, String> {
    let devices = BleClient::scan_devices(Duration::from_secs(8))
        .await
        .map_err(|err| err.to_string())?;
    Ok(devices.into_iter().map(DeviceSummary::from).collect())
}

pub(crate) async fn scan_wifi(client: SharedClient) -> Result<Vec<WifiNetwork>, String> {
    client
        .lock()
        .await
        .wifi_scan()
        .await
        .map_err(|err| err.to_string())
}

pub(crate) async fn connect_selected_wifi(
    client: SharedClient,
    network: WifiNetwork,
    password: String,
) -> Result<WifiStatus, MutationFailure> {
    let credential = wifi_credential(network.security.as_ref(), &password)
        .map_err(MutationFailure::Validation)?;
    let requested_ssid = network.ssid;
    let mut client = client.lock().await;
    client
        .connect_wifi(requested_ssid.clone(), credential)
        .await
        .map_err(|err| MutationFailure::Request(err.to_string()))?;

    tokio::time::timeout(CONVERGENCE_TIMEOUT, async {
        loop {
            let status = client.wifi_status().await.map_err(|err| err.to_string())?;
            if wifi_converged(&status, &requested_ssid) {
                return Ok(status);
            }
            tokio::time::sleep(CONVERGENCE_POLL_INTERVAL).await;
        }
    })
    .await
    .map_err(|_| {
        MutationFailure::Confirmation(format!(
            "timed out after {} seconds",
            CONVERGENCE_TIMEOUT.as_secs()
        ))
    })?
    .map_err(MutationFailure::Confirmation)
}

pub(crate) fn sort_wifi_networks(networks: &mut [WifiNetwork]) {
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
    let config = StaticIpv4 {
        address,
        gateway,
        dns,
    };
    let invalid = static_ipv4_invalid(&config);
    if invalid.address {
        return Err("Enter a valid IPv4 address and CIDR prefix.".into());
    }
    if invalid.gateway {
        return Err("Enter a valid IPv4 gateway.".into());
    }
    if invalid.dns {
        return Err("Enter valid comma-separated DNS addresses.".into());
    }
    Ok(config)
}

pub(crate) fn prepare_ip_change(
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

pub(crate) async fn apply_ip_config(
    client: SharedClient,
    iface: String,
    config: Option<StaticIpv4>,
) -> Result<IpConfig, MutationFailure> {
    let mut client = client.lock().await;
    let requested = config.clone();
    match config {
        Some(config) => client
            .set_static_ipv4(iface.clone(), config)
            .await
            .map_err(|err| MutationFailure::Request(err.to_string()))?,
        None => client
            .set_dhcp(iface.clone())
            .await
            .map_err(|err| MutationFailure::Request(err.to_string()))?,
    }

    tokio::time::timeout(CONVERGENCE_TIMEOUT, async {
        loop {
            let config = client
                .get_ip_config(iface.clone())
                .await
                .map_err(|err| err.to_string())?;
            if ip_config_converged(&config, requested.as_ref()) {
                return Ok(config);
            }
            tokio::time::sleep(CONVERGENCE_POLL_INTERVAL).await;
        }
    })
    .await
    .map_err(|_| {
        MutationFailure::Confirmation(format!(
            "timed out after {} seconds",
            CONVERGENCE_TIMEOUT.as_secs()
        ))
    })?
    .map_err(MutationFailure::Confirmation)
}

pub(crate) fn replace_interface_config(
    snapshot: &mut DeviceSnapshot,
    iface: &str,
    config: IpConfig,
) {
    if let Some(interface) = snapshot
        .interfaces
        .iter_mut()
        .find(|snapshot| snapshot.interface.name == iface)
    {
        interface.config = config;
    }
}

pub(crate) async fn connect_device(
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
    // Best-effort: an older daemon has no Current Time Service, and a clock
    // sync must never block provisioning — this is the whole point of #32,
    // "the user never thinks about it".
    let _ = client.inner().set_time(std::time::SystemTime::now()).await;
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

pub(crate) async fn disconnect_device(client: SharedClient) -> Result<(), String> {
    let client = client.lock().await;
    client
        .inner()
        .disconnect()
        .await
        .map_err(|err| err.to_string())
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
    fn rejects_static_ipv4_configs_rejected_by_server() {
        for (address, gateway, dns) in [
            ("10.0.0.1/0", "", "1.1.1.1"),
            ("10.0.0.1/31", "", "1.1.1.1"),
            ("10.0.0.1/32", "", "1.1.1.1"),
            ("127.0.0.2/8", "", "1.1.1.1"),
            ("224.0.0.1/24", "", "1.1.1.1"),
            ("255.255.255.255/24", "", "1.1.1.1"),
            ("0.0.0.0/8", "", "1.1.1.1"),
            ("192.168.1.255/24", "", "1.1.1.1"),
            ("192.168.1.0/24", "", "1.1.1.1"),
            ("192.168.1.10/24", "10.0.0.1", "1.1.1.1"),
            ("192.168.1.10/24", "192.168.1.10", "1.1.1.1"),
            ("192.168.1.10/24", "", "0.0.0.0"),
            ("192.168.1.10/24", "", "224.0.0.1"),
            ("192.168.1.10/24", "", "255.255.255.255"),
        ] {
            assert!(
                parse_static_ipv4(address, gateway, dns).is_err(),
                "server-invalid config accepted: {address}, {gateway}, {dns}"
            );
        }
    }

    #[test]
    fn accepts_static_ipv4_configs_accepted_by_server() {
        for (address, gateway, dns) in [
            ("10.0.0.1/1", "", "127.0.0.1"),
            ("10.0.0.1/30", "10.0.0.2", "1.1.1.1"),
        ] {
            assert!(
                parse_static_ipv4(address, gateway, dns).is_ok(),
                "server-valid config rejected: {address}, {gateway}, {dns}"
            );
        }
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

    #[test]
    fn static_ipv4_invalid_state_is_field_specific() {
        let invalid = static_ipv4_invalid_fields("not-an-address", "192.168.1.1", "1.1.1.1");
        assert!(invalid.address);
        assert!(!invalid.gateway);
        assert!(!invalid.dns);

        let invalid =
            static_ipv4_invalid_fields("192.168.1.20/24", "not-a-gateway", "not-a-dns-address");
        assert!(!invalid.address);
        assert!(invalid.gateway);
        assert!(invalid.dns);

        let invalid = static_ipv4_invalid_fields("192.168.1.0/24", "192.168.1.1", "1.1.1.1");
        assert!(invalid.address);
        assert!(!invalid.gateway);
        assert!(!invalid.dns);

        let invalid = static_ipv4_invalid_fields("192.168.1.20/24", "10.0.0.1", "1.1.1.1");
        assert!(!invalid.address);
        assert!(invalid.gateway);
        assert!(!invalid.dns);

        let invalid = static_ipv4_invalid_fields("192.168.1.20/24", "192.168.1.1", "224.0.0.1");
        assert!(!invalid.address);
        assert!(!invalid.gateway);
        assert!(invalid.dns);

        let invalid =
            static_ipv4_invalid_fields("192.168.1.0/24", "not-a-gateway", "not-a-dns-address");
        assert!(invalid.address);
        assert!(invalid.gateway);
        assert!(invalid.dns);
    }

    #[test]
    fn wifi_convergence_requires_the_requested_ssid() {
        let status = WifiStatus {
            ssid: Some("Workshop".into()),
            signal: Some(80),
            security: Some(Security::Wpa2Psk),
        };

        assert!(wifi_converged(&status, "Workshop"));
        assert!(!wifi_converged(&status, "Guest"));
    }

    #[test]
    fn ip_convergence_matches_static_fields_with_unordered_dns() {
        let requested = StaticIpv4 {
            address: "192.168.2.10/24".parse().unwrap(),
            gateway: Some("192.168.2.1".parse().unwrap()),
            dns: vec!["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()],
        };
        let actual = IpConfig {
            method: Ipv4Method::Manual,
            addresses: vec!["192.168.2.10/24".parse().unwrap()],
            gateway: Some("192.168.2.1".parse().unwrap()),
            dns: vec!["8.8.8.8".parse().unwrap(), "1.1.1.1".parse().unwrap()],
        };

        assert!(ip_config_converged(&actual, Some(&requested)));

        let mut wrong_gateway = actual.clone();
        wrong_gateway.gateway = Some("192.168.2.254".parse().unwrap());
        assert!(!ip_config_converged(&wrong_gateway, Some(&requested)));

        let automatic = IpConfig {
            method: Ipv4Method::Auto,
            addresses: vec!["10.0.0.20/24".parse().unwrap()],
            gateway: Some("10.0.0.1".parse().unwrap()),
            dns: vec!["10.0.0.1".parse().unwrap()],
        };
        assert!(ip_config_converged(&automatic, None));
    }

    #[test]
    fn mutation_failure_message_distinguishes_request_and_confirmation() {
        assert_eq!(
            mutation_failure_message(
                "Wi-Fi connection",
                MutationFailure::Request("radio unavailable".into()),
            ),
            "Wi-Fi connection request failed: radio unavailable"
        );
        assert_eq!(
            mutation_failure_message(
                "Wi-Fi connection",
                MutationFailure::Confirmation("timed out".into()),
            ),
            "Wi-Fi connection request was accepted, but confirmation failed: timed out"
        );
    }
}
