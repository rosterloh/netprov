//! Production NetworkFacade backed by nmrs + raw zbus.
//!
//! All operations are bound by a 30-second timeout per §8.3.

use crate::facade::NetworkFacade;
use async_trait::async_trait;
use netprov_protocol::*;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

pub const OP_TIMEOUT: Duration = Duration::from_secs(30);

pub struct NmrsFacade {
    write_guard: Arc<Mutex<()>>,
    zbus: zbus::Connection,
    _nm: nmrs::NetworkManager,
}

impl NmrsFacade {
    pub async fn new() -> anyhow::Result<Self> {
        let zbus = zbus::Connection::system().await?;
        let nm = nmrs::NetworkManager::new().await?;
        Ok(Self {
            write_guard: Arc::new(Mutex::new(())),
            zbus,
            _nm: nm,
        })
    }
}

fn nm_err<E: std::fmt::Display>(e: E) -> NetError {
    NetError::NetworkManager(e.to_string())
}

async fn find_wifi_device_path(
    conn: &zbus::Connection,
) -> Result<Option<zbus::zvariant::OwnedObjectPath>, NetError> {
    let proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.NetworkManager",
        "/org/freedesktop/NetworkManager",
        "org.freedesktop.NetworkManager",
    )
    .await
    .map_err(nm_err)?;
    let devices: Vec<zbus::zvariant::OwnedObjectPath> =
        proxy.call("GetDevices", &()).await.map_err(nm_err)?;
    for path in devices {
        let dev = zbus::Proxy::new(
            conn,
            "org.freedesktop.NetworkManager",
            path.as_str(),
            "org.freedesktop.NetworkManager.Device",
        )
        .await
        .map_err(nm_err)?;
        let dev_type: u32 = dev.get_property("DeviceType").await.map_err(nm_err)?;
        if dev_type == 2 {
            // NM_DEVICE_TYPE_WIFI
            return Ok(Some(path));
        }
    }
    Ok(None)
}

fn classify_security(flags: u32, wpa: u32, rsn: u32) -> Security {
    // NM_802_11_AP_FLAGS_PRIVACY = 0x1. If no privacy and no WPA/RSN → Open.
    if flags & 0x1 == 0 && wpa == 0 && rsn == 0 {
        return Security::Open;
    }
    // NM_802_11_AP_SEC_KEY_MGMT_SAE = 0x400
    if rsn & 0x400 != 0 {
        return Security::Wpa3;
    }
    if rsn != 0 {
        return Security::Wpa2Psk;
    }
    if wpa != 0 {
        return Security::WpaPsk;
    }
    Security::Wep
}

async fn find_device_path(
    conn: &zbus::Connection,
    iface: &str,
) -> Result<zbus::zvariant::OwnedObjectPath, NetError> {
    let proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.NetworkManager",
        "/org/freedesktop/NetworkManager",
        "org.freedesktop.NetworkManager",
    )
    .await
    .map_err(nm_err)?;
    let path: zbus::zvariant::OwnedObjectPath =
        proxy
            .call("GetDeviceByIpIface", &(iface,))
            .await
            .map_err(|_| NetError::InterfaceNotFound(iface.to_string()))?;
    Ok(path)
}

async fn get_settings_connection_for_iface(
    conn: &zbus::Connection,
    iface: &str,
) -> Result<zbus::zvariant::OwnedObjectPath, NetError> {
    let dev_path = find_device_path(conn, iface).await?;
    let dev = zbus::Proxy::new(
        conn,
        "org.freedesktop.NetworkManager",
        dev_path.as_str(),
        "org.freedesktop.NetworkManager.Device",
    )
    .await
    .map_err(nm_err)?;
    let active: zbus::zvariant::OwnedObjectPath =
        dev.get_property("ActiveConnection").await.map_err(nm_err)?;
    if active.as_str() == "/" {
        return Err(NetError::InvalidArgument(format!(
            "interface {iface} has no active connection"
        )));
    }
    let ac = zbus::Proxy::new(
        conn,
        "org.freedesktop.NetworkManager",
        active.as_str(),
        "org.freedesktop.NetworkManager.Connection.Active",
    )
    .await
    .map_err(nm_err)?;
    let settings: zbus::zvariant::OwnedObjectPath =
        ac.get_property("Connection").await.map_err(nm_err)?;
    Ok(settings)
}

async fn read_method(conn: &zbus::Connection, dev: &zbus::Proxy<'_>) -> Option<Ipv4Method> {
    let active: zbus::zvariant::OwnedObjectPath =
        dev.get_property("ActiveConnection").await.ok()?;
    if active.as_str() == "/" {
        return None;
    }
    let ac = zbus::Proxy::new(
        conn,
        "org.freedesktop.NetworkManager",
        active.as_str(),
        "org.freedesktop.NetworkManager.Connection.Active",
    )
    .await
    .ok()?;
    let conn_path: zbus::zvariant::OwnedObjectPath = ac.get_property("Connection").await.ok()?;
    let settings = zbus::Proxy::new(
        conn,
        "org.freedesktop.NetworkManager",
        conn_path.as_str(),
        "org.freedesktop.NetworkManager.Settings.Connection",
    )
    .await
    .ok()?;
    let s: std::collections::HashMap<
        String,
        std::collections::HashMap<String, zbus::zvariant::OwnedValue>,
    > = settings.call("GetSettings", &()).await.ok()?;
    let m_val = s.get("ipv4")?.get("method")?;
    let m: String = TryInto::try_into(m_val.try_clone().ok()?).ok()?;
    match m.as_str() {
        "auto" => Some(Ipv4Method::Auto),
        "manual" => Some(Ipv4Method::Manual),
        _ => None,
    }
}

#[async_trait]
impl NetworkFacade for NmrsFacade {
    async fn list_interfaces(&self) -> Result<Vec<Interface>, NetError> {
        tokio::time::timeout(OP_TIMEOUT, async {
            let proxy = zbus::Proxy::new(
                &self.zbus,
                "org.freedesktop.NetworkManager",
                "/org/freedesktop/NetworkManager",
                "org.freedesktop.NetworkManager",
            )
            .await
            .map_err(nm_err)?;
            let devices: Vec<zbus::zvariant::OwnedObjectPath> =
                proxy.call("GetDevices", &()).await.map_err(nm_err)?;
            let mut out = Vec::with_capacity(devices.len());
            for dev_path in devices {
                let dev = zbus::Proxy::new(
                    &self.zbus,
                    "org.freedesktop.NetworkManager",
                    dev_path.as_str(),
                    "org.freedesktop.NetworkManager.Device",
                )
                .await
                .map_err(nm_err)?;
                let name: String = dev.get_property("Interface").await.map_err(nm_err)?;
                let dev_type: u32 = dev.get_property("DeviceType").await.map_err(nm_err)?;
                let mac: Option<String> = dev.get_property("HwAddress").await.ok();
                let state: u32 = dev.get_property("State").await.map_err(nm_err)?;

                let iface_type = match dev_type {
                    1 => IfaceType::Ethernet,  // NM_DEVICE_TYPE_ETHERNET
                    2 => IfaceType::Wifi,      // NM_DEVICE_TYPE_WIFI
                    14 => IfaceType::Loopback, // NM_DEVICE_TYPE_LOOPBACK
                    _ => IfaceType::Other,
                };
                if matches!(iface_type, IfaceType::Loopback) {
                    continue;
                }
                let iface_state = match state {
                    100 => IfaceState::Up, // activated
                    20..=30 => IfaceState::Down,
                    _ => IfaceState::Unknown,
                };
                out.push(Interface {
                    name,
                    iface_type,
                    mac,
                    state: iface_state,
                });
            }
            Ok::<_, NetError>(out)
        })
        .await
        .map_err(|_| NetError::Timeout)?
    }

    async fn get_ip_config(&self, iface: &str) -> Result<IpConfig, NetError> {
        tokio::time::timeout(OP_TIMEOUT, async {
            let dev_path = find_device_path(&self.zbus, iface).await?;

            let dev = zbus::Proxy::new(
                &self.zbus,
                "org.freedesktop.NetworkManager",
                dev_path.as_str(),
                "org.freedesktop.NetworkManager.Device",
            )
            .await
            .map_err(nm_err)?;

            let ip4_path: zbus::zvariant::OwnedObjectPath =
                dev.get_property("Ip4Config").await.map_err(nm_err)?;

            let method = read_method(&self.zbus, &dev)
                .await
                .unwrap_or(Ipv4Method::Auto);

            if ip4_path.as_str() == "/" {
                return Ok(IpConfig {
                    method,
                    addresses: vec![],
                    gateway: None,
                    dns: vec![],
                });
            }
            let ip4 = zbus::Proxy::new(
                &self.zbus,
                "org.freedesktop.NetworkManager",
                ip4_path.as_str(),
                "org.freedesktop.NetworkManager.IP4Config",
            )
            .await
            .map_err(nm_err)?;

            let addr_data: Vec<std::collections::HashMap<String, zbus::zvariant::OwnedValue>> =
                ip4.get_property("AddressData").await.map_err(nm_err)?;
            let mut addresses = Vec::new();
            for m in addr_data {
                let addr: String = m
                    .get("address")
                    .and_then(|v| v.try_clone().ok())
                    .and_then(|v| TryInto::try_into(v).ok())
                    .unwrap_or_default();
                let prefix: u32 = m
                    .get("prefix")
                    .and_then(|v| v.try_clone().ok())
                    .and_then(|v| TryInto::try_into(v).ok())
                    .unwrap_or(32);
                if let Ok(a) = format!("{addr}/{prefix}").parse() {
                    addresses.push(a);
                }
            }

            let gw: String = ip4.get_property("Gateway").await.unwrap_or_default();
            let gateway = gw.parse().ok();

            let nameservers: Vec<u32> = ip4.get_property("Nameservers").await.unwrap_or_default();
            let dns = nameservers
                .into_iter()
                .map(|n| std::net::Ipv4Addr::from(n.to_le_bytes()))
                .collect();

            Ok::<_, NetError>(IpConfig {
                method,
                addresses,
                gateway,
                dns,
            })
        })
        .await
        .map_err(|_| NetError::Timeout)?
    }

    async fn wifi_status(&self) -> Result<WifiStatus, NetError> {
        tokio::time::timeout(OP_TIMEOUT, async {
            let wifi_dev = find_wifi_device_path(&self.zbus).await?;
            let wifi_dev = match wifi_dev {
                Some(p) => p,
                None => {
                    return Ok(WifiStatus {
                        ssid: None,
                        signal: None,
                        security: None,
                    })
                }
            };
            let dev = zbus::Proxy::new(
                &self.zbus,
                "org.freedesktop.NetworkManager",
                wifi_dev.as_str(),
                "org.freedesktop.NetworkManager.Device.Wireless",
            )
            .await
            .map_err(nm_err)?;
            let ap_path: zbus::zvariant::OwnedObjectPath = dev
                .get_property("ActiveAccessPoint")
                .await
                .map_err(nm_err)?;
            if ap_path.as_str() == "/" {
                return Ok(WifiStatus {
                    ssid: None,
                    signal: None,
                    security: None,
                });
            }
            let ap = zbus::Proxy::new(
                &self.zbus,
                "org.freedesktop.NetworkManager",
                ap_path.as_str(),
                "org.freedesktop.NetworkManager.AccessPoint",
            )
            .await
            .map_err(nm_err)?;
            let ssid_bytes: Vec<u8> = ap.get_property("Ssid").await.map_err(nm_err)?;
            let ssid = String::from_utf8(ssid_bytes).ok();
            let strength: u8 = ap.get_property("Strength").await.map_err(nm_err)?;
            let flags: u32 = ap.get_property("Flags").await.map_err(nm_err)?;
            let wpa_flags: u32 = ap.get_property("WpaFlags").await.map_err(nm_err)?;
            let rsn_flags: u32 = ap.get_property("RsnFlags").await.map_err(nm_err)?;
            Ok::<_, NetError>(WifiStatus {
                ssid,
                signal: Some(strength),
                security: Some(classify_security(flags, wpa_flags, rsn_flags)),
            })
        })
        .await
        .map_err(|_| NetError::Timeout)?
    }

    async fn scan_wifi(&self) -> Result<Vec<WifiNetwork>, NetError> {
        tokio::time::timeout(OP_TIMEOUT, async {
            let wifi_path = find_wifi_device_path(&self.zbus)
                .await?
                .ok_or(NetError::NotSupported)?;
            let dev = zbus::Proxy::new(
                &self.zbus,
                "org.freedesktop.NetworkManager",
                wifi_path.as_str(),
                "org.freedesktop.NetworkManager.Device.Wireless",
            )
            .await
            .map_err(nm_err)?;
            let before: i64 = dev.get_property("LastScan").await.unwrap_or(0);

            // RequestScan takes a dict of options; empty dict is fine.
            let opts: std::collections::HashMap<&str, zbus::zvariant::Value<'_>> =
                std::collections::HashMap::new();
            dev.call::<_, _, ()>("RequestScan", &(opts,))
                .await
                .map_err(nm_err)?;

            // Poll LastScan up to 10 seconds.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                let now: i64 = dev.get_property("LastScan").await.unwrap_or(0);
                if now != before {
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    return Err(NetError::Timeout);
                }
            }

            let aps: Vec<zbus::zvariant::OwnedObjectPath> =
                dev.call("GetAccessPoints", &()).await.map_err(nm_err)?;
            let mut out = Vec::with_capacity(aps.len());
            for ap_path in aps {
                let ap = zbus::Proxy::new(
                    &self.zbus,
                    "org.freedesktop.NetworkManager",
                    ap_path.as_str(),
                    "org.freedesktop.NetworkManager.AccessPoint",
                )
                .await
                .map_err(nm_err)?;
                let ssid_bytes: Vec<u8> = ap.get_property("Ssid").await.unwrap_or_default();
                let ssid = String::from_utf8(ssid_bytes).unwrap_or_default();
                if ssid.is_empty() {
                    continue; // skip hidden networks
                }
                let strength: u8 = ap.get_property("Strength").await.unwrap_or(0);
                let flags: u32 = ap.get_property("Flags").await.unwrap_or(0);
                let wpa: u32 = ap.get_property("WpaFlags").await.unwrap_or(0);
                let rsn: u32 = ap.get_property("RsnFlags").await.unwrap_or(0);
                let bssid: String = ap.get_property("HwAddress").await.unwrap_or_default();
                out.push(WifiNetwork {
                    ssid,
                    signal: Some(strength),
                    security: Some(classify_security(flags, wpa, rsn)),
                    bssid,
                });
            }
            Ok::<_, NetError>(out)
        })
        .await
        .map_err(|_| NetError::Timeout)?
    }

    async fn set_dhcp(&self, iface: &str) -> Result<(), NetError> {
        let _guard = self.write_guard.lock().await;
        tokio::time::timeout(OP_TIMEOUT, async {
            let settings_path = get_settings_connection_for_iface(&self.zbus, iface).await?;
            let settings = zbus::Proxy::new(
                &self.zbus,
                "org.freedesktop.NetworkManager",
                settings_path.as_str(),
                "org.freedesktop.NetworkManager.Settings.Connection",
            )
            .await
            .map_err(nm_err)?;

            use zbus::zvariant::Value;
            let mut existing: std::collections::HashMap<
                String,
                std::collections::HashMap<String, zbus::zvariant::OwnedValue>,
            > = settings.call("GetSettings", &()).await.map_err(nm_err)?;
            let ipv4 = existing.entry("ipv4".into()).or_default();
            ipv4.insert(
                "method".into(),
                Value::from("auto").try_into().map_err(nm_err)?,
            );
            ipv4.remove("addresses");
            ipv4.remove("address-data");
            ipv4.remove("gateway");
            ipv4.remove("dns");

            settings
                .call::<_, _, ()>("Update", &(existing,))
                .await
                .map_err(nm_err)?;

            // Re-activate so the new method takes effect.
            let dev = find_device_path(&self.zbus, iface).await?;
            let nm = zbus::Proxy::new(
                &self.zbus,
                "org.freedesktop.NetworkManager",
                "/org/freedesktop/NetworkManager",
                "org.freedesktop.NetworkManager",
            )
            .await
            .map_err(nm_err)?;
            let specific: zbus::zvariant::ObjectPath = "/".try_into().map_err(nm_err)?;
            nm.call::<_, _, zbus::zvariant::OwnedObjectPath>(
                "ActivateConnection",
                &(settings_path, dev, specific),
            )
            .await
            .map_err(nm_err)?;
            Ok::<(), NetError>(())
        })
        .await
        .map_err(|_| NetError::Timeout)?
    }

    async fn set_static_ipv4(&self, iface: &str, cfg: StaticIpv4) -> Result<(), NetError> {
        let _guard = self.write_guard.lock().await;
        tokio::time::timeout(OP_TIMEOUT, async {
            let settings_path = get_settings_connection_for_iface(&self.zbus, iface).await?;
            let settings = zbus::Proxy::new(
                &self.zbus,
                "org.freedesktop.NetworkManager",
                settings_path.as_str(),
                "org.freedesktop.NetworkManager.Settings.Connection",
            )
            .await
            .map_err(nm_err)?;

            use zbus::zvariant::Value;
            let mut existing: std::collections::HashMap<
                String,
                std::collections::HashMap<String, zbus::zvariant::OwnedValue>,
            > = settings.call("GetSettings", &()).await.map_err(nm_err)?;

            // AddressData entry: [{"address": "1.2.3.4", "prefix": 24}]
            let mut ad = std::collections::HashMap::new();
            ad.insert(
                "address".to_string(),
                Value::from(cfg.address.addr().to_string())
                    .try_into()
                    .map_err(nm_err)?,
            );
            ad.insert(
                "prefix".to_string(),
                Value::from(cfg.address.prefix_len() as u32)
                    .try_into()
                    .map_err(nm_err)?,
            );
            let addr_data: Vec<std::collections::HashMap<String, zbus::zvariant::OwnedValue>> =
                vec![ad];

            let ipv4 = existing.entry("ipv4".into()).or_default();
            ipv4.insert(
                "method".into(),
                Value::from("manual").try_into().map_err(nm_err)?,
            );
            ipv4.insert(
                "address-data".into(),
                Value::from(addr_data).try_into().map_err(nm_err)?,
            );
            if let Some(gw) = cfg.gateway {
                ipv4.insert(
                    "gateway".into(),
                    Value::from(gw.to_string()).try_into().map_err(nm_err)?,
                );
            } else {
                ipv4.remove("gateway");
            }
            // NM's legacy `dns` field: array of u32 in NETWORK byte order (big-endian host byte order
            // interpretation on the wire, native byte order in D-Bus per NM docs — but in practice
            // NM treats `a.b.c.d` as `((a<<24)|(b<<16)|(c<<8)|d)` written as `u32::from_be_bytes([a,b,c,d])`
            // once ActivateConnection consumes the dict. Using little-endian flips the octets,
            // so use big-endian here.)
            let dns_u32: Vec<u32> = cfg
                .dns
                .iter()
                .map(|ip| u32::from_be_bytes(ip.octets()))
                .collect();
            ipv4.insert(
                "dns".into(),
                Value::from(dns_u32).try_into().map_err(nm_err)?,
            );

            settings
                .call::<_, _, ()>("Update", &(existing,))
                .await
                .map_err(nm_err)?;

            let dev = find_device_path(&self.zbus, iface).await?;
            let nm = zbus::Proxy::new(
                &self.zbus,
                "org.freedesktop.NetworkManager",
                "/org/freedesktop/NetworkManager",
                "org.freedesktop.NetworkManager",
            )
            .await
            .map_err(nm_err)?;
            let specific: zbus::zvariant::ObjectPath = "/".try_into().map_err(nm_err)?;
            nm.call::<_, _, zbus::zvariant::OwnedObjectPath>(
                "ActivateConnection",
                &(settings_path, dev, specific),
            )
            .await
            .map_err(nm_err)?;
            Ok::<(), NetError>(())
        })
        .await
        .map_err(|_| NetError::Timeout)?
    }

    async fn connect_wifi(&self, ssid: &str, cred: WifiCredential) -> Result<(), NetError> {
        let _guard = self.write_guard.lock().await;
        tokio::time::timeout(OP_TIMEOUT, async {
            let wifi_path = find_wifi_device_path(&self.zbus)
                .await?
                .ok_or(NetError::NotSupported)?;

            use zbus::zvariant::{OwnedValue, Value};

            let (key_mgmt, psk) = match cred {
                WifiCredential::Open => ("none", None),
                WifiCredential::WpaPsk(p) | WifiCredential::Wpa2Psk(p) => ("wpa-psk", Some(p)),
                WifiCredential::Wpa3(p) => ("sae", Some(p)),
            };

            let mut conn: std::collections::HashMap<
                String,
                std::collections::HashMap<String, Value<'_>>,
            > = std::collections::HashMap::new();

            let mut connection = std::collections::HashMap::new();
            connection.insert("id".to_string(), Value::from(ssid));
            connection.insert("type".to_string(), Value::from("802-11-wireless"));
            conn.insert("connection".to_string(), connection);

            let mut wireless = std::collections::HashMap::new();
            wireless.insert("ssid".to_string(), Value::from(ssid.as_bytes().to_vec()));
            wireless.insert("mode".to_string(), Value::from("infrastructure"));
            conn.insert("802-11-wireless".to_string(), wireless);

            if key_mgmt != "none" {
                let mut sec = std::collections::HashMap::new();
                sec.insert("key-mgmt".to_string(), Value::from(key_mgmt));
                if let Some(p) = psk {
                    sec.insert("psk".to_string(), Value::from(p));
                }
                conn.insert("802-11-wireless-security".to_string(), sec);
            }

            let mut ipv4 = std::collections::HashMap::new();
            ipv4.insert("method".to_string(), Value::from("auto"));
            conn.insert("ipv4".to_string(), ipv4);

            let nm = zbus::Proxy::new(
                &self.zbus,
                "org.freedesktop.NetworkManager",
                "/org/freedesktop/NetworkManager",
                "org.freedesktop.NetworkManager",
            )
            .await
            .map_err(nm_err)?;

            // AddAndActivateConnection args:
            //   connection (a{sa{sv}})     — the settings dict built above
            //   device     (o)             — the wireless device path
            //   specific_object (o)        — use "/" for "no preference"
            // Returns a tuple (o, o): (new_connection_path, active_connection_path).
            let specific: zbus::zvariant::ObjectPath = "/".try_into().map_err(nm_err)?;
            let _: (OwnedValue, OwnedValue) = nm
                .call("AddAndActivateConnection", &(conn, wifi_path, specific))
                .await
                .map_err(nm_err)?;
            Ok::<(), NetError>(())
        })
        .await
        .map_err(|_| NetError::Timeout)?
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires NetworkManager on system bus"]
    async fn list_interfaces_live() {
        let f = NmrsFacade::new().await.expect("connect NM");
        let ifs = f.list_interfaces().await.expect("list");
        assert!(
            ifs.iter()
                .any(|i| matches!(i.iface_type, IfaceType::Ethernet | IfaceType::Wifi)),
            "expected at least one Ethernet or Wi-Fi interface, got {ifs:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires NetworkManager with an active wired or wireless interface"]
    async fn get_ip_config_live() {
        let f = NmrsFacade::new().await.unwrap();
        let ifs = f.list_interfaces().await.unwrap();
        let iface = ifs.first().expect("at least one interface");
        let cfg = f.get_ip_config(&iface.name).await.unwrap();
        println!("{cfg:?}");
    }

    #[tokio::test]
    #[ignore = "requires Wi-Fi adapter with an active AP"]
    async fn wifi_status_live() {
        let f = NmrsFacade::new().await.unwrap();
        let st = f.wifi_status().await.unwrap();
        println!("{st:?}");
    }

    #[tokio::test]
    #[ignore = "requires Wi-Fi adapter"]
    async fn wifi_scan_live() {
        let f = NmrsFacade::new().await.unwrap();
        let nets = f.scan_wifi().await.unwrap();
        println!("scanned {} networks", nets.len());
        for n in &nets {
            println!("  {n:?}");
        }
        assert!(!nets.is_empty());
    }

    #[tokio::test]
    #[ignore = "destructive; requires live-nm-destructive and a throwaway box"]
    #[cfg(feature = "live-nm-destructive")]
    async fn set_dhcp_live() {
        let f = NmrsFacade::new().await.unwrap();
        let ifs = f.list_interfaces().await.unwrap();
        let eth = ifs
            .iter()
            .find(|i| matches!(i.iface_type, IfaceType::Ethernet))
            .expect("need at least one Ethernet interface");
        f.set_dhcp(&eth.name).await.unwrap();
    }
}
