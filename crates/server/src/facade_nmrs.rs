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

async fn find_device_path(
    conn: &zbus::Connection,
    iface: &str,
) -> Result<zbus::zvariant::OwnedObjectPath, NetError> {
    let proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.NetworkManager",
        "/org/freedesktop/NetworkManager",
        "org.freedesktop.NetworkManager",
    ).await.map_err(nm_err)?;
    let path: zbus::zvariant::OwnedObjectPath =
        proxy.call("GetDeviceByIpIface", &(iface,)).await
            .map_err(|_| NetError::InterfaceNotFound(iface.to_string()))?;
    Ok(path)
}

async fn read_method(
    conn: &zbus::Connection,
    dev: &zbus::Proxy<'_>,
) -> Option<Ipv4Method> {
    let active: zbus::zvariant::OwnedObjectPath = dev.get_property("ActiveConnection").await.ok()?;
    if active.as_str() == "/" { return None; }
    let ac = zbus::Proxy::new(
        conn,
        "org.freedesktop.NetworkManager",
        active.as_str(),
        "org.freedesktop.NetworkManager.Connection.Active",
    ).await.ok()?;
    let conn_path: zbus::zvariant::OwnedObjectPath = ac.get_property("Connection").await.ok()?;
    let settings = zbus::Proxy::new(
        conn,
        "org.freedesktop.NetworkManager",
        conn_path.as_str(),
        "org.freedesktop.NetworkManager.Settings.Connection",
    ).await.ok()?;
    let s: std::collections::HashMap<
        String,
        std::collections::HashMap<String, zbus::zvariant::OwnedValue>
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
            ).await.map_err(nm_err)?;
            let devices: Vec<zbus::zvariant::OwnedObjectPath> =
                proxy.call("GetDevices", &()).await.map_err(nm_err)?;
            let mut out = Vec::with_capacity(devices.len());
            for dev_path in devices {
                let dev = zbus::Proxy::new(
                    &self.zbus,
                    "org.freedesktop.NetworkManager",
                    dev_path.as_str(),
                    "org.freedesktop.NetworkManager.Device",
                ).await.map_err(nm_err)?;
                let name: String = dev.get_property("Interface").await.map_err(nm_err)?;
                let dev_type: u32 = dev.get_property("DeviceType").await.map_err(nm_err)?;
                let mac: Option<String> = dev.get_property("HwAddress").await.ok();
                let state: u32 = dev.get_property("State").await.map_err(nm_err)?;

                let iface_type = match dev_type {
                    1 => IfaceType::Ethernet,   // NM_DEVICE_TYPE_ETHERNET
                    2 => IfaceType::Wifi,       // NM_DEVICE_TYPE_WIFI
                    14 => IfaceType::Loopback,  // NM_DEVICE_TYPE_LOOPBACK
                    _ => IfaceType::Other,
                };
                if matches!(iface_type, IfaceType::Loopback) {
                    continue;
                }
                let iface_state = match state {
                    100 => IfaceState::Up,     // activated
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
        }).await.map_err(|_| NetError::Timeout)?
    }

    async fn get_ip_config(&self, iface: &str) -> Result<IpConfig, NetError> {
        tokio::time::timeout(OP_TIMEOUT, async {
            let dev_path = find_device_path(&self.zbus, iface).await?;

            let dev = zbus::Proxy::new(
                &self.zbus,
                "org.freedesktop.NetworkManager",
                dev_path.as_str(),
                "org.freedesktop.NetworkManager.Device",
            ).await.map_err(nm_err)?;

            let ip4_path: zbus::zvariant::OwnedObjectPath =
                dev.get_property("Ip4Config").await.map_err(nm_err)?;

            let method = read_method(&self.zbus, &dev).await.unwrap_or(Ipv4Method::Auto);

            if ip4_path.as_str() == "/" {
                return Ok(IpConfig { method, addresses: vec![], gateway: None, dns: vec![] });
            }
            let ip4 = zbus::Proxy::new(
                &self.zbus,
                "org.freedesktop.NetworkManager",
                ip4_path.as_str(),
                "org.freedesktop.NetworkManager.IP4Config",
            ).await.map_err(nm_err)?;

            let addr_data: Vec<std::collections::HashMap<String, zbus::zvariant::OwnedValue>> =
                ip4.get_property("AddressData").await.map_err(nm_err)?;
            let mut addresses = Vec::new();
            for m in addr_data {
                let addr: String = m.get("address")
                    .and_then(|v| v.try_clone().ok())
                    .and_then(|v| TryInto::try_into(v).ok())
                    .unwrap_or_default();
                let prefix: u32 = m.get("prefix")
                    .and_then(|v| v.try_clone().ok())
                    .and_then(|v| TryInto::try_into(v).ok())
                    .unwrap_or(32);
                if let Ok(a) = format!("{addr}/{prefix}").parse() { addresses.push(a); }
            }

            let gw: String = ip4.get_property("Gateway").await.unwrap_or_default();
            let gateway = gw.parse().ok();

            let nameservers: Vec<u32> = ip4.get_property("Nameservers").await.unwrap_or_default();
            let dns = nameservers.into_iter()
                .map(|n| std::net::Ipv4Addr::from(n.to_le_bytes()))
                .collect();

            Ok::<_, NetError>(IpConfig { method, addresses, gateway, dns })
        }).await.map_err(|_| NetError::Timeout)?
    }

    async fn wifi_status(&self) -> Result<WifiStatus, NetError> {
        // TODO(part-2-nmrs): implement via nmrs API or raw zbus AP lookup.
        Err(NetError::NotSupported)
    }

    async fn scan_wifi(&self) -> Result<Vec<WifiNetwork>, NetError> {
        // TODO(part-2-nmrs): implement via nmrs API.
        Err(NetError::NotSupported)
    }

    async fn set_dhcp(&self, _iface: &str) -> Result<(), NetError> {
        // TODO(part-2-nmrs): use Settings.Connection.Update to set ipv4.method=auto.
        let _guard = self.write_guard.lock().await;
        Err(NetError::NotSupported)
    }

    async fn set_static_ipv4(&self, _iface: &str, _cfg: StaticIpv4) -> Result<(), NetError> {
        // TODO(part-2-nmrs): use Settings.Connection.Update to set ipv4.method=manual + addresses.
        let _guard = self.write_guard.lock().await;
        Err(NetError::NotSupported)
    }

    async fn connect_wifi(&self, _ssid: &str, _cred: WifiCredential) -> Result<(), NetError> {
        // TODO(part-2-nmrs): implement via nmrs or NM AddAndActivateConnection.
        let _guard = self.write_guard.lock().await;
        Err(NetError::NotSupported)
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
        assert!(ifs.iter().any(|i| matches!(i.iface_type, IfaceType::Ethernet | IfaceType::Wifi)),
            "expected at least one Ethernet or Wi-Fi interface, got {ifs:?}");
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
}
