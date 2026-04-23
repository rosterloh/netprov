use crate::facade::NetworkFacade;
use async_trait::async_trait;
use netprov_protocol::*;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;

/// A deterministic, in-memory NetworkFacade for tests. Not stable across
/// process restarts — pure test double.
pub struct MockFacade {
    inner: Mutex<MockState>,
}

struct MockState {
    interfaces: Vec<Interface>,
    ip_configs: HashMap<String, IpConfig>,
    scan: Vec<WifiNetwork>,
    wifi_status: WifiStatus,
    inject_error: Option<NetError>,
}

impl Default for MockFacade {
    fn default() -> Self {
        Self::new()
    }
}

impl MockFacade {
    pub fn new() -> Self {
        let interfaces = vec![
            Interface {
                name: "eth0".into(),
                iface_type: IfaceType::Ethernet,
                mac: Some("aa:bb:cc:00:11:22".into()),
                state: IfaceState::Up,
            },
            Interface {
                name: "wlan0".into(),
                iface_type: IfaceType::Wifi,
                mac: Some("aa:bb:cc:00:11:33".into()),
                state: IfaceState::Up,
            },
        ];
        let mut ip_configs = HashMap::new();
        ip_configs.insert(
            "eth0".into(),
            IpConfig {
                method: Ipv4Method::Auto,
                addresses: vec!["192.168.1.50/24".parse().unwrap()],
                gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
                dns: vec![Ipv4Addr::new(1, 1, 1, 1)],
            },
        );
        ip_configs.insert(
            "wlan0".into(),
            IpConfig {
                method: Ipv4Method::Auto,
                addresses: vec![],
                gateway: None,
                dns: vec![],
            },
        );

        Self {
            inner: Mutex::new(MockState {
                interfaces,
                ip_configs,
                scan: vec![WifiNetwork {
                    ssid: "HomeWifi".into(),
                    signal: Some(80),
                    security: Some(Security::Wpa2Psk),
                    bssid: "de:ad:be:ef:00:01".into(),
                }],
                wifi_status: WifiStatus {
                    ssid: None,
                    signal: None,
                    security: None,
                },
                inject_error: None,
            }),
        }
    }

    pub fn inject_error(&self, e: NetError) {
        self.inner.lock().unwrap().inject_error = Some(e);
    }

    pub fn clear_error(&self) {
        self.inner.lock().unwrap().inject_error = None;
    }
}

fn take_injected(s: &mut MockState) -> Option<NetError> {
    s.inject_error.take()
}

#[async_trait]
impl NetworkFacade for MockFacade {
    async fn list_interfaces(&self) -> Result<Vec<Interface>, NetError> {
        let mut s = self.inner.lock().unwrap();
        if let Some(e) = take_injected(&mut s) {
            return Err(e);
        }
        Ok(s.interfaces.clone())
    }

    async fn get_ip_config(&self, iface: &str) -> Result<IpConfig, NetError> {
        let mut s = self.inner.lock().unwrap();
        if let Some(e) = take_injected(&mut s) {
            return Err(e);
        }
        s.ip_configs
            .get(iface)
            .cloned()
            .ok_or_else(|| NetError::InterfaceNotFound(iface.to_string()))
    }

    async fn wifi_status(&self) -> Result<WifiStatus, NetError> {
        let mut s = self.inner.lock().unwrap();
        if let Some(e) = take_injected(&mut s) {
            return Err(e);
        }
        Ok(s.wifi_status.clone())
    }

    async fn scan_wifi(&self) -> Result<Vec<WifiNetwork>, NetError> {
        let mut s = self.inner.lock().unwrap();
        if let Some(e) = take_injected(&mut s) {
            return Err(e);
        }
        Ok(s.scan.clone())
    }

    async fn set_dhcp(&self, iface: &str) -> Result<(), NetError> {
        let mut s = self.inner.lock().unwrap();
        if let Some(e) = take_injected(&mut s) {
            return Err(e);
        }
        let cfg = s
            .ip_configs
            .get_mut(iface)
            .ok_or_else(|| NetError::InterfaceNotFound(iface.to_string()))?;
        cfg.method = Ipv4Method::Auto;
        cfg.addresses.clear();
        cfg.gateway = None;
        cfg.dns.clear();
        Ok(())
    }

    async fn set_static_ipv4(&self, iface: &str, new: StaticIpv4) -> Result<(), NetError> {
        let mut s = self.inner.lock().unwrap();
        if let Some(e) = take_injected(&mut s) {
            return Err(e);
        }
        let cfg = s
            .ip_configs
            .get_mut(iface)
            .ok_or_else(|| NetError::InterfaceNotFound(iface.to_string()))?;
        cfg.method = Ipv4Method::Manual;
        cfg.addresses = vec![new.address];
        cfg.gateway = new.gateway;
        cfg.dns = new.dns;
        Ok(())
    }

    async fn connect_wifi(&self, ssid: &str, _cred: WifiCredential) -> Result<(), NetError> {
        let mut s = self.inner.lock().unwrap();
        if let Some(e) = take_injected(&mut s) {
            return Err(e);
        }
        s.wifi_status = WifiStatus {
            ssid: Some(ssid.to_string()),
            signal: Some(70),
            security: Some(Security::Wpa2Psk),
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn list_interfaces_default() {
        let m = MockFacade::new();
        let ifs = m.list_interfaces().await.unwrap();
        assert_eq!(ifs.len(), 2);
    }

    #[tokio::test]
    async fn set_dhcp_clears_static_fields() {
        let m = MockFacade::new();
        m.set_dhcp("eth0").await.unwrap();
        let cfg = m.get_ip_config("eth0").await.unwrap();
        assert!(matches!(cfg.method, Ipv4Method::Auto));
        assert!(cfg.addresses.is_empty());
        assert!(cfg.gateway.is_none());
    }

    #[tokio::test]
    async fn unknown_interface_returns_error() {
        let m = MockFacade::new();
        let err = m.set_dhcp("bogus0").await.unwrap_err();
        assert!(matches!(err, NetError::InterfaceNotFound(_)));
    }

    #[tokio::test]
    async fn injected_error_is_returned_once() {
        let m = MockFacade::new();
        m.inject_error(NetError::Timeout);
        let err = m.list_interfaces().await.unwrap_err();
        assert!(matches!(err, NetError::Timeout));
        // Subsequent calls succeed — injected error is one-shot.
        assert!(m.list_interfaces().await.is_ok());
    }
}
