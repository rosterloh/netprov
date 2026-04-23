use async_trait::async_trait;
use netprov_protocol::{Interface, IpConfig, NetError, StaticIpv4, WifiCredential, WifiNetwork, WifiStatus};

#[async_trait]
pub trait NetworkFacade: Send + Sync {
    async fn list_interfaces(&self) -> Result<Vec<Interface>, NetError>;
    async fn get_ip_config(&self, iface: &str) -> Result<IpConfig, NetError>;
    async fn wifi_status(&self) -> Result<WifiStatus, NetError>;
    async fn scan_wifi(&self) -> Result<Vec<WifiNetwork>, NetError>;
    async fn set_dhcp(&self, iface: &str) -> Result<(), NetError>;
    async fn set_static_ipv4(&self, iface: &str, cfg: StaticIpv4) -> Result<(), NetError>;
    async fn connect_wifi(&self, ssid: &str, cred: WifiCredential) -> Result<(), NetError>;
}
