use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IfaceType {
    Ethernet,
    Wifi,
    Loopback,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IfaceState {
    Up,
    Down,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interface {
    pub name: String,
    pub iface_type: IfaceType,
    pub mac: Option<String>,
    pub state: IfaceState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ipv4Method {
    Auto,
    Manual,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpConfig {
    pub method: Ipv4Method,
    pub addresses: Vec<Ipv4Net>,
    pub gateway: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Security {
    Open,
    Wep,
    WpaPsk,
    Wpa2Psk,
    Wpa3,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WifiNetwork {
    pub ssid: String,
    pub signal: Option<u8>,
    pub security: Option<Security>,
    pub bssid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WifiStatus {
    pub ssid: Option<String>,
    pub signal: Option<u8>,
    pub security: Option<Security>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticIpv4 {
    pub address: Ipv4Net,
    pub gateway: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WifiCredential {
    Open,
    WpaPsk(String),
    Wpa2Psk(String),
    Wpa3(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iface_type_roundtrip() {
        for t in [
            IfaceType::Ethernet,
            IfaceType::Wifi,
            IfaceType::Loopback,
            IfaceType::Other,
        ] {
            let bytes = {
                let mut v = Vec::new();
                ciborium::into_writer(&t, &mut v).unwrap();
                v
            };
            let back: IfaceType = ciborium::from_reader(&bytes[..]).unwrap();
            assert_eq!(t, back);
        }
    }

    #[test]
    fn ip_config_roundtrip() {
        let cfg = IpConfig {
            method: Ipv4Method::Manual,
            addresses: vec!["192.168.1.10/24".parse().unwrap()],
            gateway: Some("192.168.1.1".parse().unwrap()),
            dns: vec!["1.1.1.1".parse().unwrap()],
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&cfg, &mut bytes).unwrap();
        let back: IpConfig = ciborium::from_reader(&bytes[..]).unwrap();
        assert_eq!(cfg, back);
    }
}
