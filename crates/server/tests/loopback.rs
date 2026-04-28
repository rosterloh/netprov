//! End-to-end loopback tests: client ↔ server over tokio::io::duplex,
//! driving MockFacade. No BLE, no NetworkManager.

use netprov_client::Client;
use netprov_protocol::*;
use netprov_server::{MockFacade, RateLimiter, ServerConfig, run_server};
use std::sync::Arc;

fn spawn_pair(psk: Psk) -> Client<tokio::io::DuplexStream> {
    let (server_io, client_io) = tokio::io::duplex(16 * 1024);
    let facade = Arc::new(MockFacade::new());
    let rl = Arc::new(RateLimiter::with_defaults());
    tokio::spawn(run_server(
        server_io,
        ServerConfig {
            psk,
            peer_id: "test-peer".into(),
        },
        facade,
        rl,
    ));
    Client::new(client_io, psk)
}

#[tokio::test]
async fn authenticate_and_list_interfaces() {
    let psk = [7u8; PSK_LEN];
    let mut c = spawn_pair(psk);
    c.authenticate().await.unwrap();
    let res = c.request(Op::ListInterfaces).await.unwrap();
    let ifs = match res {
        OpResult::Interfaces(v) => v,
        _ => panic!(),
    };
    assert_eq!(ifs.len(), 2);
}

#[tokio::test]
async fn wrong_psk_fails_auth() {
    let server_psk = [1u8; PSK_LEN];
    let client_psk = [2u8; PSK_LEN];
    let (server_io, client_io) = tokio::io::duplex(16 * 1024);
    tokio::spawn(run_server(
        server_io,
        ServerConfig {
            psk: server_psk,
            peer_id: "bad".into(),
        },
        Arc::new(MockFacade::new()),
        Arc::new(RateLimiter::with_defaults()),
    ));
    let mut c = Client::new(client_io, client_psk);
    assert!(matches!(
        c.authenticate().await,
        Err(netprov_client::ClientError::AuthFailed)
    ));
}

#[tokio::test]
async fn unauth_request_rejected() {
    let psk = [3u8; PSK_LEN];
    let mut c = spawn_pair(psk);
    let err = c.request(Op::ListInterfaces).await.unwrap_err();
    assert!(matches!(
        err,
        netprov_client::ClientError::Protocol(ProtocolError::NotAuthenticated)
    ));
}

#[tokio::test]
async fn get_ip_config_eth0() {
    let psk = [3u8; PSK_LEN];
    let mut c = spawn_pair(psk);
    c.authenticate().await.unwrap();
    let res = c
        .request(Op::GetIpConfig {
            iface: "eth0".into(),
        })
        .await
        .unwrap();
    match res {
        OpResult::IpConfig(cfg) => {
            assert!(!cfg.addresses.is_empty());
        }
        _ => panic!(),
    }
}

#[tokio::test]
async fn set_dhcp_then_read_back() {
    let psk = [3u8; PSK_LEN];
    let mut c = spawn_pair(psk);
    c.authenticate().await.unwrap();
    c.request(Op::SetDhcp {
        iface: "eth0".into(),
    })
    .await
    .unwrap();
    let res = c
        .request(Op::GetIpConfig {
            iface: "eth0".into(),
        })
        .await
        .unwrap();
    match res {
        OpResult::IpConfig(cfg) => {
            assert!(matches!(cfg.method, Ipv4Method::Auto));
            assert!(cfg.addresses.is_empty());
        }
        _ => panic!(),
    }
}

#[tokio::test]
async fn set_static_ipv4_then_read_back() {
    let psk = [3u8; PSK_LEN];
    let mut c = spawn_pair(psk);
    c.authenticate().await.unwrap();
    c.request(Op::SetStaticIpv4 {
        iface: "eth0".into(),
        cfg: StaticIpv4 {
            address: "192.168.2.42/24".parse().unwrap(),
            gateway: Some("192.168.2.1".parse().unwrap()),
            dns: vec!["1.1.1.1".parse().unwrap()],
        },
    })
    .await
    .unwrap();
    let res = c
        .request(Op::GetIpConfig {
            iface: "eth0".into(),
        })
        .await
        .unwrap();
    match res {
        OpResult::IpConfig(cfg) => {
            assert!(matches!(cfg.method, Ipv4Method::Manual));
            assert_eq!(cfg.addresses[0].to_string(), "192.168.2.42/24");
        }
        _ => panic!(),
    }
}

#[tokio::test]
async fn static_ipv4_validation_rejects_multicast() {
    let psk = [3u8; PSK_LEN];
    let mut c = spawn_pair(psk);
    c.authenticate().await.unwrap();
    let err = c
        .request(Op::SetStaticIpv4 {
            iface: "eth0".into(),
            cfg: StaticIpv4 {
                address: "224.0.0.1/24".parse().unwrap(),
                gateway: None,
                dns: vec![],
            },
        })
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        netprov_client::ClientError::Protocol(ProtocolError::InvalidArgument { .. })
    ));
}

#[tokio::test]
async fn wifi_scan_returns_networks() {
    let psk = [3u8; PSK_LEN];
    let mut c = spawn_pair(psk);
    c.authenticate().await.unwrap();
    let res = c.request(Op::WifiScan).await.unwrap();
    match res {
        OpResult::WifiNetworks(nets) => assert!(!nets.is_empty()),
        _ => panic!(),
    }
}

#[tokio::test]
async fn connect_wifi_then_status_reflects_ssid() {
    let psk = [3u8; PSK_LEN];
    let mut c = spawn_pair(psk);
    c.authenticate().await.unwrap();
    c.request(Op::ConnectWifi {
        ssid: "HomeWifi".into(),
        credential: WifiCredential::Wpa2Psk("super-secret".into()),
    })
    .await
    .unwrap();
    let res = c.request(Op::WifiStatus).await.unwrap();
    match res {
        OpResult::WifiStatus(st) => assert_eq!(st.ssid.as_deref(), Some("HomeWifi")),
        _ => panic!(),
    }
}
