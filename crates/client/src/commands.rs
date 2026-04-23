use crate::cli::Command;
use crate::client::Client;
use anyhow::{bail, Result};
use netprov_protocol::*;
use tokio::io::{AsyncRead, AsyncWrite};

pub async fn dispatch<IO: AsyncRead + AsyncWrite>(c: &mut Client<IO>, cmd: Command) -> Result<()> {
    match cmd {
        Command::List => {
            let res = c.request(Op::ListInterfaces).await?;
            match res {
                OpResult::Interfaces(ifs) => {
                    for i in ifs {
                        println!(
                            "{:<10} {:<10} {:<18} {:?}",
                            i.name,
                            format!("{:?}", i.iface_type),
                            i.mac.unwrap_or_else(|| "-".into()),
                            i.state,
                        );
                    }
                }
                _ => bail!("unexpected result shape"),
            }
        }
        Command::Ip { iface } => {
            let res = c
                .request(Op::GetIpConfig {
                    iface: iface.clone(),
                })
                .await?;
            match res {
                OpResult::IpConfig(cfg) => {
                    println!("iface: {iface}");
                    println!("method: {:?}", cfg.method);
                    for a in &cfg.addresses {
                        println!("  addr: {a}");
                    }
                    if let Some(gw) = cfg.gateway {
                        println!("  gw:   {gw}");
                    }
                    for d in &cfg.dns {
                        println!("  dns:  {d}");
                    }
                }
                _ => bail!("unexpected result shape"),
            }
        }
        Command::WifiStatus => {
            let res = c.request(Op::WifiStatus).await?;
            match res {
                OpResult::WifiStatus(st) => println!("{st:?}"),
                _ => bail!("unexpected result shape"),
            }
        }
        Command::WifiScan => {
            let res = c.request(Op::WifiScan).await?;
            match res {
                OpResult::WifiNetworks(nets) => {
                    for n in nets {
                        println!(
                            "{:<32} {:>3}% {:?} {}",
                            n.ssid,
                            n.signal.unwrap_or(0),
                            n.security,
                            n.bssid,
                        );
                    }
                }
                _ => bail!("unexpected result shape"),
            }
        }
        Command::WifiConnect {
            ssid,
            psk,
            security,
        } => {
            let credential = match (security.as_str(), psk) {
                ("open", _) => WifiCredential::Open,
                ("wpa2", Some(p)) => WifiCredential::Wpa2Psk(p),
                ("wpa3", Some(p)) => WifiCredential::Wpa3(p),
                _ => bail!("unsupported combination of security and psk"),
            };
            c.request(Op::ConnectWifi { ssid, credential }).await?;
            println!("ok");
        }
        Command::SetDhcp { iface } => {
            c.request(Op::SetDhcp { iface }).await?;
            println!("ok");
        }
        Command::SetStatic {
            iface,
            address,
            gateway,
            dns,
        } => {
            c.request(Op::SetStaticIpv4 {
                iface,
                cfg: StaticIpv4 {
                    address,
                    gateway,
                    dns,
                },
            })
            .await?;
            println!("ok");
        }
    }
    Ok(())
}
