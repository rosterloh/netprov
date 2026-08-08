use crate::cli::{Command, Security};
use anyhow::{Result, bail};
use netprov_protocol::*;
use netprov_sdk::ProvisioningClient;

/// Builds the `WifiCredential` for a `wifi-connect`, resolving the passphrase.
///
/// Every mismatch gets its own message. The previous single catch-all said
/// only "unsupported combination of security and psk", which covered a missing
/// passphrase, a passphrase given for an open network (silently discarded
/// before that), and a mistyped security type alike (#22).
///
/// When `--psk` is omitted for a network that needs one, the passphrase is
/// read from stdin, so it need never appear in `argv` where `ps` and shell
/// history can see it. Only when stdin is piped: on a terminal that would just
/// hang, so there it stays an error telling you the two ways to supply it.
fn credential_for(security: Security, psk: Option<String>) -> Result<WifiCredential> {
    if !security.needs_psk() {
        if psk.is_some() {
            bail!("--psk is not used with --security open; drop one of them");
        }
        return Ok(WifiCredential::Open);
    }

    let psk = match psk {
        Some(p) => p,
        None => read_psk_from_stdin(security)?,
    };
    if psk.is_empty() {
        bail!(
            "--security {} needs a non-empty passphrase",
            security.as_str()
        );
    }

    Ok(match security {
        Security::Open => unreachable!("handled above"),
        Security::Wpa => WifiCredential::WpaPsk(psk),
        Security::Wpa2 => WifiCredential::Wpa2Psk(psk),
        Security::Wpa3 => WifiCredential::Wpa3(psk),
    })
}

fn read_psk_from_stdin(security: Security) -> Result<String> {
    use std::io::{BufRead, IsTerminal};

    if std::io::stdin().is_terminal() {
        bail!(
            "--security {} needs a passphrase: pass --psk, or pipe it on stdin \
             to keep it out of `ps` and your shell history",
            security.as_str()
        );
    }
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    // Strip the line ending only. A passphrase may legitimately begin or end
    // with a space, so trimming whitespace would corrupt valid input.
    let line = line.strip_suffix('\n').unwrap_or(&line);
    Ok(line.strip_suffix('\r').unwrap_or(line).to_string())
}

pub async fn dispatch<C>(c: &mut C, cmd: Command) -> Result<()>
where
    C: ProvisioningClient + Send,
{
    match cmd {
        // Handled in `main` before a transport is opened — a scan has no peer
        // to dispatch to.
        #[cfg(feature = "ble")]
        Command::BleScan { .. } => bail!("ble-scan does not run over a connection"),
        #[cfg(feature = "ble")]
        Command::SetTime => {
            bail!("set-time requires --ble-peer; the dev-tcp transport has no Current Time Service")
        }
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
            let credential = credential_for(security, psk)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_security_maps_to_its_credential() {
        let psk = || Some("hunter2".to_string());
        assert_eq!(
            credential_for(Security::Wpa, psk()).unwrap(),
            WifiCredential::WpaPsk("hunter2".into()),
            "WPA1 must be reachable from the CLI"
        );
        assert_eq!(
            credential_for(Security::Wpa2, psk()).unwrap(),
            WifiCredential::Wpa2Psk("hunter2".into())
        );
        assert_eq!(
            credential_for(Security::Wpa3, psk()).unwrap(),
            WifiCredential::Wpa3("hunter2".into())
        );
        assert_eq!(
            credential_for(Security::Open, None).unwrap(),
            WifiCredential::Open
        );
    }

    /// Previously the passphrase was silently dropped for an open network.
    #[test]
    fn psk_with_open_is_rejected_not_ignored() {
        let err = credential_for(Security::Open, Some("hunter2".into()))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not used with --security open"), "{err}");
    }

    #[test]
    fn empty_passphrase_is_rejected() {
        let err = credential_for(Security::Wpa2, Some(String::new()))
            .unwrap_err()
            .to_string();
        assert!(err.contains("non-empty passphrase"), "{err}");
    }
}
