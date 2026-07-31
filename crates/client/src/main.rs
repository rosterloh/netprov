use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use netprov_client::cli::Cli;
#[cfg(any(feature = "ble", feature = "dev-tcp"))]
use netprov_client::commands::dispatch;
use netprov_protocol::PSK_LEN;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    // Scanning needs neither a PSK nor a peer, so it runs before either is
    // required. On macOS this is the only way to learn a peer's identifier.
    #[cfg(feature = "ble")]
    if let netprov_client::cli::Command::BleScan { timeout } = cli.command {
        return ble_scan(timeout).await;
    }

    let key_bytes = std::fs::read(&cli.key_path)
        .with_context(|| format!("read key {}", cli.key_path.display()))?;
    if key_bytes.len() != PSK_LEN {
        anyhow::bail!("key length is {}, expected {}", key_bytes.len(), PSK_LEN);
    }
    let mut psk = [0u8; PSK_LEN];
    psk.copy_from_slice(&key_bytes);

    #[cfg(feature = "ble")]
    {
        if let Some(peer) = cli.ble_peer.as_deref() {
            use netprov_client::{BleClient, parse_peer_id};
            let peer = parse_peer_id(peer)?;
            let mut client = BleClient::connect(&peer).await?;
            let result = async {
                client.authenticate(psk).await?;
                dispatch(&mut client, cli.command).await
            }
            .await;
            // Always drop the link, including on failure. A peripheral that
            // stays connected stops advertising, which makes the next scan or
            // connect intermittently find nothing (CoreBluetooth keeps the
            // peripheral alive in the system daemon past process exit).
            if let Err(e) = client.disconnect().await {
                eprintln!("warning: could not disconnect cleanly: {e}");
            }
            return result;
        }
    }
    #[cfg(not(feature = "ble"))]
    {
        if cli.ble_peer.is_some() {
            anyhow::bail!("--ble-peer requires building with --features ble");
        }
    }

    #[cfg(feature = "dev-tcp")]
    {
        use netprov_client::Client;

        let sock = tokio::net::TcpStream::connect(&cli.endpoint)
            .await
            .with_context(|| format!("connect {}", cli.endpoint))?;
        let mut client = Client::new(sock);
        client.authenticate(psk).await.context("authenticate")?;
        dispatch(&mut client, cli.command).await?;
        Ok(())
    }

    #[cfg(not(feature = "dev-tcp"))]
    {
        anyhow::bail!("TCP transport requires building with --features dev-tcp")
    }
}

#[cfg(feature = "ble")]
async fn ble_scan(timeout_secs: u64) -> Result<()> {
    use netprov_client::BleClient;
    use std::time::Duration;

    let devices = BleClient::scan_devices(Duration::from_secs(timeout_secs)).await?;
    if devices.is_empty() {
        eprintln!("no netprov devices found in {timeout_secs}s");
        return Ok(());
    }
    // The identifier column is what the user pastes into --ble-peer, so print
    // it verbatim rather than prettified.
    for device in devices {
        println!(
            "{:<40} {:<24} {}",
            device.id,
            device.name.unwrap_or_else(|| "-".into()),
            device
                .rssi
                .map(|rssi| format!("{rssi} dBm"))
                .unwrap_or_else(|| "-".into()),
        );
    }
    Ok(())
}
