use anyhow::{Context, Result};
use clap::Parser;
use netprov_client::cli::Cli;
use netprov_client::{client::Client, commands::dispatch};
use netprov_protocol::PSK_LEN;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

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
            use netprov_client::ble::{parse_peer_address, BleClient};
            let addr = parse_peer_address(peer)?;
            let mut client = BleClient::connect(addr, psk).await?;
            client.authenticate().await?;
            return netprov_client::commands::dispatch_ble(&mut client, cli.command).await;
        }
    }
    #[cfg(not(feature = "ble"))]
    {
        if cli.ble_peer.is_some() {
            anyhow::bail!("--ble-peer requires building with --features ble");
        }
    }

    let sock = tokio::net::TcpStream::connect(&cli.endpoint)
        .await
        .with_context(|| format!("connect {}", cli.endpoint))?;
    let mut client = Client::new(sock, psk);
    client.authenticate().await.context("authenticate")?;
    dispatch(&mut client, cli.command).await?;
    Ok(())
}
