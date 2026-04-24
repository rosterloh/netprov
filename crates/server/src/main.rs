use clap::{Parser, Subcommand};
use netprov_server::keygen::{run_keygen, KeygenArgs};
use netprov_server::logging::{log_startup_banner, spawn_dev_key_warn_loop};
#[cfg(feature = "live-ble")]
use netprov_server::{
    ble::{run_ble_server, BleServerConfig},
    notify::{notify_ready, notify_stopping},
};
use netprov_server::server_loop::run_tcp_server;
use netprov_server::{load_key, LoadOptions, LoadedKey, MockFacade, RateLimiter};
#[cfg(feature = "live-ble")]
use netprov_server::NmrsFacade;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "netprovd", about = "netprov daemon")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a PSK. Optionally install it.
    Keygen {
        #[arg(long)]
        install: bool,
        #[arg(long, short = 'o')]
        out: Option<PathBuf>,
    },
    /// (Dev only) Run the loopback TCP server against MockFacade.
    ServeTcp {
        #[arg(long, default_value = "127.0.0.1:9600")]
        listen: String,
    },
    /// (Production) Run the BLE GATT server against NmrsFacade.
    #[cfg(feature = "live-ble")]
    ServeBle {
        /// Which BLE controller to bind ("hci0", "hci1", …). Defaults to the
        /// adapter bluer picks.
        #[arg(long)]
        adapter: Option<String>,
        /// Model string exposed in the Info characteristic.
        #[arg(long, default_value = "netprov-dev")]
        model: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli.command {
        Cmd::Keygen { install, out } => {
            run_keygen(
                KeygenArgs {
                    install,
                    install_path: out.unwrap_or_else(|| "/etc/netprov/key".into()),
                },
                &mut std::io::stdout(),
            )?;
        }
        Cmd::ServeTcp { listen } => {
            let key = load_prod_or_dev_key()?;
            log_startup_banner(&key.source);
            let _warn = spawn_dev_key_warn_loop(key.source.clone());
            run_tcp_server(
                &listen,
                key.psk,
                Arc::new(MockFacade::new()),
                Arc::new(RateLimiter::with_defaults()),
            )
            .await?;
        }
        #[cfg(feature = "live-ble")]
        Cmd::ServeBle { adapter, model } => {
            let key = load_prod_or_dev_key()?;
            log_startup_banner(&key.source);
            let _warn = spawn_dev_key_warn_loop(key.source.clone());
            let facade = Arc::new(NmrsFacade::new().await?);
            let rl = Arc::new(RateLimiter::with_defaults());
            let cfg = BleServerConfig {
                psk: key.psk,
                model,
                adapter_name: adapter,
            };
            let result = run_ble_server(cfg, facade, rl, notify_ready).await;
            notify_stopping();
            result?;
        }
    }
    Ok(())
}

fn load_prod_or_dev_key() -> anyhow::Result<LoadedKey> {
    let production = std::env::var("NETPROV_PRODUCTION").ok().as_deref() == Some("1");
    let env_path = std::env::var_os("NETPROV_KEY_PATH").map(PathBuf::from);
    Ok(load_key(LoadOptions {
        env_path,
        default_path: "/etc/netprov/key".into(),
        production,
    })?)
}
