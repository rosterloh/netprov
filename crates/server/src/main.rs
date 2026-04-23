use clap::{Parser, Subcommand};
use netprov_server::keygen::{run_keygen, KeygenArgs};
use netprov_server::logging::{log_startup_banner, spawn_dev_key_warn_loop};
use netprov_server::server_loop::run_tcp_server;
use netprov_server::{load_key, LoadOptions, MockFacade, RateLimiter};
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
    /// Run the loopback TCP server (Part 1 only). Uses MockFacade.
    Serve {
        /// TCP listen address.
        #[arg(long, default_value = "127.0.0.1:9600")]
        listen: String,
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
        Cmd::Serve { listen } => {
            let production = std::env::var("NETPROV_PRODUCTION").ok().as_deref() == Some("1");
            let env_path = std::env::var_os("NETPROV_KEY_PATH").map(PathBuf::from);
            let key = load_key(LoadOptions {
                env_path,
                default_path: "/etc/netprov/key".into(),
                production,
            })?;
            log_startup_banner(&key.source);
            let _warn_task = spawn_dev_key_warn_loop(key.source.clone());
            let facade = Arc::new(MockFacade::new());
            let rl = Arc::new(RateLimiter::with_defaults());
            run_tcp_server(&listen, key.psk, facade, rl).await?;
        }
    }
    Ok(())
}
