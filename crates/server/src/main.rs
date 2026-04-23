use clap::{Parser, Subcommand};
use netprov_server::keygen::{run_keygen, KeygenArgs};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "netprovd", about = "netprov daemon")]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a new 32-byte PSK. Optionally install it to disk.
    Keygen {
        /// Write the generated key to the install path (default /etc/netprov/key).
        #[arg(long)]
        install: bool,
        /// Override the install path.
        #[arg(long, short = 'o')]
        out: Option<PathBuf>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Cmd::Keygen { install, out }) => {
            let args = KeygenArgs {
                install,
                install_path: out.unwrap_or_else(|| "/etc/netprov/key".into()),
            };
            run_keygen(args, &mut std::io::stdout())?;
            Ok(())
        }
        None => {
            // Default: run the daemon. Loop integration lands in Part 2
            // (BLE wiring); for now, print a usage note.
            eprintln!("Part 1 build: BLE server not wired yet. Use `netprovd keygen`.");
            std::process::exit(1);
        }
    }
}
