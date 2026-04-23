use clap::{Parser, Subcommand};
use ipnet::Ipv4Net;
use std::net::Ipv4Addr;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "netprov", about = "netprov client CLI")]
pub struct Cli {
    /// Path to the 32-byte PSK file.
    #[arg(
        long,
        short = 'k',
        env = "NETPROV_KEY_PATH",
        default_value = "/etc/netprov/key"
    )]
    pub key_path: PathBuf,

    /// TCP endpoint for loopback transport (Part 1). Part 2 will default to
    /// BLE peer discovery.
    #[arg(long, env = "NETPROV_ENDPOINT", default_value = "127.0.0.1:9600")]
    pub endpoint: String,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// List network interfaces.
    List,
    /// Print IP config for an interface.
    Ip { iface: String },
    /// Print Wi-Fi status.
    WifiStatus,
    /// Scan for Wi-Fi networks.
    WifiScan,
    /// Connect to a Wi-Fi network.
    WifiConnect {
        ssid: String,
        #[arg(long)]
        psk: Option<String>,
        /// Security type: open | wpa2 | wpa3
        #[arg(long, default_value = "wpa2")]
        security: String,
    },
    /// Configure interface for DHCP.
    SetDhcp { iface: String },
    /// Configure interface for static IPv4.
    SetStatic {
        iface: String,
        #[arg(long)]
        address: Ipv4Net,
        #[arg(long)]
        gateway: Option<Ipv4Addr>,
        #[arg(long, value_delimiter = ',')]
        dns: Vec<Ipv4Addr>,
    },
}
