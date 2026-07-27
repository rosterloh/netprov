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

    /// TCP endpoint for the dev/test loopback transport. Requires the
    /// `dev-tcp` feature.
    #[arg(long, env = "NETPROV_ENDPOINT", default_value = "127.0.0.1:9600")]
    pub endpoint: String,

    /// BLE peer identifier. If set, uses BLE transport and requires
    /// `--features ble`.
    ///
    /// On Linux this is the BD_ADDR (e.g. AA:BB:CC:DD:EE:FF). On macOS
    /// CoreBluetooth never discloses peer MACs, so use the opaque handle or
    /// the device name printed by `netprov ble-scan`.
    #[arg(long)]
    pub ble_peer: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Scan for nearby netprov devices and print their identifiers.
    ///
    /// Needs no PSK and no connection — it exists so you can discover the
    /// value to pass to `--ble-peer`, which on macOS is not something you can
    /// know in advance.
    #[cfg(feature = "ble")]
    BleScan {
        /// Seconds to listen for advertisements.
        #[arg(long, default_value_t = 8)]
        timeout: u64,
    },
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
