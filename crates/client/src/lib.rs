//! netprov client library.

pub mod cli;
pub mod commands;
#[cfg(feature = "ble")]
pub use netprov_sdk::{BleClient, parse_peer_address};
pub use netprov_sdk::{Netprov, ProvisioningClient, SdkError as ClientError, TcpClient as Client};
