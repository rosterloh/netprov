//! netprov client library.

pub mod cli;
pub mod commands;
#[cfg(feature = "dev-tcp")]
pub use netprov_sdk::TcpClient as Client;
#[cfg(feature = "ble")]
pub use netprov_sdk::{BleClient, BleDevice, PeerId, parse_peer_id};
pub use netprov_sdk::{Netprov, ProvisioningClient, SdkError as ClientError};
