//! App-facing client SDK for netprov.
//!
//! The SDK keeps UI code away from wire details. BLE is the primary product
//! transport; TCP remains available as a development and regression-test path.

#[cfg(feature = "ble")]
pub mod ble;
pub mod client;
pub mod ops;

#[cfg(feature = "ble")]
pub use ble::{BleClient, parse_peer_address};
pub use client::TcpClient;
pub use ops::{Netprov, ProvisioningClient, SdkError};
