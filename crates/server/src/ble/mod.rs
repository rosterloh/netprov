//! BLE GATT server driver.
//!
//! Only compiled when the `live-ble` feature is enabled.

pub mod conn;
pub mod gatt;
pub mod server;
pub mod uuids;

pub use server::{BleServerConfig, run_ble_server};
