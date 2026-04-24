//! netprov client library.

#[cfg(feature = "ble")]
pub mod ble;
pub mod cli;
pub mod client;
pub mod commands;
pub use client::{Client, ClientError};
