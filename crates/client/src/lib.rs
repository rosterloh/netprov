//! netprov client library.

pub mod cli;
pub mod client;
pub mod commands;
#[cfg(feature = "ble")]
pub mod ble;
pub use client::{Client, ClientError};
