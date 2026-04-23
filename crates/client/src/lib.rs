//! netprov client library.

pub mod cli;
pub mod client;
pub mod commands;
pub use client::{Client, ClientError};
