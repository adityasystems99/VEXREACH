//! Bounded 3-hop client library (`v0.1`) implementing telescopic circuit establishment and
//! onion-encrypted request/response forwarding (`Decision D-01`).

pub mod client;
pub mod error;

pub use client::{ClientCircuit, ClientConfig, RelayClient};
pub use error::ClientError;
