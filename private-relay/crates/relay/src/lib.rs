//! Relay engine (`v0.1`) parameterised cleanly by [`private_relay_network::RelayRole`].
//!
//! Each relay instance enforces link authentication (`Noise_IK`), per-hop onion decryption
//! (`Forward` / `Extend` / `Message`), role capabilities (`Entry`, `Middle`, `Exit`), bounded
//! queues, SSRF exit protections, and prompt teardown with cryptographic state zeroization.

pub mod engine;
pub mod error;

pub use engine::{RelayHandle, RelayServer};
pub use error::RelayError;
