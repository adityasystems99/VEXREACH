//! Asynchronous Noise-encrypted TCP transport, SSRF policy guard, and TOML configuration for Private-Relay.

pub mod config;
pub mod error;
pub mod metrics;
pub mod policy;
pub mod transport;

pub use config::{
    decode_hex_32, decode_hex_32_zeroizing, encode_hex, ClientConfigFile, PeerDescriptor,
    RelayConfig, RelayRole, MAX_CONFIG_TOML_BYTES,
};
pub use error::NetworkError;
pub use metrics::{RelayMetrics, SharedRelayMetrics};
pub use policy::DestinationPolicy;
pub use transport::{
    accept_noise_link, accept_noise_link_with_rekey, connect_noise_link,
    connect_noise_link_with_rekey, split_framed_session, LinkReader, LinkWriter,
};
