use private_relay_crypto::{parse_public_key, StaticKeypair};
use private_relay_protocol::X25519_KEY_LEN;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::NetworkError;

/// Structural position of a relay node inside the fixed 3-hop topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RelayRole {
    Entry,
    Middle,
    Exit,
}

impl RelayRole {
    /// Returns the hop index `{1, 2, 3}` corresponding to this relay's position in a circuit.
    pub fn hop_index(self) -> u8 {
        match self {
            Self::Entry => 1,
            Self::Middle => 2,
            Self::Exit => 3,
        }
    }
}

/// Public descriptor identifying an authorized relay peer (`v0.1` static configuration).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerDescriptor {
    pub id: String,
    pub role: RelayRole,
    pub addr: String,
    pub public_key_hex: String,
}

impl PeerDescriptor {
    pub fn public_key(&self) -> Result<[u8; X25519_KEY_LEN], NetworkError> {
        decode_hex_32(&self.public_key_hex)
    }
}

/// Complete typed startup configuration for a single relay instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    pub id: String,
    pub role: RelayRole,
    pub listen_addr: String,
    pub public_key_hex: String,
    pub private_key_hex: String,
    #[serde(default)]
    pub allowed_next_peers: Vec<PeerDescriptor>,
    #[serde(default)]
    pub allow_loopback_for_test: bool,
    #[serde(default)]
    pub allowed_targets: Vec<String>,
    #[serde(default = "default_max_concurrent_circuits")]
    pub max_concurrent_circuits: usize,
    #[serde(default = "default_max_circuits_per_peer_ip")]
    pub max_circuits_per_peer_ip: usize,
    #[serde(default = "default_channel_capacity")]
    pub circuit_channel_capacity: usize,
    #[serde(default = "default_handshake_timeout_ms")]
    pub handshake_timeout_ms: u64,
    #[serde(default = "default_io_timeout_ms")]
    pub io_timeout_ms: u64,
    #[serde(default = "default_destination_io_timeout_ms")]
    pub destination_io_timeout_ms: u64,
    #[serde(default = "default_idle_circuit_ttl_secs")]
    pub idle_circuit_ttl_secs: u64,
}

const fn default_max_concurrent_circuits() -> usize {
    1024
}
const fn default_max_circuits_per_peer_ip() -> usize {
    16
}
const fn default_channel_capacity() -> usize {
    64
}
const fn default_handshake_timeout_ms() -> u64 {
    5_000
}
const fn default_io_timeout_ms() -> u64 {
    5_000
}
const fn default_destination_io_timeout_ms() -> u64 {
    10_000
}
const fn default_idle_circuit_ttl_secs() -> u64 {
    120
}

impl RelayConfig {
    /// Creates an in-memory configuration for a relay using a caller-generated ephemeral keypair.
    pub fn with_generated_keypair(
        id: impl Into<String>,
        role: RelayRole,
        listen_addr: impl Into<String>,
        keypair: &StaticKeypair,
    ) -> Self {
        Self {
            id: id.into(),
            role,
            listen_addr: listen_addr.into(),
            public_key_hex: encode_hex(keypair.public()),
            private_key_hex: encode_hex(keypair.secret_bytes()),
            allowed_next_peers: Vec::new(),
            allow_loopback_for_test: false,
            allowed_targets: Vec::new(),
            max_concurrent_circuits: default_max_concurrent_circuits(),
            max_circuits_per_peer_ip: default_max_circuits_per_peer_ip(),
            circuit_channel_capacity: default_channel_capacity(),
            handshake_timeout_ms: default_handshake_timeout_ms(),
            io_timeout_ms: default_io_timeout_ms(),
            destination_io_timeout_ms: default_destination_io_timeout_ms(),
            idle_circuit_ttl_secs: default_idle_circuit_ttl_secs(),
        }
    }

    pub fn from_toml_str(s: &str) -> Result<Self, NetworkError> {
        let cfg: Self = toml::from_str(s).map_err(|e| NetworkError::Config(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn to_toml_string(&self) -> Result<String, NetworkError> {
        toml::to_string_pretty(self).map_err(|e| NetworkError::Config(e.to_string()))
    }

    pub fn keypair(&self) -> Result<StaticKeypair, NetworkError> {
        let priv_bytes = Zeroizing::new(decode_hex_32(&self.private_key_hex)?);
        let pub_bytes = decode_hex_32(&self.public_key_hex)?;
        Ok(StaticKeypair::from_slices(&*priv_bytes, &pub_bytes)?)
    }

    pub fn validate(&self) -> Result<(), NetworkError> {
        if self.id.trim().is_empty() {
            return Err(NetworkError::Config("relay id must not be empty".into()));
        }
        if self.listen_addr.trim().is_empty() {
            return Err(NetworkError::Config("listen_addr must not be empty".into()));
        }
        let _ = self.keypair()?;
        if self.max_concurrent_circuits == 0 || self.circuit_channel_capacity == 0 {
            return Err(NetworkError::Config(
                "circuit capacity limits must be non-zero".into(),
            ));
        }
        Ok(())
    }
}

/// Encodes arbitrary bytes into lowercase hex string without extra external dependencies.
pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decodes a 64-character hex string into a fixed 32-byte key array.
pub fn decode_hex_32(hex_str: &str) -> Result<[u8; X25519_KEY_LEN], NetworkError> {
    let trimmed = hex_str.trim();
    if trimmed.len() != X25519_KEY_LEN * 2 {
        return Err(NetworkError::Config(
            "expected 64 hex characters for 32-byte key".into(),
        ));
    }
    let mut raw = Zeroizing::new([0u8; X25519_KEY_LEN]);
    let bytes = trimmed.as_bytes();
    for i in 0..X25519_KEY_LEN {
        let hi = decode_nibble(bytes[i * 2])?;
        let lo = decode_nibble(bytes[i * 2 + 1])?;
        raw[i] = (hi << 4) | lo;
    }
    Ok(parse_public_key(&*raw)?)
}

fn decode_nibble(b: u8) -> Result<u8, NetworkError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(NetworkError::Config("invalid hex digit in key".into())),
    }
}
