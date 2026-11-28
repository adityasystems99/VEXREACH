use std::fmt;
use std::io::Read;
use std::net::SocketAddr;
use std::time::Duration;

use private_relay_crypto::{parse_public_key, LinkRekeyPolicy, StaticKeypair};
use private_relay_protocol::{
    LINK_REKEY_DEFAULT_BYTES, LINK_REKEY_DEFAULT_INTERVAL_SECS, OUTER_WIRE_FRAME_BYTES,
    X25519_KEY_LEN,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

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
#[derive(Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    pub id: String,
    pub role: RelayRole,
    pub listen_addr: String,
    pub public_key_hex: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub private_key_hex: String,
    /// Optional mounted Secret file holding the 64-hex-char X25519 private key (Kubernetes Secrets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key_file: Option<String>,
    #[serde(default)]
    pub allowed_next_peers: Vec<PeerDescriptor>,
    #[serde(default)]
    pub allow_loopback_for_test: bool,
    #[serde(default)]
    pub allow_private_targets_for_test: bool,
    #[serde(default)]
    pub allowed_targets: Vec<String>,
    #[serde(default = "default_max_concurrent_connections")]
    pub max_concurrent_connections: usize,
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
    #[serde(default = "default_link_rekey_interval_secs")]
    pub link_rekey_interval_secs: u64,
    #[serde(default = "default_link_rekey_bytes")]
    pub link_rekey_bytes: u64,
    /// Optional HTTP metrics bind address (e.g. "0.0.0.0:9091") exposing /metrics for Prometheus.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics_addr: Option<String>,
}

const fn default_max_concurrent_connections() -> usize {
    256
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
const fn default_link_rekey_interval_secs() -> u64 {
    LINK_REKEY_DEFAULT_INTERVAL_SECS
}
const fn default_link_rekey_bytes() -> u64 {
    LINK_REKEY_DEFAULT_BYTES
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
            private_key_file: None,
            allowed_next_peers: Vec::new(),
            allow_loopback_for_test: false,
            allow_private_targets_for_test: false,
            allowed_targets: Vec::new(),
            max_concurrent_connections: default_max_concurrent_connections(),
            max_concurrent_circuits: default_max_concurrent_circuits(),
            max_circuits_per_peer_ip: default_max_circuits_per_peer_ip(),
            circuit_channel_capacity: default_channel_capacity(),
            handshake_timeout_ms: default_handshake_timeout_ms(),
            io_timeout_ms: default_io_timeout_ms(),
            destination_io_timeout_ms: default_destination_io_timeout_ms(),
            idle_circuit_ttl_secs: default_idle_circuit_ttl_secs(),
            link_rekey_interval_secs: default_link_rekey_interval_secs(),
            link_rekey_bytes: default_link_rekey_bytes(),
            metrics_addr: None,
        }
    }

    pub fn link_rekey_policy(&self) -> LinkRekeyPolicy {
        LinkRekeyPolicy {
            max_bytes: self.link_rekey_bytes,
            max_age: Duration::from_secs(self.link_rekey_interval_secs),
        }
    }

    pub fn from_toml_str(s: &str) -> Result<Self, NetworkError> {
        let mut cfg: Self =
            toml::from_str(s).map_err(|e| NetworkError::Config(sanitize_toml_error(&e)))?;
        cfg.resolve_secret_file()?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Reads `private_key_hex` from `private_key_file` when omitted from non-sensitive ConfigMaps.
    /// Rejects empty paths, non-regular or oversized (> 256B) files, and conflicting inline keys.
    pub fn resolve_secret_file(&mut self) -> Result<(), NetworkError> {
        let has_inline = !self.private_key_hex.trim().is_empty();
        if has_inline && self.private_key_file.is_some() {
            return Err(NetworkError::Config(
                "specify either private_key_hex or private_key_file, not both".into(),
            ));
        }
        if !has_inline {
            if let Some(ref path) = self.private_key_file {
                if path.trim().is_empty() {
                    return Err(NetworkError::Config(
                        "private_key_file path must not be empty".into(),
                    ));
                }
                let file = std::fs::File::open(path).map_err(|e| {
                    NetworkError::Config(format!("failed to read private_key_file '{path}': {e}"))
                })?;
                if let Ok(meta) = file.metadata() {
                    if !meta.is_file() {
                        return Err(NetworkError::Config(format!(
                            "private_key_file '{path}' must be a regular file"
                        )));
                    }
                    if meta.len() > 256 {
                        return Err(NetworkError::Config(format!(
                            "private_key_file '{path}' exceeds 256-byte secret limit"
                        )));
                    }
                }
                let mut raw = Zeroizing::new(String::new());
                file.take(257).read_to_string(&mut raw).map_err(|e| {
                    NetworkError::Config(format!("failed to read private_key_file '{path}': {e}"))
                })?;
                if raw.len() > 256 {
                    return Err(NetworkError::Config(format!(
                        "private_key_file '{path}' exceeds 256-byte secret limit"
                    )));
                }
                self.private_key_hex = raw.trim().to_owned();
            }
        }
        Ok(())
    }

    /// Zeroizes any in-memory plaintext `private_key_hex` after keypair construction.
    pub fn scrub_private_key(&mut self) {
        self.private_key_hex.zeroize();
    }

    /// Returns a cloned non-sensitive configuration referencing `secret_file_path` without inline secrets.
    pub fn without_inline_secret(&self, secret_file_path: impl Into<String>) -> Self {
        let mut cloned = self.clone();
        cloned.private_key_hex = String::new();
        cloned.private_key_file = Some(secret_file_path.into());
        cloned
    }

    /// Extracts and validates only the public X25519 key from a relay TOML string without loading secrets.
    pub fn read_public_key_from_toml_str(s: &str) -> Result<[u8; X25519_KEY_LEN], NetworkError> {
        #[derive(Deserialize)]
        struct PublicOnly {
            public_key_hex: String,
        }
        let parsed: PublicOnly =
            toml::from_str(s).map_err(|e| NetworkError::Config(sanitize_toml_error(&e)))?;
        decode_hex_32(&parsed.public_key_hex)
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
        if self.listen_addr.parse::<SocketAddr>().is_err() {
            return Err(NetworkError::Config(
                "listen_addr must be a valid ip:port SocketAddr".into(),
            ));
        }
        if let Some(ref metrics_addr) = self.metrics_addr {
            if metrics_addr.parse::<SocketAddr>().is_err() {
                return Err(NetworkError::Config(
                    "metrics_addr must be a valid ip:port SocketAddr".into(),
                ));
            }
        }
        if self.allow_private_targets_for_test && self.allowed_targets.is_empty() {
            return Err(NetworkError::Config(
                "allow_private_targets_for_test requires non-empty allowed_targets allowlist"
                    .into(),
            ));
        }
        let kp = self.keypair()?;
        if self.max_concurrent_connections == 0
            || self.max_concurrent_circuits == 0
            || self.max_circuits_per_peer_ip == 0
            || self.circuit_channel_capacity == 0
        {
            return Err(NetworkError::Config(
                "connection and circuit capacity limits must be non-zero".into(),
            ));
        }
        if self.handshake_timeout_ms < 50
            || self.io_timeout_ms < 50
            || self.destination_io_timeout_ms < 50
            || self.idle_circuit_ttl_secs == 0
        {
            return Err(NetworkError::Config(
                "timeouts must be >= 50ms and idle TTL must be >= 1s".into(),
            ));
        }
        if self.link_rekey_interval_secs == 0
            || self.link_rekey_bytes < OUTER_WIRE_FRAME_BYTES as u64
        {
            return Err(NetworkError::Config(
                "link_rekey_interval_secs must be >= 1 and link_rekey_bytes >= 600".into(),
            ));
        }

        let expected_next_role = match self.role {
            RelayRole::Entry => Some(RelayRole::Middle),
            RelayRole::Middle => Some(RelayRole::Exit),
            RelayRole::Exit => None,
        };
        match expected_next_role {
            None => {
                if !self.allowed_next_peers.is_empty() {
                    return Err(NetworkError::Config(
                        "exit relay must not configure allowed_next_peers".into(),
                    ));
                }
            }
            Some(next_role) => {
                for peer in &self.allowed_next_peers {
                    validate_peer_descriptor(peer, next_role)?;
                    if peer.public_key()? == *kp.public() {
                        return Err(NetworkError::Config(
                            "allowed_next_peers cannot reference relay's own key".into(),
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

impl fmt::Debug for RelayConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayConfig")
            .field("id", &self.id)
            .field("role", &self.role)
            .field("listen_addr", &self.listen_addr)
            .field("public_key_hex", &self.public_key_hex)
            .field("private_key_hex", &"[REDACTED]")
            .field("private_key_file", &self.private_key_file)
            .field("allowed_next_peers_len", &self.allowed_next_peers.len())
            .field("allow_loopback_for_test", &self.allow_loopback_for_test)
            .field(
                "allow_private_targets_for_test",
                &self.allow_private_targets_for_test,
            )
            .field("allowed_targets_len", &self.allowed_targets.len())
            .finish()
    }
}

impl Drop for RelayConfig {
    fn drop(&mut self) {
        self.private_key_hex.zeroize();
    }
}

/// Complete typed startup configuration for `relay-client` (`configs/client.toml`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfigFile {
    pub entry: PeerDescriptor,
    pub middle: PeerDescriptor,
    pub exit: PeerDescriptor,
    #[serde(default = "default_handshake_timeout_ms")]
    pub handshake_timeout_ms: u64,
    #[serde(default = "default_io_timeout_ms")]
    pub io_timeout_ms: u64,
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default = "default_link_rekey_interval_secs")]
    pub link_rekey_interval_secs: u64,
    #[serde(default = "default_link_rekey_bytes")]
    pub link_rekey_bytes: u64,
    /// Optional HTTP metrics bind address (e.g. "0.0.0.0:9091") exposing /metrics for Prometheus.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics_addr: Option<String>,
}

const fn default_request_timeout_ms() -> u64 {
    15_000
}

impl ClientConfigFile {
    pub fn from_toml_str(s: &str) -> Result<Self, NetworkError> {
        let cfg: Self =
            toml::from_str(s).map_err(|e| NetworkError::Config(sanitize_toml_error(&e)))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn to_toml_string(&self) -> Result<String, NetworkError> {
        toml::to_string_pretty(self).map_err(|e| NetworkError::Config(e.to_string()))
    }

    pub fn link_rekey_policy(&self) -> LinkRekeyPolicy {
        LinkRekeyPolicy {
            max_bytes: self.link_rekey_bytes,
            max_age: Duration::from_secs(self.link_rekey_interval_secs),
        }
    }

    pub fn route(&self) -> [PeerDescriptor; 3] {
        [self.entry.clone(), self.middle.clone(), self.exit.clone()]
    }

    pub fn validate(&self) -> Result<(), NetworkError> {
        validate_peer_descriptor(&self.entry, RelayRole::Entry)?;
        validate_peer_descriptor(&self.middle, RelayRole::Middle)?;
        validate_peer_descriptor(&self.exit, RelayRole::Exit)?;

        if self.entry.id == self.middle.id
            || self.middle.id == self.exit.id
            || self.entry.id == self.exit.id
        {
            return Err(NetworkError::Config(
                "client route relay IDs must be distinct across Entry, Middle, and Exit".into(),
            ));
        }
        let k_e = self.entry.public_key()?;
        let k_m = self.middle.public_key()?;
        let k_x = self.exit.public_key()?;
        if k_e == k_m || k_m == k_x || k_e == k_x {
            return Err(NetworkError::Config(
                "client route public keys must be distinct across Entry, Middle, and Exit".into(),
            ));
        }
        if self.entry.addr == self.middle.addr
            || self.middle.addr == self.exit.addr
            || self.entry.addr == self.exit.addr
        {
            return Err(NetworkError::Config(
                "client route relay addresses must be distinct across hops".into(),
            ));
        }
        if self.handshake_timeout_ms < 50 || self.io_timeout_ms < 50 || self.request_timeout_ms < 50
        {
            return Err(NetworkError::Config(
                "client timeouts must be >= 50ms".into(),
            ));
        }
        if self.link_rekey_interval_secs == 0
            || self.link_rekey_bytes < OUTER_WIRE_FRAME_BYTES as u64
        {
            return Err(NetworkError::Config(
                "link_rekey_interval_secs must be >= 1 and link_rekey_bytes >= 600".into(),
            ));
        }
        Ok(())
    }
}

fn validate_peer_descriptor(
    peer: &PeerDescriptor,
    expected_role: RelayRole,
) -> Result<(), NetworkError> {
    if peer.id.trim().is_empty() {
        return Err(NetworkError::Config("peer id must not be empty".into()));
    }
    if peer.role != expected_role {
        return Err(NetworkError::Config(format!(
            "peer '{}' has inconsistent role {:?}, expected {:?}",
            peer.id, peer.role, expected_role
        )));
    }
    validate_host_port(&peer.addr)?;
    let _ = peer.public_key()?;
    Ok(())
}

pub(crate) fn validate_host_port(addr: &str) -> Result<(), NetworkError> {
    if addr.is_empty() || addr.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(NetworkError::Config("peer addr malformed".into()));
    }
    let (host, port_str) = if addr.starts_with('[') {
        let Some(end_bracket) = addr.find(']') else {
            return Err(NetworkError::Config("malformed bracketed IPv6 addr".into()));
        };
        let inner = &addr[1..end_bracket];
        if inner.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(NetworkError::Config("invalid IPv6 literal in addr".into()));
        }
        let rest = &addr[end_bracket + 1..];
        let Some(port_s) = rest.strip_prefix(':') else {
            return Err(NetworkError::Config("peer addr must include :port".into()));
        };
        (inner, port_s)
    } else {
        let Some((h, p)) = addr.rsplit_once(':') else {
            return Err(NetworkError::Config("peer addr must be host:port".into()));
        };
        if h.contains(':') {
            return Err(NetworkError::Config(
                "unbracketed IPv6 addr must use [ip]:port form".into(),
            ));
        }
        (h, p)
    };
    let port: u16 = port_str
        .parse()
        .map_err(|_| NetworkError::Config("peer addr has invalid port".into()))?;
    if host.is_empty() || port == 0 {
        return Err(NetworkError::Config(
            "peer addr must specify non-empty host and non-zero port".into(),
        ));
    }
    Ok(())
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

/// Formats TOML deserialization failures without echoing source snippets that may contain inline private keys.
fn sanitize_toml_error(err: &toml::de::Error) -> String {
    match err.span() {
        Some(span) => format!(
            "invalid TOML at bytes {}..{}: {}",
            span.start,
            span.end,
            err.message()
        ),
        None => format!("invalid TOML: {}", err.message()),
    }
}
