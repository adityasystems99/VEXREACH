use std::error::Error;
use std::fmt;

use private_relay_crypto::CryptoError;
use private_relay_network::NetworkError;
use private_relay_protocol::{DestroyReason, ProtocolError};

/// Errors produced by relay startup, link acceptance, circuit forwarding, and exit execution.
#[derive(Debug)]
pub enum RelayError {
    Network(NetworkError),
    Crypto(CryptoError),
    Protocol(ProtocolError),
    CircuitDestroyed(DestroyReason),
    CapacityExceeded(&'static str),
    PolicyDenied(&'static str),
    InvalidRoleAction(&'static str),
}

impl From<NetworkError> for RelayError {
    fn from(err: NetworkError) -> Self {
        Self::Network(err)
    }
}

impl From<CryptoError> for RelayError {
    fn from(err: CryptoError) -> Self {
        Self::Crypto(err)
    }
}

impl From<ProtocolError> for RelayError {
    fn from(err: ProtocolError) -> Self {
        Self::Protocol(err)
    }
}

impl From<std::io::Error> for RelayError {
    fn from(err: std::io::Error) -> Self {
        Self::Network(NetworkError::from(err))
    }
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(e) => write!(f, "relay network error: {e}"),
            Self::Crypto(e) => write!(f, "relay cryptographic error: {e}"),
            Self::Protocol(e) => write!(f, "relay protocol error: {e}"),
            Self::CircuitDestroyed(r) => write!(f, "circuit destroyed ({r:?})"),
            Self::CapacityExceeded(msg) => write!(f, "relay capacity exceeded: {msg}"),
            Self::PolicyDenied(msg) => write!(f, "relay policy denied: {msg}"),
            Self::InvalidRoleAction(msg) => write!(f, "invalid action for relay role: {msg}"),
        }
    }
}

impl Error for RelayError {}
