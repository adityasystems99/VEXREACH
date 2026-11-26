use std::error::Error;
use std::fmt;

use private_relay_crypto::CryptoError;
use private_relay_network::NetworkError;
use private_relay_protocol::{DestroyReason, ProtocolError, RequestErrorCode};

/// Errors returned while establishing a 3-hop circuit or executing bounded request/response exchanges.
#[derive(Debug)]
pub enum ClientError {
    Network(NetworkError),
    Crypto(CryptoError),
    Protocol(ProtocolError),
    CircuitDestroyed(DestroyReason),
    RemoteError(RequestErrorCode),
    InvalidRoute(&'static str),
    InvalidState(&'static str),
}

impl From<NetworkError> for ClientError {
    fn from(err: NetworkError) -> Self {
        Self::Network(err)
    }
}

impl From<CryptoError> for ClientError {
    fn from(err: CryptoError) -> Self {
        Self::Crypto(err)
    }
}

impl From<ProtocolError> for ClientError {
    fn from(err: ProtocolError) -> Self {
        Self::Protocol(err)
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(e) => write!(f, "client network error: {e}"),
            Self::Crypto(e) => write!(f, "client cryptographic error: {e}"),
            Self::Protocol(e) => write!(f, "client protocol error: {e}"),
            Self::CircuitDestroyed(r) => write!(f, "circuit destroyed by relay ({r:?})"),
            Self::RemoteError(code) => write!(f, "exit returned remote error: {}", code.summary()),
            Self::InvalidRoute(msg) => write!(f, "invalid 3-hop route: {msg}"),
            Self::InvalidState(msg) => write!(f, "invalid client state: {msg}"),
        }
    }
}

impl Error for ClientError {}
