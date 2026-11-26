use std::error::Error;
use std::fmt;

use private_relay_crypto::CryptoError;
use private_relay_protocol::ProtocolError;

/// Transport, policy, DNS, and configuration errors at link & exit boundaries.
#[derive(Debug)]
pub enum NetworkError {
    Io(std::io::Error),
    Timeout(&'static str),
    ConnectionClosed,
    HandshakeTooLarge { size: usize, max: usize },
    Crypto(CryptoError),
    Protocol(ProtocolError),
    PolicyDenied(String),
    DnsResolutionFailed,
    Config(String),
}

impl From<std::io::Error> for NetworkError {
    fn from(err: std::io::Error) -> Self {
        match err.kind() {
            std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe => Self::ConnectionClosed,
            _ => Self::Io(err),
        }
    }
}

impl From<CryptoError> for NetworkError {
    fn from(err: CryptoError) -> Self {
        match err {
            CryptoError::Protocol(p) => Self::Protocol(p),
            other => Self::Crypto(other),
        }
    }
}

impl From<ProtocolError> for NetworkError {
    fn from(err: ProtocolError) -> Self {
        Self::Protocol(err)
    }
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "network I/O error: {e}"),
            Self::Timeout(op) => write!(f, "operation timed out: {op}"),
            Self::ConnectionClosed => write!(f, "peer connection closed cleanly or reset"),
            Self::HandshakeTooLarge { size, max } => {
                write!(f, "handshake message size {size} exceeds max {max}")
            }
            Self::Crypto(e) => write!(f, "cryptographic error: {e}"),
            Self::Protocol(e) => write!(f, "protocol error: {e}"),
            Self::PolicyDenied(msg) => write!(f, "destination policy denied: {msg}"),
            Self::DnsResolutionFailed => write!(f, "DNS resolution returned no usable addresses"),
            Self::Config(msg) => write!(f, "configuration error: {msg}"),
        }
    }
}

impl Error for NetworkError {}
