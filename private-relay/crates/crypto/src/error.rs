use std::error::Error;
use std::fmt;

use private_relay_protocol::ProtocolError;

/// Errors returned by Noise handshakes, HKDF key derivation, and per-hop AEAD operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Wrapper around protocol encoding/validation errors during sealed frame handling.
    Protocol(ProtocolError),
    /// Handshake failed or could not verify peer authenticity (`Noise` details suppressed).
    HandshakeFailed,
    /// Remote peer static public key did not match expected identity key.
    UnexpectedPeerIdentity,
    /// Authenticated encryption or decryption tag verification failed.
    AuthenticationFailed,
    /// Incoming sequence number violated strict FIFO ordering or indicated replay.
    SequenceMismatch { expected: u64, actual: u64 },
    /// Circuit sequence space (`2^32`) exhausted; caller must tear down circuit.
    SequenceExhausted,
    /// Key material length or HKDF expansion failed.
    InvalidKeyMaterial,
    /// Cipher operation called on invalid state.
    InvalidState(&'static str),
}

impl From<ProtocolError> for CryptoError {
    fn from(err: ProtocolError) -> Self {
        Self::Protocol(err)
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(e) => write!(f, "protocol error during crypto operation: {e}"),
            Self::HandshakeFailed => write!(f, "noise handshake failed"),
            Self::UnexpectedPeerIdentity => {
                write!(f, "remote static key did not match expected peer identity")
            }
            Self::AuthenticationFailed => write!(f, "AEAD authentication failed"),
            Self::SequenceMismatch { expected, actual } => {
                write!(
                    f,
                    "replay or out-of-order sequence: expected {expected}, got {actual}"
                )
            }
            Self::SequenceExhausted => write!(f, "circuit nonce sequence limit reached"),
            Self::InvalidKeyMaterial => write!(f, "invalid cryptographic key material"),
            Self::InvalidState(msg) => write!(f, "invalid cryptographic state: {msg}"),
        }
    }
}

impl Error for CryptoError {}
