use std::error::Error;
use std::fmt;

use crate::constants::{MAX_RELAY_HOPS, MAX_TARGET_ADDR_LEN};

/// Errors raised by stateless wire encoding, decoding, and protocol state validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    UnsupportedVersion(u8),
    UnknownCommand(u8),
    UnknownSubCommand(u8),
    UnknownDestroyReason(u8),
    UnknownErrorCode(u8),
    ZeroCircuitId,
    ZeroRequestId,
    InvalidWireFrameLength {
        expected: usize,
        actual: usize,
    },
    InvalidOuterLengthPrefix {
        expected: usize,
        actual: usize,
    },
    InvalidOuterPlaintextLength {
        expected: usize,
        actual: usize,
    },
    InvalidRealCellLength {
        min: usize,
        max: usize,
        actual: usize,
    },
    InsufficientPadding {
        needed: usize,
        provided: usize,
    },
    TruncatedHeader {
        expected: usize,
        actual: usize,
    },
    BodyTooLarge {
        declared: usize,
        max: usize,
    },
    LengthMismatch {
        declared: usize,
        actual: usize,
    },
    InvalidFlags(u8),
    InvalidHopIndex(u8),
    PayloadTooLarge {
        size: usize,
        max: usize,
    },
    InvalidChunkCount {
        count: u16,
        max: u16,
    },
    ChunkCountMismatch {
        expected: u16,
        actual: u16,
    },
    InvalidChunkIndex {
        index: u16,
        count: u16,
    },
    DuplicateChunk(u16),
    OutOfOrderOrMissingChunk {
        expected: u16,
        actual: u16,
    },
    RequestIdMismatch {
        expected: u32,
        actual: u32,
    },
    PayloadAfterFinal,
    InvalidTargetAddr,
    InvalidUtf8,
    MalformedPayload(&'static str),
    InvalidCircuitTransition {
        from: &'static str,
        event: &'static str,
    },
    InvalidRequestTransition {
        from: &'static str,
        event: &'static str,
    },
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => write!(f, "unsupported protocol version: 0x{v:02x}"),
            Self::UnknownCommand(cmd) => write!(f, "unknown cell command: 0x{cmd:02x}"),
            Self::UnknownSubCommand(sub) => write!(f, "unknown relay subcommand: 0x{sub:02x}"),
            Self::UnknownDestroyReason(code) => {
                write!(f, "unknown destroy reason code: 0x{code:02x}")
            }
            Self::UnknownErrorCode(code) => write!(f, "unknown stream error code: 0x{code:02x}"),
            Self::ZeroCircuitId => write!(f, "circuit identifier must be non-zero"),
            Self::ZeroRequestId => write!(f, "request identifier must be non-zero"),
            Self::InvalidWireFrameLength { expected, actual } => {
                write!(
                    f,
                    "invalid outer wire frame length: expected {expected} bytes, got {actual}"
                )
            }
            Self::InvalidOuterLengthPrefix { expected, actual } => {
                write!(
                    f,
                    "invalid outer TCP length prefix: expected {expected}, got {actual}"
                )
            }
            Self::InvalidOuterPlaintextLength { expected, actual } => {
                write!(
                    f,
                    "invalid outer plaintext length: expected {expected} bytes, got {actual}"
                )
            }
            Self::InvalidRealCellLength { min, max, actual } => {
                write!(
                    f,
                    "outer frame real_len {actual} is outside valid cell range {min}..={max}"
                )
            }
            Self::InsufficientPadding { needed, provided } => {
                write!(
                    f,
                    "insufficient random padding supplied: need {needed} bytes, got {provided}"
                )
            }
            Self::TruncatedHeader { expected, actual } => {
                write!(f, "truncated header: need {expected} bytes, got {actual}")
            }
            Self::BodyTooLarge { declared, max } => {
                write!(f, "cell body length {declared} exceeds max {max} bytes")
            }
            Self::LengthMismatch { declared, actual } => {
                write!(
                    f,
                    "cell length mismatch: header declared {declared} body bytes, got {actual}"
                )
            }
            Self::InvalidFlags(flags) => write!(f, "invalid flags byte: 0x{flags:02x}"),
            Self::InvalidHopIndex(idx) => {
                write!(
                    f,
                    "invalid hop index {idx}: must be in 1..={MAX_RELAY_HOPS}"
                )
            }
            Self::PayloadTooLarge { size, max } => {
                write!(f, "payload length {size} bytes exceeds maximum {max} bytes")
            }
            Self::InvalidChunkCount { count, max } => {
                write!(f, "invalid chunk count {count}: must be in 1..={max}")
            }
            Self::ChunkCountMismatch { expected, actual } => {
                write!(f, "chunk count mismatch: expected {expected}, got {actual}")
            }
            Self::InvalidChunkIndex { index, count } => {
                write!(f, "invalid chunk index {index} for chunk count {count}")
            }
            Self::DuplicateChunk(idx) => write!(f, "duplicate chunk index {idx}"),
            Self::OutOfOrderOrMissingChunk { expected, actual } => {
                write!(
                    f,
                    "missing or out-of-order chunk: expected index {expected}, got {actual}"
                )
            }
            Self::RequestIdMismatch { expected, actual } => {
                write!(
                    f,
                    "chunk received for wrong request id {actual} (expected {expected})"
                )
            }
            Self::PayloadAfterFinal => {
                write!(f, "unexpected chunk received after message completion")
            }
            Self::InvalidTargetAddr => {
                write!(
                    f,
                    "invalid target address (empty or exceeds {MAX_TARGET_ADDR_LEN} UTF-8 bytes)"
                )
            }
            Self::InvalidUtf8 => write!(f, "invalid UTF-8 string in protocol payload"),
            Self::MalformedPayload(reason) => write!(f, "malformed payload: {reason}"),
            Self::InvalidCircuitTransition { from, event } => {
                write!(f, "invalid circuit transition from {from} on event {event}")
            }
            Self::InvalidRequestTransition { from, event } => {
                write!(f, "invalid request transition from {from} on event {event}")
            }
        }
    }
}

impl Error for ProtocolError {}
