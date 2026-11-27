//! Stateless wire protocol framing, validation, and lifecycle state machines for Private-Relay v0.1.

pub mod cell;
pub mod circuit;
pub mod constants;
pub mod error;
pub mod frame;
pub mod message;
pub mod request;

pub use cell::{
    build_hop_aead_aad, Cell, Command, DestroyReason, ExtendDirective, HopDirection,
    RelayHopPlaintext, RelaySubCommand,
};
pub use circuit::{CircuitId, CircuitState};
pub use constants::*;
pub use error::ProtocolError;
pub use frame::{decode_wire_record, encode_wire_record, LinkFrame, OuterFramePlaintext};
pub use message::{
    chunk_request, chunk_response, encode_error_payload, DecodedRequest, InnerFlags, InnerPayload,
    MessageReassembler, ReassembledMessage,
};
pub use request::{RequestErrorCode, RequestId, RequestState};
