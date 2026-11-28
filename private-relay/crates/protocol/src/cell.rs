use crate::circuit::CircuitId;
use crate::constants::{
    CELL_HEADER_LEN, HOP_AEAD_AAD_LEN, MAX_CELL_BODY_LEN, MAX_CELL_BYTES, MAX_RELAY_HOPS,
    MAX_TARGET_ADDR_LEN, PROTOCOL_VERSION, X25519_KEY_LEN,
};
use crate::error::ProtocolError;

/// Top-level cell commands carried inside fixed outer link frames.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Create = 0x01,
    Created = 0x02,
    Extend = 0x03,
    Extended = 0x04,
    RelayData = 0x05,
    Destroy = 0x06,
}

impl Command {
    pub fn from_u8(val: u8) -> Result<Self, ProtocolError> {
        match val {
            0x01 => Ok(Self::Create),
            0x02 => Ok(Self::Created),
            0x03 => Ok(Self::Extend),
            0x04 => Ok(Self::Extended),
            0x05 => Ok(Self::RelayData),
            0x06 => Ok(Self::Destroy),
            other => Err(ProtocolError::UnknownCommand(other)),
        }
    }
}

/// Sanitized circuit teardown reason codes (never leaks cryptographic oracle specifics).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestroyReason {
    Normal = 0x00,
    ProtocolError = 0x01,
    CryptoFail = 0x02,
    IdleTimeout = 0x03,
    PeerDisconnected = 0x04,
    ResourceLimit = 0x05,
    HandshakeTimeout = 0x06,
    PolicyDenied = 0x07,
}

impl DestroyReason {
    pub fn from_u8(val: u8) -> Result<Self, ProtocolError> {
        match val {
            0x00 => Ok(Self::Normal),
            0x01 => Ok(Self::ProtocolError),
            0x02 => Ok(Self::CryptoFail),
            0x03 => Ok(Self::IdleTimeout),
            0x04 => Ok(Self::PeerDisconnected),
            0x05 => Ok(Self::ResourceLimit),
            0x06 => Ok(Self::HandshakeTimeout),
            0x07 => Ok(Self::PolicyDenied),
            other => Err(ProtocolError::UnknownDestroyReason(other)),
        }
    }
}

/// Per-hop AEAD direction identifier (`Approved Security Correction D-07`).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HopDirection {
    Forward = 0x01,
    Backward = 0x02,
}

/// Builds canonical 15-byte AEAD AAD for end-to-end per-hop encryption (`Approved Correction D-07`).
///
/// Format: `b"PRv1" (4B) || version (1B) || direction (1B) || hop_index (1B) || seq (8B BE)`.
/// Link-local `circuit_id` is explicitly excluded because Client does not know Entry/Middle-assigned IDs.
pub fn build_hop_aead_aad(
    direction: HopDirection,
    hop_index: u8,
    seq: u64,
) -> Result<[u8; HOP_AEAD_AAD_LEN], ProtocolError> {
    if hop_index == 0 || (hop_index as usize) > MAX_RELAY_HOPS {
        return Err(ProtocolError::InvalidHopIndex(hop_index));
    }
    let mut aad = [0u8; HOP_AEAD_AAD_LEN];
    aad[0..4].copy_from_slice(b"PRv1");
    aad[4] = PROTOCOL_VERSION;
    aad[5] = direction as u8;
    aad[6] = hop_index;
    aad[7..15].copy_from_slice(&seq.to_be_bytes());
    Ok(aad)
}

/// Unpadded overlay cell header + body (`9B` header + `<= 571B` body = `<= 580B`).
///
/// Wire layout:
/// `[circuit_id: u32 BE][version: u8][command: u8][payload_len: u16 BE][flags: u8][body...]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cell {
    pub circuit_id: CircuitId,
    pub version: u8,
    pub command: Command,
    pub flags: u8,
    pub body: Vec<u8>,
}

impl Cell {
    /// Creates a validated `v0.1` `Cell` enforcing body length `<= 571` bytes.
    pub fn new(
        circuit_id: CircuitId,
        command: Command,
        flags: u8,
        body: Vec<u8>,
    ) -> Result<Self, ProtocolError> {
        if body.len() > MAX_CELL_BODY_LEN {
            return Err(ProtocolError::BodyTooLarge {
                declared: body.len(),
                max: MAX_CELL_BODY_LEN,
            });
        }
        Ok(Self {
            circuit_id,
            version: PROTOCOL_VERSION,
            command,
            flags,
            body,
        })
    }

    /// Convenience constructor for a 1-byte `DESTROY` control cell.
    pub fn destroy(circuit_id: CircuitId, reason: DestroyReason) -> Self {
        Self {
            circuit_id,
            version: PROTOCOL_VERSION,
            command: Command::Destroy,
            flags: 0,
            body: vec![reason as u8],
        }
    }

    /// Parses the 1-byte `DestroyReason` when `self.command == Command::Destroy`.
    pub fn destroy_reason(&self) -> Result<DestroyReason, ProtocolError> {
        if self.command != Command::Destroy {
            return Err(ProtocolError::MalformedPayload("not a DESTROY cell"));
        }
        if self.body.len() != 1 {
            return Err(ProtocolError::MalformedPayload(
                "DESTROY cell body must be 1 byte",
            ));
        }
        DestroyReason::from_u8(self.body[0])
    }

    /// Encodes the cell cleanly into a caller-supplied buffer (`dst.len() >= 9 + body.len()`), returning bytes written.
    pub fn encode_into_slice(&self, dst: &mut [u8]) -> Result<usize, ProtocolError> {
        if self.version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.version));
        }
        if self.body.len() > MAX_CELL_BODY_LEN {
            return Err(ProtocolError::BodyTooLarge {
                declared: self.body.len(),
                max: MAX_CELL_BODY_LEN,
            });
        }
        if self.command == Command::Destroy {
            let _ = self.destroy_reason()?;
        }

        let total = CELL_HEADER_LEN + self.body.len();
        debug_assert!(total <= MAX_CELL_BYTES);
        if dst.len() < total {
            return Err(ProtocolError::InsufficientPadding {
                needed: total,
                provided: dst.len(),
            });
        }

        dst[0..4].copy_from_slice(&self.circuit_id.get().to_be_bytes());
        dst[4] = self.version;
        dst[5] = self.command as u8;
        dst[6..8].copy_from_slice(&(self.body.len() as u16).to_be_bytes());
        dst[8] = self.flags;
        dst[9..total].copy_from_slice(&self.body);
        Ok(total)
    }

    /// Encodes the cell cleanly into bytes (`9..=580` bytes).
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let total = CELL_HEADER_LEN + self.body.len();
        let mut out = vec![0u8; total.min(MAX_CELL_BYTES)];
        let written = self.encode_into_slice(&mut out)?;
        debug_assert_eq!(written, total);
        Ok(out)
    }

    /// Decodes raw cell bytes, rejecting invalid versions, zero IDs, unknown commands, and length mismatches.
    pub fn decode(raw: &[u8]) -> Result<Self, ProtocolError> {
        if raw.len() < CELL_HEADER_LEN {
            return Err(ProtocolError::TruncatedHeader {
                expected: CELL_HEADER_LEN,
                actual: raw.len(),
            });
        }
        if raw.len() > MAX_CELL_BYTES {
            return Err(ProtocolError::InvalidRealCellLength {
                min: CELL_HEADER_LEN,
                max: MAX_CELL_BYTES,
                actual: raw.len(),
            });
        }

        let circuit_id = CircuitId::new(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))?;
        let version = raw[4];
        if version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(version));
        }

        let command = Command::from_u8(raw[5])?;
        let payload_len = u16::from_be_bytes([raw[6], raw[7]]) as usize;
        let flags = raw[8];

        if payload_len > MAX_CELL_BODY_LEN {
            return Err(ProtocolError::BodyTooLarge {
                declared: payload_len,
                max: MAX_CELL_BODY_LEN,
            });
        }

        let actual_body_len = raw.len() - CELL_HEADER_LEN;
        if actual_body_len != payload_len {
            return Err(ProtocolError::LengthMismatch {
                declared: payload_len,
                actual: actual_body_len,
            });
        }

        let cell = Self {
            circuit_id,
            version,
            command,
            flags,
            body: raw[CELL_HEADER_LEN..].to_vec(),
        };

        if cell.command == Command::Destroy {
            let _ = cell.destroy_reason()?;
        }

        Ok(cell)
    }
}

/// Inner hop-layer subcommand discriminant (`1` byte inside per-hop decrypted plaintext).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelaySubCommand {
    Forward = 0x01,
    Extend = 0x02,
    Message = 0x03,
    Extended = 0x04,
}

impl RelaySubCommand {
    pub fn from_u8(val: u8) -> Result<Self, ProtocolError> {
        match val {
            0x01 => Ok(Self::Forward),
            0x02 => Ok(Self::Extend),
            0x03 => Ok(Self::Message),
            0x04 => Ok(Self::Extended),
            other => Err(ProtocolError::UnknownSubCommand(other)),
        }
    }
}

/// Hop extension instruction encrypted under the intermediate relay's forward key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendDirective {
    pub next_hop_addr: String,
    pub next_hop_pub: [u8; X25519_KEY_LEN],
    pub handshake_msg1: Vec<u8>,
}

/// Decrypted plaintext processed at an individual relay hop (`RelaySubCommand` + body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayHopPlaintext {
    Forward(Vec<u8>),
    Extend(ExtendDirective),
    Message(Vec<u8>),
    Extended(Vec<u8>),
}

impl RelayHopPlaintext {
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        match self {
            Self::Forward(inner) => {
                if inner.is_empty() || inner.len() >= MAX_CELL_BODY_LEN {
                    return Err(ProtocolError::PayloadTooLarge {
                        size: inner.len(),
                        max: MAX_CELL_BODY_LEN - 1,
                    });
                }
                let mut out = Vec::with_capacity(1 + inner.len());
                out.push(RelaySubCommand::Forward as u8);
                out.extend_from_slice(inner);
                Ok(out)
            }
            Self::Extend(dir) => {
                let addr_bytes = dir.next_hop_addr.as_bytes();
                if addr_bytes.is_empty() || addr_bytes.len() > MAX_TARGET_ADDR_LEN {
                    return Err(ProtocolError::InvalidTargetAddr);
                }
                if dir.handshake_msg1.is_empty() || dir.handshake_msg1.len() > 256 {
                    return Err(ProtocolError::MalformedPayload(
                        "invalid Noise handshake_msg1 length",
                    ));
                }
                let total =
                    1 + 2 + addr_bytes.len() + X25519_KEY_LEN + 2 + dir.handshake_msg1.len();
                let mut out = Vec::with_capacity(total);
                out.push(RelaySubCommand::Extend as u8);
                out.extend_from_slice(&(addr_bytes.len() as u16).to_be_bytes());
                out.extend_from_slice(addr_bytes);
                out.extend_from_slice(&dir.next_hop_pub);
                out.extend_from_slice(&(dir.handshake_msg1.len() as u16).to_be_bytes());
                out.extend_from_slice(&dir.handshake_msg1);
                Ok(out)
            }
            Self::Message(payload) => {
                if payload.is_empty() || payload.len() >= MAX_CELL_BODY_LEN {
                    return Err(ProtocolError::PayloadTooLarge {
                        size: payload.len(),
                        max: MAX_CELL_BODY_LEN - 1,
                    });
                }
                let mut out = Vec::with_capacity(1 + payload.len());
                out.push(RelaySubCommand::Message as u8);
                out.extend_from_slice(payload);
                Ok(out)
            }
            Self::Extended(msg2) => {
                if msg2.is_empty() || msg2.len() > 256 {
                    return Err(ProtocolError::MalformedPayload(
                        "invalid Noise handshake_msg2 length",
                    ));
                }
                let mut out = Vec::with_capacity(1 + 2 + msg2.len());
                out.push(RelaySubCommand::Extended as u8);
                out.extend_from_slice(&(msg2.len() as u16).to_be_bytes());
                out.extend_from_slice(msg2);
                Ok(out)
            }
        }
    }

    pub fn decode(raw: &[u8]) -> Result<Self, ProtocolError> {
        if raw.is_empty() {
            return Err(ProtocolError::MalformedPayload("empty hop plaintext"));
        }
        let sub = RelaySubCommand::from_u8(raw[0])?;
        let rest = &raw[1..];
        match sub {
            RelaySubCommand::Forward => {
                if rest.is_empty() {
                    return Err(ProtocolError::MalformedPayload("empty forwarded envelope"));
                }
                if rest.len() >= MAX_CELL_BODY_LEN {
                    return Err(ProtocolError::PayloadTooLarge {
                        size: rest.len(),
                        max: MAX_CELL_BODY_LEN - 1,
                    });
                }
                Ok(Self::Forward(rest.to_vec()))
            }
            RelaySubCommand::Extend => {
                if rest.len() < 2 {
                    return Err(ProtocolError::MalformedPayload(
                        "truncated extend target len",
                    ));
                }
                let addr_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
                if addr_len == 0 || addr_len > MAX_TARGET_ADDR_LEN {
                    return Err(ProtocolError::InvalidTargetAddr);
                }
                let min_len = 2 + addr_len + X25519_KEY_LEN + 2;
                if rest.len() < min_len {
                    return Err(ProtocolError::MalformedPayload(
                        "truncated extend directive",
                    ));
                }
                let next_hop_addr = std::str::from_utf8(&rest[2..2 + addr_len])
                    .map_err(|_| ProtocolError::InvalidUtf8)?
                    .to_owned();
                let mut next_hop_pub = [0u8; X25519_KEY_LEN];
                next_hop_pub.copy_from_slice(&rest[2 + addr_len..2 + addr_len + X25519_KEY_LEN]);
                let msg1_pos = 2 + addr_len + X25519_KEY_LEN;
                let msg1_len = u16::from_be_bytes([rest[msg1_pos], rest[msg1_pos + 1]]) as usize;
                if msg1_len == 0 || msg1_len > 256 || rest.len() != min_len + msg1_len {
                    return Err(ProtocolError::MalformedPayload(
                        "extend msg1 length mismatch",
                    ));
                }
                let handshake_msg1 = rest[min_len..].to_vec();
                Ok(Self::Extend(ExtendDirective {
                    next_hop_addr,
                    next_hop_pub,
                    handshake_msg1,
                }))
            }
            RelaySubCommand::Message => {
                if rest.is_empty() {
                    return Err(ProtocolError::MalformedPayload(
                        "empty inner message payload",
                    ));
                }
                if rest.len() >= MAX_CELL_BODY_LEN {
                    return Err(ProtocolError::PayloadTooLarge {
                        size: rest.len(),
                        max: MAX_CELL_BODY_LEN - 1,
                    });
                }
                Ok(Self::Message(rest.to_vec()))
            }
            RelaySubCommand::Extended => {
                if rest.len() < 2 {
                    return Err(ProtocolError::MalformedPayload(
                        "truncated extended msg2 len",
                    ));
                }
                let msg2_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
                if msg2_len == 0 || msg2_len > 256 || rest.len() != 2 + msg2_len {
                    return Err(ProtocolError::MalformedPayload(
                        "extended msg2 length mismatch",
                    ));
                }
                Ok(Self::Extended(rest[2..].to_vec()))
            }
        }
    }
}
