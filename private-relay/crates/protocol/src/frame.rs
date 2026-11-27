use crate::cell::Cell;
use crate::constants::{
    CELL_HEADER_LEN, LINK_REKEY_MAGIC, LINK_REKEY_MARKER, MAX_CELL_BYTES, OUTER_CIPHERTEXT_LEN,
    OUTER_PLAINTEXT_LEN, OUTER_REAL_LEN_PREFIX_LEN, OUTER_WIRE_FRAME_BYTES, PROTOCOL_VERSION,
    TCP_LENGTH_PREFIX_LEN,
};
use crate::error::ProtocolError;

const LINK_REKEY_CONTROL_HEADER_LEN: usize = 2 + 8 + 1 + 8;

/// Decoded outer Noise plaintext frame: either a normal overlay [`Cell`] or an internal link rekey control signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkFrame {
    Cell(Cell),
    RekeyControl { epoch: u64 },
}

/// Reconciled `582`-byte outer Noise link plaintext buffer (`Approved Decision D-02`).
///
/// Layout prior to `Noise_IK` encryption (`582B` plaintext + `16B` Noise MAC = `598B` ciphertext;
/// prefixed by `2B` `outer_len == 598` on TCP wire = **`600B` exact total wire record**):
/// `[real_len: u16 BE (9..=580)][encoded_cell (real_len bytes)][random_padding (580 - real_len bytes)]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OuterFramePlaintext {
    pub bytes: [u8; OUTER_PLAINTEXT_LEN],
}

impl OuterFramePlaintext {
    /// Packs `cell` into exact `582`-byte plaintext padded with caller-supplied random bytes.
    ///
    /// Returns `InsufficientPadding` if fewer padding bytes are provided than `580 - encoded_cell.len()`.
    pub fn pack(cell: &Cell, random_padding: &[u8]) -> Result<Self, ProtocolError> {
        let encoded_cell = cell.encode()?;
        let real_len = encoded_cell.len();
        if !(CELL_HEADER_LEN..=MAX_CELL_BYTES).contains(&real_len) {
            return Err(ProtocolError::InvalidRealCellLength {
                min: CELL_HEADER_LEN,
                max: MAX_CELL_BYTES,
                actual: real_len,
            });
        }

        let needed_pad = MAX_CELL_BYTES - real_len;
        if random_padding.len() < needed_pad {
            return Err(ProtocolError::InsufficientPadding {
                needed: needed_pad,
                provided: random_padding.len(),
            });
        }

        let mut bytes = [0u8; OUTER_PLAINTEXT_LEN];
        bytes[0..OUTER_REAL_LEN_PREFIX_LEN].copy_from_slice(&(real_len as u16).to_be_bytes());
        bytes[OUTER_REAL_LEN_PREFIX_LEN..OUTER_REAL_LEN_PREFIX_LEN + real_len]
            .copy_from_slice(&encoded_cell);
        bytes[OUTER_REAL_LEN_PREFIX_LEN + real_len..]
            .copy_from_slice(&random_padding[..needed_pad]);

        Ok(Self { bytes })
    }

    /// Validates a decrypted `582`-byte plaintext slice and extracts the inner `Cell`.
    pub fn unpack(plaintext: &[u8]) -> Result<Cell, ProtocolError> {
        if plaintext.len() != OUTER_PLAINTEXT_LEN {
            return Err(ProtocolError::InvalidOuterPlaintextLength {
                expected: OUTER_PLAINTEXT_LEN,
                actual: plaintext.len(),
            });
        }
        let real_len = u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize;
        if !(CELL_HEADER_LEN..=MAX_CELL_BYTES).contains(&real_len) {
            return Err(ProtocolError::InvalidRealCellLength {
                min: CELL_HEADER_LEN,
                max: MAX_CELL_BYTES,
                actual: real_len,
            });
        }
        Cell::decode(&plaintext[OUTER_REAL_LEN_PREFIX_LEN..OUTER_REAL_LEN_PREFIX_LEN + real_len])
    }

    /// Packs a `582`-byte encrypted Noise link rekey control frame (`0xFFFF || b"PR_REKEY" || version || epoch || padding`).
    pub fn pack_rekey_control(epoch: u64, random_padding: &[u8]) -> Result<Self, ProtocolError> {
        if epoch == 0 {
            return Err(ProtocolError::MalformedPayload(
                "link rekey epoch must be non-zero",
            ));
        }
        let needed_pad = OUTER_PLAINTEXT_LEN - LINK_REKEY_CONTROL_HEADER_LEN;
        if random_padding.len() < needed_pad {
            return Err(ProtocolError::InsufficientPadding {
                needed: needed_pad,
                provided: random_padding.len(),
            });
        }

        let mut bytes = [0u8; OUTER_PLAINTEXT_LEN];
        bytes[0..2].copy_from_slice(&LINK_REKEY_MARKER.to_be_bytes());
        bytes[2..10].copy_from_slice(LINK_REKEY_MAGIC);
        bytes[10] = PROTOCOL_VERSION;
        bytes[11..19].copy_from_slice(&epoch.to_be_bytes());
        bytes[LINK_REKEY_CONTROL_HEADER_LEN..].copy_from_slice(&random_padding[..needed_pad]);
        Ok(Self { bytes })
    }

    /// Decodes a decrypted `582`-byte outer Noise link frame into either a [`Cell`] or a validated [`LinkFrame::RekeyControl`].
    pub fn unpack_link_frame(plaintext: &[u8]) -> Result<LinkFrame, ProtocolError> {
        if plaintext.len() != OUTER_PLAINTEXT_LEN {
            return Err(ProtocolError::InvalidOuterPlaintextLength {
                expected: OUTER_PLAINTEXT_LEN,
                actual: plaintext.len(),
            });
        }

        let marker = u16::from_be_bytes([plaintext[0], plaintext[1]]);
        if marker == LINK_REKEY_MARKER {
            if &plaintext[2..10] != LINK_REKEY_MAGIC {
                return Err(ProtocolError::MalformedPayload(
                    "invalid link rekey control magic",
                ));
            }
            if plaintext[10] != PROTOCOL_VERSION {
                return Err(ProtocolError::UnsupportedVersion(plaintext[10]));
            }
            let epoch = u64::from_be_bytes(
                plaintext[11..19]
                    .try_into()
                    .map_err(|_| ProtocolError::MalformedPayload("truncated rekey epoch"))?,
            );
            if epoch == 0 {
                return Err(ProtocolError::MalformedPayload(
                    "link rekey epoch must be non-zero",
                ));
            }
            return Ok(LinkFrame::RekeyControl { epoch });
        }

        Self::unpack(plaintext).map(LinkFrame::Cell)
    }
}

/// Wraps a `598`-byte Noise ciphertext into a fixed `600`-byte complete on-wire TCP record.
pub fn encode_wire_record(
    ciphertext_598: &[u8],
) -> Result<[u8; OUTER_WIRE_FRAME_BYTES], ProtocolError> {
    if ciphertext_598.len() != OUTER_CIPHERTEXT_LEN {
        return Err(ProtocolError::InvalidOuterLengthPrefix {
            expected: OUTER_CIPHERTEXT_LEN,
            actual: ciphertext_598.len(),
        });
    }
    let mut record = [0u8; OUTER_WIRE_FRAME_BYTES];
    record[0..TCP_LENGTH_PREFIX_LEN].copy_from_slice(&(OUTER_CIPHERTEXT_LEN as u16).to_be_bytes());
    record[TCP_LENGTH_PREFIX_LEN..].copy_from_slice(ciphertext_598);
    Ok(record)
}

/// Validates a `600`-byte on-wire TCP record and returns its `598`-byte ciphertext payload.
pub fn decode_wire_record(record: &[u8]) -> Result<&[u8], ProtocolError> {
    if record.len() != OUTER_WIRE_FRAME_BYTES {
        return Err(ProtocolError::InvalidWireFrameLength {
            expected: OUTER_WIRE_FRAME_BYTES,
            actual: record.len(),
        });
    }
    let declared_len = u16::from_be_bytes([record[0], record[1]]) as usize;
    if declared_len != OUTER_CIPHERTEXT_LEN {
        return Err(ProtocolError::InvalidOuterLengthPrefix {
            expected: OUTER_CIPHERTEXT_LEN,
            actual: declared_len,
        });
    }
    Ok(&record[TCP_LENGTH_PREFIX_LEN..])
}
