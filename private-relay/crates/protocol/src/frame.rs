use crate::cell::Cell;
use crate::constants::{
    CELL_HEADER_LEN, MAX_CELL_BYTES, OUTER_CIPHERTEXT_LEN, OUTER_PLAINTEXT_LEN,
    OUTER_REAL_LEN_PREFIX_LEN, OUTER_WIRE_FRAME_BYTES, TCP_LENGTH_PREFIX_LEN,
};
use crate::error::ProtocolError;

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
