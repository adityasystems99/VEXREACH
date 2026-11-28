use crate::constants::{
    INNER_HEADER_LEN, MAX_CHUNKS_PER_MESSAGE, MAX_ENCODED_REQUEST_BYTES, MAX_FRAGMENT_LEN,
    MAX_INNER_PAYLOAD_LEN, MAX_MESSAGE_BYTES, MAX_TARGET_ADDR_LEN,
};
use crate::error::ProtocolError;
use crate::request::{RequestErrorCode, RequestId};

/// Bitflags carried on every `InnerPayload` chunk (`Approved Decision D-01`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InnerFlags(u8);

impl InnerFlags {
    pub const NONE: u8 = 0x00;
    pub const FIRST: u8 = 0x01;
    pub const FINAL: u8 = 0x02;
    pub const ERROR: u8 = 0x04;

    const VALID_MASK: u8 = Self::FIRST | Self::FINAL | Self::ERROR;

    pub fn from_u8(raw: u8) -> Result<Self, ProtocolError> {
        if (raw & !Self::VALID_MASK) != 0 {
            return Err(ProtocolError::InvalidFlags(raw));
        }
        Ok(Self(raw))
    }

    pub fn raw(self) -> u8 {
        self.0
    }

    pub fn is_first(self) -> bool {
        (self.0 & Self::FIRST) != 0
    }

    pub fn is_final(self) -> bool {
        (self.0 & Self::FINAL) != 0
    }

    pub fn is_error(self) -> bool {
        (self.0 & Self::ERROR) != 0
    }
}

/// Innermost payload chunk carried inside `RelayHopPlaintext::Message` (`<= 496` bytes).
///
/// Layout:
/// `[request_id: u32 BE][chunk_index: u16 BE][chunk_count: u16 BE][inner_flags: u8][fragment <= 487B]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerPayload {
    pub request_id: RequestId,
    pub chunk_index: u16,
    pub chunk_count: u16,
    pub flags: InnerFlags,
    pub fragment: Vec<u8>,
}

impl InnerPayload {
    /// Constructs a validated `InnerPayload`, checking chunk indices, counts, flags, and fragment bounds.
    pub fn new(
        request_id: RequestId,
        chunk_index: u16,
        chunk_count: u16,
        flags: InnerFlags,
        fragment: Vec<u8>,
    ) -> Result<Self, ProtocolError> {
        validate_chunk_metadata(chunk_index, chunk_count, flags, fragment.len())?;
        Ok(Self {
            request_id,
            chunk_index,
            chunk_count,
            flags,
            fragment,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        validate_chunk_metadata(
            self.chunk_index,
            self.chunk_count,
            self.flags,
            self.fragment.len(),
        )?;
        let mut out = Vec::with_capacity(INNER_HEADER_LEN + self.fragment.len());
        out.extend_from_slice(&self.request_id.get().to_be_bytes());
        out.extend_from_slice(&self.chunk_index.to_be_bytes());
        out.extend_from_slice(&self.chunk_count.to_be_bytes());
        out.push(self.flags.raw());
        out.extend_from_slice(&self.fragment);
        debug_assert!(out.len() <= MAX_INNER_PAYLOAD_LEN);
        Ok(out)
    }

    pub fn decode(raw: &[u8]) -> Result<Self, ProtocolError> {
        if raw.len() < INNER_HEADER_LEN {
            return Err(ProtocolError::TruncatedHeader {
                expected: INNER_HEADER_LEN,
                actual: raw.len(),
            });
        }
        if raw.len() > MAX_INNER_PAYLOAD_LEN {
            return Err(ProtocolError::PayloadTooLarge {
                size: raw.len(),
                max: MAX_INNER_PAYLOAD_LEN,
            });
        }

        let request_id = RequestId::new(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))?;
        let chunk_index = u16::from_be_bytes([raw[4], raw[5]]);
        let chunk_count = u16::from_be_bytes([raw[6], raw[7]]);
        let flags = InnerFlags::from_u8(raw[8])?;
        let fragment = raw[INNER_HEADER_LEN..].to_vec();

        validate_chunk_metadata(chunk_index, chunk_count, flags, fragment.len())?;

        Ok(Self {
            request_id,
            chunk_index,
            chunk_count,
            flags,
            fragment,
        })
    }
}

fn validate_chunk_metadata(
    chunk_index: u16,
    chunk_count: u16,
    flags: InnerFlags,
    fragment_len: usize,
) -> Result<(), ProtocolError> {
    if chunk_count == 0 || chunk_count > MAX_CHUNKS_PER_MESSAGE {
        return Err(ProtocolError::InvalidChunkCount {
            count: chunk_count,
            max: MAX_CHUNKS_PER_MESSAGE,
        });
    }
    if chunk_index >= chunk_count {
        return Err(ProtocolError::InvalidChunkIndex {
            index: chunk_index,
            count: chunk_count,
        });
    }
    if fragment_len > MAX_FRAGMENT_LEN {
        return Err(ProtocolError::PayloadTooLarge {
            size: fragment_len,
            max: MAX_FRAGMENT_LEN,
        });
    }

    // Enforce consistent FIRST / FINAL flag positioning.
    if (chunk_index == 0) != flags.is_first() {
        return Err(ProtocolError::InvalidFlags(flags.raw()));
    }
    if (chunk_index + 1 == chunk_count) != flags.is_final() {
        return Err(ProtocolError::InvalidFlags(flags.raw()));
    }
    if flags.is_error() && (chunk_count != 1 || fragment_len != 1) {
        return Err(ProtocolError::MalformedPayload(
            "ERROR chunk must be single 1-byte error code chunk",
        ));
    }

    Ok(())
}

/// Splits a bounded request (`target_host_port` + `<= 64 KiB` body) into sequential `InnerPayload` chunks.
///
/// Target prefix format: `[target_len: u16 BE][target_utf8][body...]`.
pub fn chunk_request(
    request_id: RequestId,
    target_host_port: &str,
    body: &[u8],
) -> Result<Vec<InnerPayload>, ProtocolError> {
    let target_bytes = target_host_port.as_bytes();
    if target_bytes.is_empty() || target_bytes.len() > MAX_TARGET_ADDR_LEN {
        return Err(ProtocolError::InvalidTargetAddr);
    }
    if body.len() > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::PayloadTooLarge {
            size: body.len(),
            max: MAX_MESSAGE_BYTES,
        });
    }

    let mut combined = Vec::with_capacity(2 + target_bytes.len() + body.len());
    combined.extend_from_slice(&(target_bytes.len() as u16).to_be_bytes());
    combined.extend_from_slice(target_bytes);
    combined.extend_from_slice(body);

    chunk_bytes(request_id, &combined)
}

/// Splits a bounded response (`<= 64 KiB` body) into sequential `InnerPayload` chunks.
pub fn chunk_response(
    request_id: RequestId,
    body: &[u8],
) -> Result<Vec<InnerPayload>, ProtocolError> {
    if body.len() > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::PayloadTooLarge {
            size: body.len(),
            max: MAX_MESSAGE_BYTES,
        });
    }
    chunk_bytes(request_id, body)
}

/// Encodes a sanitized single-chunk `ERROR` message from Exit back to Client.
pub fn encode_error_payload(request_id: RequestId, code: RequestErrorCode) -> InnerPayload {
    InnerPayload {
        request_id,
        chunk_index: 0,
        chunk_count: 1,
        flags: InnerFlags::from_u8(InnerFlags::FIRST | InnerFlags::FINAL | InnerFlags::ERROR)
            .expect("static flags valid"),
        fragment: vec![code as u8],
    }
}

fn chunk_bytes(request_id: RequestId, data: &[u8]) -> Result<Vec<InnerPayload>, ProtocolError> {
    if data.is_empty() {
        return Ok(vec![InnerPayload::new(
            request_id,
            0,
            1,
            InnerFlags::from_u8(InnerFlags::FIRST | InnerFlags::FINAL)?,
            Vec::new(),
        )?]);
    }

    let slices: Vec<&[u8]> = data.chunks(MAX_FRAGMENT_LEN).collect();
    if slices.len() > MAX_CHUNKS_PER_MESSAGE as usize {
        return Err(ProtocolError::InvalidChunkCount {
            count: u16::try_from(slices.len()).unwrap_or(u16::MAX),
            max: MAX_CHUNKS_PER_MESSAGE,
        });
    }

    let chunk_count = slices.len() as u16;
    let mut chunks = Vec::with_capacity(slices.len());
    for (idx, slice) in slices.into_iter().enumerate() {
        let mut raw_flags = InnerFlags::NONE;
        if idx == 0 {
            raw_flags |= InnerFlags::FIRST;
        }
        if idx + 1 == chunk_count as usize {
            raw_flags |= InnerFlags::FINAL;
        }
        chunks.push(InnerPayload::new(
            request_id,
            idx as u16,
            chunk_count,
            InnerFlags::from_u8(raw_flags)?,
            slice.to_vec(),
        )?);
    }

    Ok(chunks)
}

/// Reassembled bounded logical message (`Data` or `Error`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReassembledMessage {
    Data(Vec<u8>),
    Error(RequestErrorCode),
}

/// Parsed logical client request extracted after request reassembly at Exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedRequest {
    pub target_host_port: String,
    pub body: Vec<u8>,
}

impl DecodedRequest {
    pub fn parse(raw: &[u8]) -> Result<Self, ProtocolError> {
        if raw.len() < 2 {
            return Err(ProtocolError::MalformedPayload(
                "missing target address length",
            ));
        }
        let target_len = u16::from_be_bytes([raw[0], raw[1]]) as usize;
        if target_len == 0 || target_len > MAX_TARGET_ADDR_LEN {
            return Err(ProtocolError::InvalidTargetAddr);
        }
        if raw.len() < 2 + target_len {
            return Err(ProtocolError::MalformedPayload("truncated target address"));
        }
        let target_host_port = std::str::from_utf8(&raw[2..2 + target_len])
            .map_err(|_| ProtocolError::InvalidUtf8)?
            .to_owned();
        let body = raw[2 + target_len..].to_vec();
        if body.len() > MAX_MESSAGE_BYTES {
            return Err(ProtocolError::PayloadTooLarge {
                size: body.len(),
                max: MAX_MESSAGE_BYTES,
            });
        }
        Ok(Self {
            target_host_port,
            body,
        })
    }
}

/// Bounded streaming reassembler enforcing monotonic chunk indices, matching counts, no duplicates,
/// and strict `max_total_bytes` ceilings before committing memory.
#[derive(Debug)]
pub struct MessageReassembler {
    request_id: RequestId,
    expected_count: Option<u16>,
    expected_index: u16,
    seen_chunks: Vec<bool>,
    completed: bool,
    buffer: Vec<u8>,
    max_total_bytes: usize,
}

impl MessageReassembler {
    /// Creates a request reassembler bounded at `MAX_ENCODED_REQUEST_BYTES` (`65,793` bytes).
    pub fn for_request(request_id: RequestId) -> Self {
        Self::with_limit(request_id, MAX_ENCODED_REQUEST_BYTES)
    }

    /// Creates a response reassembler bounded at `MAX_MESSAGE_BYTES` (`65,536` bytes).
    pub fn for_response(request_id: RequestId) -> Self {
        Self::with_limit(request_id, MAX_MESSAGE_BYTES)
    }

    /// Creates a bounded reassembler enforcing `max_total_bytes`.
    pub fn with_limit(request_id: RequestId, max_total_bytes: usize) -> Self {
        Self {
            request_id,
            expected_count: None,
            expected_index: 0,
            seen_chunks: Vec::new(),
            completed: false,
            buffer: Vec::new(),
            max_total_bytes,
        }
    }

    pub fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Consumes the next chunk; returns `Some(...)` once the final chunk completes the message.
    pub fn push(
        &mut self,
        chunk: InnerPayload,
    ) -> Result<Option<ReassembledMessage>, ProtocolError> {
        validate_chunk_metadata(
            chunk.chunk_index,
            chunk.chunk_count,
            chunk.flags,
            chunk.fragment.len(),
        )?;
        if chunk.request_id != self.request_id {
            return Err(ProtocolError::RequestIdMismatch {
                expected: self.request_id.get(),
                actual: chunk.request_id.get(),
            });
        }
        if self.completed {
            return Err(ProtocolError::PayloadAfterFinal);
        }

        let expected_count = match self.expected_count {
            Some(c) => {
                if chunk.chunk_count != c {
                    return Err(ProtocolError::ChunkCountMismatch {
                        expected: c,
                        actual: chunk.chunk_count,
                    });
                }
                c
            }
            None => {
                self.expected_count = Some(chunk.chunk_count);
                self.seen_chunks = vec![false; chunk.chunk_count as usize];
                chunk.chunk_count
            }
        };

        if chunk.chunk_index >= expected_count {
            return Err(ProtocolError::InvalidChunkIndex {
                index: chunk.chunk_index,
                count: expected_count,
            });
        }

        if self.seen_chunks[chunk.chunk_index as usize] {
            return Err(ProtocolError::DuplicateChunk(chunk.chunk_index));
        }

        if chunk.chunk_index != self.expected_index {
            return Err(ProtocolError::OutOfOrderOrMissingChunk {
                expected: self.expected_index,
                actual: chunk.chunk_index,
            });
        }

        if chunk.flags.is_error() {
            let code = RequestErrorCode::from_u8(chunk.fragment[0])?;
            self.seen_chunks[0] = true;
            self.completed = true;
            return Ok(Some(ReassembledMessage::Error(code)));
        }

        let next_len = self.buffer.len() + chunk.fragment.len();
        if next_len > self.max_total_bytes {
            return Err(ProtocolError::PayloadTooLarge {
                size: next_len,
                max: self.max_total_bytes,
            });
        }

        self.seen_chunks[chunk.chunk_index as usize] = true;
        self.buffer.extend_from_slice(&chunk.fragment);
        self.expected_index = self.expected_index.saturating_add(1);

        if chunk.flags.is_final() {
            self.completed = true;
            return Ok(Some(ReassembledMessage::Data(std::mem::take(
                &mut self.buffer,
            ))));
        }

        Ok(None)
    }
}
