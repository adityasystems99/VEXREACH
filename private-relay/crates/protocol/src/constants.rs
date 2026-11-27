//! Reconciled wire constants and bounded resource limits for Private-Relay v0.1.

/// Protocol wire version (`0x01`).
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Length of the 2-byte big-endian outer TCP framing prefix.
pub const TCP_LENGTH_PREFIX_LEN: usize = 2;

/// Poly1305 AEAD authentication tag size in bytes (Noise & ChaCha20-Poly1305).
pub const NOISE_MAC_LEN: usize = 16;

/// Complete fixed-size on-wire Noise link record in bytes (Approved Decision D-02).
///
/// Arithmetic: `2B outer_len (== 598) + 582B outer plaintext + 16B Noise MAC = 600B`.
pub const OUTER_WIRE_FRAME_BYTES: usize = 600;

/// Exact Noise ciphertext frame length declared by the 2-byte TCP outer length prefix.
pub const OUTER_CIPHERTEXT_LEN: usize = OUTER_WIRE_FRAME_BYTES - TCP_LENGTH_PREFIX_LEN;

/// Fixed outer link plaintext capacity before Noise link encryption (`582` bytes).
pub const OUTER_PLAINTEXT_LEN: usize = OUTER_CIPHERTEXT_LEN - NOISE_MAC_LEN;

/// Length of the `real_len` prefix inside outer plaintext.
pub const OUTER_REAL_LEN_PREFIX_LEN: usize = 2;

/// Maximum encoded size of an inner overlay `Cell` (`580` bytes).
pub const MAX_CELL_BYTES: usize = OUTER_PLAINTEXT_LEN - OUTER_REAL_LEN_PREFIX_LEN;

/// Fixed 9-byte cell header size (`4B circuit_id + 1B version + 1B command + 2B len + 1B flags`).
pub const CELL_HEADER_LEN: usize = 9;

/// Maximum body size carried inside a single overlay `Cell` (`571` bytes).
pub const MAX_CELL_BODY_LEN: usize = MAX_CELL_BYTES - CELL_HEADER_LEN;

/// Discriminator byte inside each encrypted hop payload (`RelaySubCommand`).
pub const PER_HOP_SUBCMD_LEN: usize = 1;

/// Per-hop monotonic 64-bit sequence prefix inside `RELAY_DATA`.
pub const PER_HOP_SEQ_LEN: usize = 8;

/// Total encapsulation overhead per onion hop (`1B subcmd + 8B seq + 16B AEAD tag = 25B`).
pub const PER_HOP_ENVELOPE_OVERHEAD: usize = PER_HOP_SUBCMD_LEN + PER_HOP_SEQ_LEN + NOISE_MAC_LEN;

/// Fixed 3-hop topology depth in v0.1 (`Entry -> Middle -> Exit`).
pub const MAX_RELAY_HOPS: usize = 3;

/// Maximum innermost `InnerPayload` size (`571 - 3 * 25 = 496` bytes).
pub const MAX_INNER_PAYLOAD_LEN: usize =
    MAX_CELL_BODY_LEN - (MAX_RELAY_HOPS * PER_HOP_ENVELOPE_OVERHEAD);

/// Fixed 9-byte `InnerPayload` header (`4B request_id + 2B chunk_index + 2B chunk_count + 1B flags`).
pub const INNER_HEADER_LEN: usize = 9;

/// Maximum fragment slice per `InnerPayload` cell (`496 - 9 = 487` bytes).
pub const MAX_FRAGMENT_LEN: usize = MAX_INNER_PAYLOAD_LEN - INNER_HEADER_LEN;

/// Maximum logical request or response body size (`64 KiB`, Approved Decision D-01).
pub const MAX_MESSAGE_BYTES: usize = 65_536;

/// Maximum UTF-8 target `host:port` length in bytes.
pub const MAX_TARGET_ADDR_LEN: usize = 255;

/// Maximum combined encoded request size (`2B target_len + 255B target + 64 KiB body = 65,793B`).
pub const MAX_ENCODED_REQUEST_BYTES: usize = 2 + MAX_TARGET_ADDR_LEN + MAX_MESSAGE_BYTES;

/// Hard cap on chunks per logical message (`ceil(65_793 / 487) = 136 <= 140`).
pub const MAX_CHUNKS_PER_MESSAGE: u16 = 140;

/// Maximum permitted X25519 public key length in bytes.
pub const X25519_KEY_LEN: usize = 32;

/// Hard ceiling on per-circuit monotonic AEAD sequence counters (`seq < 2^32`).
pub const MAX_CIRCUIT_SEQ: u64 = 1u64 << 32;

/// Fixed 15-byte AAD length (`4B "PRv1" + 1B version + 1B dir + 1B hop_index + 8B seq`).
pub const HOP_AEAD_AAD_LEN: usize = 15;

/// Default periodic Noise link rekey time threshold (`3600s` = 1 hour).
pub const LINK_REKEY_DEFAULT_INTERVAL_SECS: u64 = 3600;

/// Default Noise link rekey byte threshold (`1 GiB`).
pub const LINK_REKEY_DEFAULT_BYTES: u64 = 1_073_741_824;

/// Reserved outer plaintext prefix marker identifying an in-band Noise link control frame.
pub const LINK_REKEY_MARKER: u16 = 0xFFFF;

/// Canonical 8-byte magic header inside encrypted link rekey control frames.
pub const LINK_REKEY_MAGIC: &[u8; 8] = b"PR_REKEY";

// Compile-time verification of reconciled frame and chunk invariants.
const _: () = {
    assert!(TCP_LENGTH_PREFIX_LEN + OUTER_CIPHERTEXT_LEN == OUTER_WIRE_FRAME_BYTES);
    assert!(OUTER_PLAINTEXT_LEN + NOISE_MAC_LEN == OUTER_CIPHERTEXT_LEN);
    assert!(OUTER_REAL_LEN_PREFIX_LEN + MAX_CELL_BYTES == OUTER_PLAINTEXT_LEN);
    assert!(CELL_HEADER_LEN + MAX_CELL_BODY_LEN == MAX_CELL_BYTES);
    assert!(
        MAX_RELAY_HOPS * PER_HOP_ENVELOPE_OVERHEAD + MAX_INNER_PAYLOAD_LEN == MAX_CELL_BODY_LEN
    );
    assert!(INNER_HEADER_LEN + MAX_FRAGMENT_LEN == MAX_INNER_PAYLOAD_LEN);
    assert!((MAX_CHUNKS_PER_MESSAGE as usize) * MAX_FRAGMENT_LEN >= MAX_ENCODED_REQUEST_BYTES);
};
