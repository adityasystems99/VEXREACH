use std::sync::Arc;

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce, Tag};
use hkdf::Hkdf;
use private_relay_protocol::{
    build_hop_aead_aad, HopDirection, ProtocolError, RelayHopPlaintext, RelaySubCommand,
    MAX_CELL_BODY_LEN, MAX_CIRCUIT_SEQ, MAX_RELAY_HOPS, NOISE_MAC_LEN, PER_HOP_SEQ_LEN,
    X25519_KEY_LEN,
};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::CryptoError;
use crate::keys::{
    noise_builder, noise_builder_with_stats, ResolverDropStats, StaticKeypair, NOISE_NK_PARAMS,
};

/// Domain prologue bound into every telescopic `Noise_NK` hop handshake.
const HOP_PROLOGUE: &[u8] = b"private-relay-hop-v1";
const SEED_LEN: usize = 32;
const KEY_LEN: usize = 32;

/// Initiator side (`Client`) for a single hop's `Noise_NK_25519_ChaChaPoly_BLAKE2s` handshake.
pub struct HopHandshakeInitiator {
    hs: snow::HandshakeState,
    hop_index: u8,
    c_seed: Zeroizing<[u8; SEED_LEN]>,
}

impl HopHandshakeInitiator {
    /// Initializes a `Noise_NK` handshake authenticating `hop_static_pub` for `hop_index ∈ {1, 2, 3}`.
    pub fn new(hop_index: u8, hop_static_pub: [u8; X25519_KEY_LEN]) -> Result<Self, CryptoError> {
        Self::new_inner(hop_index, hop_static_pub, None)
    }

    /// Test-only constructor tracking `ZeroizingCryptoResolver` teardown counts.
    #[doc(hidden)]
    pub fn new_with_drop_stats(
        hop_index: u8,
        hop_static_pub: [u8; X25519_KEY_LEN],
        stats: Arc<ResolverDropStats>,
    ) -> Result<Self, CryptoError> {
        Self::new_inner(hop_index, hop_static_pub, Some(stats))
    }

    fn new_inner(
        hop_index: u8,
        hop_static_pub: [u8; X25519_KEY_LEN],
        stats: Option<Arc<ResolverDropStats>>,
    ) -> Result<Self, CryptoError> {
        validate_hop_index(hop_index)?;
        let params: snow::params::NoiseParams = NOISE_NK_PARAMS
            .parse()
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;
        let builder = match stats {
            Some(s) => noise_builder_with_stats(params, s),
            None => noise_builder(params),
        };
        let hs = builder
            .remote_public_key(&hop_static_pub)
            .prologue(HOP_PROLOGUE)
            .build_initiator()
            .map_err(|_| CryptoError::HandshakeFailed)?;

        let mut c_seed = Zeroizing::new([0u8; SEED_LEN]);
        OsRng.fill_bytes(&mut *c_seed);

        Ok(Self {
            hs,
            hop_index,
            c_seed,
        })
    }

    /// Generates `Noise_NK` `msg1` (`80B`: `32B e + 32B enc(c_seed) + 16B MAC`).
    pub fn write_msg1(&mut self) -> Result<Vec<u8>, CryptoError> {
        let mut out = Zeroizing::new([0u8; 128]);
        let len = self
            .hs
            .write_message(&*self.c_seed, &mut *out)
            .map_err(|_| CryptoError::HandshakeFailed)?;
        Ok(out[..len].to_vec())
    }

    /// Processes `Noise_NK` `msg2` (`80B`: `32B e_r + 32B enc(r_seed) + 16B MAC`), deriving forward/backward ciphers.
    pub fn finish_with_msg2(mut self, msg2: &[u8]) -> Result<HopCipherPair, CryptoError> {
        let mut r_seed = Zeroizing::new([0u8; SEED_LEN]);
        let len = self
            .hs
            .read_message(msg2, &mut *r_seed)
            .map_err(|_| CryptoError::HandshakeFailed)?;
        if len != SEED_LEN || !self.hs.is_handshake_finished() {
            return Err(CryptoError::HandshakeFailed);
        }

        let transcript_hash = self.hs.get_handshake_hash();
        let (fwd_key, bwd_key) =
            derive_directional_keys(transcript_hash, &self.c_seed, &r_seed, self.hop_index)?;

        Ok(HopCipherPair::new(self.hop_index, fwd_key, bwd_key))
    }
}

/// Responder side (`Entry`/`Middle`/`Exit` relay) for a single hop's `Noise_NK` handshake.
pub struct HopHandshakeResponder {
    hs: snow::HandshakeState,
    hop_index: u8,
}

impl HopHandshakeResponder {
    pub fn new(hop_index: u8, local_keypair: &StaticKeypair) -> Result<Self, CryptoError> {
        Self::new_inner(hop_index, local_keypair, None)
    }

    /// Test-only constructor tracking `ZeroizingCryptoResolver` teardown counts.
    #[doc(hidden)]
    pub fn new_with_drop_stats(
        hop_index: u8,
        local_keypair: &StaticKeypair,
        stats: Arc<ResolverDropStats>,
    ) -> Result<Self, CryptoError> {
        Self::new_inner(hop_index, local_keypair, Some(stats))
    }

    fn new_inner(
        hop_index: u8,
        local_keypair: &StaticKeypair,
        stats: Option<Arc<ResolverDropStats>>,
    ) -> Result<Self, CryptoError> {
        validate_hop_index(hop_index)?;
        let params: snow::params::NoiseParams = NOISE_NK_PARAMS
            .parse()
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;
        let builder = match stats {
            Some(s) => noise_builder_with_stats(params, s),
            None => noise_builder(params),
        };
        let hs = builder
            .local_private_key(local_keypair.secret_bytes())
            .prologue(HOP_PROLOGUE)
            .build_responder()
            .map_err(|_| CryptoError::HandshakeFailed)?;

        Ok(Self { hs, hop_index })
    }

    /// Processes Client's `msg1`, produces `msg2` encrypted under `(es, ee)`, and derives matching hop ciphers.
    pub fn process_msg1_and_finish(
        mut self,
        msg1: &[u8],
    ) -> Result<(Vec<u8>, HopCipherPair), CryptoError> {
        let mut c_seed = Zeroizing::new([0u8; SEED_LEN]);
        let len = self
            .hs
            .read_message(msg1, &mut *c_seed)
            .map_err(|_| CryptoError::HandshakeFailed)?;
        if len != SEED_LEN {
            return Err(CryptoError::HandshakeFailed);
        }

        let mut r_seed = Zeroizing::new([0u8; SEED_LEN]);
        OsRng.fill_bytes(&mut *r_seed);

        let mut msg2_buf = Zeroizing::new([0u8; 128]);
        let msg2_len = self
            .hs
            .write_message(&*r_seed, &mut *msg2_buf)
            .map_err(|_| CryptoError::HandshakeFailed)?;
        if !self.hs.is_handshake_finished() {
            return Err(CryptoError::HandshakeFailed);
        }

        let transcript_hash = self.hs.get_handshake_hash();
        let (fwd_key, bwd_key) =
            derive_directional_keys(transcript_hash, &c_seed, &r_seed, self.hop_index)?;

        Ok((
            msg2_buf[..msg2_len].to_vec(),
            HopCipherPair::new(self.hop_index, fwd_key, bwd_key),
        ))
    }
}

fn validate_hop_index(hop_index: u8) -> Result<(), CryptoError> {
    if hop_index == 0 || (hop_index as usize) > MAX_RELAY_HOPS {
        return Err(ProtocolError::InvalidHopIndex(hop_index).into());
    }
    Ok(())
}

type HopKey = Zeroizing<[u8; KEY_LEN]>;

/// Derives independent 256-bit forward & backward keys using HKDF-SHA256 bound to Noise transcript hash.
fn derive_directional_keys(
    transcript_hash: &[u8],
    c_seed: &[u8; SEED_LEN],
    r_seed: &[u8; SEED_LEN],
    hop_index: u8,
) -> Result<(HopKey, HopKey), CryptoError> {
    let mut ikm = Zeroizing::new([0u8; SEED_LEN * 2]);
    ikm[..SEED_LEN].copy_from_slice(c_seed);
    ikm[SEED_LEN..].copy_from_slice(r_seed);

    let hk = Hkdf::<Sha256>::new(Some(transcript_hash), &*ikm);

    let mut info_fwd = *b"private-relay-v1/fwd/hop=0";
    info_fwd[info_fwd.len() - 1] = b'0' + hop_index;
    let mut k_fwd = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(&info_fwd, &mut *k_fwd)
        .map_err(|_| CryptoError::InvalidKeyMaterial)?;

    let mut info_bwd = *b"private-relay-v1/bwd/hop=0";
    info_bwd[info_bwd.len() - 1] = b'0' + hop_index;
    let mut k_bwd = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(&info_bwd, &mut *k_bwd)
        .map_err(|_| CryptoError::InvalidKeyMaterial)?;

    Ok((k_fwd, k_bwd))
}

/// Single directional AEAD state with deterministic `[0,0,0,0] || seq_be` nonce & monotonic FIFO verification.
///
/// Both `key` and the cached `ChaCha20Poly1305` cipher schedule implement `ZeroizeOnDrop`.
#[derive(ZeroizeOnDrop)]
pub struct HopCipherState {
    key: Zeroizing<[u8; KEY_LEN]>,
    cipher: ChaCha20Poly1305,
    #[zeroize(skip)]
    direction: HopDirection,
    #[zeroize(skip)]
    hop_index: u8,
    next_seq: u64,
}

impl std::fmt::Debug for HopCipherState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HopCipherState")
            .field("direction", &self.direction)
            .field("hop_index", &self.hop_index)
            .field("next_seq", &self.next_seq)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl HopCipherState {
    pub fn new(
        key: Zeroizing<[u8; KEY_LEN]>,
        direction: HopDirection,
        hop_index: u8,
    ) -> Result<Self, CryptoError> {
        validate_hop_index(hop_index)?;
        let cipher =
            ChaCha20Poly1305::new_from_slice(&*key).map_err(|_| CryptoError::InvalidKeyMaterial)?;
        Ok(Self {
            key,
            cipher,
            direction,
            hop_index,
            next_seq: 0,
        })
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Seals `[optional_prefix_byte || plaintext]` in-place into `out`, clearing `out` first.
    /// Avoids intermediate heap allocations per hop.
    fn seal_prefixed_into(
        &mut self,
        prefix_byte: Option<u8>,
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        let seq = self.next_seq;
        if seq >= MAX_CIRCUIT_SEQ {
            return Err(CryptoError::SequenceExhausted);
        }

        let aad = build_hop_aead_aad(self.direction, self.hop_index, seq)?;
        let nonce_bytes = build_nonce(seq);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let pt_len = plaintext.len() + usize::from(prefix_byte.is_some());
        let total = PER_HOP_SEQ_LEN + pt_len + NOISE_MAC_LEN;
        out.clear();
        if out.capacity() < total {
            out.reserve(total - out.capacity());
        }
        out.extend_from_slice(&seq.to_be_bytes());
        if let Some(b) = prefix_byte {
            out.push(b);
        }
        out.extend_from_slice(plaintext);

        let tag = self
            .cipher
            .encrypt_in_place_detached(
                nonce,
                &aad,
                &mut out[PER_HOP_SEQ_LEN..PER_HOP_SEQ_LEN + pt_len],
            )
            .map_err(|_| {
                out.zeroize();
                out.clear();
                CryptoError::AuthenticationFailed
            })?;
        out.extend_from_slice(&tag);
        self.next_seq = seq + 1;
        Ok(())
    }

    /// Encrypts `plaintext`, prepending `[seq: u64 BE]` ahead of ciphertext + 16B Poly1305 tag.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut out = Vec::with_capacity(PER_HOP_SEQ_LEN + plaintext.len() + NOISE_MAC_LEN);
        self.seal_prefixed_into(None, plaintext, &mut out)?;
        Ok(out)
    }

    /// Verifies strict FIFO sequence equality (`incoming_seq == expected_seq`) and authenticates tag + AAD.
    pub fn open(&mut self, envelope: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if envelope.len() < PER_HOP_SEQ_LEN + NOISE_MAC_LEN {
            return Err(CryptoError::AuthenticationFailed);
        }
        let incoming_seq = u64::from_be_bytes([
            envelope[0],
            envelope[1],
            envelope[2],
            envelope[3],
            envelope[4],
            envelope[5],
            envelope[6],
            envelope[7],
        ]);
        let expected_seq = self.next_seq;
        if expected_seq >= MAX_CIRCUIT_SEQ {
            return Err(CryptoError::SequenceExhausted);
        }
        if incoming_seq != expected_seq {
            return Err(CryptoError::SequenceMismatch {
                expected: expected_seq,
                actual: incoming_seq,
            });
        }

        let aad = build_hop_aead_aad(self.direction, self.hop_index, incoming_seq)?;
        let nonce_bytes = build_nonce(incoming_seq);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let tag_start = envelope.len() - NOISE_MAC_LEN;
        let mut plaintext = envelope[PER_HOP_SEQ_LEN..tag_start].to_vec();
        let tag = Tag::from_slice(&envelope[tag_start..]);
        if self
            .cipher
            .decrypt_in_place_detached(nonce, &aad, &mut plaintext, tag)
            .is_err()
        {
            plaintext.zeroize();
            return Err(CryptoError::AuthenticationFailed);
        }

        self.next_seq = expected_seq + 1;
        Ok(plaintext)
    }

    /// Opens `envelope` in-place within `buf`, leaving strictly the decrypted plaintext bytes.
    fn open_in_place_buf(&mut self, buf: &mut Vec<u8>) -> Result<(), CryptoError> {
        if buf.len() < PER_HOP_SEQ_LEN + NOISE_MAC_LEN {
            return Err(CryptoError::AuthenticationFailed);
        }
        let incoming_seq = u64::from_be_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]);
        let expected_seq = self.next_seq;
        if expected_seq >= MAX_CIRCUIT_SEQ {
            return Err(CryptoError::SequenceExhausted);
        }
        if incoming_seq != expected_seq {
            return Err(CryptoError::SequenceMismatch {
                expected: expected_seq,
                actual: incoming_seq,
            });
        }

        let aad = build_hop_aead_aad(self.direction, self.hop_index, incoming_seq)?;
        let nonce_bytes = build_nonce(incoming_seq);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let tag_start = buf.len() - NOISE_MAC_LEN;
        let mut tag_bytes = [0u8; NOISE_MAC_LEN];
        tag_bytes.copy_from_slice(&buf[tag_start..]);
        let tag = Tag::from_slice(&tag_bytes);

        if self
            .cipher
            .decrypt_in_place_detached(nonce, &aad, &mut buf[PER_HOP_SEQ_LEN..tag_start], tag)
            .is_err()
        {
            buf.zeroize();
            return Err(CryptoError::AuthenticationFailed);
        }
        buf.copy_within(PER_HOP_SEQ_LEN..tag_start, 0);
        buf.truncate(tag_start - PER_HOP_SEQ_LEN);
        self.next_seq = expected_seq + 1;
        Ok(())
    }

    /// Test-only helper enabling adversarial out-of-range sequence exhaustion checks safely.
    #[doc(hidden)]
    pub fn set_seq_for_test(&mut self, seq: u64) {
        self.next_seq = seq;
    }
}

fn build_nonce(seq: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&seq.to_be_bytes());
    nonce
}

/// Symmetric forward + backward cipher pair for one hop on a circuit (zeroized on drop).
#[derive(Debug, ZeroizeOnDrop)]
pub struct HopCipherPair {
    pub forward: HopCipherState,
    pub backward: HopCipherState,
}

impl HopCipherPair {
    fn new(
        hop_index: u8,
        k_fwd: Zeroizing<[u8; KEY_LEN]>,
        k_bwd: Zeroizing<[u8; KEY_LEN]>,
    ) -> Self {
        Self {
            forward: HopCipherState::new(k_fwd, HopDirection::Forward, hop_index)
                .expect("validated hop index"),
            backward: HopCipherState::new(k_bwd, HopDirection::Backward, hop_index)
                .expect("validated hop index"),
        }
    }
}

/// Client-side telescopic key stack holding 1..=3 hops and applying nested forward/backward layers.
#[derive(Debug, Default, ZeroizeOnDrop)]
pub struct ClientCircuitCrypto {
    hops: Vec<HopCipherPair>,
}

impl ClientCircuitCrypto {
    pub fn new() -> Self {
        Self { hops: Vec::new() }
    }

    pub fn push_hop(&mut self, pair: HopCipherPair) -> Result<(), CryptoError> {
        if self.hops.len() >= MAX_RELAY_HOPS {
            return Err(CryptoError::InvalidState("circuit already has 3 hops"));
        }
        self.hops.push(pair);
        Ok(())
    }

    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    /// Wraps `inner` plaintext targeted at `target_hop` (`1..=self.hops.len()`), peeling inward on forward path.
    ///
    /// Example: when `target_hop == 3`, encrypts `inner` under Hop 3 (`K_fwd_3`), wraps inside `Forward`
    /// under Hop 2 (`K_fwd_2`), then wraps inside `Forward` under Hop 1 (`K_fwd_1`).
    pub fn seal_forward_to_hop(
        &mut self,
        target_hop: usize,
        inner: &RelayHopPlaintext,
    ) -> Result<Vec<u8>, CryptoError> {
        if target_hop == 0 || target_hop > self.hops.len() {
            return Err(CryptoError::InvalidState("target hop not yet established"));
        }

        let mut inner_bytes = Zeroizing::new(inner.encode()?);
        let mut current = Vec::with_capacity(MAX_CELL_BODY_LEN);
        self.hops[target_hop - 1]
            .forward
            .seal_prefixed_into(None, &inner_bytes, &mut current)?;
        inner_bytes.zeroize();

        let mut next_buf = Zeroizing::new(Vec::with_capacity(MAX_CELL_BODY_LEN));
        for hop_idx in (0..target_hop - 1).rev() {
            if current.len() >= MAX_CELL_BODY_LEN {
                return Err(ProtocolError::PayloadTooLarge {
                    size: current.len(),
                    max: MAX_CELL_BODY_LEN - 1,
                }
                .into());
            }
            self.hops[hop_idx].forward.seal_prefixed_into(
                Some(RelaySubCommand::Forward as u8),
                &current,
                &mut next_buf,
            )?;
            std::mem::swap(&mut current, &mut *next_buf);
        }

        if current.len() > MAX_CELL_BODY_LEN {
            return Err(ProtocolError::BodyTooLarge {
                declared: current.len(),
                max: MAX_CELL_BODY_LEN,
            }
            .into());
        }

        Ok(current)
    }

    /// Peels all established backward onion layers (`Hop 1 -> ... -> source_hop`), returning decoded `RelayHopPlaintext`.
    pub fn open_backward_from_hop(
        &mut self,
        source_hop: usize,
        outer_body: &[u8],
    ) -> Result<RelayHopPlaintext, CryptoError> {
        if source_hop == 0 || source_hop > self.hops.len() {
            return Err(CryptoError::InvalidState("source hop not yet established"));
        }

        let mut buf = Zeroizing::new(outer_body.to_vec());
        for hop_idx in 0..source_hop {
            self.hops[hop_idx].backward.open_in_place_buf(&mut buf)?;
        }

        Ok(RelayHopPlaintext::decode(&buf)?)
    }
}
