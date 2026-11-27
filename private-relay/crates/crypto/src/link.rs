use std::time::{Duration, Instant};

use private_relay_protocol::{
    decode_wire_record, encode_wire_record, Cell, LinkFrame, OuterFramePlaintext,
    LINK_REKEY_DEFAULT_BYTES, LINK_REKEY_DEFAULT_INTERVAL_SECS, MAX_CELL_BYTES,
    OUTER_CIPHERTEXT_LEN, OUTER_PLAINTEXT_LEN, OUTER_WIRE_FRAME_BYTES, X25519_KEY_LEN,
};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroize;

use crate::error::CryptoError;
use crate::keys::{StaticKeypair, NOISE_IK_PARAMS};

/// Hard safety ceiling on Noise link sequence numbers per epoch window before forced rotation/failure.
const MAX_LINK_NOISE_NONCE: u64 = 1u64 << 48;

/// Coordinated `Noise_IK` transport rekey policy thresholds (`Phase 4 / KI-08`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkRekeyPolicy {
    pub max_bytes: u64,
    pub max_age: Duration,
}

impl Default for LinkRekeyPolicy {
    fn default() -> Self {
        Self {
            max_bytes: LINK_REKEY_DEFAULT_BYTES,
            max_age: Duration::from_secs(LINK_REKEY_DEFAULT_INTERVAL_SECS),
        }
    }
}

/// Domain prologue bound into every `Noise_IK` link handshake transcript.
const LINK_PROLOGUE: &[u8] = b"private-relay-link-v1";

/// Initiator side of an adjacent-hop `Noise_IK_25519_ChaChaPoly_BLAKE2s` link handshake.
pub struct LinkInitiator {
    hs: snow::HandshakeState,
    expected_remote_pub: [u8; X25519_KEY_LEN],
}

impl LinkInitiator {
    /// Creates an initiator authenticating `expected_remote_pub`.
    ///
    /// Note: Clients should generate a fresh ephemeral `StaticKeypair::generate()` per session so
    /// the Entry relay cannot link sessions by client static key.
    pub fn new(
        local_keypair: &StaticKeypair,
        expected_remote_pub: [u8; X25519_KEY_LEN],
    ) -> Result<Self, CryptoError> {
        let params: snow::params::NoiseParams = NOISE_IK_PARAMS
            .parse()
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;
        let hs = snow::Builder::new(params)
            .local_private_key(local_keypair.secret_bytes())
            .remote_public_key(&expected_remote_pub)
            .prologue(LINK_PROLOGUE)
            .build_initiator()
            .map_err(|_| CryptoError::HandshakeFailed)?;

        Ok(Self {
            hs,
            expected_remote_pub,
        })
    }

    /// Generates `Noise_IK` message 1 (`-> e, es, s, ss`).
    pub fn write_msg1(&mut self) -> Result<Vec<u8>, CryptoError> {
        let mut out = [0u8; 256];
        let len = self
            .hs
            .write_message(&[], &mut out)
            .map_err(|_| CryptoError::HandshakeFailed)?;
        Ok(out[..len].to_vec())
    }

    /// Processes `Noise_IK` message 2 (`<- e, ee, se`), verifies expected peer key, and yields `LinkSession`.
    pub fn finish_with_msg2(mut self, msg2: &[u8]) -> Result<LinkSession, CryptoError> {
        let mut payload = [0u8; 128];
        let len = self
            .hs
            .read_message(msg2, &mut payload)
            .map_err(|_| CryptoError::HandshakeFailed)?;
        if len != 0 || !self.hs.is_handshake_finished() {
            return Err(CryptoError::HandshakeFailed);
        }

        let transport = self
            .hs
            .into_transport_mode()
            .map_err(|_| CryptoError::HandshakeFailed)?;

        let remote_pub = extract_remote_static(&transport)?;
        if remote_pub != self.expected_remote_pub {
            return Err(CryptoError::UnexpectedPeerIdentity);
        }

        Ok(LinkSession::new(transport, remote_pub))
    }
}

/// Responder side of an adjacent-hop `Noise_IK_25519_ChaChaPoly_BLAKE2s` link handshake.
pub struct LinkResponder {
    hs: snow::HandshakeState,
}

impl LinkResponder {
    pub fn new(local_keypair: &StaticKeypair) -> Result<Self, CryptoError> {
        let params: snow::params::NoiseParams = NOISE_IK_PARAMS
            .parse()
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;
        let hs = snow::Builder::new(params)
            .local_private_key(local_keypair.secret_bytes())
            .prologue(LINK_PROLOGUE)
            .build_responder()
            .map_err(|_| CryptoError::HandshakeFailed)?;
        Ok(Self { hs })
    }

    /// Validates `Noise_IK` message 1, emits message 2, and enters transport mode returning peer pubkey.
    pub fn process_msg1_and_finish(
        mut self,
        msg1: &[u8],
    ) -> Result<(Vec<u8>, LinkSession), CryptoError> {
        let mut payload = [0u8; 128];
        let payload_len = self
            .hs
            .read_message(msg1, &mut payload)
            .map_err(|_| CryptoError::HandshakeFailed)?;
        if payload_len != 0 {
            return Err(CryptoError::HandshakeFailed);
        }

        let mut msg2_buf = [0u8; 256];
        let msg2_len = self
            .hs
            .write_message(&[], &mut msg2_buf)
            .map_err(|_| CryptoError::HandshakeFailed)?;
        if !self.hs.is_handshake_finished() {
            return Err(CryptoError::HandshakeFailed);
        }

        let transport = self
            .hs
            .into_transport_mode()
            .map_err(|_| CryptoError::HandshakeFailed)?;
        let remote_pub = extract_remote_static(&transport)?;

        Ok((
            msg2_buf[..msg2_len].to_vec(),
            LinkSession::new(transport, remote_pub),
        ))
    }
}

fn extract_remote_static(
    transport: &snow::TransportState,
) -> Result<[u8; X25519_KEY_LEN], CryptoError> {
    let slice = transport
        .get_remote_static()
        .ok_or(CryptoError::UnexpectedPeerIdentity)?;
    if slice.len() != X25519_KEY_LEN {
        return Err(CryptoError::UnexpectedPeerIdentity);
    }
    let mut pub_key = [0u8; X25519_KEY_LEN];
    pub_key.copy_from_slice(slice);
    Ok(pub_key)
}

/// Authenticated `Noise_IK` link transport wrapping every cell into exact `600`-byte on-wire frames
/// and coordinating Noise Section 4.2/11.3 synchronized directional key rotation.
pub struct LinkSession {
    transport: snow::TransportState,
    remote_static_pub: [u8; X25519_KEY_LEN],
    rekey_policy: LinkRekeyPolicy,
    last_rekey_at: Instant,
    bytes_since_rekey: u64,
    outgoing_rekey_epoch: u64,
    incoming_rekey_epoch: u64,
    failed: bool,
}

impl LinkSession {
    fn new(transport: snow::TransportState, remote_static_pub: [u8; X25519_KEY_LEN]) -> Self {
        Self {
            transport,
            remote_static_pub,
            rekey_policy: LinkRekeyPolicy::default(),
            last_rekey_at: Instant::now(),
            bytes_since_rekey: 0,
            outgoing_rekey_epoch: 0,
            incoming_rekey_epoch: 0,
            failed: false,
        }
    }

    /// Configures periodic time and byte thresholds governing automatic outgoing rekey triggers.
    pub fn set_rekey_policy(&mut self, policy: LinkRekeyPolicy) {
        self.rekey_policy = policy;
    }

    /// Returns the authenticated static X25519 public key of the remote link peer.
    pub fn remote_static_pub(&self) -> &[u8; X25519_KEY_LEN] {
        &self.remote_static_pub
    }

    /// Returns `(outgoing_epoch, incoming_epoch)` counters for test and operational diagnostics.
    pub fn rekey_epochs(&self) -> (u64, u64) {
        (self.outgoing_rekey_epoch, self.incoming_rekey_epoch)
    }

    /// Returns `true` when this link session has failed closed due to crypto/rekey/framing error.
    pub fn is_failed(&self) -> bool {
        self.failed
    }

    /// Marks the link session permanently closed so subsequent seal/open calls refuse to reuse keys.
    pub fn mark_failed(&mut self) {
        self.failed = true;
    }

    /// Returns current monotonic Noise outbound cipher nonce.
    pub fn sending_nonce(&self) -> u64 {
        self.transport.sending_nonce()
    }

    /// Returns current monotonic Noise inbound cipher nonce.
    pub fn receiving_nonce(&self) -> u64 {
        self.transport.receiving_nonce()
    }

    /// Returns `true` when transmitting another cell would reach or exceed configured thresholds.
    pub fn should_rekey_outgoing(&self) -> bool {
        if self.failed {
            return false;
        }
        self.bytes_since_rekey >= self.rekey_policy.max_bytes
            || self.last_rekey_at.elapsed() >= self.rekey_policy.max_age
            || self.transport.sending_nonce() >= MAX_LINK_NOISE_NONCE
    }

    /// Emits an encrypted `RekeyControl` frame under the current outgoing key and atomically calls
    /// `TransportState::rekey_outgoing()` so subsequent cells encrypt cleanly under the rotated key
    /// without resetting nonces.
    pub fn seal_rekey_and_rotate(&mut self) -> Result<[u8; OUTER_WIRE_FRAME_BYTES], CryptoError> {
        if self.failed {
            return Err(CryptoError::InvalidState("link session failed closed"));
        }
        let next_epoch = match self.outgoing_rekey_epoch.checked_add(1) {
            Some(v) => v,
            None => {
                self.failed = true;
                return Err(CryptoError::SequenceExhausted);
            }
        };

        let mut padding = [0u8; OUTER_PLAINTEXT_LEN];
        OsRng.fill_bytes(&mut padding);
        let packed = match OuterFramePlaintext::pack_rekey_control(next_epoch, &padding) {
            Ok(p) => p,
            Err(e) => {
                padding.zeroize();
                self.failed = true;
                return Err(e.into());
            }
        };
        padding.zeroize();

        let mut ct_buf = [0u8; OUTER_CIPHERTEXT_LEN];
        let ct_len = match self.transport.write_message(&packed.bytes, &mut ct_buf) {
            Ok(len) => len,
            Err(_) => {
                self.failed = true;
                return Err(CryptoError::AuthenticationFailed);
            }
        };
        if ct_len != OUTER_CIPHERTEXT_LEN {
            self.failed = true;
            return Err(CryptoError::InvalidState(
                "unexpected Noise rekey ciphertext length",
            ));
        }

        // Advance outbound key strictly AFTER sealing the control frame at nonce `n`.
        // Receiver advances `rekey_incoming()` at exact matching nonce `n` before reading `n + 1`.
        self.transport.rekey_outgoing();
        self.outgoing_rekey_epoch = next_epoch;
        self.bytes_since_rekey = 0;
        self.last_rekey_at = Instant::now();

        encode_wire_record(&ct_buf).map_err(|e| {
            self.failed = true;
            CryptoError::from(e)
        })
    }

    /// Packs `cell` with OS CSPRNG padding into `582B`, Noise-encrypts to `598B`, and frames to `600B`.
    pub fn seal_cell(&mut self, cell: &Cell) -> Result<[u8; OUTER_WIRE_FRAME_BYTES], CryptoError> {
        if self.failed {
            return Err(CryptoError::InvalidState("link session failed closed"));
        }
        if self.transport.sending_nonce() >= MAX_LINK_NOISE_NONCE {
            self.failed = true;
            return Err(CryptoError::SequenceExhausted);
        }

        let mut padding = [0u8; MAX_CELL_BYTES];
        OsRng.fill_bytes(&mut padding);
        let packed = match OuterFramePlaintext::pack(cell, &padding) {
            Ok(p) => p,
            Err(e) => {
                padding.zeroize();
                return Err(e.into());
            }
        };
        padding.zeroize();

        let mut ct_buf = [0u8; OUTER_CIPHERTEXT_LEN];
        let ct_len = match self.transport.write_message(&packed.bytes, &mut ct_buf) {
            Ok(len) => len,
            Err(_) => {
                self.failed = true;
                return Err(CryptoError::AuthenticationFailed);
            }
        };
        if ct_len != OUTER_CIPHERTEXT_LEN {
            self.failed = true;
            return Err(CryptoError::InvalidState(
                "unexpected Noise link ciphertext length",
            ));
        }

        self.bytes_since_rekey = self
            .bytes_since_rekey
            .saturating_add(OUTER_WIRE_FRAME_BYTES as u64);

        Ok(encode_wire_record(&ct_buf)?)
    }

    /// Validates a `600`-byte TCP frame record, Noise-decrypts to `582B`, handles any `RekeyControl`
    /// atomically (rotating incoming key on strict monotonic epoch), and returns decoded [`LinkFrame`].
    pub fn open_frame(&mut self, wire_record: &[u8]) -> Result<LinkFrame, CryptoError> {
        if self.failed {
            return Err(CryptoError::InvalidState("link session failed closed"));
        }
        if self.transport.receiving_nonce() >= MAX_LINK_NOISE_NONCE {
            self.failed = true;
            return Err(CryptoError::SequenceExhausted);
        }
        let ciphertext = decode_wire_record(wire_record).map_err(|e| {
            self.failed = true;
            CryptoError::from(e)
        })?;
        let mut pt_buf = [0u8; OUTER_PLAINTEXT_LEN];
        let pt_len = match self.transport.read_message(ciphertext, &mut pt_buf) {
            Ok(len) => len,
            Err(_) => {
                pt_buf.zeroize();
                self.failed = true;
                return Err(CryptoError::AuthenticationFailed);
            }
        };

        let frame = OuterFramePlaintext::unpack_link_frame(&pt_buf[..pt_len]);
        pt_buf.zeroize();

        let frame = match frame {
            Ok(f) => f,
            Err(e) => {
                self.failed = true;
                return Err(e.into());
            }
        };

        if let LinkFrame::RekeyControl { epoch } = frame {
            let expected = match self.incoming_rekey_epoch.checked_add(1) {
                Some(v) => v,
                None => {
                    self.failed = true;
                    return Err(CryptoError::SequenceExhausted);
                }
            };
            if epoch != expected {
                self.failed = true;
                return Err(CryptoError::SequenceMismatch {
                    expected,
                    actual: epoch,
                });
            }
            self.transport.rekey_incoming();
            self.incoming_rekey_epoch = epoch;
        }

        Ok(frame)
    }

    /// Validates a `600`-byte TCP frame record, Noise-decrypts to `582B`, and decodes a [`Cell`].
    pub fn open_cell(&mut self, wire_record: &[u8]) -> Result<Cell, CryptoError> {
        match self.open_frame(wire_record)? {
            LinkFrame::Cell(cell) => Ok(cell),
            LinkFrame::RekeyControl { .. } => {
                self.failed = true;
                Err(CryptoError::InvalidState(
                    "unexpected link rekey control frame in open_cell",
                ))
            }
        }
    }
}
