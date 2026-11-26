use private_relay_protocol::{
    decode_wire_record, encode_wire_record, Cell, OuterFramePlaintext, MAX_CELL_BYTES,
    OUTER_CIPHERTEXT_LEN, OUTER_PLAINTEXT_LEN, OUTER_WIRE_FRAME_BYTES, X25519_KEY_LEN,
};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroize;

use crate::error::CryptoError;
use crate::keys::{StaticKeypair, NOISE_IK_PARAMS};

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

        Ok(LinkSession {
            transport,
            remote_static_pub: remote_pub,
        })
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
            LinkSession {
                transport,
                remote_static_pub: remote_pub,
            },
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

/// Authenticated `Noise_IK` link transport wrapping every cell into exact `600`-byte on-wire frames.
pub struct LinkSession {
    transport: snow::TransportState,
    remote_static_pub: [u8; X25519_KEY_LEN],
}

impl LinkSession {
    /// Returns the authenticated static X25519 public key of the remote link peer.
    pub fn remote_static_pub(&self) -> &[u8; X25519_KEY_LEN] {
        &self.remote_static_pub
    }

    /// Packs `cell` with OS CSPRNG padding into `582B`, Noise-encrypts to `598B`, and frames to `600B`.
    pub fn seal_cell(&mut self, cell: &Cell) -> Result<[u8; OUTER_WIRE_FRAME_BYTES], CryptoError> {
        let mut padding = [0u8; MAX_CELL_BYTES];
        OsRng.fill_bytes(&mut padding);
        let packed = OuterFramePlaintext::pack(cell, &padding)?;
        padding.zeroize();

        let mut ct_buf = [0u8; OUTER_CIPHERTEXT_LEN];
        let ct_len = self
            .transport
            .write_message(&packed.bytes, &mut ct_buf)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        if ct_len != OUTER_CIPHERTEXT_LEN {
            return Err(CryptoError::InvalidState(
                "unexpected Noise link ciphertext length",
            ));
        }

        Ok(encode_wire_record(&ct_buf)?)
    }

    /// Validates a `600`-byte TCP frame record, Noise-decrypts to `582B`, and decodes the `Cell`.
    pub fn open_cell(&mut self, wire_record: &[u8]) -> Result<Cell, CryptoError> {
        let ciphertext = decode_wire_record(wire_record)?;
        let mut pt_buf = [0u8; OUTER_PLAINTEXT_LEN];
        let pt_len = self
            .transport
            .read_message(ciphertext, &mut pt_buf)
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        let res = OuterFramePlaintext::unpack(&pt_buf[..pt_len]).map_err(CryptoError::from);
        pt_buf.zeroize();
        res
    }
}
