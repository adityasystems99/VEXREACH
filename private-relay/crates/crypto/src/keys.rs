use std::fmt;

use private_relay_protocol::X25519_KEY_LEN;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::CryptoError;

/// Noise cipher suite used across both `Noise_IK` links and `Noise_NK` telescopic hops.
pub(crate) const NOISE_IK_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
pub(crate) const NOISE_NK_PARAMS: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";

/// Static `X25519` keypair with automatic zeroization on drop and redacted debug output.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct StaticKeypair {
    secret: Zeroizing<[u8; X25519_KEY_LEN]>,
    #[zeroize(skip)]
    public: [u8; X25519_KEY_LEN],
}

impl fmt::Debug for StaticKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaticKeypair")
            .field("public", &self.public)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl StaticKeypair {
    /// Generates a fresh random `X25519` keypair using `snow`'s OS-seeded RNG backend.
    pub fn generate() -> Result<Self, CryptoError> {
        let params: snow::params::NoiseParams = NOISE_IK_PARAMS
            .parse()
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;
        let builder = snow::Builder::new(params);
        let kp = builder
            .generate_keypair()
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;

        Self::from_slices(&kp.private, &kp.public)
    }

    /// Reconstructs a `StaticKeypair` from 32-byte private and public key slices, verifying mathematical keypair consistency.
    pub fn from_slices(private: &[u8], public: &[u8]) -> Result<Self, CryptoError> {
        if private.len() != X25519_KEY_LEN || public.len() != X25519_KEY_LEN {
            return Err(CryptoError::InvalidKeyMaterial);
        }
        if private.iter().all(|&b| b == 0) || public.iter().all(|&b| b == 0) {
            return Err(CryptoError::InvalidKeyMaterial);
        }

        // Verify `public == X25519(private)` using a 1-step in-memory Noise_NK AEAD consistency check.
        let params: snow::params::NoiseParams = NOISE_NK_PARAMS
            .parse()
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;
        let mut init = snow::Builder::new(params.clone())
            .remote_public_key(public)
            .build_initiator()
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;
        let mut resp = snow::Builder::new(params)
            .local_private_key(private)
            .build_responder()
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;
        let mut probe = [0u8; 96];
        let probe_len = init
            .write_message(&[], &mut probe)
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;
        let mut out = [0u8; 32];
        resp.read_message(&probe[..probe_len], &mut out)
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;

        let mut sec = Zeroizing::new([0u8; X25519_KEY_LEN]);
        sec.copy_from_slice(private);
        let mut pub_key = [0u8; X25519_KEY_LEN];
        pub_key.copy_from_slice(public);
        Ok(Self {
            secret: sec,
            public: pub_key,
        })
    }

    /// Returns the 32-byte public key.
    pub fn public(&self) -> &[u8; X25519_KEY_LEN] {
        &self.public
    }

    /// Returns the 32-byte private key slice for trusted config serialization/Noise init.
    pub fn secret_bytes(&self) -> &[u8; X25519_KEY_LEN] {
        &self.secret
    }
}

/// Validates a 32-byte public key slice into a fixed-size array.
pub fn parse_public_key(bytes: &[u8]) -> Result<[u8; X25519_KEY_LEN], CryptoError> {
    if bytes.len() != X25519_KEY_LEN {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    let mut out = [0u8; X25519_KEY_LEN];
    out.copy_from_slice(bytes);
    Ok(out)
}
