//! Pure-Rust cryptography (`Noise_IK` links, `Noise_NK` telescopic hops, `ChaCha20-Poly1305`, `HKDF-SHA256`, `zeroize`).

pub mod error;
pub mod hop;
pub mod keys;
pub mod link;

pub use error::CryptoError;
pub use hop::{
    ClientCircuitCrypto, HopCipherPair, HopCipherState, HopHandshakeInitiator,
    HopHandshakeResponder,
};
pub use keys::{parse_public_key, StaticKeypair};
pub use link::{LinkInitiator, LinkResponder, LinkSession};
