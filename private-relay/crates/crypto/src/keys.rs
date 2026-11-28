use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use private_relay_protocol::X25519_KEY_LEN;
use snow::resolvers::{BoxedCryptoResolver, CryptoResolver, DefaultResolver};
use snow::types::{Cipher, Dh, Hash, Random};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::CryptoError;

/// Noise cipher suite used across both `Noise_IK` links and `Noise_NK` telescopic hops.
pub(crate) const NOISE_IK_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
pub(crate) const NOISE_NK_PARAMS: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";

/// Diagnostic counters recording how many wrapped Noise primitive buffers were explicitly scrubbed on Drop.
#[doc(hidden)]
#[derive(Debug, Default)]
pub struct ResolverDropStats {
    pub dh_zeroed: AtomicUsize,
    pub cipher_zeroed: AtomicUsize,
    pub hash_reset: AtomicUsize,
}

impl ResolverDropStats {
    pub fn snapshot(&self) -> (usize, usize, usize) {
        (
            self.dh_zeroed.load(Ordering::Acquire),
            self.cipher_zeroed.load(Ordering::Acquire),
            self.hash_reset.load(Ordering::Acquire),
        )
    }
}

struct ZeroizingDh {
    inner: Box<dyn Dh>,
    stats: Option<Arc<ResolverDropStats>>,
}

impl Drop for ZeroizingDh {
    fn drop(&mut self) {
        let len = self.inner.priv_len().min(64);
        let zeros = [0u8; 64];
        self.inner.set(&zeros[..len]);
        if let Some(ref s) = self.stats {
            s.dh_zeroed.fetch_add(1, Ordering::AcqRel);
        }
    }
}

impl Dh for ZeroizingDh {
    fn name(&self) -> &'static str {
        self.inner.name()
    }
    fn pub_len(&self) -> usize {
        self.inner.pub_len()
    }
    fn priv_len(&self) -> usize {
        self.inner.priv_len()
    }
    fn set(&mut self, privkey: &[u8]) {
        self.inner.set(privkey);
    }
    fn generate(&mut self, rng: &mut dyn Random) {
        self.inner.generate(rng);
    }
    fn pubkey(&self) -> &[u8] {
        self.inner.pubkey()
    }
    fn privkey(&self) -> &[u8] {
        self.inner.privkey()
    }
    fn dh(&self, pubkey: &[u8], out: &mut [u8]) -> Result<(), snow::Error> {
        self.inner.dh(pubkey, out)
    }
}

struct ZeroizingCipher {
    inner: Box<dyn Cipher>,
    stats: Option<Arc<ResolverDropStats>>,
}

impl Drop for ZeroizingCipher {
    fn drop(&mut self) {
        let zeros = [0u8; 32];
        self.inner.set(&zeros);
        if let Some(ref s) = self.stats {
            s.cipher_zeroed.fetch_add(1, Ordering::AcqRel);
        }
    }
}

impl Cipher for ZeroizingCipher {
    fn name(&self) -> &'static str {
        self.inner.name()
    }
    fn set(&mut self, key: &[u8]) {
        self.inner.set(key);
    }
    fn encrypt(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) -> usize {
        self.inner.encrypt(nonce, authtext, plaintext, out)
    }
    fn decrypt(
        &self,
        nonce: u64,
        authtext: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, snow::Error> {
        self.inner.decrypt(nonce, authtext, ciphertext, out)
    }
}

struct ZeroizingHash {
    inner: Box<dyn Hash>,
    stats: Option<Arc<ResolverDropStats>>,
}

impl Drop for ZeroizingHash {
    fn drop(&mut self) {
        self.inner.reset();
        if let Some(ref s) = self.stats {
            s.hash_reset.fetch_add(1, Ordering::AcqRel);
        }
    }
}

impl Hash for ZeroizingHash {
    fn name(&self) -> &'static str {
        self.inner.name()
    }
    fn block_len(&self) -> usize {
        self.inner.block_len()
    }
    fn hash_len(&self) -> usize {
        self.inner.hash_len()
    }
    fn reset(&mut self) {
        self.inner.reset();
    }
    fn input(&mut self, data: &[u8]) {
        self.inner.input(data);
    }
    fn result(&mut self, out: &mut [u8]) {
        self.inner.result(out);
    }
}

/// Custom `snow` CryptoResolver wrapping `DefaultResolver` DH, Cipher, and Hash objects in
/// explicit `Drop` handlers so Noise heap key material is zero-overwritten upon teardown or abort.
pub(crate) struct ZeroizingCryptoResolver {
    inner: DefaultResolver,
    stats: Option<Arc<ResolverDropStats>>,
}

impl ZeroizingCryptoResolver {
    pub(crate) fn new(stats: Option<Arc<ResolverDropStats>>) -> Self {
        Self {
            inner: DefaultResolver,
            stats,
        }
    }
}

impl CryptoResolver for ZeroizingCryptoResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        self.inner.resolve_rng()
    }

    fn resolve_dh(&self, choice: &snow::params::DHChoice) -> Option<Box<dyn Dh>> {
        self.inner.resolve_dh(choice).map(|inner| {
            Box::new(ZeroizingDh {
                inner,
                stats: self.stats.clone(),
            }) as Box<dyn Dh>
        })
    }

    fn resolve_hash(&self, choice: &snow::params::HashChoice) -> Option<Box<dyn Hash>> {
        self.inner.resolve_hash(choice).map(|inner| {
            Box::new(ZeroizingHash {
                inner,
                stats: self.stats.clone(),
            }) as Box<dyn Hash>
        })
    }

    fn resolve_cipher(&self, choice: &snow::params::CipherChoice) -> Option<Box<dyn Cipher>> {
        self.inner.resolve_cipher(choice).map(|inner| {
            Box::new(ZeroizingCipher {
                inner,
                stats: self.stats.clone(),
            }) as Box<dyn Cipher>
        })
    }
}

pub(crate) fn noise_builder<'a>(params: snow::params::NoiseParams) -> snow::Builder<'a> {
    let resolver: BoxedCryptoResolver = Box::new(ZeroizingCryptoResolver::new(None));
    snow::Builder::with_resolver(params, resolver)
}

pub(crate) fn noise_builder_with_stats<'a>(
    params: snow::params::NoiseParams,
    stats: Arc<ResolverDropStats>,
) -> snow::Builder<'a> {
    let resolver: BoxedCryptoResolver = Box::new(ZeroizingCryptoResolver::new(Some(stats)));
    snow::Builder::with_resolver(params, resolver)
}

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
        let builder = noise_builder(params);
        let mut kp = builder
            .generate_keypair()
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;

        let res = Self::from_slices(&kp.private, &kp.public);
        kp.private.zeroize();
        res
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
        let mut init = noise_builder(params.clone())
            .remote_public_key(public)
            .build_initiator()
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;
        let mut resp = noise_builder(params)
            .local_private_key(private)
            .build_responder()
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;
        let mut probe = Zeroizing::new([0u8; 96]);
        let probe_len = init
            .write_message(&[], &mut *probe)
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;
        let mut out = Zeroizing::new([0u8; 32]);
        resp.read_message(&probe[..probe_len], &mut *out)
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
