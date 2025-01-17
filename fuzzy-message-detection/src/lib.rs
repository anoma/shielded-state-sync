extern crate alloc;
pub mod fmd2;
pub use fmd2::SecretKey;
use rand_core::{CryptoRng, RngCore};

/// A trait for a Fuzzy Message Detection (FMD) scheme with restricted false positive rates.
///
/// We slightly modify the signature of [extract](FmdScheme::extract): detection keys are any ordered subset of the γ secret keys, along with their indices. This means that an implementation of [test](FmdScheme::test) should decrypt the flag ciphertexts in the positions given by those indices.
pub trait FmdScheme {
    type PublicKey;
    type SecretKey;
    type DetectionKey;
    type FlagCiphertexts;

    /// Generate keys according to the false positive rate set.
    fn generate_keys<R: RngCore + CryptoRng>(
        rates: &RestrictedRateSet,
        rng: &mut R,
    ) -> (Self::PublicKey, Self::SecretKey);

    fn flag<R: RngCore + CryptoRng>(pk: &Self::PublicKey, rng: &mut R) -> Self::FlagCiphertexts;

    /// The number of (secret key) indices gives the chosen false positive rate.
    /// Sould return `None` if the number of indices is larger than the
    /// γ parameter of the [RestrictedRateSet] used in
    /// [generate_keys](FmdScheme::generate_keys).
    fn extract(sk: &Self::SecretKey, indices: &[usize]) -> Option<Self::DetectionKey>;

    fn test(dsk: &Self::DetectionKey, flag_ciphers: &Self::FlagCiphertexts) -> bool;
}

/// For given integer γ > 0, the set of (restricted) false positive rates is 2^{-n} for 1 ≤ n ≤ γ.  
pub struct RestrictedRateSet(usize);

impl RestrictedRateSet {
    pub fn new(gamma: usize) -> Self {
        Self(gamma)
    }

    /// Returns the γ parameter
    pub fn gamma(&self) -> usize {
        self.0
    }
}

/// A marker trait used to indicate that
/// an implementation of trait [FmdScheme] is IND-CCA secure.
///
/// Only IND-CCA secure schemes should be used, as they ensure
/// generated ciphertext flags are non-malleable.
pub trait CcaSecure {}
