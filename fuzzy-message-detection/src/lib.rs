extern crate alloc;
pub mod fmd2;
pub(crate) mod fmd2_generic;
use rand_core::{CryptoRng, RngCore};

pub use crate::fmd2_generic::{DetectionKey, SecretKey};
/// A trait for a Fuzzy Message Detection (FMD) scheme with restricted false positive rates.
///
/// We slightly modify the signature of [extract](FmdScheme::extract): detection keys are any ordered subset of the γ secret keys, along with their indices. This means that an implementation of [detect](FmdScheme::detect) should decrypt the flag ciphertexts in the positions given by those indices.
pub trait FmdScheme {
    type PublicKey;
    type FlagCiphertexts;

    fn flag<R: RngCore + CryptoRng>(pk: &Self::PublicKey, rng: &mut R) -> Self::FlagCiphertexts;

    /// The number of (secret key) indices gives the chosen false positive rate.
    /// Should return `None` if the number of indices is larger than the
    /// γ parameter of the [RestrictedRateSet] used in
    /// [generate_keys](FmdKeyGen::generate_keys).
    fn extract(sk: &SecretKey, indices: &[usize]) -> Option<DetectionKey> {
        sk.extract(indices)
    }

    /// Probabilistic detection based on the number of secret keys embedded in the detection key.
    fn detect(dsk: &DetectionKey, flag_ciphers: &Self::FlagCiphertexts) -> bool;
}

/// A trait to generate the keypair of the FMD scheme.
///
/// Depending on implementations, the keypair can be compact (i.e. less than γ points/scalars).
pub trait FmdKeyGen {
    type PublicKey;
    type SecretKey;

    fn generate_keys<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> (Self::PublicKey, Self::SecretKey);
}

/// A marker trait used to indicate that
/// an implementation of trait [FmdScheme] is IND-CCA secure.
///
/// Only IND-CCA secure schemes should be used, as they ensure
/// generated ciphertext flags are non-malleable.
pub trait CcaSecure {}