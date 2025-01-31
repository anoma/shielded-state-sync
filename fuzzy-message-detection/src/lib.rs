extern crate alloc;
pub(crate) mod fmd2_generic;
pub mod fmd2;
use curve25519_dalek::Scalar;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

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
    fn extract(sk: &SecretKey, indices: &[usize]) -> Option<DetectionKey>;

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

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
/// γ secret keys (scalars). For minimum false-positive rate p:=2^{-γ}.
pub struct SecretKey(pub(crate) Vec<Scalar>);

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
/// A subset of n-out-γ secret keys and the positions
/// they occupy in [SecretKey].
pub struct DetectionKey {
    
    pub(crate) keys: Vec<Scalar>,

    pub(crate) indices: Vec<usize>,
    
}
