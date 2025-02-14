extern crate alloc;

use rand_core::{CryptoRng, RngCore};

pub mod fmd2;
pub mod fmd2_poly;
pub(crate) mod fmd2_generic;
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
    /// γ parameter of the FMD scheme.
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

/// A trait to derive onto FMD keypairs.
pub trait Derive: FmdKeyGen + FmdScheme {
    fn derive(
        &self,
        parent_sk: &<Self as FmdKeyGen>::SecretKey,
        parent_pk: &<Self as FmdKeyGen>::PublicKey,
    ) -> (SecretKey, <Self as FmdScheme>::PublicKey);

    fn derive_publicly(
        &self,
        parent_pk: &<Self as FmdKeyGen>::PublicKey,
    ) -> <Self as FmdScheme>::PublicKey;
}

/// A trait to diversify keys.
///
/// A diversification must be correct and unlinkable in the following sense.
///
/// - Correctness with respect derivation: deriving from any two diversified
/// public keys yields public keys associated to the same secret key.   
// One way to achieve correctness is ensuring the following:
//
//   (sk1,pk1)----diversify----> pk2
//      |                         |
//      |                         |
//    derive                derive_publicly
//      |                         |
//      |                         |
//      \/                        \/
//  (sk3,pk3)                    pk4 such that sk3 = secret_key(pk4)
///
/// - Unlinkability: it is not possible to tell whether any two public keys
/// where diversified from the same input keypair.
pub trait Diversify: FmdKeyGen {
    /// Diversifies from the input secret key. The diversifed public key is bound
    /// to the tag (different tags yield different diversified public keys).
    fn diversify(
        sk: &<Self as FmdKeyGen>::SecretKey,
        diversifier_tag: &[u8],
    ) -> <Self as FmdKeyGen>::PublicKey;
}

/// A marker trait used to indicate that
/// an implementation of trait [FmdScheme] is IND-CCA secure.
///
/// Only IND-CCA secure schemes should be used, as they ensure
/// generated ciphertext flags are non-malleable.
pub trait CcaSecure {}
