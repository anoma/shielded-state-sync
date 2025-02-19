extern crate alloc;

use rand_core::{CryptoRng, RngCore};

pub mod fmd2;
pub(crate) mod fmd2_generic;
pub mod fmd2_poly;
pub use crate::fmd2_generic::{DetectionKey, SecretKey};
/// A trait for a Fuzzy Message Detection (FMD) scheme with restricted false positive rates.
///
/// We slightly modify the signature of [extract](FmdScheme::extract): detection keys are any ordered subset of the γ secret keys, along with their indices. This means that an implementation of [detect](FmdScheme::detect) should decrypt the flag ciphertexts in the positions given by those indices.
pub trait FmdScheme<PK,F> {

    fn flag<R: RngCore + CryptoRng>(&self,public_key: &PK, rng: &mut R) -> F;

    /// The number of (secret key) indices gives the chosen false positive rate.
    /// Should return `None` if the number of indices is larger than the
    /// γ parameter of the FMD scheme.
    fn extract(&self,secret_key: &SecretKey, indices: &[usize]) -> Option<DetectionKey> {
        secret_key.extract(indices)
    }

    /// Probabilistic detection based on the number of secret keys embedded in the detection key.
    fn detect(&self,detection_key: &DetectionKey, flag_ciphers: &F) -> bool;
}

/// A trait to generate the keypair of the FMD scheme.
///
/// Depending on implementations, the keypair can be compact (i.e. less than γ points/scalars).
pub trait FmdKeyGen<SK,PK> {

    fn generate_keys<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> (SK, PK);
}

/// A trait to derive an FMD keypair ([SecretKey],DPK) from a keypair (SK,PK).
pub trait Derive<SK,PK,DPK>: FmdKeyGen<SK,PK> {
    fn derive(
        &self,
        parent_sk: &SK,
        parent_pk: &PK,
    ) -> (SecretKey, DPK);

    fn derive_publicly(
        &self,
        parent_pk: &PK,
    ) -> DPK;
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
pub trait Diversify<SK,PK>: FmdKeyGen<SK,PK> {
    /// Diversifies from the input secret key. The diversifed public key is bound
    /// to the tag (different tags yield different diversified public keys).
    fn diversify(
        &self,
        sk: &SK,
        diversifier_tag: &[u8],
    ) -> PK;
}

/// A marker trait used to indicate that
/// an implementation of trait [FmdScheme] is IND-CCA secure.
///
/// Only IND-CCA secure schemes should be used, as they ensure
/// generated ciphertext flags are non-malleable.
pub trait CcaSecure {}
