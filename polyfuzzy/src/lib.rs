#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use rand_core::{CryptoRng, RngCore};

pub(crate) mod combiner;
pub mod fmd2;
pub mod fmd2_compact;
pub(crate) mod fmd2_generic;
pub use crate::combiner::FilterCombiner;
pub use crate::fmd2_generic::{DetectionKey, FmdSecretKey};

/// A trait for a Fuzzy Message Detection (FMD) scheme with multi-key extraction.
pub trait MultiFmdScheme<PK, F> {
    fn flag<R: RngCore + CryptoRng>(&mut self, public_key: &PK, rng: &mut R) -> F;

    /// Returns `None` if (`leaked_rate`,`filtering_rate`) does not constitute a
    /// valid pair of rates for the given `num_detection_keys` and `threshold`.
    fn multi_extract(
        &self,
        secret_key: &FmdSecretKey,
        num_detection_keys: usize,
        threshold: usize,
        leaked_rate: usize,
        filtering_rate: usize,
    ) -> Option<Vec<DetectionKey>> {
        secret_key.multi_extract(num_detection_keys, threshold, leaked_rate, filtering_rate)
    }

    /// Probabilistic detection based on the false-positive rate associated to `detection_key`.
    fn detect(&self, detection_key: &DetectionKey, flag_ciphers: &F) -> bool;
}

/// A trait to generate the keypair of the FMD scheme.
///
/// Depending on implementations, the generated keypair can be compact.
pub trait FmdKeyGen<SK, PK> {
    fn generate_keys<R: RngCore + CryptoRng>(&self, rng: &mut R) -> (SK, PK);
}

/// A trait to derive an FMD keypair ([FmdSecretKey],DPK) from a keypair (SK,PK).
pub trait KeyExpansion<SK, PK, DPK>: FmdKeyGen<SK, PK> {
    fn expand_keypair(&self, parent_sk: &SK, parent_pk: &PK) -> (FmdSecretKey, DPK);

    fn expand_public_key(&self, parent_pk: &PK) -> DPK;
}

/// A trait to randomize public keys.
///
/// - Key expansion and key randomization are compatible if FMD secret keys
///   of FMD public keys expanded from randomized compact keys are the same.
//
//   (sk1,pk1)----randomize----> pk2
//      |                         |
//      |                         |
//  expand_keypair         expand_public_key
//      |                         |
//      |                         |
//      \/                        \/
//  (sk3,pk3)                    pk4 such that sk3 = secret_key(pk4)
///
/// - Key randomization must be unlinkable: it is not possible to tell whether any two public keys
///   were randomized from the same input keypair.
pub trait KeyRandomization<SK, PK> {
    /// The randomized public key is bound to the tag. Different tags yield
    /// different randomized public keys.
    /// The input tag _should_ be uniform (e.g. a hash digest).
    fn randomize(&self, sk: &SK, tag: &[u8; 64]) -> PK;
}
