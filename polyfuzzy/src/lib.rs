#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use rand_core::{CryptoRng, RngCore};

pub(crate) mod combiner;
pub mod fmd2;
pub mod fmd2_compact;
pub(crate) mod fmd2_generic;
pub use crate::combiner::FilterCombiner;
pub use crate::fmd2_generic::{DetectionKey, FmdSecretKey, TestResult};

/// A trait for a Fuzzy Message Detection (FMD) scheme with multi-key extraction.
pub trait MultiKeyFmd {
    type SecretKey;
    type PublicKey;
    type DetectionKey;
    type RateFunction;
    type Flag;
    type TestResult: ValidResult;

    fn generate_secret_key(threshold: usize) -> Self::SecretKey;

    fn generate_public_key(sk: &Self::SecretKey, address_tag: &[u8]) -> Self::PublicKey;

    fn extract(
        sk: &Self::SecretKey,
        number_keys: usize,
        rate: &Self::RateFunction,
    ) -> Vec<DetectionKey>;

    fn flag(pk: &Self::PublicKey) -> Self::Flag;

    fn test(detection_keys: &[Self::DetectionKey], flag: Self::Flag) -> Self::TestResult;

    fn combine(results: &[Self::TestResult]) -> Self::TestResult;
}

/// Any result must signal whether the test is successfull or not.
pub trait ValidResult {
    fn is_valid(&self) -> bool;
}

/// This trait will be deprecated.
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
    fn detect(&mut self, detection_key: &DetectionKey, flag_ciphers: &F) -> bool;
}

/// This trait will be deprecated.
pub trait FmdKeyGen<SK, PK> {
    fn generate_keys<R: RngCore + CryptoRng>(&self, rng: &mut R) -> (SK, PK);
}

///  This trait will be deprecated.
pub trait KeyExpansion<SK, PK, DPK>: FmdKeyGen<SK, PK> {
    fn expand_keypair(&self, parent_sk: &SK, parent_pk: &PK) -> (FmdSecretKey, DPK);

    fn expand_public_key(&self, parent_pk: &PK) -> DPK;
}

///  This trait will be deprecated.
pub trait KeyRandomization<SK, PK> {
    /// The randomized public key is bound to the tag. Different tags yield
    /// different randomized public keys.
    /// The input tag _should_ be uniform (e.g. a hash digest).
    fn randomize(&self, sk: &SK, tag: &[u8; 64]) -> PK;
}
