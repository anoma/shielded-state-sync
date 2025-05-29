//! The multi-key scheme multifmd1  
/// See Fig. 3 of the paper.
use alloc::vec::Vec;
use rand_core::{CryptoRng, RngCore};

use crate::{
    structs::{DetectionKey, ExpandedPublicKey, ExpandedSecretKey, RateFunction, ShortFlag},
    CombineTests, MultiKeyFmd,
};

#[derive(Debug, Clone)]
pub struct MultiFmd1 {
    gamma: usize,
    num_detection_keys: usize,
}

impl MultiFmd1 {
    /// The false-positive rate leaked to (coalition of) detection servers is 2^{-n} for 1 ≤ n ≤ γ.  
    pub fn new(num_detection_keys: usize, gamma: usize) -> MultiFmd1 {
        MultiFmd1 {
            num_detection_keys,
            gamma,
        }
    }
}

impl MultiKeyFmd for MultiFmd1 {
    type SecretKey = ExpandedSecretKey;

    type PublicKey = ExpandedPublicKey;

    type DetectionKey = DetectionKey;

    type RateFunction = RateFunction;

    type Flag = ShortFlag;

    type TestResult = bool;

    fn generate_secret_key<R: RngCore + CryptoRng>(&self, rng: &mut R) -> ExpandedSecretKey {
        ExpandedSecretKey(crate::structs::SecretKey::generate_key(self.gamma, rng))
    }

    fn generate_public_key(
        &self,
        sk: &ExpandedSecretKey,
        address_tag: &[u8; 64],
    ) -> ExpandedPublicKey {
        ExpandedPublicKey(sk.0.generate_public_key(address_tag))
    }

    fn extract(
        &self,
        sk: &Self::SecretKey,
        corruption_threshold: usize,
        rate: &Self::RateFunction,
    ) -> Option<Vec<DetectionKey>> {
        sk.extract(
            self.num_detection_keys,
            corruption_threshold,
            rate,
            self.gamma,
        )
    }

    fn flag<R: RngCore + CryptoRng>(&mut self, pk: &ExpandedPublicKey, rng: &mut R) -> ShortFlag {
        ShortFlag::generate_flag(pk, rng)
    }

    fn detect(
        &mut self,
        detection_keys: &[DetectionKey],
        flag: ShortFlag,
    ) -> Option<Self::TestResult> {
        let flattened_dsk = DetectionKey::flatten(detection_keys)?;

        Some(flattened_dsk.detect_short_flag(&mut crate::structs::CiphertextBits::new(), &flag))
    }
}

impl CombineTests for MultiFmd1 {
    type TestResult = bool;

    fn combine(&self, results: &[Self::TestResult]) -> bool {
        for result in results {
            if *result != true {
                return false;
            }
        }

        true
    }
}
