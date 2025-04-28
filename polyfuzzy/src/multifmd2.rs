//! multifmd2   scheme
/// See Fig. 3 of the paper.
use alloc::vec::Vec;
use rand_core::{CryptoRng, RngCore};

use crate::{
    config::{get_safe_parameters, NumDetectionServers, ThreatModel, GAMMA},
    structs::{DetectionKey, ExpandedPublicKey, ExpandedSecretKey, Flag, RateFunction},
    Init, MultiKeyFmd,
};

#[derive(Debug, Clone)]
pub struct MultiFmd2 {
    corruption_threshold: usize,
    num_detection_keys: usize,
    gamma: usize,
}

impl MultiFmd2 {
    /// Low-level initialization. It is recommended to use [init][crate::Init::init] instead.  
    pub fn new(corruption_threshold: usize, num_detection_keys: usize, gamma: usize) -> MultiFmd2 {
        MultiFmd2 {
            corruption_threshold,
            num_detection_keys,
            gamma,
        }
    }
}

impl Init for MultiFmd2 {
    fn init(model: ThreatModel, servers: NumDetectionServers) -> Self {
        let (corruption_threshold, num_detection_keys) = get_safe_parameters(model, servers);
        MultiFmd2::new(corruption_threshold, num_detection_keys, GAMMA)
    }
}

impl MultiKeyFmd for MultiFmd2 {
    type SecretKey = ExpandedSecretKey;

    type PublicKey = ExpandedPublicKey;

    type DetectionKey = DetectionKey;

    type RateFunction = RateFunction;

    type Flag = Flag;

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
        rate: &Self::RateFunction,
    ) -> Option<Vec<DetectionKey>> {
        sk.extract(
            self.num_detection_keys,
            self.corruption_threshold,
            rate,
            self.gamma,
        )
    }

    fn flag<R: RngCore + CryptoRng>(&mut self, pk: &ExpandedPublicKey, rng: &mut R) -> Flag {
        Flag::generate_flag(pk, rng)
    }

    fn detect(&mut self, detection_keys: &[DetectionKey], flag: &Flag) -> Option<Self::TestResult> {
        let flattened_dsk = DetectionKey::flatten(detection_keys)?;

        Some(flattened_dsk.detect_short_flag(&mut crate::structs::CiphertextBits::new(), flag))
    }
}
