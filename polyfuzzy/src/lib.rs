#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "combine")]
pub mod combiner;
pub mod config;
pub mod multifmd2;
pub mod polyfuzzy;
pub(crate) mod structs;

// Re-exports.
pub use multifmd2::MultiFmd2;
pub use polyfuzzy::Polyfuzzy;
pub use structs::CompactPublicKey;
pub use structs::CompactSecretKey;
pub use structs::DetectionKey;
pub use structs::ExpandedPublicKey;
pub use structs::ExpandedSecretKey;
pub use structs::Flag;
pub use structs::RateFunction;

/// A trait for multi-key Fuzzy Message Detection (multiFMD).
pub trait MultiKeyFmd {
    type SecretKey;
    type PublicKey;
    type DetectionKey;
    type RateFunction;
    type Flag;
    type TestResult;

    fn generate_secret_key<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Self::SecretKey;

    fn generate_public_key(&self, sk: &Self::SecretKey, address_tag: &[u8; 64]) -> Self::PublicKey;

    fn extract(
        &self,
        sk: &Self::SecretKey,
        rate: &Self::RateFunction,
    ) -> Option<Vec<Self::DetectionKey>>;

    fn flag<R: RngCore + CryptoRng>(&mut self, pk: &Self::PublicKey, rng: &mut R) -> Self::Flag;

    fn detect(
        &mut self,
        detection_keys: &[Self::DetectionKey],
        flag: &Self::Flag,
    ) -> Option<Self::TestResult>;
}

/// A trait to initialize a [MultiKeyFmd] scheme.
pub trait Init {
    /// Initialization based on the threat model and number of detection servers.
    fn init(model: config::ThreatModel, num_servers: config::NumDetectionServers) -> Self;
}
