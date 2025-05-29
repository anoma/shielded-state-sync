//! The multi-key scheme polyfuzzy  
//!
//! See Fig. 7 of the paper.
mod polynomial;

use ::alloc::vec::Vec;
use alloc::boxed::Box;

use subtle::ConstantTimeEq;

use crate::{
    structs::{
        CiphertextBits, CompactPublicKey, CompactSecretKey, DetectionKey, ExpandedPublicKey,
        ExpandedSecretKey, PublicKey, RateFunction, SecretKey, ShortFlag,
    },
    MultiKeyFmd,
};
use polynomial::Polynomial;

pub struct Polyfuzzy {
    /// The number of detection keys
    num_detection_keys: usize,
    /// The  number of indeterminates of the polynomials
    m: usize,
    /// The gamma parameter
    gamma: usize,
    /// The public polynomials to expand keys from
    vec_h: Vec<Polynomial>,
    /// Expanded key cache.
    expanded_pk: Option<Box<ExpandedKeyCache>>,
    /// Scratch buffer used to decompress flag ciphertext bits
    ciphertext_bits: CiphertextBits,
}

impl Polyfuzzy {
    pub fn new(num_detection_keys: usize, gamma: usize, m: usize) -> Polyfuzzy {
        Polyfuzzy {
            num_detection_keys,
            m,
            gamma,
            vec_h: Polynomial::linear_independent_polynomials(m, gamma),
            expanded_pk: None,
            ciphertext_bits: CiphertextBits(Vec::with_capacity(gamma)),
        }
    }

    /// Expands the compact secret key by evaluating all polynomials H in the secret scalars
    fn expand_secret_key(&self, sk: &CompactSecretKey) -> ExpandedSecretKey {
        let mut expanded_scalars = Vec::with_capacity(self.gamma);
        for h_i in self.vec_h.iter() {
            expanded_scalars.push(h_i.evaluate(&sk.into()));
        }

        ExpandedSecretKey(SecretKey(expanded_scalars))
    }

    /// Expands the compact public key by evaluating all polynomials H in the exponent
    fn expand_public_key(&self, pk: &CompactPublicKey) -> ExpandedPublicKey {
        let mut expanded_points = Vec::with_capacity(self.gamma);
        for h_i in self.vec_h.iter() {
            expanded_points.push(h_i.evaluate_in_the_exponent(&pk.into()));
        }
        ExpandedPublicKey(PublicKey {
            tagged_basepoint: pk.pk.tagged_basepoint,
            points_h: expanded_points,
        })
    }
}

impl MultiKeyFmd for Polyfuzzy {
    type SecretKey = CompactSecretKey;

    type PublicKey = CompactPublicKey;

    type DetectionKey = DetectionKey;

    type RateFunction = RateFunction;

    type Flag = ShortFlag;

    type TestResult = bool;

    fn generate_secret_key<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
    ) -> CompactSecretKey {
        CompactSecretKey(SecretKey::generate_key(self.m, rng))
    }

    fn generate_public_key(
        &self,
        sk: &CompactSecretKey,
        address_tag: &[u8; 64],
    ) -> CompactPublicKey {
        sk.0.generate_public_key(address_tag).into()
    }

    fn extract(
        &self,
        sk: &CompactSecretKey,
        corruption_threshold: usize,
        rate: &RateFunction,
    ) -> Option<Vec<DetectionKey>> {
        self.expand_secret_key(sk).extract(
            self.num_detection_keys,
            corruption_threshold,
            rate,
            self.gamma,
        )
    }

    fn flag<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        pk: &CompactPublicKey,
        rng: &mut R,
    ) -> ShortFlag {
        // Take the randomized pk to avoid getting yelled at
        // by the borrow checker
        let mut expanded_pk_cached = self.expanded_pk.take();

        let expanded_pk = expanded_pk_cached
            .get_or_insert_with(|| Box::new(ExpandedKeyCache::new(self, pk)))
            .or_update(self, pk)
            .randomized_key
            .clone();

        ShortFlag::generate_flag(&expanded_pk, rng)
    }

    fn detect(&mut self, detection_keys: &[DetectionKey], flag: ShortFlag) -> Option<bool> {
        let flattened_dsk = DetectionKey::flatten(detection_keys)?;

        Some(flattened_dsk.detect_short_flag(&mut self.ciphertext_bits, &flag))
    }
}

/// Cache of expanded FMD public keys.
#[derive(Debug, Clone)]
struct ExpandedKeyCache {
    /// Fingerprint of the [`CompactPublicKey`].
    fingerprint: [u8; 20],
    /// The expanded public key.
    randomized_key: ExpandedPublicKey,
}

impl ExpandedKeyCache {
    fn new(scheme: &Polyfuzzy, pk: &CompactPublicKey) -> Self {
        Self {
            fingerprint: pk.fingerprint,
            randomized_key: scheme.expand_public_key(pk),
        }
    }

    fn or_update(&mut self, scheme: &Polyfuzzy, pk: &CompactPublicKey) -> &mut Self {
        if self.fingerprint.ct_ne(&pk.fingerprint).into() {
            self.fingerprint = pk.fingerprint;
            self.randomized_key = scheme.expand_public_key(pk);
        }
        self
    }
}
