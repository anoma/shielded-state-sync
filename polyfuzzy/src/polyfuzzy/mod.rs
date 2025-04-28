//! polyfuzzy scheme

pub mod polynomial;

use ::alloc::vec::Vec;
use alloc::boxed::Box;

use subtle::ConstantTimeEq;

use crate::{
    config::{get_safe_parameters, NumDetectionServers, ThreatModel, GAMMA, M},
    structs::{
        CiphertextBits, CompactPublicKey, CompactSecretKey, DetectionKey, ExpandedPublicKey,
        ExpandedSecretKey, Flag, PublicKey, RateFunction, SecretKey,
    },
    Init, MultiKeyFmd,
};
use polynomial::Polynomial;

pub struct Polyfuzzy {
    corruption_threshold: usize,
    /// The number of detection keys
    num_detection_keys: usize,
    /// The  number of indeterminates of the polynomials
    m: usize,
    /// The gamma parameter
    gamma: usize,
    /// The public polynomials `H` to expand keys from
    vec_h: Vec<Polynomial>,
    /// Expanded key cache.
    expanded_pk: Option<Box<ExpandedKeyCache>>,
    /// Scratch buffer used to decompress flag ciphertext bits
    ciphertext_bits: CiphertextBits,
}

impl Polyfuzzy {
    /// Low-level initialization. It is recommended to use [init][crate::Init::init] instead.  
    pub fn new(
        corruption_threshold: usize,
        num_detection_keys: usize,
        gamma: usize,
        m: usize,
        h: &[Polynomial],
    ) -> Polyfuzzy {
        assert_eq!(gamma, h.len());
        Polyfuzzy {
            corruption_threshold,
            num_detection_keys,
            m,
            gamma,
            vec_h: h.to_vec(),
            expanded_pk: None,
            ciphertext_bits: CiphertextBits(Vec::with_capacity(gamma)),
        }
    }

    /// Expands the compact secret key by evaluating all polynomials `H``
    /// in the secret scalars.
    pub fn expand_secret_key(&self, sk: &CompactSecretKey) -> ExpandedSecretKey {
        let mut expanded_scalars = Vec::with_capacity(self.gamma);
        for h_i in self.vec_h.iter() {
            expanded_scalars.push(h_i.evaluate(&sk.into()));
        }

        ExpandedSecretKey(SecretKey(expanded_scalars))
    }

    /// Expands the compact public key by evaluating all polynomials `H`
    /// in the exponent.
    pub fn expand_public_key(&self, pk: &CompactPublicKey) -> ExpandedPublicKey {
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

impl Init for Polyfuzzy {
    fn init(model: ThreatModel, servers: NumDetectionServers) -> Self {
        let (corruption_threshold, num_detection_keys) = get_safe_parameters(model, servers);
        // Size of public keys determined by the corruption threshold.
        let m = M;
        // Default public multilinear polynomials `H`.
        let vec_h = Polynomial::linear_independent_polynomials(m, GAMMA);

        Polyfuzzy::new(corruption_threshold, num_detection_keys, GAMMA, m, &vec_h)
    }
}

impl MultiKeyFmd for Polyfuzzy {
    type SecretKey = CompactSecretKey;

    type PublicKey = CompactPublicKey;

    type DetectionKey = DetectionKey;

    type RateFunction = RateFunction;

    type Flag = Flag;

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

    fn extract(&self, sk: &CompactSecretKey, rate: &RateFunction) -> Option<Vec<DetectionKey>> {
        self.expand_secret_key(sk).extract(
            self.num_detection_keys,
            self.corruption_threshold,
            rate,
            self.gamma,
        )
    }

    fn flag<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        pk: &CompactPublicKey,
        rng: &mut R,
    ) -> Flag {
        // Take the randomized pk to avoid getting yelled at
        // by the borrow checker
        let mut expanded_pk = self.expanded_pk.take();

        let expanded_pk_ref = expanded_pk
            .get_or_insert_with(|| Box::new(ExpandedKeyCache::new(self, pk)))
            .or_update(self, pk);
        // .randomized_key
        // .clone();

        let flag = Flag::generate_flag(&expanded_pk_ref.randomized_key, rng);

        // Restore the randomized pk
        self.expanded_pk = expanded_pk;

        flag
    }

    fn detect(&mut self, detection_keys: &[DetectionKey], flag: &Flag) -> Option<bool> {
        let flattened_dsk = DetectionKey::flatten(detection_keys)?;

        Some(flattened_dsk.detect_short_flag(&mut self.ciphertext_bits, flag))
    }
}

/// Cache of expanded FMD public keys.
#[derive(Debug, Clone)]
struct ExpandedKeyCache {
    /// Fingerprint of the [`CompactPublicKey`].
    fingerprint: [u8; 20],
    /// The expanded public key.
    pub(crate) randomized_key: ExpandedPublicKey,
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

#[cfg(test)]
mod tests {
    use crate::config::{NumDetectionServers, SafeRateFunction, ThreatModel};
    use crate::polyfuzzy::Polyfuzzy;
    use crate::structs::{CompactPublicKey, ExpandedPublicKey};
    use crate::{Init, MultiKeyFmd};

    #[test]
    fn test_flagging_with_different_pks_flushes_cache() {
        let mut csprng = rand_core::OsRng;

        let mut polyfuzzy =
            Polyfuzzy::init(ThreatModel::HonestMajority, NumDetectionServers::Three);

        let sk_1 = polyfuzzy.generate_secret_key(&mut csprng);
        let sk_2 = polyfuzzy.generate_secret_key(&mut csprng);

        let pk_1: CompactPublicKey = polyfuzzy.generate_public_key(&sk_1, &[1u8; 64]);

        let pk_2: CompactPublicKey = polyfuzzy.generate_public_key(&sk_2, &[1u8; 64]);

        assert_ne!(pk_1.fingerprint, pk_2.fingerprint);

        _ = polyfuzzy.flag(&pk_1, &mut csprng);
        assert_eq!(
            polyfuzzy.expanded_pk.as_ref().unwrap().fingerprint,
            pk_1.fingerprint
        );

        _ = polyfuzzy.flag(&pk_2, &mut csprng);
        assert_eq!(
            polyfuzzy.expanded_pk.as_ref().unwrap().fingerprint,
            pk_2.fingerprint
        );

        _ = polyfuzzy.flag(&pk_1, &mut csprng);
        assert_eq!(
            polyfuzzy.expanded_pk.as_ref().unwrap().fingerprint,
            pk_1.fingerprint
        );
    }

    #[test]
    fn test_unique_flag_ciphertexts_for_same_pk() {
        let mut csprng = rand_core::OsRng;

        let mut polyfuzzy =
            Polyfuzzy::init(ThreatModel::HonestMajority, NumDetectionServers::Three);

        let sk = polyfuzzy.generate_secret_key(&mut csprng);

        let pk = polyfuzzy.generate_public_key(&sk, &[1u8; 64]);

        let flag_1 = polyfuzzy.flag(&pk, &mut csprng);
        let flag_2 = polyfuzzy.flag(&pk, &mut csprng);

        assert_ne!(flag_1.g_ch, flag_2.g_ch);
        assert_ne!(flag_1.u, flag_2.u);
        assert_ne!(flag_1.y, flag_2.y);
        assert_ne!(flag_1.c, flag_2.c);
    }

    #[test]
    fn test_expand_is_correct() {
        let mut csprng = rand_core::OsRng;

        let polyfuzzy = Polyfuzzy::init(ThreatModel::HonestMajority, NumDetectionServers::Three);

        let sk = polyfuzzy.generate_secret_key(&mut csprng);

        let expanded_pk = ExpandedPublicKey(
            polyfuzzy
                .expand_secret_key(&sk)
                .0
                .generate_public_key(&[1u8; 64]),
        );

        let pk = polyfuzzy.generate_public_key(&sk, &[1u8; 64]);

        let derived_pk = polyfuzzy.expand_public_key(&pk);

        assert_eq!(expanded_pk, derived_pk);
    }

    #[test]
    fn test_same_detection_key_for_randomized_compact_public_keys() {
        let mut csprng = rand_core::OsRng;

        let mut polyfuzzy =
            Polyfuzzy::init(ThreatModel::HonestMajority, NumDetectionServers::Three);

        let sk = polyfuzzy.generate_secret_key(&mut csprng);

        // Extract a vector of detection keys
        let dsk = polyfuzzy
            .extract(&sk, &SafeRateFunction::One.into())
            .unwrap();

        // Generate two stealth pk
        let pk_1 = polyfuzzy.generate_public_key(&sk, &[1u8; 64]);
        let pk_2 = polyfuzzy.generate_public_key(&sk, &[2u8; 64]);

        // Flags under distinct stealth public keys yield same detection output.
        for _i in 0..10 {
            let flag_1 = polyfuzzy.flag(&pk_1, &mut csprng);
            let flag_2 = polyfuzzy.flag(&pk_2, &mut csprng);

            assert_eq!(
                polyfuzzy.detect(&dsk, &flag_1),
                polyfuzzy.detect(&dsk, &flag_2)
            );
        }
    }
}
