//! A multi-key FMD scheme with key expansion and key randomization.

use alloc::boxed::Box;
use alloc::vec::Vec;

use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, RistrettoPoint, Scalar};
use polynomial::{EncodedPolynomial, PointEvaluations, Polynomial};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

mod polynomial;
use crate::{
    fmd2_generic::{
        ChamaleonHashBasepoint, CiphertextBits, GenericFlagCiphertexts, GenericFmdPublicKey,
    },
    FmdKeyGen, FmdSecretKey, KeyExpansion, KeyRandomization, MultiFmdScheme,
};

/// A polynomial over the scalar field of Ristretto of degree = `t` (the threshold parameter).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "zeroize", derive(Zeroize))]
pub struct CompactSecretKey(#[cfg_attr(feature = "zeroize", zeroize)] Polynomial);

impl CompactSecretKey {
    /// Get the public key counterpart of this key
    /// with standard basepoint.
    pub fn master_public_key(&self) -> CompactPublicKey {
        CompactPublicKey::from_poly(self.0.encode(&RISTRETTO_BASEPOINT_POINT))
    }

    /// Get the public key counterpart of this key
    /// with a basepoint randomized by the given tag.
    pub fn randomized_public_key(&self, tag: &[u8; 64]) -> CompactPublicKey {
        CompactPublicKey::from_poly(self.0.encode_with_hashed_basepoint(tag))
    }

    /// Get the public key counterpart of this key
    /// with a basepoint randomized by the given
    /// variable length tag.
    pub fn var_randomized_public_key(&self, tag: &[u8]) -> CompactPublicKey {
        let mut digest = Sha512::new();
        digest.update(tag);
        self.randomized_public_key(&digest.finalize().into())
    }
}

/// An encoded polynomial over Ristretto. t+2 points.
/// The first point is the basepoint, the remaining
/// t+1 points the encoded coefficients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactPublicKey {
    fingerprint: [u8; 20],
    polynomial: EncodedPolynomial,
}

impl CompactPublicKey {
    /// Compress this key by dropping its basepoint.
    pub fn compress(self) -> CompressedCompactPublicKey {
        CompressedCompactPublicKey {
            coeffs: self.polynomial.coeffs,
        }
    }

    fn from_poly(polynomial: EncodedPolynomial) -> Self {
        let fingerprint = {
            let mut hasher = Sha256::new();

            hasher.update(polynomial.basepoint.compress().0);

            for coeff in polynomial.coeffs.iter() {
                hasher.update(coeff.compress().0);
            }

            let hash: [u8; 32] = hasher.finalize().into();
            let mut fingerprint = [0; 20];

            fingerprint.copy_from_slice(&hash[..20]);
            fingerprint
        };

        Self {
            fingerprint,
            polynomial,
        }
    }
}

/// A compressed representation that drops the basepoint.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressedCompactPublicKey {
    coeffs: Vec<RistrettoPoint>,
}

impl CompressedCompactPublicKey {
    /// Decompress this key by deriving a new basepoint from the given tag.
    pub fn decompress(self, tag: &[u8; 64]) -> CompactPublicKey {
        CompactPublicKey::from_poly(EncodedPolynomial {
            basepoint: RistrettoPoint::from_uniform_bytes(tag),
            coeffs: self.coeffs,
        })
    }
}

/// The evaluations of the secret polynomial
/// encoded using an arbitrary basepoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FmdPublicKey(PointEvaluations);

/// The basepoint for the chamaleon hash,
/// and `u`, `y`, `c`.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlagCiphertexts(GenericFlagCiphertexts);

impl FlagCiphertexts {
    /// Return the bits of the flag ciphertext.
    #[inline]
    pub fn bits(&self) -> &[u8] {
        &self.0.c.0
    }

    /// Create a bogus flag ciphertext.
    ///
    /// This may be useful if we are generating cover traffic.
    #[inline]
    #[cfg(feature = "random-flag-ciphertexts")]
    pub fn random<R>(rng: &mut R, gamma: usize) -> Self
    where
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        Self(GenericFlagCiphertexts::random(rng, gamma))
    }
}

/// Cache of expanded FMD public keys.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ExpandedKeyCache {
    /// Fingerprint of the [`CompactPublicKey`].
    fingerprint: [u8; 20],
    /// The expanded public key.
    randomized_key: FmdPublicKey,
}

impl ExpandedKeyCache {
    fn new(scheme: &mut MultiFmd2CompactScheme, pk: &CompactPublicKey) -> Self {
        Self {
            fingerprint: pk.fingerprint,
            randomized_key: scheme.expand_public_key(pk),
        }
    }

    fn or_update(
        &mut self,
        scheme: &mut MultiFmd2CompactScheme,
        pk: &CompactPublicKey,
    ) -> &mut Self {
        if self.fingerprint.ct_ne(&pk.fingerprint).into() {
            self.fingerprint = pk.fingerprint;
            self.randomized_key = scheme.expand_public_key(pk);
        }
        self
    }
}

/// The multi-key FMD scheme supporting key expansion and key randomization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiFmd2CompactScheme {
    /// The gamma parameter
    gamma: usize,
    /// The threshold parameter
    threshold: usize,
    ///the γ public scalars to derive keys from.
    pub(crate) public_scalars: Vec<Scalar>,
    /// Expanded key cache.
    expanded_pk: Option<Box<ExpandedKeyCache>>,
    /// Scratch buffer used to decompress flag ciphertext bits
    ciphertext_bits: CiphertextBits,
}

impl MultiFmd2CompactScheme {
    /// Public scalars default to 1,...,γ in Z_q.
    pub const fn new(gamma: usize, threshold: usize) -> Self {
        MultiFmd2CompactScheme {
            gamma,
            threshold,
            public_scalars: Vec::new(),
            expanded_pk: None,
            ciphertext_bits: CiphertextBits(Vec::new()),
        }
    }

    fn init_public_scalars(&mut self) {
        if !self.public_scalars.is_empty() {
            return;
        }

        let mut scalar = Scalar::ONE;

        for _i in 0..self.gamma {
            // Safely assume γ << q
            self.public_scalars.push(scalar);
            scalar += Scalar::ONE;
        }
    }

    fn init_ciphertext_bits(&mut self) {
        self.ciphertext_bits.0.reserve(self.gamma);
    }
}

impl FmdKeyGen<CompactSecretKey, CompactPublicKey> for MultiFmd2CompactScheme {
    /// Public keys generated have basepoint hardcoded to Ristretto basepoint.
    /// Thus, the master or original public key (as opposed to diversified keys)
    fn generate_keys<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> (CompactSecretKey, CompactPublicKey) {
        let degree = self.threshold;

        let secret_polynomial = Polynomial::random(degree, rng);
        let encoded_polynomial = secret_polynomial.encode(&RISTRETTO_BASEPOINT_POINT);

        (
            CompactSecretKey(secret_polynomial),
            CompactPublicKey::from_poly(encoded_polynomial),
        )
    }
}

impl MultiFmdScheme<CompactPublicKey, FlagCiphertexts> for MultiFmd2CompactScheme {
    fn flag<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        public_key: &CompactPublicKey,
        rng: &mut R,
    ) -> FlagCiphertexts {
        // Take the randomized pk to avoid getting yelled at
        // by the borrow checker
        let mut expanded_pk = self.expanded_pk.take();

        let expanded_pk_ref = expanded_pk
            .get_or_insert_with(|| Box::new(ExpandedKeyCache::new(self, public_key)))
            .or_update(self, public_key);

        let gpk = GenericFmdPublicKey {
            basepoint_eg: expanded_pk_ref.randomized_key.0.basepoint,
            keys: expanded_pk_ref.randomized_key.0.results.clone(),
        };

        let flag = FlagCiphertexts(GenericFlagCiphertexts::generate_flag(
            &gpk,
            &ChamaleonHashBasepoint::new(rng, &gpk),
            rng,
        ));

        // Restore the randomized pk
        self.expanded_pk = expanded_pk;

        flag
    }

    fn detect(
        &mut self,
        detection_key: &crate::DetectionKey,
        flag_ciphers: &FlagCiphertexts,
    ) -> bool {
        self.init_ciphertext_bits();
        detection_key.detect(&mut self.ciphertext_bits, &flag_ciphers.0)
    }
}

impl KeyExpansion<CompactSecretKey, CompactPublicKey, FmdPublicKey> for MultiFmd2CompactScheme {
    fn expand_keypair(
        &mut self,
        parent_sk: &CompactSecretKey,
        parent_pk: &CompactPublicKey,
    ) -> (FmdSecretKey, FmdPublicKey) {
        let evaluations = parent_sk.0.evaluate({
            self.init_public_scalars();
            &self.public_scalars
        });
        let encoded_evaluations = evaluations.encode(&parent_pk.polynomial.basepoint);

        (
            FmdSecretKey(evaluations.results),
            FmdPublicKey(encoded_evaluations),
        )
    }

    fn expand_public_key(&mut self, parent_pk: &CompactPublicKey) -> FmdPublicKey {
        let encoded_evaluations = parent_pk.polynomial.evaluate({
            self.init_public_scalars();
            &self.public_scalars
        });

        FmdPublicKey(encoded_evaluations)
    }
}

impl KeyRandomization<CompactSecretKey, CompactPublicKey> for MultiFmd2CompactScheme {
    fn randomize(&mut self, sk: &CompactSecretKey, tag: &[u8; 64]) -> CompactPublicKey {
        sk.randomized_public_key(tag)
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha512};

    use super::{polynomial::encode_coefficients, MultiFmd2CompactScheme};
    use crate::{FmdKeyGen, KeyExpansion, KeyRandomization, MultiFmdScheme};

    #[test]
    fn test_flagging_with_different_pks_flushes_cache() {
        let mut csprng = rand_core::OsRng;

        let mut compact_multi_fmd2 = MultiFmd2CompactScheme::new(10, 3);

        let (_, master_cpk_1) = compact_multi_fmd2.generate_keys(&mut csprng);
        let (_, master_cpk_2) = compact_multi_fmd2.generate_keys(&mut csprng);
        assert_ne!(master_cpk_1.fingerprint, master_cpk_2.fingerprint);

        _ = compact_multi_fmd2.flag(&master_cpk_1, &mut csprng);
        assert_eq!(
            compact_multi_fmd2.expanded_pk.as_ref().unwrap().fingerprint,
            master_cpk_1.fingerprint
        );

        _ = compact_multi_fmd2.flag(&master_cpk_2, &mut csprng);
        assert_eq!(
            compact_multi_fmd2.expanded_pk.as_ref().unwrap().fingerprint,
            master_cpk_2.fingerprint
        );

        _ = compact_multi_fmd2.flag(&master_cpk_1, &mut csprng);
        assert_eq!(
            compact_multi_fmd2.expanded_pk.as_ref().unwrap().fingerprint,
            master_cpk_1.fingerprint
        );
    }

    #[test]
    fn test_unique_flag_ciphertexts_for_same_pk() {
        let mut csprng = rand_core::OsRng;

        let mut compact_multi_fmd2 = MultiFmd2CompactScheme::new(10, 3);
        let (_, master_cpk) = compact_multi_fmd2.generate_keys(&mut csprng);

        let flag_ciphers_1 = compact_multi_fmd2.flag(&master_cpk, &mut csprng);
        let flag_ciphers_2 = compact_multi_fmd2.flag(&master_cpk, &mut csprng);

        assert_ne!(flag_ciphers_1.0.basepoint_ch, flag_ciphers_2.0.basepoint_ch);
        assert_ne!(flag_ciphers_1.0.u, flag_ciphers_2.0.u);
        assert_ne!(flag_ciphers_1.0.y, flag_ciphers_2.0.y);
        assert_ne!(flag_ciphers_1.0.c, flag_ciphers_2.0.c);
    }

    #[test]
    fn test_expand_is_correct() {
        let mut csprng = rand_core::OsRng;

        let mut compact_multi_fmd2 = MultiFmd2CompactScheme::new(10, 3);
        let (master_csk, master_cpk) = compact_multi_fmd2.generate_keys(&mut csprng);

        let (_fmd_sk, fmd_pk) = compact_multi_fmd2.expand_keypair(&master_csk, &master_cpk);

        let fmd_pk_expanded_publicly = compact_multi_fmd2.expand_public_key(&master_cpk);

        assert_eq!(fmd_pk, fmd_pk_expanded_publicly);
    }

    #[test]
    fn test_expand_and_randomize_are_compatible() {
        let mut csprng = rand_core::OsRng;

        let mut compact_multi_fmd2 = MultiFmd2CompactScheme::new(10, 3);
        let (master_csk, master_cpk) = compact_multi_fmd2.generate_keys(&mut csprng);

        // Randomize then expand.
        let rand_cpk = compact_multi_fmd2.randomize(&master_csk, &[0; 64]);
        let fmd_pk = compact_multi_fmd2.expand_public_key(&rand_cpk);

        // Expand directly from master.
        let (fmd_sk, _) = compact_multi_fmd2.expand_keypair(&master_csk, &master_cpk);
        let fmd_pk_from_master = encode_coefficients(&fmd_sk.0, &rand_cpk.polynomial.basepoint);

        assert_eq!(fmd_pk.0.results, fmd_pk_from_master);
    }

    #[test]
    fn test_same_detection_key_for_randomized_compact_public_keys() {
        let mut csprng = rand_core::OsRng;

        let gamma = 10;

        let mut compact_multi_fmd2 = MultiFmd2CompactScheme::new(gamma, 3);
        let (master_csk, master_cpk) = compact_multi_fmd2.generate_keys(&mut csprng);

        // Expand onto the FMD secret key and extract a detection key.
        let (fmd_sk, _fmd_pk) = compact_multi_fmd2.expand_keypair(&master_csk, &master_cpk);
        let dsk = compact_multi_fmd2
            .multi_extract(&fmd_sk, 1, 1, 4, 4)
            .unwrap()
            .pop()
            .unwrap();

        // Randomize twice.
        let tag1 = hash_into_64_bytes(b"some public tag");
        let tag2 = hash_into_64_bytes(b"another public tag");

        let rand_cpk_1 = compact_multi_fmd2.randomize(&master_csk, &tag1);
        let rand_cpk_2 = compact_multi_fmd2.randomize(&master_csk, &tag2);

        // Flags under distinct randomized public keys yield same detection output.
        for _i in 0..10 {
            let flag_ciphers_1 = compact_multi_fmd2.flag(&rand_cpk_1, &mut csprng);
            let flag_ciphers_2 = compact_multi_fmd2.flag(&rand_cpk_2, &mut csprng);

            assert_eq!(
                compact_multi_fmd2.detect(&dsk, &flag_ciphers_1),
                compact_multi_fmd2.detect(&dsk, &flag_ciphers_2)
            );
        }
    }

    fn hash_into_64_bytes(bytes: &[u8]) -> [u8; 64] {
        let mut hasher = Sha512::new();
        hasher.update(bytes);

        hasher.finalize().into()
    }
}
