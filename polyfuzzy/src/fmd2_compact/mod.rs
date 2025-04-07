//! A multi-key FMD scheme with key expansion and key randomization.
use alloc::vec::Vec;

use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, RistrettoPoint, Scalar};
use polynomial::{EncodedPolynomial, PointEvaluations, Polynomial};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

mod polynomial;
use crate::{
    fmd2_generic::{ChamaleonHashBasepoint, GenericFlagCiphertexts, GenericFmdPublicKey},
    FmdKeyGen, FmdSecretKey, KeyExpansion, KeyRandomization, MultiFmdScheme,
};

/// A polynomial over the scalar field of Ristretto of degree = `t` (the threshold parameter).
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CompactSecretKey(Polynomial);

impl CompactSecretKey {
    pub fn evaluate(&self, values: &[Scalar]) -> Vec<Scalar> {
        self.0.evaluate(values).results
    }

    /// Get the public key counterpart of this key
    /// with standard basepoint
    pub fn public_key(&self) -> CompactPublicKey {
        CompactPublicKey(self.0.encode(&RISTRETTO_BASEPOINT_POINT))
    }
}

/// An encoded polynomial over Ristretto. t+2 points.
/// The first point is the basepoint, the remaining
/// t+1 points the encoded coefficients.
pub struct CompactPublicKey(EncodedPolynomial);

impl CompactPublicKey {
    /// Compress this key by dropping its basepoint.
    pub fn compress(&self) -> CompressedCompactPublicKey {
        CompressedCompactPublicKey {
            coeffs: self.0.coeffs.clone(),
        }
    }
}

/// A compressed representation that drops the basepoint.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CompressedCompactPublicKey {
    coeffs: Vec<RistrettoPoint>,
}

impl CompressedCompactPublicKey {
    pub fn decompress(&self, tag: &[u8; 64]) -> CompactPublicKey {
        CompactPublicKey(EncodedPolynomial {
            basepoint: RistrettoPoint::from_uniform_bytes(tag),
            coeffs: self.coeffs.clone(),
        })
    }
}

/// The evaluations of the secret polynomial
/// encoded using an arbitrary basepoint.
#[derive(PartialEq, Debug, Clone)]
pub struct FmdPublicKey(PointEvaluations);

/// The basepoint for the chamaleon hash,
/// and `u`, `y`, `c`.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FlagCiphertexts(GenericFlagCiphertexts);

/// The multi-key FMD scheme supporting key expansion and key randomization.
pub struct MultiFmd2CompactScheme {
    /// The threshold parameter
    threshold: usize,
    ///the γ public scalars to derive keys from.
    pub(crate) public_scalars: Vec<Scalar>,
    /// The randomized public key.
    randomized_pk: Option<FmdPublicKey>,
}

impl MultiFmd2CompactScheme {
    /// Public scalars default to 1,...,γ in Z_q.
    pub fn new(gamma: usize, threshold: usize) -> Self {
        let mut public_scalars = Vec::new();
        let mut scalar = Scalar::ONE;
        for _i in 0..gamma {
            // Safely assume γ << q
            public_scalars.push(scalar);
            scalar += Scalar::ONE;
        }
        MultiFmd2CompactScheme {
            threshold,
            public_scalars,
            randomized_pk: None,
        }
    }
}

impl FmdKeyGen<CompactSecretKey, CompactPublicKey> for MultiFmd2CompactScheme {
    /// Public keys generated have basepoint hardcoded to Ristretto basepoint.
    /// Thus, the master or original public key (as opposed to diversified keys)
    fn generate_keys<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
    ) -> (CompactSecretKey, CompactPublicKey) {
        let degree = self.threshold;

        let secret_polynomial = Polynomial::random(degree, rng);
        let encoded_polynomial = secret_polynomial.encode(&RISTRETTO_BASEPOINT_POINT);

        (
            CompactSecretKey(secret_polynomial),
            CompactPublicKey(encoded_polynomial),
        )
    }
}

impl MultiFmdScheme<CompactPublicKey, FlagCiphertexts> for MultiFmd2CompactScheme {
    fn flag<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        public_key: &CompactPublicKey,
        rng: &mut R,
    ) -> FlagCiphertexts {
        if self.randomized_pk.is_none() {
            // Just derive on first call.
            let derived_pk = self.expand_public_key(public_key);
            self.randomized_pk = Some(derived_pk);
        }

        let gpk = GenericFmdPublicKey {
            basepoint_eg: self.randomized_pk.clone().unwrap().0.basepoint,
            keys: self.randomized_pk.clone().unwrap().0.results.clone(),
        };
        let trapdoor = Scalar::random(rng);

        FlagCiphertexts(GenericFlagCiphertexts::generate_flag(
            &gpk,
            &ChamaleonHashBasepoint::new(&gpk, &trapdoor),
            rng,
        ))
    }

    fn detect(&self, detection_key: &crate::DetectionKey, flag_ciphers: &FlagCiphertexts) -> bool {
        detection_key.detect(&flag_ciphers.0)
    }
}

impl KeyExpansion<CompactSecretKey, CompactPublicKey, FmdPublicKey> for MultiFmd2CompactScheme {
    fn expand_keypair(
        &self,
        parent_sk: &CompactSecretKey,
        parent_pk: &CompactPublicKey,
    ) -> (FmdSecretKey, FmdPublicKey) {
        let evaluations = parent_sk.0.evaluate(&self.public_scalars);
        let encoded_evaluations = evaluations.encode(&parent_pk.0.basepoint);

        (
            FmdSecretKey(evaluations.results),
            FmdPublicKey(encoded_evaluations),
        )
    }

    fn expand_public_key(&self, parent_pk: &CompactPublicKey) -> FmdPublicKey {
        let encoded_evaluations = parent_pk.0.evaluate(&self.public_scalars);

        FmdPublicKey(encoded_evaluations)
    }
}

impl KeyRandomization<CompactSecretKey, CompactPublicKey> for MultiFmd2CompactScheme {
    fn randomize(&self, sk: &CompactSecretKey, tag: &[u8; 64]) -> CompactPublicKey {
        let encoded_polynomial = sk.0.encode_with_hashed_basepoint(tag);

        CompactPublicKey(encoded_polynomial)
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha512};

    use super::{polynomial::encode_coefficients, MultiFmd2CompactScheme};
    use crate::{FmdKeyGen, KeyExpansion, KeyRandomization, MultiFmdScheme};

    #[test]
    fn test_expand_is_correct() {
        let mut csprng = rand_core::OsRng;

        let compact_multi_fmd2 = MultiFmd2CompactScheme::new(10, 3);
        let (master_csk, master_cpk) = compact_multi_fmd2.generate_keys(&mut csprng);

        let (_fmd_sk, fmd_pk) = compact_multi_fmd2.expand_keypair(&master_csk, &master_cpk);

        let fmd_pk_expanded_publicly = compact_multi_fmd2.expand_public_key(&master_cpk);

        assert_eq!(fmd_pk, fmd_pk_expanded_publicly);
    }

    #[test]
    fn test_expand_and_randomize_are_compatible() {
        let mut csprng = rand_core::OsRng;

        let compact_multi_fmd2 = MultiFmd2CompactScheme::new(10, 3);
        let (master_csk, master_cpk) = compact_multi_fmd2.generate_keys(&mut csprng);

        // Randomize then expand.
        let rand_cpk = compact_multi_fmd2.randomize(&master_csk, &[0; 64]);
        let fmd_pk = compact_multi_fmd2.expand_public_key(&rand_cpk);

        // Expand directly from master.
        let (fmd_sk, _) = compact_multi_fmd2.expand_keypair(&master_csk, &master_cpk);
        let fmd_pk_from_master = encode_coefficients(&fmd_sk.0, &rand_cpk.0.basepoint);

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
