//! The FMD2 scheme with key derivation and diversification.
//!
//! Implements the scheme sketched [here](https://research.anoma.net/t/shorter-fmd-public-keys-is-it-possible/1074/4?u=kike).
use alloc::vec::Vec;

use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, Scalar};
use polynomial::{EncodedPolynomial, PointEvaluations, Polynomial};

mod polynomial;
use crate::{
    fmd2_generic::{ChamaleonHashBasepoint, GenericFlagCiphertexts, GenericPublicKey},
    CcaSecure, Derive, Diversify, FmdKeyGen, FmdScheme, SecretKey,
};

/// A polynomial over the scalar field of Ristretto of degree = `t` (the threshold parameter).
pub struct CompactSecretKey(Polynomial);

/// An encoded polynomial over Ristretto. t+2 points.
/// The first point is the basepoint, the remaining
/// t+1 points the encoded coefficients.
pub struct CompactPublicKey(EncodedPolynomial);

/// The evaluations of the secret polynomial
/// encoded using an arbitrary basepoint.
#[derive(PartialEq, Debug, Clone)]
pub struct FmdPolyPublicKey(PointEvaluations);

/// The basepoint for the chamaleon hash,
/// and `u`, `y`, `c`.
pub struct FmdPolyCiphertexts(GenericFlagCiphertexts);

/// The polyonmial-based FMD2 scheme.
pub struct Fmd2Poly {
    // The threshold parameter
    threshold: usize,
    //the γ public scalars to derive keys from.
    pub(crate) public_scalars: Vec<Scalar>,
    // The derived public key.
    derived_pk: Option<FmdPolyPublicKey>,
}

impl Fmd2Poly {
    /// Public scalars default to 1,...,γ in Z_q.
    pub fn new(gamma: usize, threshold: usize) -> Self {
        let mut public_scalars = Vec::new();
        let mut scalar = Scalar::ONE;
        for _i in 0..gamma {
            // Safely assume γ << q
            public_scalars.push(scalar);
            scalar += Scalar::ONE;
        }
        Fmd2Poly {
            threshold,
            public_scalars,
            derived_pk: None,
        }
    }
}

impl FmdKeyGen<CompactSecretKey, CompactPublicKey> for Fmd2Poly {
    // Public keys generated have basepoint hardcoded to Ristretto basepoint.
    // Thus, the master or original public key (as opposed to diversified keys)
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

impl FmdScheme<CompactPublicKey, FmdPolyCiphertexts> for Fmd2Poly {
    fn flag<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        public_key: &CompactPublicKey,
        rng: &mut R,
    ) -> FmdPolyCiphertexts {
        if self.derived_pk.is_none() {
            // Just derive on first call.
            let derived_pk = self.derive_publicly(public_key);
            self.derived_pk = Some(derived_pk);
        }

        let gpk = GenericPublicKey {
            basepoint_eg: self.derived_pk.clone().unwrap().0.basepoint,
            keys: self.derived_pk.clone().unwrap().0.results.clone(),
        };
        let trapdoor = Scalar::random(rng);

        FmdPolyCiphertexts(GenericFlagCiphertexts::generate_flag(
            &gpk,
            &ChamaleonHashBasepoint::new(&gpk, &trapdoor),
            rng,
        ))
    }

    fn detect(
        &self,
        detection_key: &crate::DetectionKey,
        flag_ciphers: &FmdPolyCiphertexts,
    ) -> bool {
        detection_key.detect(&flag_ciphers.0)
    }
}

impl Derive<CompactSecretKey, CompactPublicKey, FmdPolyPublicKey> for Fmd2Poly {
    fn derive(
        &self,
        parent_sk: &CompactSecretKey,
        parent_pk: &CompactPublicKey,
    ) -> (SecretKey, FmdPolyPublicKey) {
        let evaluations = parent_sk.0.evaluate(&self.public_scalars);
        let encoded_evaluations = evaluations.encode(&parent_pk.0.basepoint);

        (
            SecretKey(evaluations.results),
            FmdPolyPublicKey(encoded_evaluations),
        )
    }

    fn derive_publicly(&self, parent_pk: &CompactPublicKey) -> FmdPolyPublicKey {
        let encoded_evaluations = parent_pk.0.evaluate(&self.public_scalars);

        FmdPolyPublicKey(encoded_evaluations)
    }
}

impl Diversify<CompactSecretKey, CompactPublicKey> for Fmd2Poly {
    fn diversify(&self, sk: &CompactSecretKey, diversifier_tag: &[u8; 64]) -> CompactPublicKey {
        let encoded_polynomial = sk.0.encode_with_hashed_basepoint(diversifier_tag);

        CompactPublicKey(encoded_polynomial)
    }
}

impl CcaSecure for Fmd2Poly {}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha512};

    use super::{polynomial::encode_coefficients, Fmd2Poly};
    use crate::{Derive, Diversify, FmdKeyGen, FmdScheme};

    #[test]
    fn test_derive_is_correct() -> () {
        let mut csprng = rand_core::OsRng;

        let fmdpoly = Fmd2Poly::new(10, 3);
        let (master_csk, master_cpk) = fmdpoly.generate_keys(&mut csprng);

        let (_fmd_sk, fmd_pk) = fmdpoly.derive(&master_csk, &master_cpk);

        let fmd_pk_derived_publicly = fmdpoly.derive_publicly(&master_cpk);

        assert_eq!(fmd_pk, fmd_pk_derived_publicly);
    }

    #[test]
    fn test_derive_and_diversify_are_compatible() -> () {
        let mut csprng = rand_core::OsRng;

        let fmdpoly = Fmd2Poly::new(10, 3);
        let (master_csk, master_cpk) = fmdpoly.generate_keys(&mut csprng);

        // Diversify and derive.
        let cpk_diversified = fmdpoly.diversify(&master_csk, &[0; 64]);
        let fmd_pk_from_diversified = fmdpoly.derive_publicly(&cpk_diversified);

        // Derive directly from master.
        let (fmd_sk, _) = fmdpoly.derive(&master_csk, &master_cpk);
        let fmd_pk_from_master = encode_coefficients(&fmd_sk.0, &cpk_diversified.0.basepoint);

        assert_eq!(fmd_pk_from_diversified.0.results, fmd_pk_from_master);
    }

    #[test]
    fn test_same_detection_key_for_diversified_fmd_public_keys() -> () {
        let mut csprng = rand_core::OsRng;

        let gamma = 10;

        let mut fmdpoly = Fmd2Poly::new(gamma, 3);
        let (master_csk, master_cpk) = fmdpoly.generate_keys(&mut csprng);

        // Generate the FMD secret key and extract a detection key.
        let (fmd_sk, _fmd_pk) = fmdpoly.derive(&master_csk, &master_cpk);
        let dsk = fmdpoly.extract(&fmd_sk, &[0, 2, 6, 8]).unwrap();

        // Diversify twice.

        let tag1 = hash_into_64_bytes(b"some diversifier tag");
        let tag2 = hash_into_64_bytes(b"another diversifier tag");

        let cpk_diversified_1 = fmdpoly.diversify(&master_csk, &tag1);
        let cpk_diversified_2 = fmdpoly.diversify(&master_csk, &tag2);

        // Flags under distinct diversified public keys yield same detection output.
        for _i in 0..10 {
            let flag_ciphers_1 = fmdpoly.flag(&cpk_diversified_1, &mut csprng);
            let flag_ciphers_2 = fmdpoly.flag(&cpk_diversified_2, &mut csprng);

            assert_eq!(
                fmdpoly.detect(&dsk, &flag_ciphers_1),
                fmdpoly.detect(&dsk, &flag_ciphers_2)
            );
        }
    }

    fn hash_into_64_bytes(bytes: &[u8]) -> [u8; 64] {
        let mut hasher = Sha512::new();
        hasher.update(bytes);

        hasher.finalize().try_into().unwrap()
    }
}
