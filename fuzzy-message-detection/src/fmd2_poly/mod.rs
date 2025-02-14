//! The FMD2 scheme with key derivation and diversification.
//!
//! Implements the scheme sketched [here](https://research.anoma.net/t/shorter-fmd-public-keys-is-it-possible/1074/4?u=kike).
mod polynomial;

use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, Scalar};
use polynomial::{EncodedPolynomial, PointEvaluations, Polynomial};

use crate::{
    fmd2_generic::{GenericFlagCiphertexts, GenericPublicKey, ChamaleonHashBasepoint},
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
#[derive(PartialEq, Debug)]
pub struct FmdPolyPublicKey(PointEvaluations);

/// The basepoint for the chamaleon hash,
/// and `u`, `y`, `c`.
pub struct FmdPolyCiphertexts(GenericFlagCiphertexts);

/// The polyonmial-based FMD2 scheme.
// The threshold parameter and the γ public scalars to
// derive keys from.
pub struct Fmd2Poly {
    threshold: usize,
    pub(crate) public_scalars: Vec<Scalar>,
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
        }
    }
}

impl FmdKeyGen for Fmd2Poly {
    type PublicKey = CompactPublicKey;
    type SecretKey = CompactSecretKey;

    // Public keys generated have basepoint hardcoded to Ristretto basepoint.
    // Thus, the master or original public key (as opposed to diversified keys)
    fn generate_keys<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
    ) -> (CompactPublicKey, CompactSecretKey) {
        let degree = self.threshold;

        let secret_polynomial = Polynomial::random(degree, rng);
        let encoded_polynomial = secret_polynomial.encode(&RISTRETTO_BASEPOINT_POINT);

        (
            CompactPublicKey(encoded_polynomial),
            CompactSecretKey(secret_polynomial),
        )
    }
}

impl FmdScheme for Fmd2Poly {
    type PublicKey = FmdPolyPublicKey;

    type FlagCiphertexts = FmdPolyCiphertexts;

    fn flag<R: rand_core::RngCore + rand_core::CryptoRng>(
        pk: &Self::PublicKey,
        rng: &mut R,
    ) -> Self::FlagCiphertexts {
        let gpk = GenericPublicKey {
            basepoint_eg: pk.0.basepoint,
            keys: pk.0.results.clone(),
        };
        let trapdoor = Scalar::random(rng);

        FmdPolyCiphertexts(GenericFlagCiphertexts::generate_flag(
            &gpk,
            &ChamaleonHashBasepoint::new(&gpk, &trapdoor),
            rng,
        ))
    }

    fn extract(sk: &SecretKey, indices: &[usize]) -> Option<crate::DetectionKey> {
        sk.extract(indices)
    }

    fn detect(dsk: &crate::DetectionKey, flag_ciphers: &Self::FlagCiphertexts) -> bool {
        dsk.detect(&flag_ciphers.0)
    }
}

impl Derive for Fmd2Poly {
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

impl Diversify for Fmd2Poly {
    fn diversify(sk: &CompactSecretKey, diversifier_tag: &[u8]) -> CompactPublicKey {
        let encoded_polynomial = sk.0.encode_with_hashed_basepoint(diversifier_tag);

        CompactPublicKey(encoded_polynomial)
    }
}

impl CcaSecure for Fmd2Poly {}

#[cfg(test)]
mod tests {
    use crate::{Derive, Diversify, FmdKeyGen};

    use super::{polynomial::encode_coefficients, Fmd2Poly};

    #[test]
    fn test_derive_is_correct() -> () {
        let mut csprng = rand_core::OsRng;

        let fmdpoly = Fmd2Poly::new(10, 3);
        let (master_cpk, master_csk) = fmdpoly.generate_keys(&mut csprng);

        let (_fmd_sk, fmd_pk) = fmdpoly.derive(&master_csk, &master_cpk);

        let fmd_pk_derived_publicly = fmdpoly.derive_publicly(&master_cpk);

        assert_eq!(fmd_pk, fmd_pk_derived_publicly);
    }

    #[test]
    fn test_derive_and_diversify_are_compatible() -> () {
        let mut csprng = rand_core::OsRng;

        let fmdpoly = Fmd2Poly::new(10, 3);
        let (master_cpk, master_csk) = fmdpoly.generate_keys(&mut csprng);

        // Diversify and derive.
        let cpk_diversified = <Fmd2Poly as Diversify>::diversify(&master_csk, &[0; 32]);
        let fmd_pk_from_diversified = fmdpoly.derive_publicly(&cpk_diversified);

        // Derive directly from master.
        let (fmd_sk, _) = fmdpoly.derive(&master_csk, &master_cpk);
        let fmd_pk_from_master = encode_coefficients(&fmd_sk.0, &cpk_diversified.0.basepoint);

        assert_eq!(fmd_pk_from_diversified.0.results, fmd_pk_from_master);
    }
}
