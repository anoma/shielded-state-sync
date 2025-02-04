//! The FMD2 scheme.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use alloc::collections::BTreeSet;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};

use rand_core::{CryptoRng, RngCore};

use crate::{
    fmd2_generic::{GenericFlagCiphertexts, GenericPublicKey, TrapdoorBasepoint}, 
    SecretKey, DetectionKey, CcaSecure, FmdKeyGen, FmdScheme};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
/// γ points. The basepoint is hardcoded to the Ristretto basepoint.
pub struct PublicKey {
    keys: Vec<RistrettoPoint>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
/// A point `u`, a scalar `y`, and γ ciphertext bits `c`.
pub struct FlagCiphertexts {
    u: RistrettoPoint,
    y: Scalar,
    c: Vec<u8>,
}

impl From<GenericFlagCiphertexts> for FlagCiphertexts {
    fn from(value: GenericFlagCiphertexts) -> Self {
        FlagCiphertexts { u: value.u, y: value.y, c: value.c } // Ignore basepoint.
    }
}

impl SecretKey {
    fn generate_keys<R: RngCore + CryptoRng>(gamma: usize, rng: &mut R) -> Self {
        let keys = (0..gamma).map(|_| Scalar::random(rng)).collect();

        Self(keys)
    }

    fn extract(&self, indices: &[usize]) -> Option<DetectionKey> {
        // check that input indices are distinct
        let index_set = BTreeSet::from_iter(indices);
        if index_set.len() != indices.len() {
            return None;
        }

        // If number of indices is larger than the γ parameter.
        if index_set.len() > self.0.len() {
            return None;
        }

        let mut keys = Vec::with_capacity(indices.len());
        for ix in indices {
            keys.push(*self.0.get(*ix)?);
        }

        Some(DetectionKey {
            indices: indices.to_vec(),
            keys,
        })
    }

    fn generate_public_key(&self) -> PublicKey {
        let keys = self
            .0
            .iter()
            .map(|k| k * RISTRETTO_BASEPOINT_POINT)
            .collect();
        PublicKey { keys }
    }
}


/// The γ > 0 parameter. 
/// The set of (restricted) false positive rates is 2^{-n} for 1 ≤ n ≤ γ.  
pub struct Fmd2Params {
    gamma: usize,
}

impl Fmd2Params {

    /// Generate keys according to the minimum false positive rate γ.
    pub fn new(gamma: usize) -> Fmd2Params {
        Fmd2Params { gamma }
    }

    /// Returns the γ parameter
    pub fn gamma(&self) -> usize {
        self.gamma
    }
}

impl FmdKeyGen for Fmd2Params {
    type PublicKey = PublicKey;

    type SecretKey = SecretKey;

    fn generate_keys<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> (Self::PublicKey, Self::SecretKey) {
        let gamma = self.gamma();

        // Secret key.
        let sk = SecretKey::generate_keys(gamma, rng);

        // Public key.
        let pk = sk.generate_public_key();

        (pk,sk)
    }
}

/// The implementation from Figure 3 of the [FMD paper](https://eprint.iacr.org/2021/089).
pub struct Fmd2;

impl FmdScheme for Fmd2 {
    type PublicKey = PublicKey;

    type FlagCiphertexts = FlagCiphertexts;

    fn flag<R: RngCore + CryptoRng>(pk: &Self::PublicKey, rng: &mut R) -> Self::FlagCiphertexts {
        let gpk = GenericPublicKey{ basepoint_eg: RISTRETTO_BASEPOINT_POINT, keys: pk.keys.clone() };

        GenericFlagCiphertexts::generate_flag(
            &gpk, 
            &TrapdoorBasepoint::new(&gpk, &Scalar::ONE), 
            rng
        ).into()
    }

    fn extract(sk: &SecretKey, indices: &[usize]) -> Option<DetectionKey> {
        
        sk.extract(indices)
    }

    fn detect(dsk: &DetectionKey, flag_ciphers: &Self::FlagCiphertexts) -> bool {

        let gfc = GenericFlagCiphertexts::new( 
            &RISTRETTO_BASEPOINT_POINT,
            &flag_ciphers.u, 
            &flag_ciphers.y, 
            &flag_ciphers.c);

        dsk.detect(&gfc)
    }
}

/// FMD2 is proven to be IND-CCA secure in the [FMD paper](https://eprint.iacr.org/2021/089).
impl CcaSecure for Fmd2Params {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flag_detect() {
        let mut csprng = rand_core::OsRng;

        let pp = Fmd2Params::new(5);
        let (pk, sk) = pp.generate_keys(&mut csprng);
        let flag_cipher = <Fmd2 as FmdScheme>::flag(&pk, &mut csprng);
        let dk = <Fmd2 as FmdScheme>::extract(&sk, &(0..pp.gamma()).collect::<Vec<_>>());
        assert!(<Fmd2 as FmdScheme>::detect(&dk.unwrap(), &flag_cipher));
    }

    /// Test that we perform checks on the input indices when extract flags.
    #[test]
    fn test_extract_checks() {
        let mut csprng = rand_core::OsRng;

        let pp = Fmd2Params::new(5);
        let (_pk, sk) = pp.generate_keys(&mut csprng);

        assert!(<Fmd2 as FmdScheme>::extract(&sk, &[0, 0, 1]).is_none());
        assert!(<Fmd2 as FmdScheme>::extract(&sk, &[0, 1, 2, 3, 4, 5, 6]).is_none());
        assert!(<Fmd2 as FmdScheme>::extract(&sk, &[6]).is_none());
    }

    #[test]
    fn test_flag_detect_with_partial_detection_key() {
        let mut csprng = rand_core::OsRng;

        let pp = Fmd2Params::new(5);
        let (pk, sk) = pp.generate_keys(&mut csprng);
        for _i in 0..10 {
            let flag_cipher = <Fmd2 as FmdScheme>::flag(&pk, &mut csprng);
            let dk = <Fmd2 as FmdScheme>::extract(&sk, &[0, 2, 4]);
            assert!(<Fmd2 as FmdScheme>::detect(&dk.unwrap(), &flag_cipher));
        }
    }
}
