//! The FMD2 scheme.

use alloc::vec::Vec;

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    fmd2_generic::{ChamaleonHashBasepoint, GenericFlagCiphertexts, GenericPublicKey},
    CcaSecure, DetectionKey, FmdKeyGen, FmdScheme, SecretKey,
};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
/// γ points. The basepoint is hardcoded to the Ristretto basepoint.
pub struct PublicKey {
    keys: Vec<RistrettoPoint>,
}

impl From<GenericPublicKey> for PublicKey {
    fn from(value: GenericPublicKey) -> Self {
        PublicKey { keys: value.keys } // Ignore basepoint.
    }
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
        FlagCiphertexts {
            u: value.u,
            y: value.y,
            c: value.c,
        } // Ignore basepoint.
    }
}

/// The implementation from Figure 3 of the [FMD paper](https://eprint.iacr.org/2021/089).
pub struct Fmd2 {
    gamma: usize,
}

impl Fmd2 {
    /// Generate keys according to the minimum false positive rate γ.
    /// The set of (restricted) false positive rates is 2^{-n} for 1 ≤ n ≤ γ.  
    pub fn new(gamma: usize) -> Fmd2 {
        Fmd2 { gamma }
    }

    /// Returns the γ parameter
    pub fn gamma(&self) -> usize {
        self.gamma
    }
}

impl FmdKeyGen<SecretKey, PublicKey> for Fmd2 {
    fn generate_keys<R: RngCore + CryptoRng>(&self, rng: &mut R) -> (SecretKey, PublicKey) {
        let gamma = self.gamma();

        // Secret key.
        let sk = SecretKey::generate_keys(gamma, rng);

        // Public key.
        let pk = sk.generate_public_key(&RISTRETTO_BASEPOINT_POINT);

        (sk, pk.into())
    }
}

impl FmdScheme<PublicKey, FlagCiphertexts> for Fmd2 {
    fn flag<R: RngCore + CryptoRng>(
        &mut self,
        public_key: &PublicKey,
        rng: &mut R,
    ) -> FlagCiphertexts {
        let gpk = GenericPublicKey {
            basepoint_eg: RISTRETTO_BASEPOINT_POINT,
            keys: public_key.keys.clone(),
        };

        GenericFlagCiphertexts::generate_flag(&gpk, &ChamaleonHashBasepoint::default(), rng).into()
    }

    fn detect(&self, detection_key: &DetectionKey, flag_ciphers: &FlagCiphertexts) -> bool {
        let gfc = GenericFlagCiphertexts::new(
            &RISTRETTO_BASEPOINT_POINT,
            &flag_ciphers.u,
            &flag_ciphers.y,
            &flag_ciphers.c,
        );

        detection_key.detect(&gfc)
    }
}

/// FMD2 is proven to be IND-CCA secure in the [FMD paper](https://eprint.iacr.org/2021/089).
impl CcaSecure for Fmd2 {}
