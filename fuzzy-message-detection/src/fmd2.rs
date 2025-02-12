//! The FMD2 scheme.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};

use rand_core::{CryptoRng, RngCore};

use crate::{
    fmd2_generic::{GenericFlagCiphertexts, GenericPublicKey, ChamaleonHashBasepoint},
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
        let pk = sk.generate_public_key(&RISTRETTO_BASEPOINT_POINT);

        (pk.into(), sk)
    }
}

/// The implementation from Figure 3 of the [FMD paper](https://eprint.iacr.org/2021/089).
pub struct Fmd2;

impl FmdScheme for Fmd2 {
    type PublicKey = PublicKey;

    type FlagCiphertexts = FlagCiphertexts;

    fn flag<R: RngCore + CryptoRng>(pk: &Self::PublicKey, rng: &mut R) -> Self::FlagCiphertexts {
        let gpk = GenericPublicKey {
            basepoint_eg: RISTRETTO_BASEPOINT_POINT,
            keys: pk.keys.clone(),
        };

        GenericFlagCiphertexts::generate_flag(
            &gpk,
            &ChamaleonHashBasepoint::new(&gpk, &Scalar::ONE),
            rng,
        )
        .into()
    }

    fn detect(dsk: &DetectionKey, flag_ciphers: &Self::FlagCiphertexts) -> bool {
        let gfc = GenericFlagCiphertexts::new(
            &RISTRETTO_BASEPOINT_POINT,
            &flag_ciphers.u,
            &flag_ciphers.y,
            &flag_ciphers.c,
        );

        dsk.detect(&gfc)
    }
}

/// FMD2 is proven to be IND-CCA secure in the [FMD paper](https://eprint.iacr.org/2021/089).
impl CcaSecure for Fmd2Params {}
