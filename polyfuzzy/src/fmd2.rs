//! A multi-key FMD scheme based in FMD2.

use alloc::vec::Vec;

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    fmd2_generic::{
        ChamaleonHashBasepoint, CiphertextBits, GenericFlagCiphertexts, GenericFmdPublicKey,
    },
    DetectionKey, FmdKeyGen, FmdSecretKey, MultiFmdScheme,
};

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
/// γ public subkeys (points). The basepoint is hardcoded to the Ristretto basepoint.
pub struct FmdPublicKey {
    subkeys: Vec<RistrettoPoint>,
}

impl From<GenericFmdPublicKey> for FmdPublicKey {
    fn from(value: GenericFmdPublicKey) -> Self {
        FmdPublicKey {
            subkeys: value.keys,
        } // Ignore basepoint.
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
/// A point `u`, a scalar `y`, and γ ciphertext bits `c`.
pub struct FlagCiphertexts {
    u: RistrettoPoint,
    y: Scalar,
    c: Vec<u8>,
}

impl FlagCiphertexts {
    /// Return the bits of the flag ciphertext.
    #[inline]
    pub fn bits(&self) -> &[u8] {
        &self.c
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
        GenericFlagCiphertexts::random(rng, gamma).into()
    }
}

impl From<GenericFlagCiphertexts> for FlagCiphertexts {
    fn from(value: GenericFlagCiphertexts) -> Self {
        FlagCiphertexts {
            u: value.u,
            y: value.y,
            c: value.c.0,
        } // Ignore basepoint.
    }
}

/// The multi-key scheme.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fmd2MultikeyScheme {
    gamma: usize,
}

impl Fmd2MultikeyScheme {
    /// The set of (restricted) false positive rates is 2^{-n} for 1 ≤ n ≤ γ.  
    pub fn new(gamma: usize) -> Fmd2MultikeyScheme {
        Fmd2MultikeyScheme { gamma }
    }

    /// Returns the γ parameter
    pub fn gamma(&self) -> usize {
        self.gamma
    }
}

impl FmdKeyGen<FmdSecretKey, FmdPublicKey> for Fmd2MultikeyScheme {
    /// Generates as many subkeys as the γ parameter of `self`.
    fn generate_keys<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> (FmdSecretKey, FmdPublicKey) {
        let gamma = self.gamma();

        // Secret key.
        let sk = FmdSecretKey::generate_keys(gamma, rng);

        // Public key.
        let pk = sk.generate_public_key(&RISTRETTO_BASEPOINT_POINT);

        (sk, pk.into())
    }
}

impl MultiFmdScheme<FmdPublicKey, FlagCiphertexts> for Fmd2MultikeyScheme {
    fn flag<R: RngCore + CryptoRng>(
        &mut self,
        public_key: &FmdPublicKey,
        rng: &mut R,
    ) -> FlagCiphertexts {
        let gpk = GenericFmdPublicKey {
            basepoint_eg: RISTRETTO_BASEPOINT_POINT,
            keys: public_key.subkeys.clone(),
        };

        GenericFlagCiphertexts::generate_flag(&gpk, &ChamaleonHashBasepoint::default(), rng).into()
    }

    fn detect(&mut self, detection_key: &DetectionKey, flag_ciphers: &FlagCiphertexts) -> bool {
        let gfc = GenericFlagCiphertexts::new(
            &RISTRETTO_BASEPOINT_POINT,
            &flag_ciphers.u,
            &flag_ciphers.y,
            &flag_ciphers.c,
        );

        detection_key.detect(&mut CiphertextBits::new(), &gfc)
    }
}
