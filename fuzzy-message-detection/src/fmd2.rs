//! The FMD2 scheme specified in Figure 3 of the [FMD paper](https://eprint.iacr.org/2021/089).

use crate::{CcaSecure, FmdScheme, RestrictedRateSet};
use alloc::collections::BTreeSet;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use std::hint::black_box;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretKey(pub Vec<Scalar>);

#[derive(Debug, Clone)]
pub struct PublicKey {
    keys: Vec<RistrettoPoint>,
}

#[derive(Debug, Clone)]
pub struct DetectionKey {
    indices: Vec<usize>,
    keys: Vec<Scalar>,
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

#[derive(Debug, Clone)]
pub struct FlagCiphertexts {
    u: RistrettoPoint,
    y: Scalar,
    c: Vec<u8>,
}

impl FlagCiphertexts {
    fn generate_flag<R: RngCore + CryptoRng>(pk: &PublicKey, rng: &mut R) -> Self {
        let r = Scalar::random(rng);
        let z = Scalar::random(rng);
        let u = RISTRETTO_BASEPOINT_POINT * r;
        let w = RISTRETTO_BASEPOINT_POINT * z;

        let bit_ciphertexts: Vec<u8> = pk
            .keys
            .iter()
            .map(|pk_i| {
                let k_i = hash_to_flag_ciphertext_bit(&u, &(pk_i * r), &w);
                k_i ^ 1u8 // Encrypt bit 1 with hashed mask k_i.
            })
            .collect();

        let m = hash_flag_ciphertexts(&u, &bit_ciphertexts);

        let r_inv = r.invert();
        let y = (z - m) * r_inv;

        let c = FlagCiphertexts::to_bytes(&bit_ciphertexts);

        Self { u, y, c }
    }

    /// Compressed representation of the γ bit-ciphertexts of a FlagCiphertext.
    fn to_bytes(bit_ciphertexts: &[u8]) -> Vec<u8> {
        let c: Vec<u8> = bit_ciphertexts
            .chunks(8)
            .map(|bits| {
                let mut byte = 0u8;
                for (i, bit) in bits.iter().enumerate() {
                    byte ^= bit << i
                }
                byte
            })
            .collect();
        c
    }

    /// Decompress the inner bit-ciphertexts of this FlagCiphertext.
    fn to_bits(&self) -> Vec<u8> {
        let mut bit_ciphertexts: Vec<u8> = Vec::with_capacity(self.c.len() * 8);
        for byte in self.c.iter() {
            for i in 0..8 {
                bit_ciphertexts.push(byte >> i & 1u8);
            }
        }

        bit_ciphertexts
    }
}

/// This is the hash H from Fig.3 of the FMD paper, instantiated with SHA256.
fn hash_to_flag_ciphertext_bit(
    u: &RistrettoPoint,
    ddh_mask: &RistrettoPoint,
    w: &RistrettoPoint,
) -> u8 {
    let mut hasher = Sha256::new();

    hasher.update(u.compress().to_bytes());
    hasher.update(ddh_mask.compress().to_bytes());
    hasher.update(w.compress().to_bytes());

    hasher.finalize().as_slice()[0] & 1u8
}

/// This is the hash G from Fig.3 of the FMD paper, instantiated with SHA512.
fn hash_flag_ciphertexts(u: &RistrettoPoint, bit_ciphertexts: &[u8]) -> Scalar {
    let mut m_bytes = u.compress().to_bytes().to_vec();
    m_bytes.extend_from_slice(&FlagCiphertexts::to_bytes(bit_ciphertexts));

    Scalar::hash_from_bytes::<Sha512>(&m_bytes)
}

pub struct Fmd2;

impl FmdScheme for Fmd2 {
    type PublicKey = PublicKey;

    type SecretKey = SecretKey;

    type DetectionKey = DetectionKey;

    type FlagCiphertexts = FlagCiphertexts;

    fn generate_keys<R: RngCore + CryptoRng>(
        rates: &RestrictedRateSet,
        rng: &mut R,
    ) -> (Self::PublicKey, Self::SecretKey) {
        let gamma = rates.gamma();

        // Secret key.
        let sk = SecretKey::generate_keys(gamma, rng);

        // Public key.
        let pk = sk.generate_public_key();

        (pk, sk)
    }

    fn flag<R: RngCore + CryptoRng>(pk: &Self::PublicKey, rng: &mut R) -> Self::FlagCiphertexts {
        FlagCiphertexts::generate_flag(pk, rng)
    }

    fn extract(sk: &Self::SecretKey, indices: &[usize]) -> Option<Self::DetectionKey> {
        sk.extract(indices)
    }

    fn test(dsk: &Self::DetectionKey, flag_ciphers: &Self::FlagCiphertexts) -> bool {
        let u = flag_ciphers.u;
        let bit_ciphertexts = flag_ciphers.to_bits();
        let m = hash_flag_ciphertexts(&u, &bit_ciphertexts);
        let w = RISTRETTO_BASEPOINT_POINT * m + flag_ciphers.u * flag_ciphers.y;
        let mut success = 1u8;
        for (xi, index) in dsk.keys.iter().zip(dsk.indices.iter()) {
            let k_i = hash_to_flag_ciphertext_bit(&u, &(u * xi), &w);
            success = black_box(success & k_i ^ bit_ciphertexts[*index])
        }

        success == 1u8
    }
}

/// FMD2 is proven to be IND-CCA secure in the [FMD paper](https://eprint.iacr.org/2021/089).
impl CcaSecure for Fmd2 {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flag_test() {
        let mut csprng = rand_core::OsRng;

        let rates = RestrictedRateSet::new(5);
        let (pk, sk) = <Fmd2 as FmdScheme>::generate_keys(&rates, &mut csprng);
        let flag_cipher = <Fmd2 as FmdScheme>::flag(&pk, &mut csprng);
        let dk = <Fmd2 as FmdScheme>::extract(&sk, &(0..rates.gamma()).collect::<Vec<_>>());
        assert!(<Fmd2 as FmdScheme>::test(&dk.unwrap(), &flag_cipher));
    }

    /// Test that we perform checks on the input indices when extract flags.
    #[test]
    fn test_extract_checks() {
        let mut csprng = rand_core::OsRng;

        let rates = RestrictedRateSet::new(5);
        let (pk, sk) = <Fmd2 as FmdScheme>::generate_keys(&rates, &mut csprng);
        let flag_cipher = <Fmd2 as FmdScheme>::flag(&pk, &mut csprng);

        assert!(<Fmd2 as FmdScheme>::extract(&sk, &[0, 0, 1]).is_none());
        assert!(<Fmd2 as FmdScheme>::extract(&sk, &[0, 1, 2, 3, 4, 5, 6]).is_none());
        assert!(<Fmd2 as FmdScheme>::extract(&sk, &[6]).is_none());
    }

    #[test]
    fn test_flag_test_with_partial_detection_key() {
        let mut csprng = rand_core::OsRng;

        let rates = RestrictedRateSet::new(5);
        let (pk, sk) = <Fmd2 as FmdScheme>::generate_keys(&rates, &mut csprng);
        for _i in 0..10 {
            let flag_cipher = <Fmd2 as FmdScheme>::flag(&pk, &mut csprng);
            let dk = <Fmd2 as FmdScheme>::extract(&sk, &[0, 2, 4]);
            assert!(<Fmd2 as FmdScheme>::test(&dk.unwrap(), &flag_cipher));
        }
    }

    /// Test when test fails
    #[test]
    fn test_test_fail() {
        let mut csprng = rand_core::OsRng;

        let rates = RestrictedRateSet::new(5);
        let (pk, sk) = <Fmd2 as FmdScheme>::generate_keys(&rates, &mut csprng);

        let mut flag_cipher = <Fmd2 as FmdScheme>::flag(&pk, &mut csprng);
        let mut bits = flag_cipher.to_bits();
        bits[1] ^= 1u8;
        flag_cipher.c = FlagCiphertexts::to_bytes(&bits);
        let dk = <Fmd2 as FmdScheme>::extract(&sk, &[0, 1, 2, 3, 4]);
        assert!(!<Fmd2 as FmdScheme>::test(&dk.unwrap(), &flag_cipher));
    }
}
