//! The FMD2 scheme specified in Figure 3 of the [FMD paper](https://eprint.iacr.org/2021/089).

#[cfg(feature = "borsh")]
mod borsh_serialization;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use alloc::collections::BTreeSet;
use alloc::vec;
use alloc::vec::Vec;
use core::hint::black_box;

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;

use crate::{CcaSecure, FmdScheme, RestrictedRateSet};

fn check_key_size(
    expected_key_size: usize,
    got_data_len: usize,
) -> Result<(), DeserializationError> {
    if got_data_len % expected_key_size == 0 {
        Ok(())
    } else {
        Err(DeserializationError::InvalidSize { expected_key_size })
    }
}

#[derive(Debug, Error)]
pub enum DeserializationError {
    #[error("Invalid number of sub-keys")]
    InvalidNumSubKeys,
    #[error("Expected data size to be a multiple of {expected_key_size} bytes")]
    InvalidSize { expected_key_size: usize },
    #[error("Got non-canonical representation of scalar")]
    NonCanonicalScalar,
    #[error("Got invalid representation of ristretto point")]
    InvalidRistrettoPoint,
    #[error("Flag ciphertext too short")]
    ShortFlagCiphertext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecretKey(pub Vec<Scalar>);

impl From<Vec<Scalar>> for SecretKey {
    #[inline]
    fn from(scalars: Vec<Scalar>) -> Self {
        Self(scalars)
    }
}

impl SecretKey {
    pub fn public_key(&self) -> PublicKey {
        self.diversified_public_key(RISTRETTO_BASEPOINT_POINT)
    }

    pub fn diversified_public_key(&self, div: RistrettoPoint) -> PublicKey {
        let keys = self.0.iter().map(|k| k * div).collect();
        PublicKey { div, keys }
    }

    pub fn to_bytes(&self) -> Vec<[u8; 32]> {
        self.0.iter().map(Scalar::to_bytes).collect()
    }

    pub fn to_bytes_flattened(&self) -> Vec<u8> {
        self.to_bytes().into_flattened()
    }

    pub fn from_bytes_mod_order_flattened(bytes: &[u8]) -> Result<Self, DeserializationError> {
        check_key_size(32, bytes.len())?;

        Ok(Self::from_bytes_mod_order(bytes.chunks(32).map(
            |dyn_chunk| {
                let mut chunk = [0u8; 32];
                chunk.copy_from_slice(dyn_chunk);
                chunk
            },
        )))
    }

    pub fn from_bytes_mod_order<I>(seeds: I) -> Self
    where
        I: IntoIterator<Item = [u8; 32]>,
    {
        Self(
            seeds
                .into_iter()
                .map(Scalar::from_bytes_mod_order)
                .collect(),
        )
    }

    pub fn from_canonical_bytes_flattened(bytes: &[u8]) -> Result<Self, DeserializationError> {
        check_key_size(32, bytes.len())?;

        Self::from_canonical_bytes(bytes.chunks(32).map(|dyn_chunk| {
            let mut chunk = [0u8; 32];
            chunk.copy_from_slice(dyn_chunk);
            chunk
        }))
    }

    pub fn from_canonical_bytes<I>(seeds: I) -> Result<Self, DeserializationError>
    where
        I: IntoIterator<Item = [u8; 32]>,
    {
        Ok(Self(
            seeds
                .into_iter()
                .map(|encoded_scalar| Scalar::from_canonical_bytes(encoded_scalar).into())
                .collect::<Option<Vec<_>>>()
                .ok_or(DeserializationError::NonCanonicalScalar)?,
        ))
    }

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
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PublicKey {
    div: RistrettoPoint,
    keys: Vec<RistrettoPoint>,
}

impl PublicKey {
    pub const fn from_parts(div: RistrettoPoint, keys: Vec<RistrettoPoint>) -> Self {
        Self { div, keys }
    }

    pub fn to_bytes(&self) -> Vec<[u8; 32]> {
        self.keys
            .iter()
            .map(|point| point.compress().to_bytes())
            .chain(core::iter::once_with(|| self.div.compress().to_bytes()))
            .collect()
    }

    pub fn to_bytes_flattened(&self) -> Vec<u8> {
        self.to_bytes().into_flattened()
    }

    pub fn from_bytes_flattened(bytes: &[u8]) -> Result<Self, DeserializationError> {
        check_key_size(32, bytes.len())?;

        Self::from_bytes(bytes.chunks(32).map(|dyn_chunk| {
            let mut chunk = [0u8; 32];
            chunk.copy_from_slice(dyn_chunk);
            chunk
        }))
    }

    pub fn from_bytes<I>(public_keys: I) -> Result<Self, DeserializationError>
    where
        I: IntoIterator<Item = [u8; 32]>,
    {
        let mut keys: Vec<_> = public_keys
            .into_iter()
            .map(|key| CompressedRistretto(key).decompress())
            .collect::<Option<Vec<_>>>()
            .ok_or(DeserializationError::InvalidRistrettoPoint)?;
        Ok(Self {
            div: keys.pop().ok_or(DeserializationError::InvalidNumSubKeys)?,
            keys,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DetectionKey {
    indices: Vec<usize>,
    keys: Vec<Scalar>,
}

impl DetectionKey {
    pub fn to_bytes(&self) -> Vec<[u8; 40]> {
        self.indices
            .iter()
            .zip(self.keys.iter())
            .map(|(index, key)| {
                let mut output = [0u8; 40];

                let index = *index as u64;

                let encoded_index = index.to_le_bytes();
                let encoded_scalar = key.to_bytes();

                output[..8].copy_from_slice(&encoded_index);
                output[8..].copy_from_slice(&encoded_scalar);

                output
            })
            .collect()
    }

    pub fn to_bytes_flattened(&self) -> Vec<u8> {
        self.to_bytes().into_flattened()
    }

    pub fn from_bytes_flattened(bytes: &[u8]) -> Result<Self, DeserializationError> {
        check_key_size(40, bytes.len())?;

        Self::from_bytes(bytes.chunks(40).map(|dyn_chunk| {
            let mut chunk = [0u8; 40];
            chunk.copy_from_slice(dyn_chunk);
            chunk
        }))
    }

    pub fn from_bytes<I>(bytes: I) -> Result<Self, DeserializationError>
    where
        I: IntoIterator<Item = [u8; 40]>,
    {
        let (indices, keys) = bytes
            .into_iter()
            .try_fold((vec![], vec![]), |(mut indices, mut keys), chunk| {
                indices.push({
                    let mut encoded_index = [0u8; 8];
                    encoded_index.copy_from_slice(&chunk[..8]);
                    usize::try_from(u64::from_le_bytes(encoded_index)).ok()?
                });
                keys.push({
                    let mut encoded_scalar = [0u8; 32];
                    encoded_scalar.copy_from_slice(&chunk[8..]);
                    Option::<_>::from(Scalar::from_canonical_bytes(encoded_scalar))?
                });
                Some((indices, keys))
            })
            .ok_or(DeserializationError::NonCanonicalScalar)?;

        Ok(Self { indices, keys })
    }
}

/// Compressed representation of the γ bit-ciphertexts of a [`FlagCiphertext`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
struct CompressedCiphertext(Vec<u8>);

impl CompressedCiphertext {
    fn decompress(&self) -> Ciphertext {
        let mut bit_ciphertexts = Vec::with_capacity(self.0.len() * 8);
        for byte in self.0.iter() {
            for i in 0..8 {
                bit_ciphertexts.push(byte >> i & 1u8);
            }
        }

        Ciphertext(bit_ciphertexts)
    }
}

/// Decompressed inner bit-ciphertexts of a [`FlagCiphertext`].
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
struct Ciphertext(Vec<u8>);

impl Ciphertext {
    fn compress(&self) -> CompressedCiphertext {
        CompressedCiphertext(
            self.0
                .chunks(8)
                .map(|bits| {
                    let mut byte = 0u8;
                    for (i, bit) in bits.iter().enumerate() {
                        byte ^= bit << i
                    }
                    byte
                })
                .collect(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FlagCiphertexts {
    u: RistrettoPoint,
    y: Scalar,
    div: RistrettoPoint,
    c: CompressedCiphertext,
}

impl FlagCiphertexts {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(32 + 32 + self.c.0.len());

        output.extend_from_slice(&self.u.compress().to_bytes());
        output.extend_from_slice(&self.y.to_bytes());
        output.extend_from_slice(&self.div.compress().to_bytes());
        output.extend_from_slice(&self.c.0);

        output
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        if bytes.len() < 96 {
            return Err(DeserializationError::ShortFlagCiphertext);
        }

        let u = {
            let mut point = CompressedRistretto([0u8; 32]);
            point.0.copy_from_slice(&bytes[..32]);
            point
                .decompress()
                .ok_or(DeserializationError::InvalidRistrettoPoint)?
        };

        let y = {
            let mut encoded_scalar = [0u8; 32];
            encoded_scalar.copy_from_slice(&bytes[32..64]);
            Option::<_>::from(Scalar::from_canonical_bytes(encoded_scalar))
                .ok_or(DeserializationError::NonCanonicalScalar)?
        };

        let div = {
            let mut point = CompressedRistretto([0u8; 32]);
            point.0.copy_from_slice(&bytes[64..96]);
            point
                .decompress()
                .ok_or(DeserializationError::InvalidRistrettoPoint)?
        };

        Ok(Self {
            div,
            u,
            y,
            c: CompressedCiphertext(bytes[96..].to_vec()),
        })
    }

    fn generate_flag<R: RngCore + CryptoRng>(pk: &PublicKey, rng: &mut R) -> Self {
        let r = Scalar::random(rng);
        let z = Scalar::random(rng);
        let u = pk.div * r;
        let w = pk.div * z;

        let bit_ciphertexts = Ciphertext(
            pk.keys
                .iter()
                .map(|pk_i| {
                    let k_i = hash_to_flag_ciphertext_bit(&u, &(pk_i * r), &w);
                    k_i ^ 1u8 // Encrypt bit 1 with hashed mask k_i.
                })
                .collect(),
        );

        let c = bit_ciphertexts.compress();
        let m = hash_flag_ciphertexts(&u, &c);

        let r_inv = r.invert();
        let y = (z - m) * r_inv;

        Self {
            u,
            y,
            c,
            div: pk.div,
        }
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
fn hash_flag_ciphertexts(
    u: &RistrettoPoint,
    CompressedCiphertext(ciphertexts): &CompressedCiphertext,
) -> Scalar {
    let mut digest = Sha512::new();

    digest.update(u.compress().to_bytes());
    digest.update(ciphertexts);

    Scalar::from_hash(digest)
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
        let pk = sk.public_key();

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
        let bit_ciphertexts = flag_ciphers.c.decompress();
        let m = hash_flag_ciphertexts(&u, &flag_ciphers.c);
        let w = flag_ciphers.div * m + flag_ciphers.u * flag_ciphers.y;
        let mut success = 1u8;
        for (xi, index) in dsk.keys.iter().zip(dsk.indices.iter()) {
            let k_i = hash_to_flag_ciphertext_bit(&u, &(u * xi), &w);
            success = black_box(success & k_i ^ bit_ciphertexts.0[*index])
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
        let (_pk, sk) = <Fmd2 as FmdScheme>::generate_keys(&rates, &mut csprng);

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

    /// Test round-trip serialization of data
    #[test]
    fn test_round_trip_deserialization() {
        let mut csprng = rand_core::OsRng;

        let non_zero_key = [
            36u8, 61, 27, 180, 246, 173, 254, 184, 58, 116, 25, 110, 50, 23, 50, 252, 16, 17, 17,
            17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 1,
        ];
        let sk = SecretKey::from(vec![
            Scalar::from_bytes_mod_order([0u8; 32]),
            Scalar::from_bytes_mod_order(non_zero_key),
        ]);

        let serialized = sk.to_bytes();
        assert_eq!(serialized, vec![[0u8; 32], non_zero_key]);
        let deserialized = SecretKey::from_bytes_mod_order(serialized);
        assert_eq!(deserialized, sk);

        let pk = sk.public_key();
        let serialized = pk.to_bytes_flattened();
        let deserialized = PublicKey::from_bytes_flattened(&serialized).expect("Test failed");
        assert_eq!(deserialized, pk);

        let dk = sk.extract(&[0, 1]).expect("Test failed");
        let serialized = dk.to_bytes_flattened();
        let deserialized = DetectionKey::from_bytes_flattened(&serialized).expect("Test failed");
        assert_eq!(dk, deserialized);

        let flag_ciphertext = FlagCiphertexts::generate_flag(&pk, &mut csprng);
        let serialized = flag_ciphertext.to_bytes();
        let deserialized = FlagCiphertexts::from_bytes(&serialized).expect("Test failed");
        assert_eq!(flag_ciphertext, deserialized);
    }

    /// Test that non-canonical serialization of scalars
    /// will fail
    #[test]
    fn test_non_canonical_serialization_fails() {
        const NON_CANONICAL_SCALAR_ENCODING: [u8; 32] = [0x11_u8; 32];

        assert!(matches!(
            SecretKey::from_canonical_bytes_flattened(&NON_CANONICAL_SCALAR_ENCODING),
            Err(DeserializationError::NonCanonicalScalar),
        ));

        let mut detection_key_encoding = vec![0u8; 8];
        detection_key_encoding.extend_from_slice(&NON_CANONICAL_SCALAR_ENCODING);

        assert!(matches!(
            DetectionKey::from_bytes_flattened(&detection_key_encoding),
            Err(DeserializationError::NonCanonicalScalar),
        ));

        let point_encoding = [
            126, 76, 53, 87, 109, 161, 50, 197, 114, 116, 159, 169, 132, 199, 118, 106, 113, 179,
            232, 112, 190, 164, 188, 74, 103, 85, 129, 6, 59, 91, 240, 119,
        ];
        let mut flag_ciphertext_encoding = point_encoding.to_vec();
        flag_ciphertext_encoding.extend_from_slice(&NON_CANONICAL_SCALAR_ENCODING);
        flag_ciphertext_encoding.extend_from_slice(&point_encoding);
        flag_ciphertext_encoding.extend_from_slice(&[1]);

        assert!(matches!(
            FlagCiphertexts::from_bytes(&flag_ciphertext_encoding),
            Err(DeserializationError::NonCanonicalScalar),
        ));
    }

    /// Test that invalid compressed ristretto serialization of points
    /// will fail
    #[test]
    fn test_invalid_compressed_ristretto_points() {
        const INVALID_COMPRESSED_RISTRETTO_POINT: [u8; 32] = [0x11_u8; 32];

        assert!(matches!(
            PublicKey::from_bytes_flattened(&INVALID_COMPRESSED_RISTRETTO_POINT),
            Err(DeserializationError::InvalidRistrettoPoint),
        ));

        let valid_scalar_encoding = [
            151, 68, 196, 236, 135, 31, 86, 78, 159, 251, 95, 245, 158, 182, 173, 110, 197, 45,
            214, 4, 185, 122, 47, 222, 77, 200, 135, 194, 211, 9, 80, 0,
        ];
        let mut flag_ciphertext_encoding = INVALID_COMPRESSED_RISTRETTO_POINT.to_vec();
        flag_ciphertext_encoding.extend_from_slice(&valid_scalar_encoding);
        flag_ciphertext_encoding.extend_from_slice(&INVALID_COMPRESSED_RISTRETTO_POINT);
        flag_ciphertext_encoding.extend_from_slice(&[1]);

        assert!(matches!(
            FlagCiphertexts::from_bytes(&flag_ciphertext_encoding),
            Err(DeserializationError::InvalidRistrettoPoint),
        ));
    }
}
