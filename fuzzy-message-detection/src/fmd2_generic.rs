// An internal generic implementation of the flag and detect algorithms
// used by the MultiFMd2 and MultiFmd2Compact implementations.
// It uses arbitrary basepoints for  ElGamal encryption and the Chamaleon Hash.
use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
/// γ secret subkeys (scalars). For minimum false-positive rate p:=2^{-γ}.
pub struct FmdSecretKey(pub(crate) Vec<Scalar>);

impl FmdSecretKey {
    pub(crate) fn generate_keys<R: RngCore + CryptoRng>(gamma: usize, rng: &mut R) -> Self {
        let keys = (0..gamma).map(|_| Scalar::random(rng)).collect();

        Self(keys)
    }

    pub(crate) fn extract(&self, indices: &[usize]) -> Option<DetectionKey> {
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
            subkeys: keys,
        })
    }

    pub(crate) fn multi_extract(
        &self,
        num_detection_keys: usize,
        threshold: usize,
        leaked_rate: usize,
        filtering_rate: usize,
    ) -> Option<Vec<DetectionKey>> {
        // Check valid rates
        if threshold > num_detection_keys
        || num_detection_keys > self.0.len() // #{detection keys} > γ parameter
        || threshold > leaked_rate
        || filtering_rate != leaked_rate + (num_detection_keys-threshold) * leaked_rate / threshold
        || filtering_rate > self.0.len()
        {
            return None;
        }

        let mut detection_keys = Vec::with_capacity(num_detection_keys);
        let mut start_index = 0;
        for j in 0..num_detection_keys {
            let n_j = if j == num_detection_keys - 1 {
                leaked_rate - (threshold - 1) * leaked_rate / threshold
            } else {
                leaked_rate / threshold
            };

            let indices: Vec<usize> = (start_index..(start_index + n_j)).collect();
            let dsk = self.extract(&indices)?;
            detection_keys.push(dsk);

            start_index += n_j;
        }

        Some(detection_keys)
    }

    pub(crate) fn generate_public_key(&self, basepoint: &RistrettoPoint) -> GenericFmdPublicKey {
        let keys = self.0.iter().map(|k| k * basepoint).collect();
        GenericFmdPublicKey {
            basepoint_eg: *basepoint,
            keys,
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
/// A subset of n-out-γ secret subkeys, and the positions
/// they occupy in [FmdSecretKey].
pub struct DetectionKey {
    pub(crate) subkeys: Vec<Scalar>,

    pub(crate) indices: Vec<usize>,
}

impl DetectionKey {
    pub(crate) fn detect(&self, flag_ciphers: &GenericFlagCiphertexts) -> bool {
        let u = flag_ciphers.u;
        let bit_ciphertexts = flag_ciphers.to_bits();
        let m = hash_flag_ciphertexts(&u, &bit_ciphertexts);
        let w = flag_ciphers.basepoint_ch * m + flag_ciphers.u * flag_ciphers.y;
        let mut success = true;
        for (xi, index) in self.subkeys.iter().zip(self.indices.iter()) {
            let k_i = hash_to_flag_ciphertext_bit(&u, &(u * xi), &w);
            success = success && k_i != bit_ciphertexts[*index]
        }

        success
    }
}

#[derive(Debug, Clone)]
pub(crate) struct GenericFmdPublicKey {
    pub(crate) basepoint_eg: RistrettoPoint, // Basepoint to generate the DDH mask (for ElGamal).
    pub(crate) keys: Vec<RistrettoPoint>,
}

pub(crate) struct ChamaleonHashBasepoint {
    base: RistrettoPoint, // Basepoint for the Chamaleon Hash.
    dlog: Scalar,         // Discrete log of `basepoint_ch` in base `GenericPublicKey.basepoint_eg`.
}

impl ChamaleonHashBasepoint {
    pub(crate) fn new(pk: &GenericFmdPublicKey, dlog: &Scalar) -> ChamaleonHashBasepoint {
        ChamaleonHashBasepoint {
            base: pk.basepoint_eg * dlog,
            dlog: *dlog,
        }
    }
}

impl Default for ChamaleonHashBasepoint {
    fn default() -> Self {
        Self {
            base: RISTRETTO_BASEPOINT_POINT,
            dlog: Scalar::ONE,
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]

pub(crate) struct GenericFlagCiphertexts {
    pub(crate) basepoint_ch: RistrettoPoint, // Basepoint for the Chamaleon Hash.
    pub(crate) u: RistrettoPoint,
    pub(crate) y: Scalar,
    pub(crate) c: Vec<u8>,
}

impl GenericFlagCiphertexts {
    pub(crate) fn new(
        basepoint_ch: &RistrettoPoint,
        u: &RistrettoPoint,
        y: &Scalar,
        c: &[u8],
    ) -> GenericFlagCiphertexts {
        GenericFlagCiphertexts {
            basepoint_ch: *basepoint_ch,
            u: *u,
            y: *y,
            c: c.to_vec(),
        }
    }

    pub(crate) fn generate_flag<R: RngCore + CryptoRng>(
        pk: &GenericFmdPublicKey,
        basepoint_ch: &ChamaleonHashBasepoint,
        rng: &mut R,
    ) -> Self {
        let r = Scalar::random(rng);
        let z = Scalar::random(rng);
        let u = pk.basepoint_eg * r;
        let w = basepoint_ch.base * z;

        let bit_ciphertexts: Vec<bool> = pk
            .keys
            .iter()
            .map(|pk_i| {
                let k_i = hash_to_flag_ciphertext_bit(&u, &(pk_i * r), &w);
                !k_i // Encrypt bit 1 with hashed mask k_i.
            })
            .collect();

        let m = hash_flag_ciphertexts(&u, &bit_ciphertexts);

        let r_inv = r.invert();
        let y = (z - m) * r_inv * basepoint_ch.dlog;

        let c = GenericFlagCiphertexts::to_bytes(&bit_ciphertexts);

        Self {
            basepoint_ch: basepoint_ch.base,
            u,
            y,
            c,
        }
    }

    // Compressed representation of the γ bit-ciphertexts of an GenericFlagCiphertext.
    fn to_bytes(bit_ciphertexts: &[bool]) -> Vec<u8> {
        let c: Vec<u8> = bit_ciphertexts
            .chunks(8)
            .map(|bits| {
                let mut byte = 0u8;
                for (i, bit) in bits.iter().enumerate() {
                    if *bit {
                        byte ^= 1u8 << i
                    }
                }
                byte
            })
            .collect();
        c
    }

    // Decompress the inner bit-ciphertexts of this GenericFlagCiphertext.
    fn to_bits(&self) -> Vec<bool> {
        let mut bit_ciphertexts: Vec<bool> = Vec::new();
        for byte in self.c.iter() {
            for i in 0..8 {
                bit_ciphertexts.push(1u8 == (byte >> i) & 1u8);
            }
        }

        bit_ciphertexts
    }
}

// This is the hash H from Fig.3 of the FMD paper, instantiated with SHA256.
fn hash_to_flag_ciphertext_bit(
    u: &RistrettoPoint,
    ddh_mask: &RistrettoPoint,
    w: &RistrettoPoint,
) -> bool {
    let mut hasher = Sha256::new();

    hasher.update(u.compress().to_bytes());
    hasher.update(ddh_mask.compress().to_bytes());
    hasher.update(w.compress().to_bytes());

    let k_i_byte = hasher.finalize().as_slice()[0] & 1u8;

    k_i_byte == 1u8
}

// This is the hash G from Fig.3 of the FMD paper, instantiated with SHA512.
fn hash_flag_ciphertexts(u: &RistrettoPoint, bit_ciphertexts: &[bool]) -> Scalar {
    let mut m_bytes = u.compress().to_bytes().to_vec();
    m_bytes.extend_from_slice(&GenericFlagCiphertexts::to_bytes(bit_ciphertexts));
    let mut hasher = Sha512::default();
    Digest::update(&mut hasher, &m_bytes);
    Scalar::from_bytes_mod_order_wide(&hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

    #[test]
    fn test_flag_detect() {
        let mut csprng = rand_core::OsRng;

        let gamma = 5;

        let (sk, pk, basepoint_ch) = generate_keys_and_basepoint_ch(gamma);

        let flag_cipher = GenericFlagCiphertexts::generate_flag(&pk, &basepoint_ch, &mut csprng);
        let dk = sk.extract(&(0..gamma).collect::<Vec<_>>()).unwrap();
        assert!(dk.detect(&flag_cipher));
    }

    // Test that we perform checks on the input indices when extract flags.
    #[test]
    fn test_extract_checks() {
        let mut csprng = rand_core::OsRng;

        let sk = FmdSecretKey::generate_keys(5, &mut csprng);

        assert!(sk.extract(&[0, 0, 1]).is_none());
        assert!(sk.extract(&[0, 1, 2, 3, 4, 5, 6]).is_none());
        assert!(sk.extract(&[6]).is_none());
    }

    #[test]
    #[allow(clippy::identity_op)]
    fn test_multi_extract_works() {
        let mut csprng = rand_core::OsRng;

        let gamma = 12;
        let sk = FmdSecretKey::generate_keys(gamma, &mut csprng);

        let detection_keys = sk.multi_extract(5, 3, 7, 7 + (5 - 3) * 7 / 3).unwrap();
        // check correct split size: n_1 = n_2 = n_3 = n_4 = 2, n_5 = 3
        assert_eq!(detection_keys[0].subkeys.len(), 2);
        assert_eq!(detection_keys[1].subkeys.len(), 2);
        assert_eq!(detection_keys[2].subkeys.len(), 2);
        assert_eq!(detection_keys[3].subkeys.len(), 2);
        assert_eq!(detection_keys[4].subkeys.len(), 3);
        // check disjoint split
        for i in 0..5 {
            for j in i + 1..5 {
                for key in detection_keys[i].subkeys.iter() {
                    assert!(!detection_keys[j].subkeys.contains(key));
                }
            }
        }

        // check invalid rates are rejected
        assert!(
            // threshold > #keys
            sk.multi_extract(1, 2, 2, 2 + 1 - 2).is_none()
        );
        assert!(
            // #keys > gamma
            sk.multi_extract(gamma + 1, 2, 2, 2 + (gamma + 1) - 2)
                .is_none()
        );
        assert!(
            // threshold > leaked rate
            sk.multi_extract(4, 3, 2, 2 + 4 - 3).is_none()
        );
        assert!(
            // bad filtering rate
            sk.multi_extract(4, 3, 3, (3 + 4 - 3) + 1).is_none()
        );
        assert!(
            // filtering rate > gamma
            sk.multi_extract(4, 3, 9, 10 + (4 - 3) * 10 / 3).is_none()
        );
    }

    #[test]
    fn test_flag_detect_with_partial_detection_key() {
        let mut csprng = rand_core::OsRng;

        let gamma = 5;

        let (sk, pk, basepoint_ch) = generate_keys_and_basepoint_ch(gamma);

        for _i in 0..10 {
            let flag_cipher =
                GenericFlagCiphertexts::generate_flag(&pk, &basepoint_ch, &mut csprng);
            let dk = sk.extract(&[0, 2, 4]).unwrap();
            assert!(dk.detect(&flag_cipher));
        }
    }

    fn generate_keys_and_basepoint_ch(
        gamma: usize,
    ) -> (FmdSecretKey, GenericFmdPublicKey, ChamaleonHashBasepoint) {
        let mut csprng = rand_core::OsRng;

        let sk = FmdSecretKey::generate_keys(gamma, &mut csprng);
        let pk = sk.generate_public_key(&RISTRETTO_BASEPOINT_POINT);
        let basepoint_ch = ChamaleonHashBasepoint {
            base: RISTRETTO_BASEPOINT_POINT,
            dlog: Scalar::ONE,
        };

        (sk, pk, basepoint_ch)
    }
}
