// An internal generic implementation of the FMD2 flag and detect algorithms.
// It uses arbitrary basepoints for ElGamal encryption and the Chamaleon Hash.

use std::collections::BTreeSet;

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256, Sha512};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
/// γ secret keys (scalars). For minimum false-positive rate p:=2^{-γ}.
pub struct SecretKey(pub(crate) Vec<Scalar>);

impl SecretKey {
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
            keys,
        })
    }

    pub(crate) fn generate_public_key(&self, basepoint: &RistrettoPoint) -> GenericPublicKey {
        let keys = self.0.iter().map(|k| k * basepoint).collect();
        GenericPublicKey {
            basepoint_eg: *basepoint,
            keys,
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
/// A subset of n-out-γ secret keys and the positions
/// they occupy in [SecretKey].
pub struct DetectionKey {
    pub(crate) keys: Vec<Scalar>,

    pub(crate) indices: Vec<usize>,
}

impl DetectionKey {
    pub(crate) fn detect(&self, flag_ciphers: &GenericFlagCiphertexts) -> bool {
        let u = flag_ciphers.u;
        let bit_ciphertexts = flag_ciphers.to_bits();
        let m = hash_flag_ciphertexts(&u, &bit_ciphertexts);
        let w = flag_ciphers.basepoint_ch * m + flag_ciphers.u * flag_ciphers.y;
        let mut success = true;
        for (xi, index) in self.keys.iter().zip(self.indices.iter()) {
            let k_i = hash_to_flag_ciphertext_bit(&u, &(u * xi), &w);
            success = success && k_i != bit_ciphertexts[*index]
        }

        success
    }
}

#[derive(Debug, Clone)]
pub(crate) struct GenericPublicKey {
    pub(crate) basepoint_eg: RistrettoPoint, // Basepoint to generate the DDH mask (for ElGamal).
    pub(crate) keys: Vec<RistrettoPoint>,
}

pub(crate) struct ChamaleonHashBasepoint {
    base: RistrettoPoint, // Basepoint for the Chamaleon Hash.
    dlog: Scalar, // Discrete log of `basepoint_ch` in base `GenericPublicKey.basepoint_eg`.
}

impl ChamaleonHashBasepoint {
    pub(crate) fn new(pk: &GenericPublicKey, dlog: &Scalar) -> ChamaleonHashBasepoint {
        ChamaleonHashBasepoint {
            base: pk.basepoint_eg * dlog,
            dlog: *dlog,
        }
    }
}

#[derive(Debug, Clone)]
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
        pk: &GenericPublicKey,
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

    Scalar::hash_from_bytes::<Sha512>(&m_bytes)
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

        let sk = SecretKey::generate_keys(5, &mut csprng);

        assert!(sk.extract(&[0, 0, 1]).is_none());
        assert!(sk.extract(&[0, 1, 2, 3, 4, 5, 6]).is_none());
        assert!(sk.extract(&[6]).is_none());
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
    ) -> (SecretKey, GenericPublicKey, ChamaleonHashBasepoint) {
        let mut csprng = rand_core::OsRng;

        let sk = SecretKey::generate_keys(gamma, &mut csprng);
        let pk = sk.generate_public_key(&RISTRETTO_BASEPOINT_POINT);
        let basepoint_ch = ChamaleonHashBasepoint {
            base: RISTRETTO_BASEPOINT_POINT,
            dlog: Scalar::ONE,
        };

        (sk, pk, basepoint_ch)
    }
}
