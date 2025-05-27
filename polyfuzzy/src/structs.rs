use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
/// A subset of n-out-γ scalars, and the positions
/// they occupy in a (expanded) FMD secret key [`ExpandedSecretKey`].
pub struct DetectionKey {
    pub(crate) scalars: Vec<Scalar>,

    pub(crate) indices: Vec<usize>,
}

impl DetectionKey {
    pub(crate) fn detect_short_flag(
        &self,
        bit_ciphertexts: &mut CiphertextBits,
        flag: &ShortFlag,
    ) -> bool {
        let ShortFlag { g_ch, u, y, c } = flag;

        c.decompress_into(bit_ciphertexts);

        let CiphertextBits(bit_ciphertexts) = bit_ciphertexts;

        // the false positive rate isn't private so this
        // can run in variable time
        if self
            .indices
            .iter()
            .copied()
            .any(|index| index >= bit_ciphertexts.len())
        {
            return false;
        }

        let m = RO::g(u, c);
        let w = g_ch * m + u * y;

        // however, when dealing with key material, we should only
        // perform constant time ops
        let mut success = 1u8;
        for (xi, index) in self.scalars.iter().zip(self.indices.iter()) {
            let k_i = RO::h(u, &(u * xi), &w) as u8;
            let flag_bit = unsafe {
                // SAFETY: we have asserted that no index within the dsk has
                // a value greater than the length of the bit ciphertexts
                *bit_ciphertexts.get_unchecked(*index) as u8
            };
            success = core::hint::black_box(success & k_i ^ flag_bit);
        }

        success == 1u8
    }

    /// Enforces detection keys are disjoint (as they should), and if
    /// so outputs all their indices and scalars.
    pub(crate) fn flatten(keys: &[DetectionKey]) -> Option<DetectionKey> {
        if keys.is_empty() {
            return None;
        }

        for i in 0..keys.len() {
            for j in i + 1..keys.len() {
                let indices_i = &keys[i].indices;
                let indices_j = &keys[j].indices;
                let common_indices: Vec<_> = BTreeSet::from_iter(indices_i)
                    .intersection(&BTreeSet::from_iter(indices_j))
                    .cloned()
                    .collect();

                if !common_indices.is_empty() {
                    return None;
                }
            }
        }

        // Since they are disjoint, just grab all scalars.
        let mut scalars = Vec::new();
        let mut indices = Vec::new();

        for dsk in keys {
            scalars.append(&mut dsk.scalars.clone());
            indices.append(&mut dsk.indices.clone());
        }

        Some(DetectionKey { scalars, indices })
    }
}

/// A long FMD secret key used in [crate::multifmd1::MultiFmd1] and multifmd2 schemes.
pub struct ExpandedSecretKey(pub(crate) SecretKey);

impl ExpandedSecretKey {
    fn extract_single(&self, indices: &[usize]) -> Option<DetectionKey> {
        // check that input indices are distinct
        let index_set = BTreeSet::from_iter(indices);
        if index_set.len() != indices.len() {
            return None;
        }

        // If number of indices is larger than the number of scalars of this secret key.
        if index_set.len() > self.0 .0.len() {
            return None;
        }

        let mut scalars = Vec::with_capacity(indices.len());
        for ix in indices {
            scalars.push(*self.0 .0.get(*ix)?);
        }

        Some(DetectionKey {
            indices: indices.to_vec(),
            scalars,
        })
    }

    pub(crate) fn extract(
        &self,
        num_detection_keys: usize,
        corruption_threshold: usize,
        rate: &RateFunction,
        gamma: usize,
    ) -> Option<Vec<DetectionKey>> {
        let d = num_detection_keys;
        let n = rate.0; // the leaked rate
        let t = corruption_threshold;

        // Check valid rate
        if !rate.is_valid(d, t, gamma) {
            return None;
        }

        let mut detection_keys = Vec::with_capacity(d);
        let mut start_index = 0;
        for j in 0..d {
            let n_j = if j == d - 1 {
                n - (t - 1) * n / t
            } else {
                n / t
            };

            let indices: Vec<usize> = (start_index..(start_index + n_j)).collect();
            let dsk = self.extract_single(&indices)?;
            detection_keys.push(dsk);

            start_index += n_j;
        }

        Some(detection_keys)
    }
}

/// A long FMD public key used in [crate::multifmd1::MultiFmd1] and multifmd2.
pub struct ExpandedPublicKey(pub(crate) PublicKey);

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
/// Flags used in multifmd1 and polyfuzzy schemes
pub struct ShortFlag {
    g_ch: RistrettoPoint, // Basepoint for the Chamaleon Hash.
    u: RistrettoPoint,
    y: Scalar,
    c: CompressedCiphertextBits,
}

impl ShortFlag {
    pub(crate) fn generate_flag<R: RngCore + CryptoRng>(
        pk: &ExpandedPublicKey,
        rng: &mut R,
    ) -> Self {
        let r = Scalar::random(rng);
        let s = Scalar::random(rng);
        let z = Scalar::random(rng);

        let u = pk.0.tagged_basepoint * r;
        let g_ch = pk.0.tagged_basepoint * s;
        let w = g_ch * z;

        let bit_ciphertexts = CiphertextBits(
            pk.0.points_h
                .iter()
                .map(|h_i| {
                    let k_i = RO::h(&u, &(h_i * r), &w);
                    !k_i // Encrypt bit 1 with hashed mask k_i.
                })
                .collect(),
        );

        let c = bit_ciphertexts.compress();
        let m = RO::g(&u, &c);

        let y = (z - m) * s * r.invert();

        Self { g_ch, u, y, c }
    }
}

pub struct RateFunction(pub(crate) usize);

impl RateFunction {
    pub fn is_valid(&self, number_keys: usize, corruption_threshold: usize, gamma: usize) -> bool {
        let n = self.0;
        let d = number_keys;
        let t = corruption_threshold;

        if t > d {
            return false;
        }

        if d > gamma {
            return false;
        }

        if ((d - t) * d / t + n) > gamma {
            return false;
        };

        return true;
    }
}

// Compact or expanded secret keys are a vector x of scalars.
pub(crate) struct SecretKey(pub(crate) Vec<Scalar>);

impl SecretKey {
    pub(crate) fn generate_key<R: RngCore + CryptoRng>(length: usize, rng: &mut R) -> Self {
        let scalars_x = (0..length).map(|_| Scalar::random(rng)).collect();

        Self(scalars_x)
    }

    pub(crate) fn generate_public_key(&self, address_tag: &[u8; 64]) -> PublicKey {
        let tagged_basepoint = RistrettoPoint::from_uniform_bytes(address_tag);
        let points_h = self.0.iter().map(|x| x * tagged_basepoint).collect();
        PublicKey {
            tagged_basepoint,
            points_h,
        }
    }
}

// Compact or expanded public keys consist of a tagged basepoint and a vector H of points.
pub(crate) struct PublicKey {
    tagged_basepoint: RistrettoPoint, // Basepoint
    points_h: Vec<RistrettoPoint>,
}

/// Compressed representation of the γ bit-ciphertexts of a [`ShortFlag`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub(crate) struct CompressedCiphertextBits(pub(crate) Vec<u8>);

impl CompressedCiphertextBits {
    fn decompress_into(&self, CiphertextBits(bit_ciphertexts): &mut CiphertextBits) {
        bit_ciphertexts.clear();

        for byte in self.0.iter() {
            for i in 0..8 {
                bit_ciphertexts.push(1u8 == (byte >> i) & 1u8);
            }
        }
    }
}

/// Decompressed inner bit-ciphertexts of a [`ShortFlag`].
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub(crate) struct CiphertextBits(pub(crate) Vec<bool>);

impl CiphertextBits {
    pub(crate) const fn new() -> CiphertextBits {
        Self(Vec::new())
    }

    fn compress(&self) -> CompressedCiphertextBits {
        CompressedCiphertextBits(
            self.0
                .chunks(8)
                .map(|bits| {
                    bits.iter()
                        .copied()
                        .enumerate()
                        .fold(0u8, |accum_byte, (i, bit)| accum_byte ^ ((bit as u8) << i))
                })
                .collect(),
        )
    }
}

/// Instantiation of the different random oracles.
struct RO;

impl RO {
    /// This is the random oracle G from Fig.3 of the original FMD paper, instantiated with SHA512.
    fn g(
        u: &RistrettoPoint,
        CompressedCiphertextBits(ciphertexts): &CompressedCiphertextBits,
    ) -> Scalar {
        let mut digest = Sha512::new();

        digest.update(u.compress().to_bytes());
        digest.update(ciphertexts);

        Scalar::from_bytes_mod_order_wide(&digest.finalize().into())
    }

    /// This is the random oracle H from Fig.3 of the original FMD paper, instantiated with SHA256.
    fn h(u: &RistrettoPoint, mask: &RistrettoPoint, w: &RistrettoPoint) -> bool {
        let mut hasher = Sha256::new();

        hasher.update(u.compress().to_bytes());
        hasher.update(mask.compress().to_bytes());
        hasher.update(w.compress().to_bytes());

        let k_i_byte = hasher.finalize().as_slice()[0] & 1u8;

        k_i_byte == 1u8
    }
}
