// An internal generic implementation of the FMD2 flag and detect algorithms.
// It uses arbitrary basepoints for ElGamal encryption and the Chamaleon Hash.

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256, Sha512};

use crate::DetectionKey;



#[derive(Debug, Clone)]
pub(crate) struct GenericPublicKey {
    pub(crate) basepoint_eg: RistrettoPoint, // Basepoint to generate the DDH mask (for ElGamal).
    pub(crate) keys: Vec<RistrettoPoint>,
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

pub(crate) struct TrapdoorBasepoint {
    b: RistrettoPoint,
    t: Scalar, // Dlog of b.
}

impl TrapdoorBasepoint {

    pub(crate) fn new(pk: &GenericPublicKey, trapdoor: &Scalar) -> TrapdoorBasepoint {
        TrapdoorBasepoint{
            b: pk.basepoint_eg * trapdoor,
            t: *trapdoor
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct GenericFlagCiphertexts {
    basepoint_eg: RistrettoPoint, // ElGamal basepoint.
    basepoint_ch: RistrettoPoint, // Basepoint for the Chamaleon Hash.
    u: RistrettoPoint,
    y: Scalar,
    c: Vec<u8>,
}

impl GenericFlagCiphertexts {
    pub(crate) fn new(
        basepoint_eg: &RistrettoPoint, 
        basepoint_ch: &RistrettoPoint,
        u: &RistrettoPoint, 
        y: &Scalar, 
        c: &[u8]) 
    -> GenericFlagCiphertexts {

        GenericFlagCiphertexts {
            basepoint_eg: *basepoint_eg,
            basepoint_ch: *basepoint_ch,
            u: *u,
            y: *y,
            c: c.to_vec()
        }
    }

    pub(crate) fn generate_flag<R: RngCore + CryptoRng>(
        pk: &GenericPublicKey, 
        basepoint_ch: &TrapdoorBasepoint, 
        rng: &mut R) 
    -> Self {
        let r = Scalar::random(rng);
        let z = Scalar::random(rng);
        let u = pk.basepoint_eg * r;
        let w = basepoint_ch.b * z;

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
        let y = (z - m) * r_inv * basepoint_ch.t;

        let c = GenericFlagCiphertexts::to_bytes(&bit_ciphertexts);

        Self { 
            basepoint_eg: pk.basepoint_eg, 
            basepoint_ch: basepoint_ch.b,
            u, 
            y, 
            c 
        }
    }

    pub(crate) fn get_u(&self) -> RistrettoPoint {
        self.u
    }

    pub(crate) fn get_y(&self) -> Scalar {
        self.y
    }

    pub(crate) fn get_c(&self) -> Vec<u8> {
        self.c.clone()
    }

    /// Compressed representation of the γ bit-ciphertexts of an GenericFlagCiphertext.
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

    /// Decompress the inner bit-ciphertexts of this GenericFlagCiphertext.
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

/// This is the hash H from Fig.3 of the FMD paper, instantiated with SHA256.
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

/// This is the hash G from Fig.3 of the FMD paper, instantiated with SHA512.
fn hash_flag_ciphertexts(u: &RistrettoPoint, bit_ciphertexts: &[bool]) -> Scalar {
    let mut m_bytes = u.compress().to_bytes().to_vec();
    m_bytes.extend_from_slice(&GenericFlagCiphertexts::to_bytes(bit_ciphertexts));

    Scalar::hash_from_bytes::<Sha512>(&m_bytes)
}