use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256, Sha512};

#[derive(Debug, Clone)]
pub struct SecretKey {
    pub gamma: usize,
    pub keys: Vec<Scalar>,
}

#[derive(Debug, Clone)]
pub struct PublicKey {
    pub keys: Vec<RistrettoPoint>,
}

#[derive(Debug, Clone)]
pub struct DetectionKey {
    pub indices: Vec<usize>,
    pub keys: Vec<Scalar>,
}

impl SecretKey {
    pub fn generate_keys<R: RngCore + CryptoRng>(gamma: usize, rng: &mut R) -> Self {
        let keys = (0..gamma).map(|_| Scalar::random(rng)).collect();

        Self { gamma, keys }
    }

    pub fn extract(&self, indices: &[usize]) -> DetectionKey {
        for &i in indices {
            if i >= self.keys.len() {
                panic!("Index out of bounds");
            }
        }
        let keys = indices.iter().map(|&i| self.keys[i]).collect();
        DetectionKey {
            indices: indices.to_vec(),
            keys,
        }
    }

    pub fn generate_public_key(&self) -> PublicKey {
        let keys = self
            .keys
            .iter()
            .map(|k| k * &RISTRETTO_BASEPOINT_POINT)
            .collect();
        PublicKey { keys }
    }
}

#[derive(Debug, Clone)]
pub struct FlagCiphertext {
    pub u: RistrettoPoint,
    pub y: Scalar,
    pub c: Vec<u8>,
}

impl FlagCiphertext {
    pub fn generate_flag<R: RngCore + CryptoRng>(pk: &PublicKey, rng: &mut R) -> Self {
        let r = Scalar::random(rng);
        let z = Scalar::random(rng);
        let u = RISTRETTO_BASEPOINT_POINT * &r;
        let w = RISTRETTO_BASEPOINT_POINT * &z;

        let c: Vec<u8> = pk
            .keys
            .iter()
            .map(|k| {
                let mut hasher = Sha256::new();
                hasher.update(u.compress().to_bytes());
                hasher.update((k * &r).compress().to_bytes());
                hasher.update(w.compress().to_bytes());
                let k_i = hasher.finalize().as_slice()[0] & 1u8;
                k_i ^ 1u8
            })
            .collect();

        let mut m_bytes = u.compress().to_bytes().to_vec();
        m_bytes.extend_from_slice(&c);
        let m = Scalar::hash_from_bytes::<Sha512>(&m_bytes);

        let r_inv = r.invert();
        let y = (z - m) * r_inv;

        Self { u, y, c }
    }
}

pub fn flag_test(dsk: &DetectionKey, flag_cipher: &FlagCiphertext) -> bool {
    let mut m_bytes = flag_cipher.u.compress().to_bytes().to_vec();
    m_bytes.extend_from_slice(&flag_cipher.c);
    let m = Scalar::hash_from_bytes::<Sha512>(&m_bytes);

    let w = RISTRETTO_BASEPOINT_POINT * &m + flag_cipher.u * &flag_cipher.y;

    for (xi, ci) in dsk.keys.iter().zip(flag_cipher.c.iter()) {
        let mut hasher = Sha256::new();
        hasher.update(flag_cipher.u.compress().to_bytes());
        hasher.update((flag_cipher.u * xi).compress().to_bytes());
        hasher.update(w.compress().to_bytes());
        let k_i = hasher.finalize().as_slice()[0] & 1u8;
        if k_i == *ci {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flag_test() {
        let mut csprng = rand_core::OsRng;

        let gamma = 5;
        let sk = SecretKey::generate_keys(gamma, &mut csprng);
        let pk = sk.generate_public_key();
        let flag = FlagCiphertext::generate_flag(&pk, &mut csprng);
        let dk = sk.extract(&(0..gamma).collect::<Vec<_>>());
        assert!(flag_test(&dk, &flag));
    }

    #[test]
    fn test_flag_test_with_partial_detection_key() {
        let mut csprng = rand_core::OsRng;

        let gamma = 5;
        let sk = SecretKey::generate_keys(gamma, &mut csprng);
        let pk = sk.generate_public_key();
        let flag = FlagCiphertext::generate_flag(&pk, &mut csprng);
        let dk = sk.extract(&[0, 2, 4]);
        assert!(flag_test(&dk, &flag));
    }
}
