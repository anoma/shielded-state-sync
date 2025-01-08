use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256, Sha512};

use crate::{CcaSecure, FmdScheme, RestrictedRateSet};




#[derive(Debug, Clone)]
pub struct SecretKey(Vec<Scalar>);

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
        
        // If number of indices is larger than the γ parameter.
        if indices.len() > self.0.len() { return None } 
            
        let keys = indices.iter().map(|&i| self.0[i]).collect();
        
        Some(
            DetectionKey {
            indices: indices.to_vec(),
            keys,
            }
        )
    }

    fn generate_public_key(&self) -> PublicKey {
        let keys = self.0
            .iter()
            .map(|k| k * &RISTRETTO_BASEPOINT_POINT)
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

/// The FMD2 scheme specified in Figure 3 of the [FMD paper](https://eprint.iacr.org/2021/089).
pub struct Fmd2;

impl FmdScheme for Fmd2 {
    
    type PublicKey=PublicKey;

    type SecretKey=SecretKey;

    type DetectionKey=DetectionKey;

    type FlagCiphertexts=FlagCiphertexts;

    fn generate_keys<R: RngCore + CryptoRng>(rates: &RestrictedRateSet, rng: &mut R) -> (Self::PublicKey,Self::SecretKey) {
        let gamma = rates.gamma();
        
        // Secret key.
        let sk = SecretKey::generate_keys(gamma, rng);

        // Public key.
        let pk = sk.generate_public_key();

        (pk,sk)
    }

    fn flag<R: RngCore + CryptoRng>(pk:&Self::PublicKey, rng: &mut R) -> Self::FlagCiphertexts {
        FlagCiphertexts::generate_flag(pk, rng)
    }

    fn extract(sk: &Self::SecretKey, indices: &[usize]) -> Option<Self::DetectionKey> {
        sk.extract(indices)
    }

    fn test(dsk: &Self::DetectionKey, flag_ciphers: &Self::FlagCiphertexts) -> bool {
        let mut m_bytes = flag_ciphers.u.compress().to_bytes().to_vec();
    m_bytes.extend_from_slice(&flag_ciphers.c);
    let m = Scalar::hash_from_bytes::<Sha512>(&m_bytes);

    let w = RISTRETTO_BASEPOINT_POINT * &m + flag_ciphers.u * &flag_ciphers.y;

    for (xi, index) in dsk.keys.iter().zip(dsk.indices.iter()) {
        let mut hasher = Sha256::new();
        hasher.update(flag_ciphers.u.compress().to_bytes());
        hasher.update((flag_ciphers.u * xi).compress().to_bytes());
        hasher.update(w.compress().to_bytes());
        let k_i = hasher.finalize().as_slice()[0] & 1u8;
        if k_i == flag_ciphers.c[*index] {
            return false;
        }
    }

    true    
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
        let (pk,sk) = <Fmd2 as FmdScheme>::generate_keys(&rates, &mut csprng);
        let flag_cipher = <Fmd2 as FmdScheme>::flag(&pk, &mut csprng);
        let dk = <Fmd2 as FmdScheme>::extract(&sk,&(0..rates.gamma()).collect::<Vec<_>>());
        assert!(<Fmd2 as FmdScheme>::test(&dk.unwrap(), &flag_cipher));
    }

    #[test]
    fn test_flag_test_with_partial_detection_key() {
        let mut csprng = rand_core::OsRng;

        let rates = RestrictedRateSet::new(5);
        let (pk,sk) = <Fmd2 as FmdScheme>::generate_keys(&rates, &mut csprng);
        for _i in 0..10 {
            let flag_cipher = <Fmd2 as FmdScheme>::flag(&pk, &mut csprng);
            let dk = <Fmd2 as FmdScheme>::extract(&sk,&(0..rates.gamma()).collect::<Vec<_>>());
            assert!(<Fmd2 as FmdScheme>::test(&dk.unwrap(), &flag_cipher));
        }
    }
}
