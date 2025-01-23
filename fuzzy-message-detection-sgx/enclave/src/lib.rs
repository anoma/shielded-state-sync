// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

#![cfg_attr(not(target_vendor = "teaclave"), no_std)]
#![cfg_attr(target_vendor = "teaclave", feature(rustc_private))]

#[cfg(not(target_vendor = "teaclave"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_types;

use sgx_types::error::SgxStatus;
use std::io::{self, Write};
use std::slice;
use std::string::String;
use std::vec::Vec;

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use rand_chacha::ChaCha8Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use sha3::{Digest, Sha3_256, Sha3_512};

const NUM_REPETITIONS: usize = 1 << 20;


#[derive(Debug, Clone)]
pub struct DetectionKey {
    indices: Vec<usize>,
    keys: Vec<Scalar>,
}

#[derive(Debug, Clone)]
pub struct FlagCiphertexts {
    u: RistrettoPoint,
    y: Scalar,
    c: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SecretKey(Vec<Scalar>);

#[derive(Debug, Clone)]
pub struct PublicKey {
    keys: Vec<RistrettoPoint>,
}

pub struct RestrictedRateSet(usize);

impl RestrictedRateSet {
    pub fn new(gamma: usize) -> Self {
        Self(gamma)
    }

    /// Returns the γ parameter
    pub fn gamma(&self) -> usize {
        self.0
    }
}

impl SecretKey {
    fn generate_keys<R: RngCore + CryptoRng>(gamma: usize, rng: &mut R) -> Self {
        let keys = (0..gamma).map(|_| Scalar::random(rng)).collect();

        Self(keys)
    }

    fn extract(&self, indices: &[usize]) -> Option<DetectionKey> {
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

impl FlagCiphertexts {
    fn generate_flag<R: RngCore + CryptoRng>(pk: &PublicKey, rng: &mut R) -> Self {
        let r = Scalar::random(rng);
        let z = Scalar::random(rng);
        let u = RISTRETTO_BASEPOINT_POINT * r;
        let w = RISTRETTO_BASEPOINT_POINT * z;

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
        let y = (z - m) * r_inv;

        let c = FlagCiphertexts::to_bytes(&bit_ciphertexts);

        Self { u, y, c }
    }

    /// Compressed representation of the γ bit-ciphertexts of a FlagCiphertext.
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

    /// Decompress the inner bit-ciphertexts of this FlagCiphertext.
    fn to_bits(&self) -> Vec<bool> {
        let mut bit_ciphertexts: Vec<bool> = Vec::new();
        for byte in self.c.iter() {
            for i in 0..8 {
                bit_ciphertexts.push(1u8 == byte >> i & 1u8);
            }
        }

        bit_ciphertexts
    }
}

fn hash_to_flag_ciphertext_bit(
    u: &RistrettoPoint,
    ddh_mask: &RistrettoPoint,
    w: &RistrettoPoint,
) -> bool {
    let mut hasher = Sha3_256::new();

    hasher.update(u.compress().to_bytes());
    hasher.update(ddh_mask.compress().to_bytes());
    hasher.update(w.compress().to_bytes());

    let k_i_byte = hasher.finalize().as_slice()[0] & 1u8;

    k_i_byte == 1u8
}

fn hash_flag_ciphertexts(u: &RistrettoPoint, bit_ciphertexts: &[bool]) -> Scalar {
    let mut m_bytes = u.compress().to_bytes().to_vec();
    let flag_bytes: Vec<u8> = bit_ciphertexts
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
    m_bytes.extend_from_slice(&flag_bytes);

    Scalar::hash_from_bytes::<Sha3_512>(&m_bytes)
}

fn generate_keys<R: RngCore + CryptoRng>(
    rates: &RestrictedRateSet,
    rng: &mut R,
) -> (PublicKey, SecretKey) {
    let gamma = rates.gamma();

    // Secret key.
    let sk = SecretKey::generate_keys(gamma, rng);

    // Public key.
    let pk = sk.generate_public_key();

    (pk, sk)
}

fn flag<R: RngCore + CryptoRng>(pk: &PublicKey, rng: &mut R) -> FlagCiphertexts {
    FlagCiphertexts::generate_flag(pk, rng)
}

fn extract(sk: &SecretKey, indices: &[usize]) -> Option<DetectionKey> {
    sk.extract(indices)
}

fn detect(dsk: &DetectionKey, flag_ciphers: &FlagCiphertexts) -> bool {
    let u = flag_ciphers.u;
    let bit_ciphertexts = flag_ciphers.to_bits();
    let m = hash_flag_ciphertexts(&u, &bit_ciphertexts);
    let w = RISTRETTO_BASEPOINT_POINT * m + flag_ciphers.u * flag_ciphers.y;
    let mut success = true;
    for (xi, index) in dsk.keys.iter().zip(dsk.indices.iter()) {
        let k_i = hash_to_flag_ciphertext_bit(&u, &(u * xi), &w);
        success = success && k_i != bit_ciphertexts[*index]
    }

    success
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn say_something(some_string: *const u8, some_len: usize) -> SgxStatus {
    let str_slice = slice::from_raw_parts(some_string, some_len);
    let _ = io::stdout().write(str_slice);

    // A sample &'static string
    let rust_raw_string = "This is a in-Enclave ";
    // An array
    let word: [u8; 4] = [82, 117, 115, 116];
    // An vector
    let word_vec: Vec<u8> = vec![32, 115, 116, 114, 105, 110, 103, 33];

    // Construct a string from &'static string
    let mut hello_string = String::from(rust_raw_string);

    // Iterate on word array
    for c in word.iter() {
        hello_string.push(*c as char);
    }

    // Rust style convertion
    hello_string += String::from_utf8(word_vec).expect("Invalid UTF-8").as_str();

    // Ocall to normal world for output
    println!("{}", &hello_string);

    let mut csprng = ChaCha8Rng::seed_from_u64(42);

    let rates = RestrictedRateSet::new(5);
    let (pk, sk) = generate_keys(&rates, &mut csprng);
    let flag_cipher = flag(&pk, &mut csprng);
    let dk = extract(&sk, &[0, 2, 4]);

    assert!(detect(&dk.unwrap(), &flag_cipher));

    let start = std::time::Instant::now();
    for _ in 0..NUM_VERIFY_REPETITIONS {
        detect(&dk.unwrap(), &flag_cipher);
    }

    println!(
        "detect time: {} ns",
        start.elapsed().as_nanos() / NUM_VERIFY_REPETITIONS as u128
    );

    SgxStatus::Success
}
