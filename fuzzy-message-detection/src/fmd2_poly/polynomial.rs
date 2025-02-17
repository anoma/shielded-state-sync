use std::ops::{Add, Mul};

use curve25519_dalek::{RistrettoPoint, Scalar};
use sha2::Sha512;

// A degree `t` polynomial p(X) in Z_q[X] given by its t+1 coefficients.
pub(crate) struct Polynomial {
    coeffs: Vec<Scalar>,
}

// A degree t polynomial encoded in the exponent of a Ristretto point
// given by its t+1 points.
pub(crate) struct EncodedPolynomial {
    pub(crate) basepoint: RistrettoPoint,
    pub(crate) coeffs: Vec<RistrettoPoint>,
}

// γ scalar evaluations of the polynomial p(X) at public scalars.
// result[i] = p(public_scalar[i])
pub(crate) struct ScalarEvaluations {
    pub(crate) results: Vec<Scalar>,
}

// γ point evaluations of the polynomial p(X) at public scalars.
// result[i] = p(public_scalar[i]) * basepoint
#[derive(PartialEq, Debug)]
pub(crate) struct PointEvaluations {
    pub(crate) basepoint: RistrettoPoint,
    pub(crate) results: Vec<RistrettoPoint>,
}

impl Polynomial {
    pub(crate) fn random<R: rand_core::RngCore + rand_core::CryptoRng>(
        degree: usize,
        rng: &mut R,
    ) -> Polynomial {
        let coeffs: Vec<Scalar> = (0..degree + 1).map(|_| Scalar::random(rng)).collect();

        Polynomial { coeffs }
    }

    pub(crate) fn encode(&self, basepoint: &RistrettoPoint) -> EncodedPolynomial {
        let coeffs_encoded = encode_coefficients(&self.coeffs, basepoint);

        EncodedPolynomial {
            basepoint: *basepoint,
            coeffs: coeffs_encoded,
        }
    }

    // Basepoint determined by input bytes.
    pub(crate) fn encode_with_hashed_basepoint(&self, public_bytes: &[u8]) -> EncodedPolynomial {
        let basepoint = RistrettoPoint::hash_from_bytes::<Sha512>(public_bytes);

        self.encode(&basepoint)
    }

    pub(crate) fn evaluate(&self, public_scalars: &[Scalar]) -> ScalarEvaluations {
        ScalarEvaluations {
            results: evaluate_inner(public_scalars, &self.coeffs),
        }
    }
}

impl EncodedPolynomial {
    pub(crate) fn evaluate(&self, public_scalars: &[Scalar]) -> PointEvaluations {
        PointEvaluations {
            basepoint: self.basepoint,
            results: evaluate_inner(public_scalars, &self.coeffs),
        }
    }
}

impl ScalarEvaluations {
    pub(crate) fn encode(&self, basepoint: &RistrettoPoint) -> PointEvaluations {
        let coeffs_encoded = encode_coefficients(&self.results, basepoint);

        PointEvaluations {
            basepoint: *basepoint,
            results: coeffs_encoded,
        }
    }
}

pub(crate) fn encode_coefficients(
    coeffs: &[Scalar],
    basepoint: &RistrettoPoint,
) -> Vec<RistrettoPoint> {
    let coeffs_encoded: Vec<RistrettoPoint> = coeffs.iter().map(|c| *basepoint * c).collect();

    coeffs_encoded
}

fn evaluate_inner<E>(public_scalars: &[Scalar], coeffs: &[E]) -> Vec<E>
where
    E: Add<E, Output = E> + Mul<Scalar, Output = E> + Clone,
{
    let evaluations: Vec<E> = public_scalars
        .iter()
        .map(|scalar| {
            let mut res = coeffs[0].clone();
            let mut pow = Scalar::ONE;
            for coeff in coeffs.iter().skip(1) {
                pow *= scalar;
                res = res + coeff.clone() * pow;
            }

            res
        })
        .collect();

    evaluations
}
