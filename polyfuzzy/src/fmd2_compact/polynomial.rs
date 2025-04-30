use alloc::vec::Vec;

use curve25519_dalek::{RistrettoPoint, Scalar};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A degree `t` polynomial p(X) in Z_q[X] given by its t+1 coefficients.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub(crate) struct Polynomial {
    coeffs: Vec<Scalar>,
}

/// A degree t polynomial encoded in the exponent of a Ristretto point
/// given by its t+1 points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EncodedPolynomial {
    pub(crate) basepoint: RistrettoPoint,
    pub(crate) coeffs: Vec<RistrettoPoint>,
}

/// γ scalar evaluations of the polynomial p(X) at public scalars.
/// result[i] = p(public_scalar[i])
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ScalarEvaluations {
    pub(crate) results: Vec<Scalar>,
}

/// γ point evaluations of the polynomial p(X) at public scalars.
/// result[i] = p(public_scalar[i]) * basepoint
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PointEvaluations {
    pub(crate) basepoint: RistrettoPoint,
    pub(crate) results: Vec<RistrettoPoint>,
}

impl Polynomial {
    pub(crate) fn random<R: rand_core::RngCore + rand_core::CryptoRng>(
        degree: usize,
        rng: &mut R,
    ) -> Polynomial {
        Polynomial {
            coeffs: core::iter::repeat_with(|| Scalar::random(rng))
                .take(degree + 1)
                .collect(),
        }
    }

    pub(crate) fn encode(&self, basepoint: &RistrettoPoint) -> EncodedPolynomial {
        let coeffs_encoded = encode_coefficients(&self.coeffs, basepoint);

        EncodedPolynomial {
            basepoint: *basepoint,
            coeffs: coeffs_encoded,
        }
    }

    /// Basepoint determined by input bytes.
    /// The input bytes should be uniform to ensure the dlog generated point is unknown.
    pub(crate) fn encode_with_hashed_basepoint(
        &self,
        public_bytes: &[u8; 64],
    ) -> EncodedPolynomial {
        let basepoint = RistrettoPoint::from_uniform_bytes(public_bytes);

        self.encode(&basepoint)
    }

    pub(crate) fn evaluate(&self, public_scalars: &[Scalar]) -> ScalarEvaluations {
        let evaluations = public_scalars
            .iter()
            .map(|scalar| evaluate_scalar(scalar, &self.coeffs))
            .collect();

        ScalarEvaluations {
            results: evaluations,
        }
    }
}

fn evaluate_scalar<C>(public_scalar: &Scalar, coeffs: &[C]) -> C
where
    C: Clone + core::ops::AddAssign,
    for<'coeff> &'coeff C: core::ops::Mul<Scalar, Output = C>,
{
    let mut res = coeffs[0].clone();
    let mut pow = Scalar::ONE;

    for coeff in &coeffs[1..] {
        pow *= public_scalar;
        res += coeff * pow;
    }

    res
}

impl EncodedPolynomial {
    pub(crate) fn evaluate(&self, public_scalars: &[Scalar]) -> PointEvaluations {
        let evaluations = public_scalars
            .iter()
            .map(|scalar| evaluate_scalar(scalar, &self.coeffs))
            .collect();

        PointEvaluations {
            basepoint: self.basepoint,
            results: evaluations,
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
