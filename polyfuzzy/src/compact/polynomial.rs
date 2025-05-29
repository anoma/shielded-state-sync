use alloc::vec::Vec;
use core::ops::{Add, Mul};

use curve25519_dalek::{traits::MultiscalarMul, RistrettoPoint, Scalar};

use crate::structs::{CompactPublicKey, CompactSecretKey};

/// A point in Z_q^{m} given by its m coordinates.
pub(crate) struct Point {
    coords: Vec<Scalar>,
}

impl From<&CompactSecretKey> for Point {
    fn from(value: &CompactSecretKey) -> Self {
        Point {
            coords: value.scalars(),
        }
    }
}

/// A multilinear polynomial in Z_q[[X_1,....,X_m]] given by its m coefficients.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Default)]
pub(crate) struct Polynomial {
    coeffs: Vec<Scalar>,
}

impl Polynomial {
    /// Returns `gamma` multilinear polynomials on `m` indeterminates.
    /// Every subset of `m` polynomials are linearly independent.
    pub(crate) fn linear_independent_polynomials(m: usize, gamma: usize) -> Vec<Polynomial> {
        let him = hyper_invertible_matrix(gamma, m);
        let mut vec_h = Vec::new();
        for column in him {
            vec_h.push(Polynomial { coeffs: column });
        }

        vec_h
    }

    /// Evaluates the polynomial at `point`.
    /// Errors if mismatch in coefficients and coordinates lengths.
    pub(crate) fn evaluate(&self, point: &Point) -> Scalar {
        assert!(self.coeffs.len() == point.coords.len());

        let mut res = Scalar::ZERO;
        for (coeff, var) in self.coeffs.iter().zip(point.coords.iter()) {
            res += coeff * var;
        }

        res
    }

    /// Evaluate the polynomial at `encoded_point` in the exponent.
    /// Errors if mismatch in coefficients and coordinates lengths.
    pub(crate) fn evaluate_in_the_exponent(&self, encoded_point: &EncodedPoint) -> RistrettoPoint {
        assert!(self.coeffs.len() == encoded_point.coords.len());

        RistrettoPoint::multiscalar_mul(&self.coeffs, &encoded_point.coords)
    }
}

impl Add for Polynomial {
    type Output = Polynomial;

    fn add(self, rhs: Self) -> Self::Output {
        let mut res_coeffs = Vec::new();
        for (lhs, rhs) in self.coeffs.iter().zip(rhs.coeffs) {
            res_coeffs.push(lhs + rhs);
        }
        Polynomial { coeffs: res_coeffs }
    }
}

impl Mul<Scalar> for Polynomial {
    type Output = Polynomial;

    fn mul(self, rhs: Scalar) -> Self::Output {
        let mut res_coeffs = Vec::new();
        for coeff in self.coeffs {
            res_coeffs.push(rhs * coeff);
        }
        Polynomial { coeffs: res_coeffs }
    }
}

/// A point in Z_q^m  encoded in the exponent. Given by its
/// m point coordinates and the basepoint.
#[derive(Debug, Clone)]
pub(crate) struct EncodedPoint {
    pub(crate) coords: Vec<RistrettoPoint>,
}

impl From<&CompactPublicKey> for EncodedPoint {
    fn from(value: &CompactPublicKey) -> Self {
        EncodedPoint {
            coords: value.pk.points_h.clone(),
        }
    }
}

/// Returns a column-vector matrix.
/// The hyper invertible matrix from BH08, Construction 1.
/// See https://www.iacr.org/archive/tcc2008/49480207/49480207.pdf
/// Assume size of field > `num_rows` + `num_columns`
fn hyper_invertible_matrix(num_rows: usize, num_columns: usize) -> Vec<Vec<Scalar>> {
    let mut alpha = Vec::new();
    let mut beta = Vec::new();

    let mut v = Scalar::ZERO;
    for i in 0..num_rows + num_columns {
        v += Scalar::ONE;
        if i < num_rows {
            alpha.push(v);
        } else {
            beta.push(v);
        }
    }

    let mut matrix = Vec::new();
    for j in 0..num_columns {
        let mut column_j = Vec::new();
        let mut lambda_ij = Scalar::ONE;
        for i in 0..num_rows {
            for k in 0..num_columns {
                if k != j {
                    lambda_ij *= (beta[i] - alpha[k]) * (alpha[j] - alpha[k]).invert();
                }
            }
            column_j.push(lambda_ij);
        }
        matrix.push(column_j);
    }

    matrix
}
