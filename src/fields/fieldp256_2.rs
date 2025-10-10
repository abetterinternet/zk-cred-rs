use std::{
    fmt::{self, Debug},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use subtle::ConstantTimeEq;

use crate::fields::{FieldElement, QuadraticExtension, fieldp256::FieldP256};

/// The quadratic extension of the P-256 base field.
///
/// This is defined as F_p256\[x\]/(x^2 + 1).
#[derive(Clone, Copy, Default)]
pub struct FieldP256_2(pub(super) QuadraticExtension<FieldP256>);

impl FieldElement for FieldP256_2 {
    const ZERO: Self = Self(QuadraticExtension::<FieldP256>::ZERO);

    const ONE: Self = Self(QuadraticExtension::<FieldP256>::ONE);

    const TWO: Self = Self(QuadraticExtension::<FieldP256>::TWO);

    fn from_u128(value: u128) -> Self {
        Self(QuadraticExtension::<FieldP256>::from_u128(value))
    }
}

impl Debug for FieldP256_2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl ConstantTimeEq for FieldP256_2 {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for FieldP256_2 {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for FieldP256_2 {}

impl From<u64> for FieldP256_2 {
    fn from(value: u64) -> Self {
        Self(QuadraticExtension::from(value))
    }
}

impl Add for FieldP256_2 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Add<&Self> for FieldP256_2 {
    type Output = Self;

    #[allow(clippy::op_ref)]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0 + &rhs.0)
    }
}

impl AddAssign for FieldP256_2 {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl Sub for FieldP256_2 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl Sub<&Self> for FieldP256_2 {
    type Output = Self;

    #[allow(clippy::op_ref)]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0 - &rhs.0)
    }
}

impl SubAssign for FieldP256_2 {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

impl Mul for FieldP256_2 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl Mul<&Self> for FieldP256_2 {
    type Output = Self;

    #[allow(clippy::op_ref)]
    fn mul(self, rhs: &Self) -> Self::Output {
        Self(self.0 * &rhs.0)
    }
}

impl MulAssign for FieldP256_2 {
    fn mul_assign(&mut self, rhs: Self) {
        self.0 *= rhs.0;
    }
}

impl Neg for FieldP256_2 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(-self.0)
    }
}
