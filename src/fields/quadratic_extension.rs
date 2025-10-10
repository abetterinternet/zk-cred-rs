use std::{
    fmt::{self, Debug},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use subtle::ConstantTimeEq;

use crate::fields::FieldElement;

/// The quadratic extension of another base field.
///
/// This is defined as F\[x\]/(x^2 + 1), where F is the base field. Thus, it can only be safely used
/// with base fields in which x^2 + 1 is irreducible. Therefore this generic type is private, and we
/// only expose quadratic extensions of specific fields, where this construction is well-defined.
#[derive(Clone, Copy, Default)]
pub(super) struct QuadraticExtension<B> {
    real: B,
    imag: B,
}

impl<B: FieldElement> FieldElement for QuadraticExtension<B> {
    const ZERO: Self = Self {
        real: B::ZERO,
        imag: B::ZERO,
    };

    const ONE: Self = Self {
        real: B::ONE,
        imag: B::ZERO,
    };

    const TWO: Self = Self {
        real: B::TWO,
        imag: B::ZERO,
    };

    fn from_u128(value: u128) -> Self {
        Self {
            real: B::from_u128(value),
            imag: B::ZERO,
        }
    }
}

impl<B: Debug> Debug for QuadraticExtension<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("")
            .field(&self.real)
            .field(&self.imag)
            .finish()
    }
}

impl<B: ConstantTimeEq> ConstantTimeEq for QuadraticExtension<B> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.real.ct_eq(&other.real) & self.imag.ct_eq(&other.imag)
    }
}

impl<B: ConstantTimeEq> PartialEq for QuadraticExtension<B> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<B: ConstantTimeEq> Eq for QuadraticExtension<B> {}

impl<B: FieldElement> From<u64> for QuadraticExtension<B> {
    fn from(value: u64) -> Self {
        Self {
            real: B::from(value),
            imag: B::ZERO,
        }
    }
}

impl<B: Add<Output = B>> Add for QuadraticExtension<B> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            real: self.real + rhs.real,
            imag: self.imag + rhs.imag,
        }
    }
}

impl<'a, B: Add<&'a B, Output = B>> Add<&'a Self> for QuadraticExtension<B> {
    type Output = Self;

    fn add(self, rhs: &'a Self) -> Self::Output {
        Self {
            real: self.real + &rhs.real,
            imag: self.imag + &rhs.imag,
        }
    }
}

impl<B: AddAssign> AddAssign for QuadraticExtension<B> {
    fn add_assign(&mut self, rhs: Self) {
        self.real += rhs.real;
        self.imag += rhs.imag;
    }
}

impl<B: Sub<Output = B>> Sub for QuadraticExtension<B> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self {
            real: self.real - rhs.real,
            imag: self.imag - rhs.imag,
        }
    }
}

impl<'a, B: Sub<&'a B, Output = B>> Sub<&'a Self> for QuadraticExtension<B> {
    type Output = Self;

    fn sub(self, rhs: &'a Self) -> Self::Output {
        Self {
            real: self.real - &rhs.real,
            imag: self.imag - &rhs.imag,
        }
    }
}

impl<B: SubAssign> SubAssign for QuadraticExtension<B> {
    fn sub_assign(&mut self, rhs: Self) {
        self.real -= rhs.real;
        self.imag -= rhs.imag;
    }
}

impl<B: FieldElement> Mul for QuadraticExtension<B> {
    type Output = Self;

    #[allow(clippy::op_ref)]
    fn mul(self, rhs: Self) -> Self::Output {
        self * &rhs
    }
}

impl<B: FieldElement> Mul<&Self> for QuadraticExtension<B> {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        // We use Karatsuba multiplication to implement this operation.
        //
        // Let self = p(x) = (a + bx) and rhs = q(x) = (c + dx).
        // We want to compute r(x) = p(x) * q(x), and then reduce that by x^2 + 1.
        // Decompose the polynomials into p(x) = p1(x) + x * p2(x), and
        // q(x) = q1(x) + x * q2(x).
        // Thus we have the constant functions p1(x) = a, p2(x) = b, q1(x) = c,
        // and q2(x) = d.
        // We perform two multiplications to get the following:
        // r1(x) = p1(x) * q1(x) = ac
        // r4(x) = p2(x) * q2(x) = bd
        // Add to get p'(x) = p1(x) + p2(x) = a + b and
        // q'(x) = q1(x) + q2(x) = c + d.
        // Perform a third multiplication to get
        // s(x) = p'(x) * q'(x) = (a + b) * (c + d).
        // Subtract twice to get t(x) = s(x) - r1(x) - r4(x).
        // Then t(x) = (a + b) * (c + d) - ac - bd.
        // Expanding this, we get
        // t(x) = ac + ad + bc + bd - ac - bd = ad + bc.
        // The final result is given by r(x) = r1(x) + x * t(x) + x^2 * r4(x).
        // This results in r(x) = ac + adx + bcx + bdx^2, which matches what we
        // would get from directly expanding r(x) = p(x) * q(x).
        // This method allows us to only perform three multiplications in the
        // base field, while performing more additions and subtractions in the
        // base field, which is a worthwhile tradeoff.
        //
        // Next, we need to reduce modulo x^2 + 1.
        // r(x) = r1(x) + x * t(x) + x^2 * r4(x) - (x^2 + 1) * r4(x) (mod x^2 + 1)
        // r(x) = r1(x) - r4(x) + x * t(x) (mod x^2 + 1)

        let r1 = self.real * rhs.real;
        let r4 = self.imag * rhs.imag;
        let p_prime = self.real + self.imag;
        let q_prime = rhs.real + rhs.imag;
        let s = p_prime * q_prime;
        let t = s - r1 - r4;
        Self {
            real: r1 - r4,
            imag: t,
        }
    }
}

impl<B: FieldElement> MulAssign for QuadraticExtension<B> {
    fn mul_assign(&mut self, rhs: Self) {
        let r1 = self.real * rhs.real;
        let r4 = self.imag * rhs.imag;
        let p_prime = self.real + self.imag;
        let q_prime = rhs.real + rhs.imag;
        let s = p_prime * q_prime;
        let t = s - r1 - r4;
        self.real = r1 - r4;
        self.imag = t;
    }
}

impl<B: Neg<Output = B>> Neg for QuadraticExtension<B> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            real: -self.real,
            imag: -self.imag,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::fields::{
        FieldElement, fieldp128::FieldP128, fieldp256::FieldP256, fieldp256_2::FieldP256_2,
        quadratic_extension::QuadraticExtension,
    };

    #[test]
    fn test_debug() {
        assert_eq!(
            format!(
                "{:?}",
                QuadraticExtension {
                    real: FieldP128::from(7),
                    imag: FieldP128::from(4)
                }
            ),
            "(FieldP128(7), FieldP128(4))"
        );
    }

    #[test]
    fn test_extension_field() {
        let x = FieldP256_2(QuadraticExtension {
            real: FieldP256::ZERO,
            imag: FieldP256::ONE,
        });
        assert_ne!(x, FieldP256_2::ZERO);
        assert_ne!(x, FieldP256_2::ONE);
        let neg_1 = -FieldP256_2::ONE;
        assert_eq!(neg_1 * x + x, FieldP256_2::ZERO);
        let x_plus_one = x + FieldP256_2::ONE;
        assert_eq!(x_plus_one * x_plus_one, x + x);
        assert_eq!(
            (FieldP256_2::from(3) + FieldP256_2::from(7) * x)
                * (FieldP256_2::from(2) + FieldP256_2::from(11) * x),
            -FieldP256_2::from(71) + FieldP256_2::from(47) * x
        );
    }
}
