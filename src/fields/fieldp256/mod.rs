use std::{
    cmp::Ordering,
    fmt::{self, Debug},
    io::{self, Read},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use anyhow::{Context, anyhow};
use subtle::ConstantTimeEq;

use crate::{
    Codec,
    fields::{
        FieldElement,
        fieldp256::ops::{
            fiat_p256_add, fiat_p256_from_bytes, fiat_p256_from_montgomery,
            fiat_p256_montgomery_domain_field_element, fiat_p256_mul,
            fiat_p256_non_montgomery_domain_field_element, fiat_p256_opp, fiat_p256_sub,
            fiat_p256_to_bytes, fiat_p256_to_montgomery,
        },
    },
};

/// FieldP256 is the field for the NIST P-256 elliptic curve.
///
/// Field elements are serialized in little-endian form, per [Section 7.2.1 of draft-google-cfrg-libzk-00][1].
///
/// [1]: https://www.ietf.org/archive/id/draft-google-cfrg-libzk-00.html#section-7.2.1
// The `fiat_p128_montgomery_domain_field_element` member must follow the invariant from fiat-crypto
// that its value must be "strictly less than the prime modulus (m)". We also rely on this invariant
// for comparison operations.
#[derive(Clone, Copy)]
pub struct FieldP256(fiat_p256_montgomery_domain_field_element);

impl FieldP256 {
    /// Bytes of the prime modulus, in little endian order.
    ///
    /// This is used to validate encoded field elements before passing them to fiat-crypto routines,
    /// because they have preconditions requiring that inputs are less than the modulus.
    const MODULUS_BYTES: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff,
        0xff, 0xff,
    ];

    /// Converts a field element to the non-Montgomery domain form.
    fn as_residue(&self) -> fiat_p256_non_montgomery_domain_field_element {
        let mut out = fiat_p256_non_montgomery_domain_field_element([0; 4]);
        fiat_p256_from_montgomery(&mut out, &self.0);
        out
    }

    /// Project a u128 integer into a field element.
    ///
    /// This duplicates `FieldElement::from_u128()` in order to provide a const function with the
    /// same functionality, since trait methods cannot be used in const contexts yet.
    #[inline]
    const fn from_u128_const(value: u128) -> Self {
        let mut out = fiat_p256_montgomery_domain_field_element([0; 4]);
        fiat_p256_to_montgomery(
            &mut out,
            &fiat_p256_non_montgomery_domain_field_element([
                value as u64,
                (value >> 64) as u64,
                0,
                0,
            ]),
        );
        Self(out)
    }
}

impl FieldElement for FieldP256 {
    const NUM_BITS: u32 = 256;
    const ZERO: Self = Self(fiat_p256_montgomery_domain_field_element([0; 4]));
    const ONE: Self = Self::from_u128_const(1);
    const TWO: Self = Self::from_u128_const(2);

    fn from_u128(value: u128) -> Self {
        Self::from_u128_const(value)
    }
}

impl Debug for FieldP256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let residue = self.as_residue();
        write!(
            f,
            "FieldP256(0x{:016x}{:016x}{:016x}{:016x})",
            residue.0[3], residue.0[2], residue.0[1], residue.0[0]
        )
    }
}

impl Default for FieldP256 {
    fn default() -> Self {
        Self::ZERO
    }
}

impl ConstantTimeEq for FieldP256 {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        // Since we ensure that the `fiat_p256_montgomery_domain_field_element` value is always less
        // than the prime modulus, and the Montgomery domain map is an isomorphism, we can directly
        // compare Montgomery domain values for equality without converting.
        self.0.0.ct_eq(&other.0.0)
    }
}

impl PartialEq for FieldP256 {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for FieldP256 {}

impl From<u64> for FieldP256 {
    fn from(value: u64) -> Self {
        let mut out = fiat_p256_montgomery_domain_field_element([0; 4]);
        fiat_p256_to_montgomery(
            &mut out,
            &fiat_p256_non_montgomery_domain_field_element([value, 0, 0, 0]),
        );
        Self(out)
    }
}

impl TryFrom<&[u8; 32]> for FieldP256 {
    type Error = anyhow::Error;

    fn try_from(value: &[u8; 32]) -> Result<Self, Self::Error> {
        if value.iter().rev().cmp(Self::MODULUS_BYTES.iter().rev()) != Ordering::Less {
            return Err(anyhow!(
                "serialized FieldP256 element is not less than the modulus"
            ));
        }
        let mut temp = fiat_p256_non_montgomery_domain_field_element([0; 4]);
        fiat_p256_from_bytes(&mut temp.0, value);
        let mut out = fiat_p256_montgomery_domain_field_element([0; 4]);
        fiat_p256_to_montgomery(&mut out, &temp);
        Ok(Self(out))
    }
}

impl TryFrom<&[u8]> for FieldP256 {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let array_reference = <&[u8; 32]>::try_from(value).context("failed to decode FieldP256")?;
        Self::try_from(array_reference)
    }
}

impl Codec for FieldP256 {
    fn decode(bytes: &mut io::Cursor<&[u8]>) -> Result<Self, anyhow::Error> {
        let mut buffer = [0u8; 32];
        bytes
            .read_exact(&mut buffer)
            .context("failed to read FieldP256 element")?;
        Self::try_from(&buffer)
    }

    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        let mut non_montgomery = fiat_p256_non_montgomery_domain_field_element([0; 4]);
        fiat_p256_from_montgomery(&mut non_montgomery, &self.0);
        let mut out = [0u8; 32];
        fiat_p256_to_bytes(&mut out, &non_montgomery.0);
        bytes.extend_from_slice(&out);
        Ok(())
    }
}

impl Add<&Self> for FieldP256 {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        let mut out = fiat_p256_montgomery_domain_field_element([0; 4]);
        fiat_p256_add(&mut out, &self.0, &rhs.0);
        Self(out)
    }
}

impl Add for FieldP256 {
    type Output = Self;

    #[allow(clippy::op_ref)]
    fn add(self, rhs: Self) -> Self::Output {
        self + &rhs
    }
}

impl AddAssign for FieldP256 {
    fn add_assign(&mut self, rhs: Self) {
        let copy = *self;
        fiat_p256_add(&mut self.0, &copy.0, &rhs.0);
    }
}

impl Sub<&Self> for FieldP256 {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        let mut out = fiat_p256_montgomery_domain_field_element([0; 4]);
        fiat_p256_sub(&mut out, &self.0, &rhs.0);
        Self(out)
    }
}

impl Sub for FieldP256 {
    type Output = Self;

    #[allow(clippy::op_ref)]
    fn sub(self, rhs: Self) -> Self::Output {
        self - &rhs
    }
}

impl SubAssign for FieldP256 {
    fn sub_assign(&mut self, rhs: Self) {
        let copy = *self;
        fiat_p256_sub(&mut self.0, &copy.0, &rhs.0);
    }
}

impl Mul<&Self> for FieldP256 {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        let mut out = fiat_p256_montgomery_domain_field_element([0; 4]);
        fiat_p256_mul(&mut out, &self.0, &rhs.0);
        Self(out)
    }
}

impl Mul<Self> for FieldP256 {
    type Output = Self;

    #[allow(clippy::op_ref)]
    fn mul(self, rhs: Self) -> Self::Output {
        self * &rhs
    }
}

impl MulAssign for FieldP256 {
    fn mul_assign(&mut self, rhs: Self) {
        let copy = *self;
        fiat_p256_mul(&mut self.0, &copy.0, &rhs.0)
    }
}

impl Neg for FieldP256 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let mut out = fiat_p256_montgomery_domain_field_element([0; 4]);
        fiat_p256_opp(&mut out, &self.0);
        Self(out)
    }
}

#[allow(unused, clippy::unnecessary_cast, clippy::needless_lifetimes)]
#[rustfmt::skip]
mod ops;

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::{
        Codec,
        fields::{FieldElement, fieldp256::FieldP256},
    };

    #[test]
    fn modulus_bytes_correct() {
        let mut p_minus_one_bytes = FieldP256::MODULUS_BYTES;
        p_minus_one_bytes[0] -= 1;
        let p_minus_one = FieldP256::decode(&mut Cursor::new(&p_minus_one_bytes)).unwrap();
        assert_eq!(p_minus_one + FieldP256::ONE, FieldP256::ZERO);
    }
}
