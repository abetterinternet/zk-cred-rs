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
        fieldp128::ops::{
            fiat_p128_add, fiat_p128_from_bytes, fiat_p128_from_montgomery,
            fiat_p128_montgomery_domain_field_element, fiat_p128_mul,
            fiat_p128_non_montgomery_domain_field_element, fiat_p128_opp, fiat_p128_sub,
            fiat_p128_to_bytes, fiat_p128_to_montgomery,
        },
    },
};

/// FieldP128 is the field with modulus 2^128 - 2^108 + 1, described in [Section 7.2 of
/// draft-google-cfrg-libzk-00][1]. The field does not get a name in the draft, but P128 comes from
/// the longfellow implementation ([3]).
///
/// Field elements are serialized in little-endian form, per [Section 7.2.1 of draft-google-cfrg-libzk-00][2].
///
/// [1]: https://www.ietf.org/archive/id/draft-google-cfrg-libzk-00.html#section-7.2
/// [2]: https://www.ietf.org/archive/id/draft-google-cfrg-libzk-00.html#section-7.2.1
/// [3]: https://github.com/google/longfellow-zk/blob/main/lib/algebra/fp_p128.h
// The `fiat_p128_montgomery_domain_field_element` member must follow the invariant from fiat-crypto
// that its value must be "strictly less than the prime modulus (m)". We also rely on this invariant
// for comparison operations.
#[derive(Clone, Copy)]
pub struct FieldP128(fiat_p128_montgomery_domain_field_element);

impl FieldP128 {
    /// The prime modulus as an integer.
    const MODULUS: u128 = 0xfffff000000000000000000000000001;

    /// Bytes of the prime modulus, in little endian order.
    ///
    /// This is used to validate encoded field elements before passing them to fiat-crypto routines,
    /// because they have preconditions requiring that inputs are less than the modulus.
    const MODULUS_BYTES: [u8; 16] = [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff,
        0xff,
    ];

    /// Converts a field element to the non-Montgomery domain form.
    fn as_residue(&self) -> fiat_p128_non_montgomery_domain_field_element {
        let mut out = fiat_p128_non_montgomery_domain_field_element([0; 2]);
        fiat_p128_from_montgomery(&mut out, &self.0);
        out
    }

    /// Project a u128 integer into a field element.
    ///
    /// This duplicates `FieldElement::from_u128()` in order to provide a const function with the
    /// same functionality, since trait methods cannot be used in const contexts yet.
    #[inline]
    const fn from_u128_const(value: u128) -> Self {
        let mut out = fiat_p128_montgomery_domain_field_element([0; 2]);
        let reduced = value % Self::MODULUS;
        fiat_p128_to_montgomery(
            &mut out,
            &fiat_p128_non_montgomery_domain_field_element([
                reduced as u64,
                (reduced >> 64) as u64,
            ]),
        );
        Self(out)
    }
}

impl FieldElement for FieldP128 {
    const NUM_BITS: u32 = 128;
    const ZERO: Self = Self(fiat_p128_montgomery_domain_field_element([0; 2]));
    const ONE: Self = Self::from_u128_const(1);
    const TWO: Self = Self::from_u128_const(2);

    fn from_u128(value: u128) -> Self {
        Self::from_u128_const(value)
    }
}

impl Debug for FieldP128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let residue = self.as_residue();
        let value = residue.0[0] as u128 | ((residue.0[1] as u128) << 64);
        write!(f, "FieldP128({value})")
    }
}

impl Default for FieldP128 {
    fn default() -> Self {
        Self::ZERO
    }
}

impl ConstantTimeEq for FieldP128 {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        // Since we ensure that the `fiat_p128_montgomery_domain_field_element` value is always less
        // than the prime modulus, and the Montgomery domain map is an isomorphism, we can directly
        // compare Montgomery domain values for equality without converting.
        self.0.0.ct_eq(&other.0.0)
    }
}

impl PartialEq for FieldP128 {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for FieldP128 {}

impl From<u64> for FieldP128 {
    fn from(value: u64) -> Self {
        let mut out = fiat_p128_montgomery_domain_field_element([0; 2]);
        fiat_p128_to_montgomery(
            &mut out,
            &fiat_p128_non_montgomery_domain_field_element([value, 0]),
        );
        Self(out)
    }
}

impl TryFrom<&[u8; 16]> for FieldP128 {
    type Error = anyhow::Error;

    fn try_from(value: &[u8; 16]) -> Result<Self, Self::Error> {
        if value.iter().rev().cmp(Self::MODULUS_BYTES.iter().rev()) != Ordering::Less {
            return Err(anyhow!(
                "serialized FieldP128 element is not less than the modulus"
            ));
        }
        let mut temp = fiat_p128_non_montgomery_domain_field_element([0; 2]);
        fiat_p128_from_bytes(&mut temp.0, value);
        let mut out = fiat_p128_montgomery_domain_field_element([0; 2]);
        fiat_p128_to_montgomery(&mut out, &temp);
        Ok(Self(out))
    }
}

impl TryFrom<&[u8]> for FieldP128 {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let array_reference = <&[u8; 16]>::try_from(value).context("failed to decode FieldP128")?;
        Self::try_from(array_reference)
    }
}

impl Codec for FieldP128 {
    fn decode(bytes: &mut io::Cursor<&[u8]>) -> Result<Self, anyhow::Error> {
        let mut buffer = [0u8; 16];
        bytes
            .read_exact(&mut buffer)
            .context("failed to read FieldP128 element")?;
        Self::try_from(&buffer)
    }

    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        let mut non_montgomery = fiat_p128_non_montgomery_domain_field_element([0; 2]);
        fiat_p128_from_montgomery(&mut non_montgomery, &self.0);
        let mut out = [0u8; 16];
        fiat_p128_to_bytes(&mut out, &non_montgomery.0);
        bytes.extend_from_slice(&out);
        Ok(())
    }
}

impl Add<&Self> for FieldP128 {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        let mut out = fiat_p128_montgomery_domain_field_element([0; 2]);
        fiat_p128_add(&mut out, &self.0, &rhs.0);
        Self(out)
    }
}

impl Add for FieldP128 {
    type Output = Self;

    #[allow(clippy::op_ref)]
    fn add(self, rhs: Self) -> Self::Output {
        self + &rhs
    }
}

impl AddAssign for FieldP128 {
    fn add_assign(&mut self, rhs: Self) {
        let copy = *self;
        fiat_p128_add(&mut self.0, &copy.0, &rhs.0);
    }
}

impl Sub<&Self> for FieldP128 {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        let mut out = fiat_p128_montgomery_domain_field_element([0; 2]);
        fiat_p128_sub(&mut out, &self.0, &rhs.0);
        Self(out)
    }
}

impl Sub for FieldP128 {
    type Output = Self;

    #[allow(clippy::op_ref)]
    fn sub(self, rhs: Self) -> Self::Output {
        self - &rhs
    }
}

impl SubAssign for FieldP128 {
    fn sub_assign(&mut self, rhs: Self) {
        let copy = *self;
        fiat_p128_sub(&mut self.0, &copy.0, &rhs.0);
    }
}

impl Mul<&Self> for FieldP128 {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        let mut out = fiat_p128_montgomery_domain_field_element([0; 2]);
        fiat_p128_mul(&mut out, &self.0, &rhs.0);
        Self(out)
    }
}

impl Mul<Self> for FieldP128 {
    type Output = Self;

    #[allow(clippy::op_ref)]
    fn mul(self, rhs: Self) -> Self::Output {
        self * &rhs
    }
}

impl MulAssign for FieldP128 {
    fn mul_assign(&mut self, rhs: Self) {
        let copy = *self;
        fiat_p128_mul(&mut self.0, &copy.0, &rhs.0)
    }
}

impl Neg for FieldP128 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let mut out = fiat_p128_montgomery_domain_field_element([0; 2]);
        fiat_p128_opp(&mut out, &self.0);
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
        fields::{FieldElement, fieldp128::FieldP128},
    };

    #[test]
    fn modulus_bytes_correct() {
        let mut p_minus_one_bytes = FieldP128::MODULUS_BYTES;
        p_minus_one_bytes[0] -= 1;
        let p_minus_one = FieldP128::decode(&mut Cursor::new(&p_minus_one_bytes)).unwrap();
        assert_eq!(p_minus_one + FieldP128::ONE, FieldP128::ZERO);
    }
}
