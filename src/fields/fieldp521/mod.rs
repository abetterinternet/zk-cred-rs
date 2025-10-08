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
        fieldp521::ops::{
            fiat_p521_carry_add, fiat_p521_carry_mul, fiat_p521_carry_opp, fiat_p521_carry_sub,
            fiat_p521_from_bytes, fiat_p521_loose_field_element, fiat_p521_relax,
            fiat_p521_tight_field_element, fiat_p521_to_bytes,
        },
    },
};

/// FieldP521 is the field with modulus 2^521 - 1, described in [Section 7.2 of
/// draft-google-cfrg-libzk-00][1]. It is also the base field of the NIST P-521 elliptic curve.
///
/// Field elements are serialized in little-endian form, per [Section 7.2.1 of draft-google-cfrg-libzk-00][2].
///
/// [1]: https://www.ietf.org/archive/id/draft-google-cfrg-libzk-00.html#section-7.2
/// [2]: https://www.ietf.org/archive/id/draft-google-cfrg-libzk-00.html#section-7.2.1
#[derive(Clone, Copy)]
pub struct FieldP521(fiat_p521_tight_field_element);

impl FieldP521 {
    /// Bytes of the prime modulus, in little endian order.
    ///
    /// This is used to validate encoded field elements.
    const MODULUS_BYTES: [u8; 66] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
    ];

    /// Project a u128 integer into a field element.
    ///
    /// This duplicates `FieldElement::from_u128()` in order to provide a const function with the
    /// same functionality, since trait methods cannot be used in const contexts yet.
    #[inline]
    const fn from_u128_const(value: u128) -> Self {
        let mut bytes = [0u8; 66];
        // We can't use `bytes[0..16]` because IndexMut is not yet const stable.
        bytes
            .as_mut_slice()
            .split_at_mut(16)
            .0
            .copy_from_slice(&value.to_le_bytes());
        let mut out = fiat_p521_tight_field_element([0; 9]);
        fiat_p521_from_bytes(&mut out, &bytes);
        Self(out)
    }
}

impl FieldElement for FieldP521 {
    const NUM_BITS: u32 = 521;
    const ZERO: Self = Self(fiat_p521_tight_field_element([0; 9]));
    const ONE: Self = Self::from_u128_const(1);
    const TWO: Self = Self::from_u128_const(2);

    fn from_u128(value: u128) -> Self {
        Self::from_u128_const(value)
    }
}

impl Debug for FieldP521 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut bytes = [0u8; 66];
        fiat_p521_to_bytes(&mut bytes, &self.0);
        write!(f, "FieldP521(0x")?;
        for byte in bytes.iter().rev() {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

impl Default for FieldP521 {
    fn default() -> Self {
        Self::ZERO
    }
}

impl ConstantTimeEq for FieldP521 {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        // It seems that field elements may not have unique representations in limb form, even with
        // tight bounds. Thus, we need to convert to bytes first, and then compare that.
        let mut left_bytes = [0u8; 66];
        fiat_p521_to_bytes(&mut left_bytes, &self.0);
        let mut right_bytes = [0u8; 66];
        fiat_p521_to_bytes(&mut right_bytes, &other.0);
        left_bytes.ct_eq(&right_bytes)
    }
}

impl PartialEq for FieldP521 {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for FieldP521 {}

impl From<u64> for FieldP521 {
    fn from(value: u64) -> Self {
        let mut bytes = [0u8; 66];
        bytes[0..8].copy_from_slice(&value.to_le_bytes());
        let mut out = fiat_p521_tight_field_element([0; 9]);
        fiat_p521_from_bytes(&mut out, &bytes);
        Self(out)
    }
}

impl TryFrom<&[u8; 66]> for FieldP521 {
    type Error = anyhow::Error;

    fn try_from(value: &[u8; 66]) -> Result<Self, Self::Error> {
        if value.iter().rev().cmp(Self::MODULUS_BYTES.iter().rev()) != Ordering::Less {
            return Err(anyhow!(
                "serialized FieldP521 element is not less than the modulus"
            ));
        }
        let mut out = fiat_p521_tight_field_element([0; 9]);
        fiat_p521_from_bytes(&mut out, value);
        Ok(Self(out))
    }
}

impl TryFrom<&[u8]> for FieldP521 {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let array_reference = <&[u8; 66]>::try_from(value).context("failed to decode FieldP521")?;
        Self::try_from(array_reference)
    }
}

impl Codec for FieldP521 {
    fn decode(bytes: &mut io::Cursor<&[u8]>) -> Result<Self, anyhow::Error> {
        let mut buffer = [0u8; 66];
        bytes
            .read_exact(&mut buffer)
            .context("failed to read FieldP521 element")?;
        Self::try_from(&buffer)
    }

    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        let mut out = [0u8; 66];
        fiat_p521_to_bytes(&mut out, &self.0);
        bytes.extend_from_slice(&out);
        Ok(())
    }
}

impl Add<&Self> for FieldP521 {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        let mut out = fiat_p521_tight_field_element([0; 9]);
        fiat_p521_carry_add(&mut out, &self.0, &rhs.0);
        Self(out)
    }
}

impl Add for FieldP521 {
    type Output = Self;

    #[allow(clippy::op_ref)]
    fn add(self, rhs: Self) -> Self::Output {
        self + &rhs
    }
}

impl AddAssign for FieldP521 {
    fn add_assign(&mut self, rhs: Self) {
        let copy = *self;
        fiat_p521_carry_add(&mut self.0, &copy.0, &rhs.0);
    }
}

impl Sub<&Self> for FieldP521 {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        let mut out = fiat_p521_tight_field_element([0; 9]);
        fiat_p521_carry_sub(&mut out, &self.0, &rhs.0);
        Self(out)
    }
}

impl Sub for FieldP521 {
    type Output = Self;

    #[allow(clippy::op_ref)]
    fn sub(self, rhs: Self) -> Self::Output {
        self - &rhs
    }
}

impl SubAssign for FieldP521 {
    fn sub_assign(&mut self, rhs: Self) {
        let copy = *self;
        fiat_p521_carry_sub(&mut self.0, &copy.0, &rhs.0);
    }
}

impl Mul<&Self> for FieldP521 {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        let mut left_loose = fiat_p521_loose_field_element([0; 9]);
        fiat_p521_relax(&mut left_loose, &self.0);
        let mut right_loose = fiat_p521_loose_field_element([0; 9]);
        fiat_p521_relax(&mut right_loose, &rhs.0);
        let mut out = fiat_p521_tight_field_element([0; 9]);
        fiat_p521_carry_mul(&mut out, &left_loose, &right_loose);
        Self(out)
    }
}

impl Mul<Self> for FieldP521 {
    type Output = Self;

    #[allow(clippy::op_ref)]
    fn mul(self, rhs: Self) -> Self::Output {
        self * &rhs
    }
}

impl MulAssign for FieldP521 {
    fn mul_assign(&mut self, rhs: Self) {
        let mut self_loose = fiat_p521_loose_field_element([0; 9]);
        fiat_p521_relax(&mut self_loose, &self.0);
        let mut right_loose = fiat_p521_loose_field_element([0; 9]);
        fiat_p521_relax(&mut right_loose, &rhs.0);
        fiat_p521_carry_mul(&mut self.0, &self_loose, &right_loose);
    }
}

impl Neg for FieldP521 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let mut out = fiat_p521_tight_field_element([0; 9]);
        fiat_p521_carry_opp(&mut out, &self.0);
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
        fields::{FieldElement, fieldp521::FieldP521},
    };

    #[test]
    fn modulus_bytes_correct() {
        let mut p_minus_one_bytes = FieldP521::MODULUS_BYTES;
        p_minus_one_bytes[0] -= 1;
        let p_minus_one = FieldP521::decode(&mut Cursor::new(&p_minus_one_bytes)).unwrap();
        assert_eq!(p_minus_one + FieldP521::ONE, FieldP521::ZERO);
    }
}
