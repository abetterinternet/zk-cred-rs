//! Various finite field implementations.
use crate::{
    Codec,
    fields::{fieldp128::FieldP128, fieldp256::FieldP256},
};
use anyhow::{Context, anyhow};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use rand::RngCore;
use std::{
    fmt::Debug,
    io::Cursor,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use subtle::{Choice, ConstantTimeEq};

pub trait FieldElement:
    Debug
    + Clone
    + Copy
    + ConstantTimeEq
    + Default
    + From<u64>
    + Add<Output = Self>
    + for<'a> Add<&'a Self, Output = Self>
    + AddAssign
    + Sub<Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + SubAssign
    + Mul<Output = Self>
    + for<'a> Mul<&'a Self, Output = Self>
    + MulAssign
    + Neg<Output = Self>
    + for<'a> TryFrom<&'a [u8], Error = anyhow::Error>
    + Codec
{
    const NUM_BITS: u32;
    const ZERO: Self;
    const ONE: Self;
    const TWO: Self;

    /// Number of bytes needed to represent a field element.
    fn num_bytes() -> usize {
        (Self::NUM_BITS as usize).div_ceil(8)
    }

    /// Project an integer into the field.
    fn from_u128(value: u128) -> Self;

    /// Test whether this element is zero.
    fn is_zero(&self) -> Choice {
        self.ct_eq(&Self::ZERO)
    }

    /// Generate a field element by rejection sampling.
    fn sample() -> Self {
        Self::sample_from_source(|num_bytes| {
            let mut bytes = vec![0; num_bytes];
            rand::thread_rng().fill_bytes(&mut bytes);

            bytes
        })
    }

    /// Generate a field element by rejection sampling, sampling random bytes from the provided
    /// source.
    fn sample_from_source<F>(source: F) -> Self
    where
        F: FnMut(usize) -> Vec<u8>,
    {
        Self::sample_counting_rejections(source).0
    }

    /// Generate a field element by rejection sampling and return how many rejections were observed.
    fn sample_counting_rejections<F>(mut source: F) -> (Self, usize)
    where
        F: FnMut(usize) -> Vec<u8>,
    {
        let mut rejections = 0;
        let field_element = loop {
            // Some fields like P521 have a bit count that isn't congruent to 8. We sample
            // enough excess bits to get whole bytes and then mask off the excess, which can be
            // at most 7 bits.
            // https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-3.3
            let num_sampled_bytes = Self::num_bytes();
            let mut sampled_bytes = source(num_sampled_bytes);
            let excess_bits = num_sampled_bytes * 8 - Self::NUM_BITS as usize;
            if excess_bits != 0 {
                sampled_bytes[num_sampled_bytes - 1] &= (1 << (8 - excess_bits)) - 1;
            }
            // FE::try_from rejects if the value is still too big after masking.
            // TODO: FE::try_from could fail for reasons besides the generated value being too big
            if let Ok(fe) = Self::try_from(&sampled_bytes) {
                break fe;
            }
            rejections += 1;
        };

        (field_element, rejections)
    }
}

/// Field identifier. According to the draft specification, the encoding is of variable length ([1])
/// but in the Longfellow implementation ([2]), they're always 3 bytes long.
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-00#section-7.2
/// [2]: https://github.com/google/longfellow-zk/blob/902a955fbb22323123aac5b69bdf3442e6ea6f80/lib/proto/circuit.h#L309
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u8)]
pub enum FieldId {
    /// The absence of a field, presumably if some circuit or proof has no subfield. This isn't
    /// described in the specification (FieldID values start at 1) but is present in the Longfellow
    /// implementation ([1]).
    ///
    /// [1]: https://github.com/google/longfellow-zk/blob/87474f308020535e57a778a82394a14106f8be5b/lib/proto/circuit.h#L55
    None = 0,
    /// NIST P256.
    P256 = 1,
    /// [`FieldP128`]
    FP128 = 6,
    // TODO: other field IDs as we need them
}

impl TryFrom<u8> for FieldId {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::P256),
            6 => Ok(Self::FP128),
            _ => Err(anyhow!("unknown field ID")),
        }
    }
}

impl Codec for FieldId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, anyhow::Error> {
        let value = bytes
            .read_u24::<LittleEndian>()
            .context("failed to read u24")?;
        let as_u8: u8 = value.try_into().context("decoded value too big for u8")?;
        Self::try_from(as_u8)
    }

    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        bytes
            .write_u24::<LittleEndian>(*self as u32)
            .context("failed to write u24")
    }
}

impl FieldId {
    /// Returns the number of bytes occupied by the encoding of a field element of this ID.
    pub fn encoded_length(&self) -> usize {
        match self {
            FieldId::None => 0,
            FieldId::P256 => FieldP256::num_bytes(),
            FieldId::FP128 => FieldP128::num_bytes(),
        }
    }
}

/// A serialized field element. The encoded length depends on the [`FieldId`].
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct SerializedFieldElement(pub Vec<u8>);

impl SerializedFieldElement {
    // Annoyingly we can't implement Codec for this: encoding or decoding a field element requires
    // knowledge of the field element in use by the circuit, which means we can't decode without
    // some context.
    pub fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        u8::encode_fixed_array(&self.0, bytes)
    }

    pub fn decode(field_id: FieldId, bytes: &mut Cursor<&[u8]>) -> Result<Self, anyhow::Error> {
        Ok(Self(u8::decode_fixed_array(
            bytes,
            field_id.encoded_length(),
        )?))
    }
}

impl TryFrom<SerializedFieldElement> for u128 {
    type Error = anyhow::Error;

    fn try_from(value: SerializedFieldElement) -> Result<Self, Self::Error> {
        Ok(u128::from_le_bytes(value.0.try_into().map_err(|_| {
            anyhow!("byte array wrong length for u128")
        })?))
    }
}

pub mod fieldp128;
pub mod fieldp256;
pub mod fieldp521;

#[cfg(test)]
mod tests {
    use rand::RngCore;

    use crate::{
        Codec,
        fields::{
            FieldElement, FieldId, SerializedFieldElement, fieldp128::FieldP128,
            fieldp256::FieldP256,
        },
    };
    use std::io::Cursor;

    use super::fieldp521::FieldP521;

    #[test]
    fn codec_roundtrip_field_p128() {
        let element = SerializedFieldElement(Vec::from([
            0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
            0xfe, 0xff,
        ]));

        let mut encoded = Vec::new();
        element.encode(&mut encoded).unwrap();

        let decoded =
            SerializedFieldElement::decode(FieldId::FP128, &mut Cursor::new(&encoded)).unwrap();

        assert_eq!(element, decoded)
    }

    #[test]
    fn field_p128_from_bytes_accept() {
        FieldP128::try_from(
            &[
                0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ][..],
        )
        .expect("Exactly the length of a field element (16 bytes), but a legal field value.");
    }

    #[test]
    fn field_p128_from_bytes_reject() {
        for (label, invalid_element) in [
            ("Empty slice", &[][..]),
            ("Slice is too short for the field", &[0xff][..]),
            (
                "Value is too big for the field",
                &[
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff,
                ][..],
            ),
            (
                "Slice is too long for the field",
                &[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ][..],
            ),
        ] {
            FieldP128::try_from(invalid_element).expect_err(label);
        }
    }

    #[test]
    fn codec_roundtrip_field_p256() {
        let element = SerializedFieldElement(Vec::from([
            0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
            0xfe, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xfe, 0xff,
            0xff, 0xff, 0xfe, 0xff,
        ]));

        let mut encoded = Vec::new();
        element.encode(&mut encoded).unwrap();

        let decoded =
            SerializedFieldElement::decode(FieldId::P256, &mut Cursor::new(&encoded)).unwrap();

        assert_eq!(element, decoded)
    }

    #[test]
    fn field_p256_from_bytes_accept() {
        FieldP256::try_from(
            &[
                0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ][..],
        )
        .expect("Exactly the length of a field element (32 bytes), but a legal field value.");
    }

    #[test]
    fn field_p256_from_bytes_reject() {
        for (label, invalid_element) in [
            ("Empty slice", &[][..]),
            ("Slice is too short for the field", &[0xff][..]),
            (
                "Value is too big for the field",
                &[
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ][..],
            ),
            (
                "Slice is too long for the field",
                &[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00,
                ][..],
            ),
        ] {
            FieldP256::try_from(invalid_element).expect_err(label);
        }
    }

    #[test]
    fn field_p256_roundtrip() {
        FieldP256::from_u128(111).roundtrip();
    }

    #[test]
    fn field_p128_roundtrip() {
        FieldP128::from_u128(111).roundtrip();
    }

    #[test]
    fn field_p521_roundtrip() {
        FieldP521::from_u128(111).roundtrip();
    }

    #[allow(clippy::op_ref, clippy::eq_op)]
    fn field_element_test<F: FieldElement>() {
        let three = F::from(3);
        let nine = F::from(9);
        let neg_one = -F::ONE;

        assert_eq!(F::from(0), F::ZERO);
        assert_eq!(F::from(1), F::ONE);
        assert_eq!(F::from(2), F::TWO);

        assert_ne!(F::ZERO, F::ONE);
        assert_ne!(F::ONE, three);
        assert_ne!(three, nine);
        assert_ne!(nine, neg_one);

        assert_eq!(neg_one + &F::ONE, F::ZERO);
        assert_eq!(neg_one + F::ONE, F::ZERO);
        let mut temp = neg_one;
        temp += F::ONE;
        assert_eq!(temp, F::ZERO);

        assert_eq!(F::ONE + &F::ONE, F::TWO);
        assert_eq!(F::ONE + F::ONE, F::TWO);
        let mut temp = F::ONE;
        temp += F::ONE;
        assert_eq!(temp, F::TWO);

        assert_eq!(three + &F::ZERO, three);
        assert_eq!(three + F::ZERO, three);
        let mut temp = three;
        temp += F::ZERO;
        assert_eq!(temp, three);

        assert_eq!(three * &three, nine);
        assert_eq!(three * three, nine);
        assert_eq!(three * &F::ONE, three);
        assert_eq!(three * F::ONE, three);
        assert_eq!(three * &F::ZERO, F::ZERO);
        assert_eq!(three * F::ZERO, F::ZERO);

        let mut temp = F::ONE;
        temp *= F::ONE;
        assert_eq!(temp, F::ONE);
        temp *= three;
        assert_eq!(temp, three);
        temp *= three;
        assert_eq!(temp, three + three + three);

        assert_eq!(-neg_one, F::ONE);

        assert_eq!(F::ONE - F::ONE, F::ZERO);
        assert_eq!(F::ZERO - F::ONE, neg_one);
        assert_eq!(three - F::ZERO, three);
        let mut temp = three;
        temp -= F::ONE;
        assert_eq!(temp, F::TWO);

        for x in [F::ZERO, F::ONE, three, nine, neg_one] {
            let encoded = x.get_encoded().unwrap();
            assert_eq!(encoded.len(), F::num_bytes());
            let mut cursor = Cursor::new(&encoded[..]);
            let decoded = F::decode(&mut cursor).unwrap();
            assert_eq!(cursor.position(), encoded.len() as u64);
            assert_eq!(decoded, x);
        }

        let max_int_encoded = vec![0xffu8; F::num_bytes()];
        F::decode(&mut Cursor::new(&max_int_encoded)).unwrap_err();

        let zero_encoded = vec![0u8; F::num_bytes()];
        assert_eq!(F::decode(&mut Cursor::new(&zero_encoded)).unwrap(), F::ZERO);

        let mut one_encoded = zero_encoded.clone();
        one_encoded[0] = 1;
        assert_eq!(F::decode(&mut Cursor::new(&one_encoded)).unwrap(), F::ONE);

        assert_eq!(F::from_u128(u64::MAX as u128), F::from(u64::MAX));
    }

    #[test]
    fn test_field_p256() {
        field_element_test::<FieldP256>();
    }

    #[test]
    fn test_field_p128() {
        field_element_test::<FieldP128>();
    }

    #[test]
    fn test_field_p521() {
        field_element_test::<FieldP521>();
    }

    #[test]
    fn sample_field_without_excess_bits() {
        // Crude test that checks the rejection rate is below 50%.
        let count = 100;
        let mut total_rejections = 0;
        for _ in 0..count {
            let (_, rejections) = FieldP256::sample_counting_rejections(|num_bytes| {
                let mut bytes = vec![0; num_bytes];
                rand::thread_rng().fill_bytes(&mut bytes);

                bytes
            });

            total_rejections += rejections;
        }
        assert!(total_rejections as f64 / (total_rejections as f64 + count as f64) < 0.5);
    }

    #[test]
    fn sample_field_with_excess_bits_without_rejections() {
        // FieldP521 has excess bits, but every 521 bit integer except the field prime itself, is a
        // valid field element, so if excess bit masking is correctly implemented, the chance of
        // rejections is negligible
        let mut total_rejections = 0;
        for _ in 0..100 {
            let (_, rejections) = FieldP521::sample_counting_rejections(|num_bytes| {
                let mut bytes = vec![0; num_bytes];
                rand::thread_rng().fill_bytes(&mut bytes);

                bytes
            });
            total_rejections += rejections;
        }
        assert_eq!(total_rejections, 0);
    }
}
