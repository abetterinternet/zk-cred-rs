use crate::{Byte, Codec};
use anyhow::{Context, anyhow};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::Cursor;
use zk_cred_longfellow_fields::FieldElement;

impl<FE: FieldElement> Codec for FE {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, anyhow::Error> {
        Self::try_from(
            &Byte::decode_fixed_array(bytes, Self::num_bytes())?
                .into_iter()
                .map(|b| b.0)
                .collect::<Vec<_>>(),
        )
    }

    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        // Get the repr, which will be extra long to fit the limbs, then truncate down to the
        // encoded length.
        Byte::encode_fixed_array(
            &self.to_repr().as_ref()[..Self::num_bytes()]
                .iter()
                .map(|b| Byte(*b))
                .collect::<Vec<_>>(),
            bytes,
        )
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
            FieldId::P256 => 32,
            FieldId::FP128 => 16,
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
        Byte::encode_fixed_array(&self.0.iter().map(|b| Byte(*b)).collect::<Vec<_>>(), bytes)
    }

    pub fn decode(field_id: FieldId, bytes: &mut Cursor<&[u8]>) -> Result<Self, anyhow::Error> {
        Ok(Self(
            Byte::decode_fixed_array(bytes, field_id.encoded_length())?
                .into_iter()
                .map(|b| b.0)
                .collect::<Vec<_>>(),
        ))
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

#[cfg(test)]
mod tests {
    use crate::{
        Codec,
        fields::{FieldId, SerializedFieldElement},
    };
    use ff::PrimeField;
    use std::io::Cursor;
    use zk_cred_longfellow_fields::{
        fieldp128::FieldP128, fieldp256::FieldP256, fieldp521::FieldP521,
    };

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
        for (label, valid_element) in [
            (
                "Fewer bytes than the repr. We should pad with zeroes.",
                &[0xff][..],
            ),
            (
                "Exactly the length of the repr (40 bytes), but a legal field value.",
                &[
                    0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00,
                ][..],
            ),
            (
                "Empty slice should be padded and evaluate to zero.",
                &[][..],
            ),
        ] {
            FieldP256::try_from(valid_element).expect(label);
        }
    }

    #[test]
    fn field_p256_from_bytes_reject() {
        for (label, invalid_element) in [
            (
                "Value is too big for the field",
                &[
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff,
                ][..],
            ),
            (
                "Slice is too long for the field repr",
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
}
