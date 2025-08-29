use anyhow::{Context, anyhow};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::Cursor;

pub mod sumcheck;

pub enum Error {
    BadKeyLength,
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

/// FieldP128 is the field with modulus 2^128 - 2^108 + 1, described in [Section 7.2 of
/// draft-google-cfrg-libzk-00][1]. The field does not get a name in the draft, but P128 comes from
/// the longfellow implementation ([3]).
///
/// The generator was computed in SageMath as `GF(2^128-2^108+1).primitive_element()` (thanks to the
/// hint in [`PrimeField::MULTIPLICATIVE_GENERATOR`]).
///
/// The endianness is per [Section 7.2.1 of draft-google-cfrg-libzk-00][2].
///
/// [1]: https://www.ietf.org/id/draft-google-cfrg-libzk-00.html#section-7.2
/// [2]: https://www.ietf.org/id/draft-google-cfrg-libzk-00.html#section-7.2.1
/// [3]: https://github.com/google/longfellow-zk/blob/main/lib/algebra/fp_p128.h
#[derive(ff::PrimeField)]
#[PrimeFieldModulus = "340282042402384805036647824275747635201"]
#[PrimeFieldGenerator = "59"]
#[PrimeFieldReprEndianness = "little"]
// ff requires that the repr be an array of u64 and despite the fact that 128 bits should be big
// enough, also requires 3 u64s.
pub struct FieldP128([u64; 3]);

/// A serialized size, which is in the range [1, 2^24 -1] per [draft-google-cfrg-libzk-00 section
/// 7][1]. Serialized in little endian order, occupying 3 bytes.
///
/// [1]: https://www.ietf.org/id/draft-google-cfrg-libzk-00.html#section-7
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord, Default, Hash)]
pub struct Size(u32);

impl From<u32> for Size {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<Size> for usize {
    fn from(value: Size) -> Self {
        // XXX shouldn't assume that usize is big enough for u32
        value.0 as Self
    }
}

impl Codec for Size {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, anyhow::Error> {
        Ok(Self(
            bytes
                .read_u24::<LittleEndian>()
                .context("failed to read u24")?,
        ))
    }

    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        if self.0 >= (1 << 24) {
            return Err(anyhow!(
                "size {} too big to be serialized in 3 bytes",
                self.0
            ));
        }
        bytes
            .write_u24::<LittleEndian>(self.0)
            .context("failed to write u24")
    }
}

impl PartialEq<usize> for Size {
    fn eq(&self, other: &usize) -> bool {
        usize::from(*self) == *other
    }
}

impl PartialOrd<usize> for Size {
    fn partial_cmp(&self, other: &usize) -> Option<std::cmp::Ordering> {
        usize::from(*self).partial_cmp(other)
    }
}

impl Size {
    /// Encode this value as a delta from the previous value in some sequence. The least significant
    /// bit is used as the sign bit, with the actual value shifted up by one position ([1]).
    ///
    /// [1]: https://www.ietf.org/id/draft-google-cfrg-libzk-00.html#section-7.6-5
    pub fn encode_delta(&self, previous: Size, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        let delta = if self.0 >= previous.0 {
            // Delta is positive: shift the delta up by one, leaving sign bit clear
            (self.0 - previous.0)
                .checked_mul(2)
                .ok_or_else(|| anyhow!("shift would overflow"))?
        } else {
            // Delta is negative: shift the delta up by one and set the sign bit
            (previous.0 - self.0)
                .checked_mul(2)
                .ok_or_else(|| anyhow!("shift would overflow"))?
                | 1
        };

        Size::from(delta).encode(bytes)
    }

    /// Decode this value as a delta from the previous value in some sequence.
    pub fn decode_delta(previous: Size, bytes: &mut Cursor<&[u8]>) -> Result<Self, anyhow::Error> {
        let encoded_delta = Size::decode(bytes)?.0;
        let sign = encoded_delta & 1;
        let delta = encoded_delta >> 1;

        let decoded = if sign == 1 {
            // Delta is negative
            previous.0 - delta
        } else {
            // Delta is positive
            previous.0 + delta
        };

        Ok(Self(decoded))
    }
}

/// Describes how to encode and decode an object from a byte sequence, per the rules in
/// [draft-google-cfrg-libzk-00 section 7][1].
///
/// Adapted from [prio::codec].
///
/// [1]: https://www.ietf.org/id/draft-google-cfrg-libzk-00.html#section-7
pub trait Codec: Sized + PartialEq + Eq + std::fmt::Debug {
    /// Decode an opaque byte buffer into an instance of this type.
    ///
    /// XXX: we could take something more sophisticated than a byte slice here, like a Cursor, or a
    /// Read impl, or an Iterator<Item = u8>.
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, anyhow::Error>;

    /// Decode a variable length array of items.
    fn decode_array(bytes: &mut Cursor<&[u8]>) -> Result<Vec<Self>, anyhow::Error> {
        // Variable length array encoding: length as a Size, then the elements one after the other.
        // Empirically, based on the test vector, it's length in *elements*, not bytes.
        let elements = Size::decode(bytes)?;
        Self::decode_fixed_array(bytes, elements.into())
    }

    /// Decode a fixed length array of items.
    fn decode_fixed_array(
        bytes: &mut Cursor<&[u8]>,
        count: usize,
    ) -> Result<Vec<Self>, anyhow::Error> {
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            let item = Self::decode(bytes)?;
            items.push(item);
        }

        Ok(items)
    }

    /// Append the encoded form of this object to the end of `bytes`, growing the vector as needed.
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error>;

    /// Encode a variable length array of items.
    fn encode_array(items: &[Self], bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        // Variable length array encoding: length in elements as a Size, then the elements one after
        // the other.
        Size(
            items
                .len()
                .try_into()
                .context("vector length too big for u32")?,
        )
        .encode(bytes)?;
        Self::encode_fixed_array(items, bytes)
    }

    /// Encode a fixed length array of items.
    fn encode_fixed_array(items: &[Self], bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        for item in items {
            item.encode(bytes)?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn roundtrip(&self) {
        let mut encoded = Vec::new();
        self.encode(&mut encoded).unwrap();

        let decoded = Self::decode(&mut Cursor::new(&encoded)).unwrap();

        assert_eq!(*self, decoded)
    }
}

impl Codec for u8 {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, anyhow::Error> {
        bytes.read_u8().context("failed to read u8")
    }

    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        bytes.push(*self);

        Ok(())
    }
}

impl Codec for u32 {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, anyhow::Error> {
        bytes
            .read_u32::<LittleEndian>()
            .context("failed to read u32")
    }

    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        bytes
            .write_u32::<LittleEndian>(*self)
            .context("failed to write u32")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codec_roundtrip_u8() {
        12u8.roundtrip();
    }

    #[test]
    fn codec_roundtrip_u32() {
        0xffffab65u32.roundtrip();
    }

    #[test]
    fn codec_roundtrip_size() {
        Size::from(12345).roundtrip();
    }

    #[test]
    fn encode_size_too_big() {
        // 1 << 24 is too big to be encoded as a 3 byte size, so this should fail
        let mut bytes = Vec::new();
        Size::from(1 << 24).encode(&mut bytes).unwrap_err();
    }

    #[test]
    fn encode_delta_positive_overflow() {
        // (1 << 31 - 0) << 1 will overflow u32, so this should fail
        let mut bytes = Vec::new();
        Size::from(1 << 31)
            .encode_delta(Size::from(0), &mut bytes)
            .unwrap_err();
    }

    #[test]
    fn encode_delta_negative_overflow() {
        // (1 << 31 - 0) << 1 will overflow u32, so this should fail
        let mut bytes = Vec::new();
        Size::from(0)
            .encode_delta(Size::from(1 << 31), &mut bytes)
            .unwrap_err();
    }
}
