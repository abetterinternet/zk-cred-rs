//! Implements a transcript of prover messages, used to apply the Fiat-Shamir transform to an
//! interactive protocol.
//!
//! https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-00#section-3

use crate::{Codec, fields::FieldElement};
use aes::{
    Aes256,
    cipher::{BlockEncrypt, KeyInit},
};
use anyhow::{Context, anyhow};
use crypto_common::{BlockSizeUser, generic_array::GenericArray};
use sha2::{Digest, Sha256};

/// A transcript of the prover's execution of a protocol, used to generate the verifier's public
/// coin challenges based on the state of the transcript at some moment.
pub struct Transcript {
    /// Accumulated hash of messages written to the transcript, used as the seed to
    /// [`FiatShamirPseudoRandomFunction`] to generate verifier challenges.
    fsprf_seed: Sha256,
    /// An FSPRF, seeded with the transcript up to some point.
    current_fsprf: Option<FiatShamirPseudoRandomFunction>,
}

impl Transcript {
    /// Initialize a transcript.
    ///
    /// The specification is not clear about what `session_id` is, but in the C++ implementation,
    /// it's an opaque byte buffer ([1]).
    ///
    /// https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-00#section-3.1.1
    /// [1]: https://github.com/google/longfellow-zk/blob/87474f308020535e57a778a82394a14106f8be5b/lib/random/transcript.h#L76
    pub fn initialize(session_id: &[u8]) -> Result<Self, anyhow::Error> {
        let mut transcript = Self {
            fsprf_seed: Sha256::new(),
            current_fsprf: None,
        };

        // Initialize the transcript with the session ID
        transcript.write_bytes(session_id)?;

        Ok(transcript)
    }

    /// Write a field element to the transcript.
    ///
    /// https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-00#section-3.1.2
    pub fn write_field_element<FE: FieldElement>(
        &mut self,
        field_element: &FE,
    ) -> Result<(), anyhow::Error> {
        // Write tag for a single field element
        self.write_bytes(&[0x1])?;

        // Write field element
        self.write_bytes(field_element.get_encoded()?.as_ref())?;

        Ok(())
    }

    pub fn write_field_element_array<FE: FieldElement>(
        &mut self,
        field_elements: &[FE],
    ) -> Result<(), anyhow::Error> {
        // Length prefix is 8 bytes, so reject slices that are too big
        if field_elements.len()
            > usize::try_from(u64::MAX).context("can't fit u64::MAX in a usize")?
        {
            return Err(anyhow!("field element array too big for transcript"));
        }

        // Write tag for field element array
        self.write_bytes(&[0x3])?;

        // Write length of array as little endian bytes
        self.write_bytes(&(field_elements.len() as u64).to_le_bytes())?;

        // Write array
        for field_element in field_elements {
            self.write_bytes(field_element.get_encoded()?.as_ref())?;
        }

        Ok(())
    }

    /// Write a slice of bytes to the transcript.
    ///
    /// https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-3.1.2
    pub fn write_byte_array(&mut self, bytes: &[u8]) -> Result<(), anyhow::Error> {
        // Length prefix is 8 bytes, so reject slices that are too big
        // TODO: casting u64 to usize won't work on LP32
        if bytes.len() > u64::MAX as usize {
            return Err(anyhow!("byte array too big for transcript"));
        }

        // Write tag for byte array
        self.write_bytes(&[0x2])?;

        // Write length of array as 8 little endian bytes
        self.write_bytes(&(bytes.len() as u64).to_le_bytes())?;

        // Write array
        self.write_bytes(bytes)?;

        Ok(())
    }

    /// Write a slice of bytes to the transcript, with no tag or length.
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), anyhow::Error> {
        // Invalidate any FSPRF we have because any challenges generated past this point need to
        // incorporate the new bytes.
        self.current_fsprf = None;

        // Saying we "write" or "append" is something of a misnomer: really we are updating a
        // SHA-256 hash with the bytes, and then that will be used as the seed for a
        // [`FiatShamirPseudoRandomFunction`] used to generate challenges.
        self.fsprf_seed.update(bytes);

        Ok(())
    }

    /// Generate a challenge, consisting of `length` field elements.
    pub fn generate_challenge<FE: FieldElement>(
        &mut self,
        length: usize,
    ) -> Result<Vec<FE>, anyhow::Error> {
        let fsprf = self.current_fsprf.get_or_insert_with(|| {
            // Clone the SHA256 state so we can finalize it
            let fsprf_seed = self.fsprf_seed.clone().finalize();
            // TODO: handle fallible initialization here
            FiatShamirPseudoRandomFunction::new(fsprf_seed.as_slice())
                .expect("failed to init FSPRF")
        });

        // TODO: the case where the "field element" is a polynomial?

        Ok(std::iter::from_fn(|| Some(fsprf.sample_field_element()))
            .take(length)
            .collect())
    }
}

/// An iterator producing an infinite stream of bytes based on the provided key.
///
/// XXX: Could we just use the XOF from crate prio?
///
/// https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-00#section-3.2
#[derive(Clone, Debug)]
pub struct FiatShamirPseudoRandomFunction {
    cipher: Aes256,
    /// Current position of the infinite stream, in bytes.
    position: usize,
    /// Current block of generated bytes.
    current_block: Vec<u8>,
}

impl FiatShamirPseudoRandomFunction {
    /// Initialize the FSPRF with the provided key, which must be the correct length for AES256.
    pub fn new(seed: &[u8]) -> Result<Self, anyhow::Error> {
        let cipher = Aes256::new_from_slice(seed).context("bad key length")?;

        Ok(Self {
            cipher,
            position: 0,
            current_block: Vec::new(),
        })
    }

    fn current_block(cipher: &Aes256, position: usize) -> Vec<u8> {
        // Get the current block index as a u128, which is 16 bytes, which is the AES block size.
        let block: u128 = (position / Aes256::block_size()).try_into().unwrap();
        // Get the block index as little endian bytes, per 3.2.
        let mut block = block.to_le_bytes();

        // Encrypt the block index under the seed
        cipher.encrypt_block(GenericArray::from_mut_slice(&mut block));

        block.to_vec()
    }

    pub fn sample_field_element<FE: FieldElement>(&mut self) -> FE {
        self.sample_field_element_counting_rejections().0
    }

    /// Generate a field element by rejection sampling and return how many rejections were observed.
    fn sample_field_element_counting_rejections<FE: FieldElement>(&mut self) -> (FE, usize) {
        let mut rejections = 0;
        let field_element = loop {
            // Some fields like P521 have a bit count that isn't congruent to 8. We sample
            // enough excess bits to get whole bytes and then mask off the excess, which can be
            // at most 7 bits.
            // https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-3.3
            let num_sampled_bytes = (FE::NUM_BITS as usize).div_ceil(8);
            let mut sampled_bytes = self.take(num_sampled_bytes).collect::<Vec<_>>();
            let excess_bits = num_sampled_bytes * 8 - FE::NUM_BITS as usize;
            if excess_bits != 0 {
                sampled_bytes[num_sampled_bytes - 1] &= (1 << (8 - excess_bits)) - 1;
            }
            // FE::try_from rejects if the value is still too big after masking.
            // TODO: FE::try_from could fail for reasons besides the generated value being too big
            if let Ok(fe) = FE::try_from(&sampled_bytes) {
                break fe;
            }
            rejections += 1;
        };

        (field_element, rejections)
    }
}

impl Iterator for FiatShamirPseudoRandomFunction {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let position_in_block = self.position % Aes256::block_size();
        if position_in_block == 0 {
            // Exhausted current block, compute the next
            self.current_block = Self::current_block(&self.cipher, self.position);
        }

        let value = self.current_block[position_in_block];

        self.position += 1;

        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use ff::PrimeField;

    use super::*;
    use crate::fields::{fieldp256::FieldP256, fieldp521::FieldP521};

    #[test]
    fn deterministic() {
        fn run_transcript() -> Vec<FieldP256> {
            let mut transcript = Transcript::initialize(b"test").unwrap();

            transcript
                .write_field_element(&FieldP256::from_u128(10))
                .unwrap();

            transcript
                .write_field_element_array(&[FieldP256::from_u128(11), FieldP256::from_u128(12)])
                .unwrap();

            transcript.write_byte_array(b"some bytes").unwrap();

            let challenge = transcript.generate_challenge(10).unwrap();

            assert_eq!(challenge.len(), 10);

            challenge
        }

        assert_eq!(
            run_transcript(),
            run_transcript(),
            "running the same transcript twice should yield identical challenges"
        );
    }

    #[test]
    fn distinct_session_id() {
        let mut transcript1 = Transcript::initialize(b"test1").unwrap();
        transcript1.write_byte_array(b"some bytes").unwrap();
        let challenge1 = transcript1.generate_challenge::<FieldP256>(10).unwrap();

        let mut transcript2 = Transcript::initialize(b"test2").unwrap();
        transcript2.write_byte_array(b"some bytes").unwrap();
        let challenge2 = transcript2.generate_challenge::<FieldP256>(10).unwrap();

        assert_ne!(
            challenge1, challenge2,
            "running the same transcript with distinct session IDs should yield distinct challenges"
        );
    }

    #[test]
    fn distinct_messages() {
        let mut transcript1 = Transcript::initialize(b"test").unwrap();
        transcript1.write_byte_array(b"some bytes").unwrap();
        let challenge1 = transcript1.generate_challenge::<FieldP256>(10).unwrap();

        let mut transcript2 = Transcript::initialize(b"test").unwrap();
        transcript2.write_byte_array(b"some other bytes").unwrap();
        let challenge2 = transcript2.generate_challenge::<FieldP256>(10).unwrap();

        assert_ne!(
            challenge1, challenge2,
            "running the same transcript with distinct session IDs should yield distinct challenges"
        );
    }

    #[test]
    fn writing_messages_changes_challenge() {
        let mut transcript = Transcript::initialize(b"test").unwrap();
        transcript.write_byte_array(b"some bytes").unwrap();
        let challenge1 = transcript.generate_challenge::<FieldP256>(10).unwrap();
        transcript.write_byte_array(b"some more bytes").unwrap();
        let challenge2 = transcript.generate_challenge::<FieldP256>(10).unwrap();

        assert_ne!(
            challenge1, challenge2,
            "generated challenge should differ after writing new bytes"
        );
    }

    #[test]
    fn sample_field_without_excess_bits() {
        let mut fsprf = FiatShamirPseudoRandomFunction::new(&[0; 32]).unwrap();
        // Crude test that checks the rejection rate is below 50%.
        let count = 100;
        for _ in 0..count {
            let (_, rejections) = fsprf.sample_field_element_counting_rejections::<FieldP256>();
            assert!(rejections as f64 / (rejections as f64 + count as f64) < 0.5);
        }
    }

    #[test]
    fn sample_field_with_excess_bits_without_rejections() {
        // FieldP521 has excess bits, but every 521 bit integer except the field prime itself, is a
        // valid field element, so if excess bit masking is correctly implemented, the chance of
        // rejections is negligible.
        let mut fsprf = FiatShamirPseudoRandomFunction::new(&[0; 32]).unwrap();
        for _ in 0..100 {
            let (_, rejections) = fsprf.sample_field_element_counting_rejections::<FieldP521>();
            assert_eq!(rejections, 0);
        }
    }
}
