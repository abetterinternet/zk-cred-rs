//! Implements a transcript of prover messages, used to apply the Fiat-Shamir transform to an
//! interactive protocol.
//!
//! https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-00#section-3

use crate::fields::FieldElement;
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

/// Tag written to the transcript to identify message type.
///
/// The values used in [longfellow-zk][1] disagree with those in [draft-google-cfrg-libzk-01][2]. In
/// this implementation we aim to interop with longfellow-zk, so we use its values.
///
/// [1]: https://github.com/google/longfellow-zk/blob/7a329b35b846fa5b9eca6f0143d0197a73e126a2/lib/random/transcript.h#L71
/// [2]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-3.1.2
enum Tag {
    ByteArray,
    FieldElement,
    FieldElementArray,
}

impl From<Tag> for &'static [u8] {
    fn from(value: Tag) -> Self {
        match value {
            Tag::ByteArray => &[0],
            Tag::FieldElement => &[1],
            // Even in longfellow-zk, this should be 2, but when they run their tests they use
            // version = 3 which evidently had a bug where field element arrays are incorrectly
            // tagged.
            Tag::FieldElementArray => &[1],
        }
    }
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
        transcript.write_byte_array(session_id)?;

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
        self.write_bytes(Tag::FieldElement.into())?;

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
        self.write_bytes(Tag::FieldElementArray.into())?;

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
        println!("write byte array {bytes:02x?}");
        // Length prefix is 8 bytes, so reject slices that are too big
        if bytes.len() > usize::try_from(u64::MAX).context("can't fit u64::MAX in a usize")? {
            return Err(anyhow!("byte array too big for transcript"));
        }

        // Write tag for byte array.
        self.write_bytes(Tag::ByteArray.into())?;

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

    fn get_current_fsprf(&mut self) -> &mut FiatShamirPseudoRandomFunction {
        self.current_fsprf.get_or_insert_with(|| {
            // Clone the SHA256 state so we can finalize it
            let fsprf_seed = self.fsprf_seed.clone().finalize();
            // TODO: handle fallible initialization here
            FiatShamirPseudoRandomFunction::new(fsprf_seed.as_slice())
                .expect("failed to init FSPRF")
        })
    }

    /// Generate a challenge, consisting of `length` field elements.
    pub fn generate_challenge<FE: FieldElement>(
        &mut self,
        length: usize,
    ) -> Result<Vec<FE>, anyhow::Error> {
        let fsprf = self.get_current_fsprf();

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

    /// Sample a field element from this FSPRF.
    pub fn sample_field_element<FE: FieldElement>(&mut self) -> FE {
        FE::sample_from_source(|num_bytes| self.take(num_bytes).collect::<Vec<_>>())
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
    use super::*;
    use crate::fields::{FieldElement, fieldp256::FieldP256};
    use std::iter::Iterator;

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
    fn writing_messages_resets_challenge() {
        let mut transcript = Transcript::initialize(b"test").unwrap();
        transcript.write_byte_array(b"some bytes").unwrap();
        transcript.generate_challenge::<FieldP256>(10).unwrap();
        transcript.write_byte_array(b"more bytes").unwrap();
        let challenge1 = transcript.generate_challenge::<FieldP256>(10).unwrap();

        let mut transcript2 = Transcript::initialize(b"test").unwrap();
        transcript2.write_byte_array(b"some bytes").unwrap();
        let _ = transcript2.generate_challenge::<FieldP256>(40).unwrap();
        transcript2.write_byte_array(b"more bytes").unwrap();
        let challenge2 = transcript2.generate_challenge(10).unwrap();

        assert_eq!(
            challenge1, challenge2,
            "despite sampling different numbers of field elements after the first write, writing \
            again should reset the FSPRF seed such that the second challenge generated is the same \
            for both transcripts"
        );
    }

    #[test]
    fn test_vector() {
        // FSPRF test vector adapted from longfellow-zk/lib/random/transcript_test.cc
        // https://github.com/google/longfellow-zk/blob/7a329b35b846fa5b9eca6f0143d0197a73e126a2/lib/random/transcript_test.cc#L97
        let mut transcript = Transcript::initialize(b"test").unwrap();
        let bytes: Vec<_> = (0..100).collect();
        transcript.write_byte_array(&bytes).unwrap();

        // Check that seed matches SHA-256 of bytes written
        let seed = transcript.fsprf_seed.clone().finalize();
        assert_eq!(
            seed.as_slice(),
            &[
                0x60, 0xcd, 0x16, 0x34, 0x92, 0x0f, 0x1c, 0xf2, 0xae, 0x83, 0x15, 0x02, 0xbf, 0x4b,
                0xb9, 0x3a, 0x60, 0xcd, 0x03, 0xee, 0xb1, 0x9f, 0x93, 0xe2, 0xd6, 0xd5, 0x0d, 0xbd,
                0x09, 0x84, 0xcb, 0xd8
            ],
        );

        let sampled_bytes: Vec<_> = transcript.get_current_fsprf().take(32).collect();

        // Check that sampled bytes match AES256 of counters under the seed
        assert_eq!(
            sampled_bytes.as_slice(),
            &[
                0x14, 0x1B, 0xBC, 0xBB, 0x54, 0x10, 0xDD, 0xEB, 0x70, 0x39, 0x83, 0x3B, 0x73, 0x65,
                0x86, 0xA0, 0x20, 0xFD, 0xD5, 0x85, 0x63, 0x79, 0xB6, 0xC6, 0xC6, 0x83, 0xD5, 0xFF,
                0x0B, 0x7F, 0x29, 0x8B
            ],
        );

        // Write another zero byte and check that the seed changes as expected.
        transcript.write_byte_array(&[0]).unwrap();
        let seed = transcript.fsprf_seed.clone().finalize();
        assert_eq!(
            seed.as_slice(),
            &[
                0x18, 0x19, 0x78, 0x38, 0x0b, 0x6f, 0xf3, 0x21, 0x85, 0xc8, 0x28, 0xd9, 0xa0, 0x07,
                0xee, 0x93, 0x0b, 0xce, 0x2e, 0x94, 0x7f, 0x88, 0x7f, 0x85, 0xb6, 0x4f, 0x39, 0x9a,
                0x94, 0xcb, 0xe4, 0xa8
            ],
        )
    }

    // The following tests check our transcript against the output of
    // longfellow-zk/lib/random/transcript.h. The test vectors were generated using the tests in
    // branch https://github.com/tgeoghegan/longfellow-zk/tree/transcript-test-vectors at commit
    // 7f4b9bf1ee7d6c9a13068375620e9026992d0261.
    // These allow us to verify that we writing each type of transcript message, as well as writing
    // all of them together, yields the expected challenges.

    #[test]
    fn test_against_longfellow_zk() {
        let mut transcript = Transcript::initialize(b"test").unwrap();

        // Write a byte array
        let bytes: Vec<_> = (0..100).collect();
        transcript.write_byte_array(&bytes).unwrap();

        // Write a single field element
        transcript
            .write_field_element(&FieldP256::from_u128(7))
            .unwrap();

        // Write an array of field elements
        transcript
            .write_field_element_array(&[FieldP256::from_u128(8), FieldP256::from_u128(9)])
            .unwrap();

        // Sample 16 field elements
        let sampled = transcript.generate_challenge::<FieldP256>(16).unwrap();

        for (expected_challenge, sampled) in [
            "56d1d29388737105265b24587e17478db5cf281f6379356a999ff471aa629d9c",
            "46b49914ac7b79688532aee9fde3845dbc07735842d5d3661754993fbb27a4ad",
            "bde5153c546a54b454e6704ae5befaeae6ba41f9a0d4d9d6b689bd1f642bf077",
            "64796fab12c29526076341f49e193977a0ce73cae39caf8455b911385159c56a",
            "a48c89dfb09e18b5a1ead094e5d8014a9a52ee20d767fc031caf0da52861df6e",
            "55bce962ec1f6ad34193a3c3a7b59209842c41d297c199005626ac4e5212120c",
            "36a2e10d3ca3b03471ff91e6313c41bfd252ccff1fed98936be7d12af875ba0b",
            "f44d4c25022a65fee87503a337953eb3de8343178b4f251c10e2c4446742a3e8",
            "50bfb64435e7b715b2221cd96674e1b370c3c09492577e9e5b32fc0efebac7f7",
            "b8b879fcecea04d3a33beb0222f44c7c0b00eac7119957b1ba285f546eaceaa1",
            "d55ac67c9c1299ec4f0d74cc518a65db326c3844ecb8379acaa3dc8c478ccd3f",
            "18846c55321f503b079793753999d3b40d3fd6007ac3a4138c4d5b38d854c4f7",
            "087e553b81b23462b9a08158f4fd07ce173072eb64381686ed913681462d9128",
            "5564f1f67097e2baea06554129dc05d2bc1e2544d50772af02f2aa9e3133c65e",
            "a387cbf874a79958171dda43c37d461f0be4c17a312893bfdb617c645a00ebda",
            "bd7f5cde08bd403e98c89f26a43a026d6b56940f034c6ee89c3603e6cd99cbb3",
        ]
        .into_iter()
        .zip(sampled)
        {
            let expected_field =
                FieldP256::try_from(hex::decode(expected_challenge).unwrap().as_slice()).unwrap();

            assert_eq!(expected_field, sampled);
        }
    }

    #[test]
    fn test_against_longfellow_zk_byte_array() {
        let mut transcript = Transcript::initialize(b"test").unwrap();

        let bytes: Vec<_> = (0..100).collect();
        transcript.write_byte_array(&bytes).unwrap();

        let sampled = transcript.generate_challenge::<FieldP256>(16).unwrap();

        for (expected_challenge, sampled) in
            ["141bbcbb5410ddeb7039833b736586a020fdd5856379b6c6c683d5ff0b7f298b"]
                .into_iter()
                .zip(sampled)
        {
            let expected_field =
                FieldP256::try_from(hex::decode(expected_challenge).unwrap().as_slice()).unwrap();

            assert_eq!(expected_field, sampled);
        }
    }

    #[test]
    fn test_against_longfellow_zk_single_field_element() {
        let mut transcript = Transcript::initialize(b"test").unwrap();

        transcript
            .write_field_element(&FieldP256::from_u128(7))
            .unwrap();

        let sampled = transcript.generate_challenge::<FieldP256>(16).unwrap();

        for (expected_challenge, sampled) in
            ["7e2697c3bd904dc9b9d9090eacf63d18ce837da2797fc353df98dbaadcf7db79"]
                .into_iter()
                .zip(sampled)
        {
            let expected_field =
                FieldP256::try_from(hex::decode(expected_challenge).unwrap().as_slice()).unwrap();

            assert_eq!(expected_field, sampled);
        }
    }

    #[test]
    fn test_against_longfellow_zk_field_element_array() {
        let mut transcript = Transcript::initialize(b"test").unwrap();

        transcript
            .write_field_element_array(&[FieldP256::from_u128(8), FieldP256::from_u128(9)])
            .unwrap();

        let sampled = transcript.generate_challenge::<FieldP256>(16).unwrap();

        for (expected_challenge, sampled) in
            ["1c6f759de80bdcf538d0bc95cf4cc5e819f207d1904ed533678dfa46a7ffeedc"]
                .into_iter()
                .zip(sampled)
        {
            let expected_field =
                FieldP256::try_from(hex::decode(expected_challenge).unwrap().as_slice()).unwrap();

            assert_eq!(expected_field, sampled);
        }
    }
}
