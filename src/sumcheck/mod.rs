//! Commitment to a padded proof of circuit evaluation, per Section 6 ([1]).
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6

use crate::{
    circuit::{Circuit, CircuitLayer, Evaluation},
    fields::FieldElement,
    sumcheck::bind::SumcheckArray,
    transcript::Transcript,
};
use std::mem::swap;

mod bind;

/// Proof constructed by sumcheck.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof<FieldElement> {
    layers: Vec<ProofLayer<FieldElement>>,
}

impl<FE: FieldElement> Proof<FE> {
    /// Decode a proof from the bytes. This can't be an implementation of [`Codec`] because we need
    /// the circuit this is a proof of to know how many layers there rae.
    pub fn decode(
        circuit: &Circuit,
        bytes: &mut std::io::Cursor<&[u8]>,
    ) -> Result<Self, anyhow::Error> {
        let mut proof_layers = Vec::with_capacity(circuit.num_layers.into());

        for circuit_layer in &circuit.layers {
            proof_layers.push(ProofLayer::decode(circuit_layer, bytes)?);
        }

        Ok(Self {
            layers: proof_layers,
        })
    }

    pub fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        // Encode the layers as a fixed length array. That is, no length prefix.
        for layer in &self.layers {
            layer.encode(bytes)?;
        }

        Ok(())
    }
}

impl<FE: FieldElement> Proof<FE> {
    /// Construct a commitment to a padded transcript of the given evaluation of the circuit.
    pub fn new<PadGenerator>(
        circuit: &Circuit,
        evaluation: &Evaluation<FE>,
        transcript: &mut Transcript,
        mut pad_generator: PadGenerator,
    ) -> Result<Proof<FE>, anyhow::Error>
    where
        PadGenerator: FnMut() -> FE,
    {
        let mut proof = Proof {
            layers: Vec::with_capacity(circuit.num_layers.into()),
        };

        // Choose the bindings for the output layer.
        // The spec says to generate "circuit.lv" field elements, which I think has to mean the number
        // of bits needed to describe an output wire.
        let output_wire_bindings = transcript.generate_challenge(circuit.layers[0].logw.into())?;
        let mut bindings = [output_wire_bindings.clone(), output_wire_bindings];

        // Initialize the transcript per "special rules for the first message", with adjustments to
        // match longfellow-zk.
        // https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-3.1.3
        // 3.1.3 item 1 says to append the "Prover message", "which is usually a commitment". I
        // interpret that to mean the first thing written after the session ID (which was handled in
        // Transcript::initialize). But longfellow-zk doesn't do this, so we don't either..
        // 3.1.3 item 2: write circuit ID
        transcript.write_byte_array(&circuit.id)?;
        // 3.1.3 item 2: write inputs. Per the specification, this should be an array of field
        // elements, but longfellow-zk writes each input as an individual field element. Also,
        // longfellow-zk only appends the *public* inputs, but the specification isn't clear about
        // that.
        for input in evaluation
            .inputs()
            .iter()
            .take(circuit.num_public_inputs.into())
        {
            transcript.write_field_element(input)?;
        }

        // 3.1.3 item 2: write outputs. We should look at the output layer of `evaluation` here and
        // write an array of field elements. But longfellow-zk writes a single zero, regardless of
        // how many outputs the actual circuit has.
        transcript.write_field_element(&FE::ZERO)?;

        for (layer_index, layer) in circuit.layers.iter().enumerate() {
            // Choose alpha and beta for this layer
            let alpha = transcript.generate_challenge(1)?[0];
            let beta = transcript.generate_challenge(1)?[0];

            // The combined quad, aka QZ[g, l, r], a three dimensional array.
            let combined_quad = circuit.combined_quad(layer_index, beta)?;

            // Bind the combined quad to g. Because the length of g is the same as the number of bits
            // needed to describe wires on this layer (logw), bound_quad[g, l, r] = 0 for any g > 0.
            // Thus bound_quad is effectively two-dimensional.
            // bound_quad = bound_quad_1 + bound_quad_2; we don't support summing SumcheckArrays
            // together.
            let mut bound_quad_1 = SumcheckArray::bind(&combined_quad, &bindings[0]);
            let mut bound_quad_2 = SumcheckArray::bind(&combined_quad, &bindings[1]) * alpha;

            // Generate the pad for this layer. The pad has the same structure as the proof since the
            // one has to be substracted from the other.
            let layer_pad = ProofLayer {
                polynomials: vec![
                    [Polynomial {
                        p0: pad_generator(),
                        p2: pad_generator(),
                    }; 2];
                    layer.logw.into()
                ],
                vl: pad_generator(),
                vr: pad_generator(),
            };

            // Allocate the proof for this layer. The zero values in the polynomial are not
            // significant. We just need an initial value.
            let mut layer_proof_polynomials = vec![
                [Polynomial {
                    p0: FE::ZERO,
                    p2: FE::ZERO
                }; 2];
                layer.logw.into()
            ];

            let mut left_wires = SumcheckArray::bind(&evaluation.wires[layer_index], &[]);
            let mut right_wires = SumcheckArray::bind(&evaluation.wires[layer_index], &[]);

            for (round, (pad_polynomials, proof_polynomials)) in layer_pad
                .polynomials
                .into_iter()
                .zip(&mut layer_proof_polynomials)
                .enumerate()
            {
                for hand in 0..2 {
                    // Implements the polynomial from the specification:
                    // Let p(x) = SUM_{l, r} bind(QUAD, x)[l, r] * bind(VL, x)[l] * VR[r]
                    let evaluate_polynomial = |at: FE| {
                        let mut point = FE::ZERO;
                        let bind = &[at];
                        let bound_quad_1_at = SumcheckArray::bind(&bound_quad_1, bind);
                        let bound_quad_2_at = SumcheckArray::bind(&bound_quad_2, bind);
                        let bound_left_wires = SumcheckArray::bind(&left_wires, bind);

                        for left_wire_index in 0..layer.num_wires.into() {
                            for right_wire_index in 0..layer.num_wires.into() {
                                // Fix g = 0 when indexing into the bound quad since all other
                                // elements are zero
                                let bound_quad_index = &[0, left_wire_index, right_wire_index];
                                point +=
                                // bind(QUAD, x)[l, r]
                                (bound_quad_1_at.get(bound_quad_index)
                                    + bound_quad_2_at.get(bound_quad_index))
                                // bind(VL, x)[l]
                                * bound_left_wires.get(&[left_wire_index])
                                // VR[r]
                                * right_wires.get(&[right_wire_index]);
                            }
                        }
                        point
                    };

                    // Evaluate the polynomial at P0 and P2, substracting the pad
                    let poly_evaluation = Polynomial {
                        p0: evaluate_polynomial(FE::ZERO) - pad_polynomials[hand].p0,
                        p2: evaluate_polynomial(FE::ONE + FE::ONE) - pad_polynomials[hand].p2,
                    };

                    // Commit to the padded polynomial.
                    transcript
                        .write_field_element_array(&[poly_evaluation.p0, poly_evaluation.p2])?;

                    proof_polynomials[hand] = poly_evaluation;

                    let challenge = transcript.generate_challenge(1)?;

                    // Generate an element of the binding for the next layer.
                    bindings[hand][round] = challenge[0];

                    // Bind the current left wires and the quad to the challenge
                    left_wires.rebind(&challenge);
                    bound_quad_1.rebind(&challenge);
                    bound_quad_2.rebind(&challenge);

                    swap(&mut left_wires, &mut right_wires);
                    bound_quad_1.transpose();
                    bound_quad_2.transpose();
                }
            }

            let layer_proof = ProofLayer {
                polynomials: layer_proof_polynomials,
                vl: left_wires.get(&[0]) - layer_pad.vl,
                vr: right_wires.get(&[0]) - layer_pad.vr,
            };

            // Commit to the padded evaluations of l and r
            transcript.write_field_element(&layer_proof.vl)?;
            transcript.write_field_element(&layer_proof.vr)?;

            proof.layers.push(layer_proof);
        }

        Ok(proof)
    }
}

/// Sumcheck proof for a circuit layer.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ProofLayer<FieldElement> {
    /// A pair of polynomials (one for each hand) for each bit needed to describe a wire on the
    /// layer. That is, there are logw pairs.
    polynomials: Vec<[Polynomial<FieldElement>; 2]>,
    /// vl is (perhaps?) the evaluation of the "unique multi-linear extension" for the array of
    /// wires at this layer, evaluated at a random point l. Referred to as "wc0" elsewhere.
    /// See https://eprint.iacr.org/2024/2010.pdf p. 9
    vl: FieldElement,
    /// vr is similar to vl but evaluated at random point r. Referred to as "wc1" elsewhere.
    vr: FieldElement,
}

/// Proof layer serialization corresponds to PaddedTranscriptLayer in [7.3][1].
///
/// https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-7.3
impl<FE: FieldElement> ProofLayer<FE> {
    /// Decode a proof layer from the bytes. We can't implement [`Codec`] here because we need some
    /// context (the corresponding circuit layer) to determine how many elements the layer should
    /// contain.
    pub fn decode(
        circuit_layer: &CircuitLayer,
        bytes: &mut std::io::Cursor<&[u8]>,
    ) -> Result<Self, anyhow::Error> {
        // The specification's "wires" corresponds to our "polynomials".
        // For each bit needed to describe a wire (logw), we have tow hands and two polynomial
        // evaluations (at P0 and P2).
        let wires = FE::decode_fixed_array(bytes, usize::from(circuit_layer.logw) * 4)?;

        // Each 4 field elements in the array makes a pair of Polynomials.
        // It would be good to avoid the copies of field elements here, but none of the methods that
        // would do the trick (Vec::into_chunks or Iterator::array_chunks) are in stable Rust.
        let polynomials = wires
            .as_chunks::<4>()
            .0
            .iter()
            .map(|[p0_0, p2_0, p0_1, p2_1]| {
                [
                    Polynomial {
                        p0: *p0_0,
                        p2: *p2_0,
                    },
                    Polynomial {
                        p0: *p0_1,
                        p2: *p2_1,
                    },
                ]
            })
            .collect();

        // In the specification, this is wc0
        let vl = FE::decode(bytes)?;
        let vr = FE::decode(bytes)?;

        Ok(Self {
            polynomials,
            vl,
            vr,
        })
    }

    /// Encode the proof layer into the provided bytes.
    pub fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        // Fixed length array, whose length depends on the circuit this is a proof of.
        for pair in &self.polynomials {
            for polynomial in pair {
                polynomial.p0.encode(bytes)?;
                polynomial.p2.encode(bytes)?;
            }
        }

        self.vl.encode(bytes)?;
        self.vr.encode(bytes)?;

        Ok(())
    }
}

/// A polynomial of degree 2, represented by its evaluations at points `p0` (the field's additive
/// identity, aka 0) and `p2` (the field's multiplicative identity added to itself, aka 1 + 1) (see
/// [6.4][1]. The  evaluation at `p1` (the multiplicative identity aka 1) is "implied and not
/// needed" ([6.5][2]).
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.4
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.5
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Polynomial<FE> {
    p0: FE,
    p2: FE,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{circuit::tests::CircuitTestVector, fields::fieldp128::FieldP128};
    use std::io::Cursor;

    #[test]
    fn longfellow_rfc_1_87474f308020535e57a778a82394a14106f8be5b() {
        let (_, circuit) =
            CircuitTestVector::decode("longfellow-rfc-1-87474f308020535e57a778a82394a14106f8be5b");

        // This circuit verifies that 2n = (s-2)m^2 - (s - 4)*m. For example, C(45, 5, 6) = 0.
        let evaluation: Evaluation<FieldP128> = circuit.evaluate(&[45, 5, 6]).unwrap();

        // Matches session used in longfellow-zk/lib/zk/zk_test.cc
        let mut transcript = Transcript::initialize(b"test").unwrap();

        let proof = Proof::new(
            &circuit,
            &evaluation,
            &mut transcript,
            // Transcript/FSPRF output is deterministic for a given session ID and sequence of
            // inputs, but the pad is implied to be constructed of uniformly sampled field elements.
            // To get deterministic output we can test against vectors, fix the pad source to
            // always yield zero.
            || FieldP128::ZERO,
        )
        .unwrap();

        let mut proof_encoded = Vec::new();
        proof.encode(&mut proof_encoded).unwrap();

        let test_vector_serialized = hex::decode(
            "0000000000000000000000000000000000000000000000000000000000000000e7c951af1bc374e667d6025d0c22f4cb6f3fc9110e466e520aa972c8cdc6c51d71133660d6eb7076da4104ec524752036815eeb3babca7df4ee98ed27f014a5bbf3471cc49ff778705d70baaab6d33a9e8e604e93758ce8e89f9e8060b0172a0d73b90e11fa6aa778da869a07819df713221d02687d9939d2fb921e7351beb0626db9648984cd44c549c562dc65d1ef751b1b825a26eaf195238c0c5c14b6ede2ea2ee8c3d6cc4f5df3086cc6330879c532fceabb2620fa8bd6999a64406b39d5c9f3038bf87bba0a0f7c926fbfafe012832d053f8473bf298a01ae125f54723aebb0e85a2e1220d4c5e0f8b6c4ee3f51d7d6bfaf324fd6838d746057121e1ece7885531ce13bd3403e0ddfcc317faf0fbba77ed493e086026764482ad07c3973971564c1ebff1704d3b0c2f2de798ec036102a6e830db10d8a0c8666099a3ff14bda7be46c71704b8f0294a306084fee067e9b17ff8a6ade920a6097dc095a3",
        ).unwrap();

        let test_vector_decoded =
            Proof::decode(&circuit, &mut Cursor::new(&test_vector_serialized)).unwrap();

        assert_eq!(
            proof, test_vector_decoded,
            "ours: {proof:#?}\n\ntheirs: {test_vector_decoded:#?}"
        );

        // ours is 9 bytes too long? I expect it ot be wrong because I haven't done the magic in 3.1.3
        // yet but including more stuff in the FSPRF shouldn't affect the size of the serialized message
        // the leading 0s in theirs are suspicious
        println!(
            "proof_encoded: {} theirs encoded {}",
            proof_encoded.len(),
            test_vector_serialized.len()
        );

        assert_eq!(proof_encoded, test_vector_serialized);
    }
}
