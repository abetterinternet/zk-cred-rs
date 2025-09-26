use std::mem::swap;

use crate::{
    circuit::{Circuit, Evaluation},
    sumcheck::bind::SumcheckArray,
    transcript::Transcript,
};
use rand::prelude::*;
use zk_cred_longfellow_fields::FieldElement;

mod bind;

/// Proof constructed by sumcheck.
#[derive(Clone, Debug)]
pub struct Proof<FieldElement> {
    layers: Vec<ProofLayer<FieldElement>>,
}

/// Sumcheck proof for a circuit layer.
#[derive(Clone, Debug)]
struct ProofLayer<FieldElement> {
    /// For each wire in the layer, a pair of polynomials is generated (one for each hand)
    polynomials: Vec<[Polynomial<FieldElement>; 2]>,
    /// vl is (perhaps?) the evaluation of the "unique multi-linear extension" for the array of
    /// wires at this layer, evaluated at a random point l.
    /// See https://eprint.iacr.org/2024/2010.pdf p. 9
    vl: FieldElement,
    /// vr is similar to vl but evaluated at random point r.
    vr: FieldElement,
}

/// A polynomial of degree 2, represented by its evaluations at points `p0` (the field's additive
/// identity, aka 0) and `p2` (the field's multiplicative identity added to itself, aka 1 + 1) (see
/// [6.4][1]. The  evaluation at `p1` (the multiplicative identity aka 1) is "implied and not
/// needed" ([6.5][2]).
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.4
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.5
#[derive(Clone, Copy, Debug)]
struct Polynomial<FE> {
    p0: FE,
    p2: FE,
}

pub fn sumcheck_circuit<FE: FieldElement>(
    circuit: &Circuit,
    evaluation: &Evaluation<FE>,
    transcript: &mut Transcript,
) -> Result<Proof<FE>, anyhow::Error> {
    let mut proof = Proof {
        layers: Vec::with_capacity(circuit.num_layers.into()),
    };

    // Choose the bindings for the output layer.
    // The spec says to generate "circuit.lv" field elements, which I think has to mean the number
    // of bits needed to describe an output wire.
    let output_wire_bindings = transcript.generate_challenge(circuit.layers[0].logw.into())?;
    let mut bindings = [output_wire_bindings.clone(), output_wire_bindings];

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
                    p0: FE::random(thread_rng()),
                    p2: FE::random(thread_rng())
                }; 2];
                layer.logw.into()
            ],
            vl: FE::random(thread_rng()),
            vr: FE::random(thread_rng()),
        };

        // Allocate the proof for this layer. The zero values in the polynomial don't mean anything.
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
                            // Fix g = 0 when indexing into the bound quad since all other elements
                            // are zero
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
                transcript.write_field_element_array(&[poly_evaluation.p0, poly_evaluation.p2])?;

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
