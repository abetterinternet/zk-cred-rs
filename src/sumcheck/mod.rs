use crate::{
    circuit::{Circuit, Evaluation},
    fields::FieldElement,
    sumcheck::bind::SumcheckArray,
    transcript::Transcript,
};

mod bind;

/// Proof constructed by sumcheck.
pub struct Proof<FieldElement> {
    // I think this is a 2d ragged array of field elements.
    elements: Vec<Vec<FieldElement>>,
}

pub fn sumcheck_circuit<FE: FieldElement>(
    circuit: &Circuit,
    wires: &Evaluation<FE>,
    pad: Vec<Vec<FE>>,
    transcript: &mut Transcript,
) -> Result<Proof<FE>, anyhow::Error> {
    // Choose the bindings for the output layer.
    // The spec says to generate "circuit.lv" field elements, but this is really
    // circuit.layers[0].logw, the number of bits needed to describe an output wire.
    let output_wire_bindings =
        transcript.generate_challenge::<FE>(circuit.layers[0].logw.into())?;
    let g = [&output_wire_bindings, &output_wire_bindings];
    let mut proof = Vec::new();

    for (layer_index, layer) in circuit.layers.iter().enumerate() {
        // Choose alpha and beta for this layer
        let alpha: FE = transcript.generate_challenge(1)?[0];
        let beta: FE = transcript.generate_challenge(1)?[0];

        // The combined quad, aka QZ[g, l, r], a three dimensional matrix
        let combined_quad = circuit.combined_quad(layer_index, beta)?;

        // Bind the combined quad to g, reducing it to a two dimensional matrix
        // QUAD[l, r].
        let bound_quad1 = SumcheckArray::bind(&combined_quad, g[0]);
        let bound_quad_2 = SumcheckArray::bind(&combined_quad, g[1]) * alpha;

        /*

        (proof[j], G) =
            sumcheck_layer(QUAD, wires[j], circuit.layer[j].lv,
                           pad[j], transcript)
                           */
        for round in 0..layer.logw {}
    }
    todo!()
}
