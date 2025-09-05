//! Implements sumcheck, which is a system that for some circuit `C`, an input `x` and a witness
//! `w`, `C(x, w) = 0`.

use crate::{circuit::Circuit, fields::FieldElement};
use anyhow::{Context, anyhow};
use ff::PrimeField;
use std::collections::BTreeMap;

pub trait Evaluate<FieldElement: PrimeField> {
    /// Evaluate the circuit with the provided inputs.
    ///
    /// Bugs: taking inputs as u128 is inadequate for larger fields like P256.
    fn evaluate(&self, inputs: &[u128]) -> Result<Evaluation<FieldElement>, anyhow::Error>;
}

impl<FE: FieldElement> Evaluate<FE> for Circuit {
    /// Evaluate the circuit with the provided inputs.
    ///
    /// Bugs: taking inputs as u128 is inadequate for larger fields like P256.
    fn evaluate(&self, inputs: &[u128]) -> Result<Evaluation<FE>, anyhow::Error> {
        let inputs: Vec<_> = inputs.iter().map(|input| FE::from_u128(*input)).collect();
        // There are n layers of gates, but with the inputs, we have n + 1 layers of wires.
        let mut wires = Vec::with_capacity(self.layers.len() + 1);

        // "By convention, the input wire Vj[0] = 1 for all layers, and thus the quad representation
        // handles the classic add and multiplication gates in a uniform manner."
        // This is because we represent constants in the circuit by multiplying the input 1 by
        // whatever the value we need. We apply this fixup only for the first layer, as subsequent
        // layers are constructed to propagate the constant 1.
        //
        // https://eprint.iacr.org/2024/2010.pdf, section 2.1
        wires.push([&[FE::ONE], inputs.as_slice()].concat());

        for (layer_index, layer) in self
            .layers
            .iter()
            // In the serialized format, the input layer comes last, so reverse the layers iterator.
            .rev()
            .enumerate()
        {
            // A single gate may receive contributions from multiple quads, so accumulate gate
            // evaluations into a BTreeMap keyed by gate number, which can then be efficiently
            // converted to a vector of gate output values.
            let mut gate_outputs = BTreeMap::new();
            for (quad_index, quad) in layer.quads.iter().enumerate() {
                // Evaluate this quad: look up its value in the constants table, then multiply that
                // by the value of the input wires.
                let quad_value: FE = self.constant(quad.const_table_index).context(format!(
                    "constant missing in quad {quad_index} on layer {layer_index}"
                ))?;
                let left_wire = wires[layer_index]
                    .get(usize::from(quad.left_wire))
                    .ok_or_else(|| {
                        anyhow!(
                            "quad {quad_index} on layer {layer_index} contains left wire index {} \
                        not present in previous layer of circuit {:?}",
                            quad.left_wire,
                            wires[layer_index],
                        )
                    })?;
                let right_wire = wires[layer_index]
                    .get(usize::from(quad.right_wire))
                    .ok_or_else(|| {
                        anyhow!(
                            "quad {quad_index} on layer {layer_index} contains right wire index \
                            {} not present in previous layer of circuit {:?}",
                            quad.right_wire,
                            wires[layer_index],
                        )
                    })?;

                let quad_output = quad_value * left_wire * right_wire;

                gate_outputs
                    .entry(quad.gate_number)
                    .and_modify(|v| *v += quad_output)
                    .or_insert(quad_output);
            }

            wires.push(gate_outputs.into_values().collect());
        }

        // Reverse wires so that the inputs come last and the outputs come first.
        wires.reverse();
        Ok(Evaluation { wires })
    }
}

/// The evaluation of a circuit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evaluation<FieldElement> {
    /// The value of each of the wires of the circuit after evaluation. An n-layer circuit has n+1
    /// layers of wire values. Layer index 0 is the outputs and layer index n is the inputs. The
    /// length of each layer depends on the number of gates on each later.
    wires: Vec<Vec<FieldElement>>,
}

impl<FieldElement> Evaluation<FieldElement> {
    pub fn outputs(&self) -> &[FieldElement] {
        self.wires[0].as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::tests::CircuitTestVector;
    use crate::fields::fieldp128::FieldP128;
    use ff::Field;

    #[test]
    fn evaluate_circuit_longfellow_rfc_1_true() {
        let (_, circuit) =
            CircuitTestVector::decode("longfellow-rfc-1-87474f308020535e57a778a82394a14106f8be5b");

        // This circuit verifies that 2n = (s-2)m^2 - (s - 4)*m. For example, C(45, 5, 6) = 0.
        let evaluation: Evaluation<FieldP128> = circuit.evaluate(&[45, 5, 6]).unwrap();

        // Output size should match circuit serialization and values should all be zero
        assert_eq!(circuit.num_outputs, evaluation.wires[0].len());
        for output in evaluation.outputs() {
            assert_eq!(*output, FieldP128::ZERO);
        }

        // The remaining wire layers should match wire counts claimed by circuit serialization
        for (circuit_layer, evaluation_layer) in
            circuit.layers.iter().zip(evaluation.wires[1..].iter())
        {
            assert_eq!(circuit_layer.num_wires, evaluation_layer.len());
        }
    }

    #[test]
    fn evaluate_circuit_longfellow_rfc_1_false() {
        let (_, circuit) =
            CircuitTestVector::decode("longfellow-rfc-1-87474f308020535e57a778a82394a14106f8be5b");

        // Evaluate with other values. At least one output element should be nonzero.
        assert!(
            circuit
                .evaluate(&[45, 5, 7])
                .unwrap()
                .outputs()
                .iter()
                .any(|output: &FieldP128| *output != FieldP128::ZERO)
        );
    }
}
