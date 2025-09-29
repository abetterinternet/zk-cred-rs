use std::{fs, io::Cursor, path::PathBuf};

use anyhow::anyhow;
use zk_cred_rs::{
    Codec, Size,
    circuit::{Circuit, CircuitLayer, Quad},
};

fn main() {
    // Decode 1-parameter mdoc circuits.
    let path = PathBuf::from(
        "test-vectors/89288b9aa69d2120d211618fcca8345deb4f85d2e710c220cc9c059bbee4c91f",
    );
    let compressed_original = fs::read(path).unwrap();
    let decompressed_original = zstd::decode_all(compressed_original.as_slice()).unwrap();
    let mut cursor = Cursor::new(decompressed_original.as_slice());
    let sig_circuit = Circuit::decode(&mut cursor).unwrap();
    let hash_circuit = Circuit::decode(&mut cursor).unwrap();
    assert_eq!(
        cursor.position(),
        cursor.get_ref().len().try_into().unwrap()
    );

    let mut decompressed_no_delta = Vec::new();
    alternate_encode_circuit(&sig_circuit, &mut decompressed_no_delta).unwrap();
    alternate_encode_circuit(&hash_circuit, &mut decompressed_no_delta).unwrap();
    let compressed_no_delta = zstd::encode_all(decompressed_no_delta.as_slice(), 16).unwrap();

    assert_eq!(decompressed_original.len(), decompressed_no_delta.len());
    println!("Decompressed size:     {}", decompressed_original.len());
    println!("Zstd + delta encoding: {}", compressed_original.len());
    println!("Zstd alone:            {}", compressed_no_delta.len());
}

fn alternate_encode_circuit(circuit: &Circuit, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
    circuit.version.encode(bytes)?;
    circuit.field.encode(bytes)?;
    circuit.num_outputs.encode(bytes)?;
    circuit.num_copies.encode(bytes)?;
    circuit.num_public_inputs.encode(bytes)?;
    circuit.subfield_boundary.encode(bytes)?;
    circuit.num_inputs.encode(bytes)?;
    circuit.num_layers.encode(bytes)?;

    // Encode constant table: first a count of elements, then each element's length is obtained
    // from the field ID.
    Size::from(circuit.constant_table.len() as u32).encode(bytes)?;
    for constant in &circuit.constant_table {
        constant.encode(bytes)?;
    }

    if usize::from(circuit.num_layers) != circuit.layers.len() {
        return Err(anyhow!("num_layers does not match length of layers array"));
    }
    for layer in circuit.layers.iter() {
        alternate_encode_layer(layer, bytes)?;
    }
    bytes.extend_from_slice(&circuit.id);

    Ok(())
}

fn alternate_encode_layer(layer: &CircuitLayer, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
    layer.logw.encode(bytes)?;
    layer.num_wires.encode(bytes)?;
    Size::from(layer.quads.len() as u32).encode(bytes)?;

    for quad in &layer.quads {
        alternate_encode_quad(quad, bytes)?;
    }

    Ok(())
}

fn alternate_encode_quad(quad: &Quad, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
    quad.gate_index.encode(bytes)?;
    quad.left_wire_index.encode(bytes)?;
    quad.right_wire_index.encode(bytes)?;
    quad.const_table_index.encode(bytes)?;

    Ok(())
}
