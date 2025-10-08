# Test vectors

## Circuits

[`draft-google-cfrg-libzk-00`][draft-google-cfrg-libzk] contains a test vector for a serialized
circuit, but it does not appear to correspond to either the structure definitions in that same
document, or to the circuit serialization implementation in
[`longfellow-zk/lib/proto/circuit.h`][longfellow-circuit-proto].

Presumably the test vector was generated from some intermediate version of longfellow-zk, but
there's not much to be done with it.

The test vector format is a JSON document describing the test vector. Alongside it are files
containing:

- the zstd compressed serialization of the circuit. Circuits are compressed using `zstd(1)` with
  default options:

```sh
> zstd --version
*** Zstandard CLI (64-bit) v1.5.7, by Yann Collet ***
> zstd /path/to/uncompressed/circuit test-vectors/circuit/circuit-name.circuit.zst
```

- the serialization of the padded sumcheck proof of the evaluation of the circuit. These are not
  compressed since proofs are padded with random values and thus don't compress efficiently. Not
  every test vector includes a proof.

[longfellow-circuit-proto]: https://github.com/google/longfellow-zk/blob/main/lib/proto/circuit.h

### `longfellow-rfc-1-87474f308020535e57a778a82394a14106f8be5b-1`

This test vector was generated using [`longfellow-zk/lib/zk/zk-test.cc`][rfc-1-test-vector] at
commit 87474f308020535e57a778a82394a14106f8be5b and the serializations for circuits, layers and
quads at that version.

[rfc-1-test-vector]: https://github.com/google/longfellow-zk/blob/87474f308020535e57a778a82394a14106f8be5b/lib/zk/zk_test.cc

### `longfellow-mac-circuit-902a955fbb22323123aac5b69bdf3442e6ea6f80-1`

This test vector was generated using [`longfellow-zk/lib/circuits/mac/mac_circuit_test.cc`][mac-test-vector-1]
at commit 902a955fbb22323123aac5b69bdf3442e6ea6f80 and the serializations for circuits, layers and
quads at that version.

[mac-test-vector-1]: https://github.com/google/longfellow-zk/blob/902a955fbb22323123aac5b69bdf3442e6ea6f80/lib/circuits/mac/mac_circuit_test.cc

[draft-google-cfrg-libzk]: https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/
