# Test vectors

## Circuits

[`draft-google-cfrg-libzk-00`][draft-google-cfrg-libzk] contains a test vector for a serialized
circuit, but it does not appear to correspond to either the structure definitions in that same
document, or to the circuit serialization implementation in
[`longfellow-zk/lib/proto/circuit.h`](https://github.com/google/longfellow-zk/blob/main/lib/proto/circuit.h).
Presumably the test vector was generated from some intermediate version of longfellow-zk, but
there's not much to be done with it.

### `longfellow-87474f308020535e57a778a82394a14106f8be5b-1`

This test vector was generated using [`longfellow-zk/lib/zk/zk-test.cc`](https://github.com/google/longfellow-zk/blob/main/lib/zk/zk_test.cc)
at commit 87474f308020535e57a778a82394a14106f8be5b and the serializations for circuits, layers and
quads at that version.

[draft-google-cfrg-libzk]: https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/
