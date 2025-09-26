#!/usr/bin/env sh
set -ev

# The fiat-crypto binaries must be on the path already. These are at
# `src/ExtractionOCaml/word_by_word_montgomery` and
# `src/ExtractionOCaml/unsaturated_solinas` in the checkout. See README.md for
# compilation instructions.

cd "$(dirname "$0")"

word_by_word_montgomery \
    --lang Rust \
    --inline \
    -o fieldp256/ops.rs \
    p256 \
    64 \
    '2^256 - 2^224 + 2^192 + 2^96 - 1' \
    to_montgomery from_montgomery \
    to_bytes from_bytes \
    add sub opp \
    mul square \
    selectznz \
    one

unsaturated_solinas \
    --lang Rust \
    --inline \
    -o fieldp521/ops.rs \
    p521 \
    64 \
    '(auto)' \
    '2^521 - 1' \
    carry relax \
    to_bytes from_bytes \
    add sub opp \
    carry_add carry_sub carry_opp \
    carry_mul carry_square \
    selectznz

word_by_word_montgomery \
    --lang Rust \
    --inline \
    -o fieldp128/ops.rs \
    p128 \
    64 \
    '2^128 - 2^108 + 1' \
    to_montgomery from_montgomery \
    to_bytes from_bytes \
    add sub opp \
    mul square \
    selectznz \
    one
