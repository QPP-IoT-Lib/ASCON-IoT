# Differential and negative-authentication validation

## Reference implementations

ASCON-IoT Rust baseline commit before this phase:

`978ecb08e409f96bda6270f9a661396f3619ca79`

Canonical C reference repository:

`ascon/ascon-c`

Pinned C reference commit:

`446347f21b209f3921c65ece70027c366cbe1693`

RustCrypto AEAD implementation:

`677cf651adcf22321d57c46e52f67afc36d36014`

Rust toolchain:

`1.97.1`

## Differential encryption/interoperability test

The deterministic differential test used SHAKE256-derived inputs and
did not use QPP-RNG or operating-system randomness.

Cases:

`1000`

Input coverage included boundary lengths around:

- 0 bytes
- 8 bytes
- 16 bytes
- 32 bytes
- 64 bytes
- 128 bytes
- 256 bytes

Additional deterministic cases covered plaintext and associated-data
lengths up to 1024 bytes.

Results:

- Rust/C encryption identical: 1000 / 1000
- Rust successfully decrypted C output: 1000 / 1000
- C successfully decrypted Rust output: 1000 / 1000
- Ciphertext mismatches: 0
- Tag mismatches: 0
- Plaintext mismatches: 0

Result:

`PASS`

## Internal negative-authentication tests

Cases:

`256`

Each valid case was first successfully decrypted as a control.

For every case, the following manipulations were tested:

- modified authentication tag
- modified ciphertext
- modified associated data
- wrong nonce
- wrong key

Results:

- Valid decryptions: 256 / 256
- Modified tag rejected: 256 / 256
- Modified ciphertext rejected: 256 / 256
- Modified associated data rejected: 256 / 256
- Wrong nonce rejected: 256 / 256
- Wrong key rejected: 256 / 256

Total negative checks:

`1280`

Unexpected acceptances:

`0`

Result:

`PASS`

## Cross-implementation negative tests

Cases:

`256`

Valid interoperability controls:

- Rust valid controls: 256 / 256
- C valid controls: 256 / 256

Each manipulated input was submitted independently to both the Rust
implementation and the pinned C reference.

Results:

- Modified tag rejected: 512 / 512
- Modified ciphertext rejected: 512 / 512
- Modified associated data rejected: 512 / 512
- Wrong nonce rejected: 512 / 512
- Wrong key rejected: 512 / 512

Total cross-implementation negative checks:

`2560`

Unexpected acceptances:

`0`

Result:

`PASS`

## Summary

Differential/interoperability comparisons:

`3000`

Internal negative-authentication checks:

`1280`

Cross-implementation negative-authentication checks:

`2560`

Total targeted checks:

`6840`

In addition, the negative-test suites executed 768 valid decryption
controls.

No cryptographic output discrepancies or unexpected authentication
acceptances were observed.

These tests provide local reproducible implementation-equivalence and
authentication-failure evidence. They are not a formal CAVP validation
or NIST certification.

## SHA-256 evidence

`tools/differential/ascon_c_driver.c`

`ed063d598be558bb546bf868bd115b29d381bfddc0ff46959414e8a19e9dd6cd`

`tools/differential/run_differential.py`

`7343d0dfd95f564d6d6fa9954791746781849250b6065219ea5ac93f7f56f246`

`tools/differential/run_negative_cross.py`

`92e15747b67476fc43f95f0ba26321c4b3b492c059d51bd35607bd6cc256e363`

`crates/ascon-iot/examples/differential_case.rs`

`92b8d1e4d8bdd7de586bb0ca3d006886ba3135d23304520155686a5493b1f441`

`crates/ascon-iot/tests/negative_auth.rs`

`fd67d9cff0f628f7f15c8c3486175581ad3364ab8417718e901de0fc67235740`

