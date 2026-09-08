# Ascon-AEAD128 test-vector provenance

The file:

`LWC_AEAD_KAT_128_128.txt`

comes from the canonical `ascon/ascon-c` repository.

Source repository:

https://github.com/ascon/ascon-c

Pinned source commit:

`446347f21b209f3921c65ece70027c366cbe1693`

Source path:

`crypto_aead/asconaead128/LWC_AEAD_KAT_128_128.txt`

SHA-256:

`bbbc34692fe05e5fda0a3b025585622ab3e3747495e5e3655b29aae8c2a4bd33`

The vector set contains 1089 Ascon-AEAD128 test cases.

At the pinned source commit, the reference C implementation was
compiled locally using `tests/genkat_aead.c`.

The generated `LWC_AEAD_KAT_128_128.txt` was compared byte-for-byte
against the repository vector file using `diff`, with no differences.

ASCON-IoT verifies all 1089 vectors for both encryption and decryption
in `tests/full_kat.rs`.
