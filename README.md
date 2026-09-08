# ASCON-IoT

A baseline NIST SP 800-232 Ascon-AEAD128 implementation, kept
deliberately decoupled from any particular random-number generator.

The `ascon-iot` crate wraps a pinned RustCrypto Ascon-AEAD128
implementation without changing its cryptographic behavior
(`no_std`, in-place authenticated encryption, no heap), so that
optimized IoT variants can later be compared against a reproducible
baseline.

RustCrypto is used as the Rust baseline implementation. The canonical
independent reference used for verification is the `ascon/ascon-c`
implementation.

Callers supply random material (keys, nonces) from any source
implementing `rand_core::Rng`. The integration test in
[`crates/ascon-iot/tests/qpp_integration.rs`](crates/ascon-iot/tests/qpp_integration.rs)
demonstrates this using [QPP-RNG](https://github.com/QPP-IoT-Lib/QPP-RNG-IoT),
pulled in as a dev-dependency rather than a workspace member, so the
two projects stay independently versioned and released.

## Layout

```
crates/
  ascon-iot/        # Baseline Ascon-AEAD128 implementation
```

## Testing

```bash
cargo test --workspace --all-targets
```


## Verification

ASCON-IoT has been verified using:

- the complete 1089-case Ascon-AEAD128 KAT set;
- encryption and decryption verification for all 1089 vectors;
- independent reproduction of the KAT file using the pinned
  `ascon/ascon-c` reference implementation;
- a local NIST ACVP end-to-end validation for the supported profile.

The ACVP test set contained 120 AFT cases:

- 60 encryption cases;
- 60 decryption cases;
- 30 valid decryptions accepted;
- 30 invalid authentication cases rejected.

The NIST GenVal validator reported:

`120 / 120 passed`

Full ACVP provenance and SHA-256 evidence are documented in:

`docs/validation-acvp.md`

KAT provenance is documented in:

`crates/ascon-iot/tests/vectors/README.md`

This local ACVP verification is not a formal CAVP validation or NIST
certification.
