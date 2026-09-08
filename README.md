# ASCON-IoT

A baseline NIST SP 800-232 Ascon-AEAD128 implementation, kept
deliberately decoupled from any particular random-number generator.

The `ascon-iot` crate wraps the reference RustCrypto Ascon-AEAD128
implementation unmodified (`no_std`, in-place authenticated
encryption, no heap) so that optimized IoT variants can later be
compared against a known-good baseline.

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
