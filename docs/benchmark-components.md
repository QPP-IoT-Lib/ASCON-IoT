# ASCON-IoT component and associated-data benchmark

## Scope

This document records the second host performance characterization
phase for ASCON-IoT.

The purpose is to separate and characterize:

- cipher-object construction from an already available key;
- baseline AEAD operation cost;
- plaintext processing cost;
- associated-data processing cost;
- behavior at 16-byte associated-data boundaries.

The cryptographic implementation itself was not modified for this
benchmark.

Validated cryptographic baseline:

`0f6f3a853fa0731edaf986c60d30f945a299b007`

Previous host benchmark commit:

`0472962dcc1a30217d0c6c439e52c85a2dfc274b`

## Environment

The measurements were performed on the same host environment used for
the host baseline benchmark:

- WSL2
- x86_64
- Intel Core i5-1135G7
- 4 physical cores / 8 logical CPUs
- Rust 1.97.1

The benchmark process was pinned to logical CPU 0 with:

`taskset -c 0`

These results are host software measurements and must not be
extrapolated to Raspberry Pi, ESP32, AVR, or other embedded targets.

## Methodology

Algorithm:

`Ascon-AEAD128`

Authentication tag:

`128 bits`

Plaintext sizes:

- 0 bytes
- 64 bytes
- 256 bytes

Associated-data sizes:

- 0 bytes
- 1 byte
- 15 bytes
- 16 bytes
- 17 bytes
- 31 bytes
- 32 bytes
- 33 bytes
- 64 bytes
- 128 bytes
- 256 bytes
- 512 bytes
- 1024 bytes

Each benchmark execution used seven timing samples per configuration.

Five independent executions were performed.

The official values are the medians across those five executions.

Plaintext generation, ciphertext preparation, and tag preparation were
performed outside the timed regions.

## Cipher construction

The benchmark separately measured construction of
`BaselineAsconAead128` from an already available 128-bit key.

Median result:

`0.59 ns/op`

Observed range:

`0.53 - 0.73 ns/op`

This measurement does not include:

- QPP-RNG execution;
- entropy collection;
- key generation;
- nonce generation;
- AEAD state initialization;
- permutation execution.

The sub-nanosecond result should therefore be interpreted only as
evidence that wrapper/cipher-object construction is negligible on this
host relative to an AEAD operation.

It should not be treated as a precise architecture-independent
cryptographic initialization cost.

## Associated-data boundary behavior

Ascon-AEAD128 uses a 16-byte rate.

The benchmark deliberately included measurements immediately around
16-byte boundaries.

### Zero-byte plaintext

| Operation | AD | Median ns/op |
| --- | ---: | ---: |
| Encrypt | 15 B | 174.09 |
| Encrypt | 16 B | 205.18 |
| Encrypt | 17 B | 211.87 |
| Encrypt | 31 B | 211.33 |
| Encrypt | 32 B | 247.43 |
| Encrypt | 33 B | 252.20 |
| Decrypt | 15 B | 172.17 |
| Decrypt | 16 B | 203.05 |
| Decrypt | 17 B | 212.54 |
| Decrypt | 31 B | 218.79 |
| Decrypt | 32 B | 246.08 |
| Decrypt | 33 B | 247.94 |

Observed median boundary increments:

- Encrypt 15 -> 16 B: +31.09 ns
- Encrypt 31 -> 32 B: +36.10 ns
- Decrypt 15 -> 16 B: +30.88 ns
- Decrypt 31 -> 32 B: +27.29 ns

### 64-byte plaintext

| Operation | AD | Median ns/op |
| --- | ---: | ---: |
| Encrypt | 15 B | 341.35 |
| Encrypt | 16 B | 378.38 |
| Encrypt | 17 B | 381.75 |
| Encrypt | 31 B | 377.79 |
| Encrypt | 32 B | 414.47 |
| Encrypt | 33 B | 421.00 |
| Decrypt | 15 B | 321.93 |
| Decrypt | 16 B | 350.30 |
| Decrypt | 17 B | 362.04 |
| Decrypt | 31 B | 366.00 |
| Decrypt | 32 B | 401.33 |
| Decrypt | 33 B | 402.56 |

Observed median boundary increments:

- Encrypt 15 -> 16 B: +37.03 ns
- Encrypt 31 -> 32 B: +36.68 ns
- Decrypt 15 -> 16 B: +28.37 ns
- Decrypt 31 -> 32 B: +35.33 ns

These measurements are consistent with the block-oriented processing
of associated data.

Individual short-duration measurements remain sensitive to WSL2
scheduling, frequency changes, and timer noise, so the boundary values
should be interpreted from the repeated-run medians rather than from a
single execution.

## Large associated-data cost

For 1024 bytes of associated data, the measured incremental cost
relative to AD=0 was:

| Operation | PT | Increment |
| --- | ---: | ---: |
| Encrypt | 0 B | +2768.25 ns |
| Encrypt | 64 B | +2834.80 ns |
| Encrypt | 256 B | +2754.19 ns |
| Decrypt | 0 B | +2739.54 ns |
| Decrypt | 64 B | +2731.87 ns |
| Decrypt | 256 B | +2728.98 ns |

The similar increments across different plaintext sizes indicate that
the benchmark is successfully isolating a largely independent
associated-data processing cost.

For this specific x86_64/WSL2 implementation and environment, the
large-AD measurements are consistent with an incremental cost on the
order of roughly 42-44 ns per 16-byte absorption step.

This is an implementation- and platform-specific observation, not a
portable Ascon performance constant.

## Reproducibility

Benchmark source:

`crates/ascon-iot/examples/benchmark_components.rs`

SHA-256:

`bbff97d069a395aa5a090aa411b8e55dfa86c690ee5a327eb3bc3493d3eda5c8`

Aggregation script:

`tools/benchmark/summarize_components.py`

SHA-256:

`b73d2d81dcdae7bf4ad183cf5613686e80a963728853276e1c66a0255a2796d0`

Pinned run 1:

`4249c4e601aac022e48f2824a7f61e488ef9c580280a3b7811359ff6dcd42aad`

Pinned run 2:

`c6d38f121bdc31e942a7bbb8168d658d7d848812603c0d6bac73a27c042c2896`

Pinned run 3:

`a204c0fbb1766c8cc02152a0f54d0e2ffa3b9fae56989a43af9895521deba987`

Pinned run 4:

`cd4d6582a79e4159db0b8531e2621710deaa4774694b7f8d2840d99b03f22fbe`

Pinned run 5:

`2ef3d02f2686bc0bd161c8f1ae9929bf074f39fd1ec9cd4df1fdaddace3a2933`

Aggregated summary:

`acb0ade667d16d3a0a331be3dac4bea21a4d79b3e2c8c3862f8f05f278db0400`

The raw run files and generated CSV summary remain outside the Git
repository in the local validation-artifacts directory.

## Limitations

These measurements were collected under WSL2.

Therefore:

- CPU frequency was not locked;
- scheduler and virtualization noise remain possible;
- hardware performance counters were not collected;
- sub-nanosecond cipher-construction timing should not be interpreted
  as a precise physical latency;
- results must be independently measured on actual embedded hardware.

This benchmark establishes a reproducible host comparison baseline for
later architecture-specific measurements.
