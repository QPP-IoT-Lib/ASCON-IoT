# ASCON-IoT host baseline benchmark

## Scope

This document records the host timing baseline for the validated
ASCON-IoT Ascon-AEAD128 implementation.

The cryptographic baseline preceding this benchmark is:

`0f6f3a853fa0731edaf986c60d30f945a299b007`

This benchmark is intended as a reproducible software baseline.

It is not representative of Raspberry Pi, ESP32, AVR, or other IoT
hardware performance.

## Host environment

Operating environment:

- WSL2
- Linux kernel:
  `6.18.33.2-microsoft-standard-WSL2`
- Architecture:
  `x86_64`

Processor:

- Intel Core i5-1135G7 @ 2.40 GHz
- 4 physical cores
- 8 logical CPUs
- 2 threads per core

WSL memory available to the environment during characterization:

- RAM: approximately 3.7 GiB
- Swap: 1.0 GiB

Toolchain:

- Rust:
  `rustc 1.97.1 (8bab26f4f 2026-07-14)`
- Cargo:
  `cargo 1.97.1 (c980f4866 2026-06-30)`
- GCC:
  `13.3.0`
- GNU Binutils:
  `2.42`

`perf` was not available in the WSL environment, so hardware-cycle
measurements were not included in this host baseline.

## Algorithm configuration

Algorithm:

`Ascon-AEAD128`

Standard:

`NIST SP 800-232`

Authentication tag:

`128 bits`

Associated data for this benchmark:

`0 bytes`

Key setup was performed outside the timed encryption and decryption
regions.

The same deterministic key and nonce were reused exclusively for
performance isolation inside the benchmark.

This nonce reuse is acceptable only for this controlled timing
experiment and must not be used as a production nonce strategy.

## Benchmark methodology

Message sizes:

- 0 bytes
- 16 bytes
- 32 bytes
- 64 bytes
- 128 bytes
- 256 bytes
- 512 bytes
- 1024 bytes
- 4096 bytes

Each operation was measured using seven timing samples.

The reported value inside each benchmark execution is the median of
those seven samples.

Five independent benchmark executions were then performed.

The process was pinned to logical CPU 0 using:

`taskset -c 0`

The official result below is the median across those five independent
runs.

Input-buffer construction and ciphertext preparation were performed
outside the measured regions.

The release profile was used.

## Iterations per timing sample

| Message size | Iterations |
| ---: | ---: |
| 0-16 B | 400000 |
| 32-64 B | 200000 |
| 128 B | 100000 |
| 256 B | 80000 |
| 512 B | 40000 |
| 1024 B | 20000 |
| 4096 B | 5000 |

## Official host baseline

| Operation | Size | Median ns/op | Median MiB/s | Inter-run spread |
| --- | ---: | ---: | ---: | ---: |
| Encrypt | 0 B | 121.57 | 0.000 | 3.83% |
| Decrypt | 0 B | 129.01 | 0.000 | 7.79% |
| Encrypt | 16 B | 165.72 | 92.076 | 10.05% |
| Decrypt | 16 B | 170.25 | 89.626 | 5.05% |
| Encrypt | 32 B | 203.22 | 150.168 | 11.32% |
| Decrypt | 32 B | 209.31 | 145.800 | 7.67% |
| Encrypt | 64 B | 294.04 | 207.578 | 5.22% |
| Decrypt | 64 B | 289.03 | 211.175 | 3.28% |
| Encrypt | 128 B | 468.66 | 260.469 | 3.18% |
| Decrypt | 128 B | 429.36 | 284.311 | 6.91% |
| Encrypt | 256 B | 822.16 | 296.949 | 2.57% |
| Decrypt | 256 B | 740.37 | 329.756 | 6.19% |
| Encrypt | 512 B | 1488.44 | 328.048 | 6.07% |
| Decrypt | 512 B | 1330.56 | 366.973 | 4.46% |
| Encrypt | 1024 B | 2875.23 | 339.646 | 5.01% |
| Decrypt | 1024 B | 2487.20 | 392.635 | 0.77% |
| Encrypt | 4096 B | 11112.74 | 351.511 | 3.85% |
| Decrypt | 4096 B | 9469.40 | 412.513 | 1.97% |

## Interpretation

The fixed per-operation cost is visible most clearly for very small
messages.

As message size increases, throughput rises and approaches a steadier
large-message regime.

For this specific x86_64 WSL2 environment, the 4096-byte median
throughput was:

- encryption: 351.511 MiB/s
- decryption: 412.513 MiB/s

These values must not be extrapolated to embedded targets.

The higher relative spread observed for some small-message
measurements, particularly 16-byte and 32-byte encryption, is
consistent with greater sensitivity to scheduling, virtualization,
frequency scaling, and timer noise when individual operations are
extremely short.

For future architecture comparisons, embedded-device measurements
will be collected independently on the actual target hardware.

## Result provenance

Benchmark source:

`crates/ascon-iot/examples/benchmark_host.rs`

SHA-256:

`ae74dcfd03805e0e59c818a07b172c913d32c764aa5cbf5640170c29ccd986bb`

Aggregation script:

`tools/benchmark/summarize_host.py`

SHA-256:

`76660b2415679b76ba1411952fae3b5ab11cec0ff997121bd500c5c275e22bd2`

Pinned run 1:

`d1155e20997e4e03fd5335aeaba5f257a8029b7c85c05defd15d6f1b0ca59a71`

Pinned run 2:

`b4914e4379b1ba2b81a74ec8ec5052edbfa3f3231b33623c3f4c02bf6acada36`

Pinned run 3:

`ca19069fbd8dc92cb45ff50372463986d60324299d342e07803219937cceb20d`

Pinned run 4:

`049737c1cae17f873e86e33b30a074bf127d37b6e3c3d76f79d8051e80987d77`

Pinned run 5:

`453841d19b47e34b133f14968948c79b7718ab61b730ad91c1ced1c20c85d41c`

Aggregated summary:

`6a858d3cda36ffe1c77098913a41208aadf8a0d84903aef929c5798683771edb`

The raw timing files and generated summary are stored outside the Git
repository under the local validation-artifacts directory.

The benchmark harness and aggregation script are version controlled so
that the measurements can be reproduced.

## Limitations

WSL2 is a virtualized execution environment.

Therefore:

- CPU-frequency behavior is not tightly controlled;
- host scheduling can affect short measurements;
- hardware performance counters were not available;
- these measurements are not a substitute for native embedded-device
  benchmarks.

The results should be used as the host software baseline and for
controlled relative comparisons performed under the same environment.

## Host executable footprint

The final release benchmark executable produced on this host had the
following GNU `size` values:

| Section | Bytes |
| --- | ---: |
| `.text` | 338971 |
| `.data` | 10184 |
| `.bss` | 914 |
| Total (`dec`) | 350069 |

The ELF file size was approximately:

`417 KiB`

SHA-256 of the final release executable:

`bdf37b7a85bcce221d077087d183c386c2d5f741c66ecd1bd19509fa6c462d2a`

This executable footprint includes the Rust host runtime and benchmark
harness. It must not be interpreted as the Flash or RAM footprint of
Ascon-AEAD128 on an embedded target.
