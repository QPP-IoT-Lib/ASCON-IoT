#!/usr/bin/env python3

import hashlib
import os
import subprocess
import sys

ROOT = os.path.expanduser("~/projects/ASCON-IoT")
C_DRIVER = os.path.expanduser(
    "~/projects/ascon-validation-artifacts/differential/ascon_c_driver"
)
RUST_DRIVER = os.path.join(
    ROOT, "target/debug/examples/differential_case"
)

TOTAL_CASES = 1000

BOUNDARIES = [
    0, 1, 2, 7, 8, 9,
    15, 16, 17,
    31, 32, 33,
    63, 64, 65,
    127, 128, 129,
    255, 256, 257,
]


def deterministic_bytes(case_id, label, length):
    seed = f"ASCON-IoT-DIFF-v1|{case_id}|{label}".encode()
    return hashlib.shake_256(seed).digest(length)


def hexstr(data):
    return data.hex().upper()


def run(cmd, allow_fail=False):
    p = subprocess.run(
        cmd,
        text=True,
        capture_output=True,
    )

    if p.returncode != 0 and not allow_fail:
        print("COMMAND FAILED:")
        print(" ".join(cmd))
        print("stdout:")
        print(p.stdout)
        print("stderr:")
        print(p.stderr)
        sys.exit(1)

    return p


def parse_encrypt(text):
    result = {}

    for line in text.splitlines():
        if line.startswith("CT="):
            result["ct"] = line[3:].strip()
        elif line.startswith("TAG="):
            result["tag"] = line[4:].strip()

    if "ct" not in result or "tag" not in result:
        raise RuntimeError(f"invalid encrypt output:\n{text}")

    return result["ct"], result["tag"]


def parse_plaintext(text):
    for line in text.splitlines():
        if line.startswith("PT="):
            return line[3:].strip()

    raise RuntimeError(f"invalid decrypt output:\n{text}")


def lengths_for_case(i):
    if i < len(BOUNDARIES) ** 2:
        pt_len = BOUNDARIES[i % len(BOUNDARIES)]
        ad_len = BOUNDARIES[i // len(BOUNDARIES)]
        return pt_len, ad_len

    digest = hashlib.sha256(
        f"ASCON-IoT-LENGTH-v1|{i}".encode()
    ).digest()

    pt_len = int.from_bytes(digest[0:4], "big") % 1025
    ad_len = int.from_bytes(digest[4:8], "big") % 1025

    return pt_len, ad_len


def main():
    if not os.path.isfile(C_DRIVER):
        raise SystemExit(f"C driver not found: {C_DRIVER}")

    if not os.path.isfile(RUST_DRIVER):
        raise SystemExit(f"Rust driver not found: {RUST_DRIVER}")

    encrypt_matches = 0
    rust_decrypt_matches = 0
    c_decrypt_matches = 0

    max_pt = 0
    max_ad = 0

    for i in range(TOTAL_CASES):
        pt_len, ad_len = lengths_for_case(i)

        max_pt = max(max_pt, pt_len)
        max_ad = max(max_ad, ad_len)

        key = hexstr(deterministic_bytes(i, "KEY", 16))
        nonce = hexstr(deterministic_bytes(i, "NONCE", 16))
        ad = hexstr(deterministic_bytes(i, "AD", ad_len))
        pt = hexstr(deterministic_bytes(i, "PT", pt_len))

        c_enc = run([
            C_DRIVER,
            "enc",
            key,
            nonce,
            ad,
            pt,
        ])

        rust_enc = run([
            RUST_DRIVER,
            "enc",
            key,
            nonce,
            ad,
            pt,
        ])

        c_ct, c_tag = parse_encrypt(c_enc.stdout)
        rust_ct, rust_tag = parse_encrypt(rust_enc.stdout)

        if c_ct != rust_ct or c_tag != rust_tag:
            print()
            print("DIFFERENTIAL FAILURE")
            print("case:", i)
            print("pt_len:", pt_len)
            print("ad_len:", ad_len)
            print("key:", key)
            print("nonce:", nonce)
            print("ad:", ad)
            print("pt:", pt)
            print("C CT:", c_ct)
            print("R CT:", rust_ct)
            print("C TAG:", c_tag)
            print("R TAG:", rust_tag)
            sys.exit(1)

        encrypt_matches += 1

        rust_dec = run([
            RUST_DRIVER,
            "dec",
            key,
            nonce,
            ad,
            c_ct,
            c_tag,
        ])

        rust_pt = parse_plaintext(rust_dec.stdout)

        if rust_pt != pt:
            raise SystemExit(
                f"Rust failed to decrypt C output at case {i}"
            )

        rust_decrypt_matches += 1

        c_dec = run([
            C_DRIVER,
            "dec",
            key,
            nonce,
            ad,
            rust_ct,
            rust_tag,
        ])

        c_pt = parse_plaintext(c_dec.stdout)

        if c_pt != pt:
            raise SystemExit(
                f"C failed to decrypt Rust output at case {i}"
            )

        c_decrypt_matches += 1

        if (i + 1) % 100 == 0:
            print(f"progress: {i + 1}/{TOTAL_CASES}")

    print()
    print("=== ASCON DIFFERENTIAL TEST ===")
    print("Reference:          ascon-c 446347f21b209f3921c65ece70027c366cbe1693")
    print("Rust baseline:      ASCON-IoT")
    print("Generator:          SHAKE256 deterministic test data")
    print("Cases:              ", TOTAL_CASES)
    print("Encrypt identical:  ", encrypt_matches)
    print("Rust decrypt C:     ", rust_decrypt_matches)
    print("C decrypt Rust:     ", c_decrypt_matches)
    print("Maximum PT bytes:   ", max_pt)
    print("Maximum AD bytes:   ", max_ad)
    print("Cipher mismatches:   0")
    print("Tag mismatches:      0")
    print("Plaintext mismatch:  0")
    print("Result:              PASS")


if __name__ == "__main__":
    main()
