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
    ROOT,
    "target/debug/examples/differential_case",
)

CASES = 256

LENGTHS = [
    0, 1, 2, 7, 8, 9,
    15, 16, 17,
    31, 32, 33,
    63, 64, 65,
    127, 128, 129,
    255, 256,
]


def data(case_id, label, length):
    seed = (
        f"ASCON-IoT-NEG-CROSS-v1|"
        f"{case_id}|{label}"
    ).encode()

    return hashlib.shake_256(seed).digest(length)


def hx(b):
    return b.hex().upper()


def mutate(b):
    b = bytearray(b)

    if len(b) == 0:
        return bytes([0x80])

    b[0] ^= 0x80
    return bytes(b)


def run(cmd):
    return subprocess.run(
        cmd,
        text=True,
        capture_output=True,
    )


def parse_encrypt(text):
    ct = None
    tag = None

    for line in text.splitlines():
        if line.startswith("CT="):
            ct = line[3:].strip()

        elif line.startswith("TAG="):
            tag = line[4:].strip()

    if ct is None or tag is None:
        raise RuntimeError(
            f"invalid encrypt output:\n{text}"
        )

    return ct, tag


def expect_successful_decrypt(
    driver,
    key,
    nonce,
    ad,
    ct,
    tag,
    expected_pt,
    label,
):
    p = run([
        driver,
        "dec",
        key,
        nonce,
        ad,
        ct,
        tag,
    ])

    if p.returncode != 0:
        raise RuntimeError(
            f"{label}: valid decrypt failed\n"
            f"stdout={p.stdout}\n"
            f"stderr={p.stderr}"
        )

    expected = f"PT={expected_pt}"

    if expected not in p.stdout.splitlines():
        raise RuntimeError(
            f"{label}: plaintext mismatch\n"
            f"stdout={p.stdout}"
        )


def expect_auth_fail(
    driver,
    key,
    nonce,
    ad,
    ct,
    tag,
    label,
):
    p = run([
        driver,
        "dec",
        key,
        nonce,
        ad,
        ct,
        tag,
    ])

    if p.returncode == 0:
        raise RuntimeError(
            f"{label}: manipulated input was ACCEPTED\n"
            f"stdout={p.stdout}"
        )

    if "AUTHFAIL" not in p.stdout:
        raise RuntimeError(
            f"{label}: unexpected failure mode\n"
            f"returncode={p.returncode}\n"
            f"stdout={p.stdout}\n"
            f"stderr={p.stderr}"
        )


def main():
    if not os.path.isfile(C_DRIVER):
        raise SystemExit(
            f"C driver not found: {C_DRIVER}"
        )

    if not os.path.isfile(RUST_DRIVER):
        raise SystemExit(
            f"Rust driver not found: {RUST_DRIVER}"
        )

    control_c = 0
    control_rust = 0

    rejects = {
        "tag": 0,
        "ciphertext": 0,
        "ad": 0,
        "nonce": 0,
        "key": 0,
    }

    for case_id in range(CASES):
        pt_len = LENGTHS[
            case_id % len(LENGTHS)
        ]

        ad_len = LENGTHS[
            (case_id // len(LENGTHS))
            % len(LENGTHS)
        ]

        key_b = data(case_id, "KEY", 16)
        nonce_b = data(case_id, "NONCE", 16)
        ad_b = data(case_id, "AD", ad_len)
        pt_b = data(case_id, "PT", pt_len)

        key = hx(key_b)
        nonce = hx(nonce_b)
        ad = hx(ad_b)
        pt = hx(pt_b)

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

        if c_enc.returncode != 0:
            raise RuntimeError(
                f"case {case_id}: C encrypt failed"
            )

        if rust_enc.returncode != 0:
            raise RuntimeError(
                f"case {case_id}: Rust encrypt failed"
            )

        c_ct, c_tag = parse_encrypt(c_enc.stdout)
        r_ct, r_tag = parse_encrypt(rust_enc.stdout)

        if c_ct != r_ct or c_tag != r_tag:
            raise RuntimeError(
                f"case {case_id}: encrypt mismatch"
            )

        # Control: C output must decrypt in Rust.
        expect_successful_decrypt(
            RUST_DRIVER,
            key,
            nonce,
            ad,
            c_ct,
            c_tag,
            pt,
            f"case {case_id} Rust control",
        )

        control_rust += 1

        # Control: Rust output must decrypt in C.
        expect_successful_decrypt(
            C_DRIVER,
            key,
            nonce,
            ad,
            r_ct,
            r_tag,
            pt,
            f"case {case_id} C control",
        )

        control_c += 1

        variants = {
            "tag": (
                key,
                nonce,
                ad,
                c_ct,
                hx(mutate(bytes.fromhex(c_tag))),
            ),

            "ciphertext": (
                key,
                nonce,
                ad,
                hx(mutate(bytes.fromhex(c_ct))),
                c_tag,
            ),

            "ad": (
                key,
                nonce,
                hx(mutate(ad_b)),
                c_ct,
                c_tag,
            ),

            "nonce": (
                key,
                hx(mutate(nonce_b)),
                ad,
                c_ct,
                c_tag,
            ),

            "key": (
                hx(mutate(key_b)),
                nonce,
                ad,
                c_ct,
                c_tag,
            ),
        }

        for name, args in variants.items():
            expect_auth_fail(
                RUST_DRIVER,
                *args,
                f"case {case_id} Rust {name}",
            )

            expect_auth_fail(
                C_DRIVER,
                *args,
                f"case {case_id} C {name}",
            )

            rejects[name] += 2

        if (case_id + 1) % 32 == 0:
            print(
                f"progress: "
                f"{case_id + 1}/{CASES}"
            )

    total_negative = sum(rejects.values())

    print()
    print(
        "=== ASCON CROSS-IMPLEMENTATION "
        "NEGATIVE TEST ==="
    )
    print(f"Cases:                    {CASES}")
    print(f"Rust valid controls:      {control_rust}")
    print(f"C valid controls:         {control_c}")
    print(f"Modified tag rejected:    {rejects['tag']}")
    print(
        f"Modified CT rejected:     "
        f"{rejects['ciphertext']}"
    )
    print(f"Modified AD rejected:     {rejects['ad']}")
    print(f"Wrong nonce rejected:     {rejects['nonce']}")
    print(f"Wrong key rejected:       {rejects['key']}")
    print(f"Total negative checks:    {total_negative}")
    print("Unexpected acceptances:   0")
    print("Result:                    PASS")


if __name__ == "__main__":
    main()
