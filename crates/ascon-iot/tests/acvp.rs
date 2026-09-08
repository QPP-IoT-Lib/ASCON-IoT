use std::{
    env, fs,
    path::{Path, PathBuf},
};

use ascon_iot::{BaselineAsconAead128, KeyBytes, NonceBytes, TagBytes};
use serde_json::Value;

fn load_json(path: &Path) -> Value {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()));

    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("invalid JSON in {}: {e}", path.display()))
}

fn acvp_document(value: &Value) -> &Value {
    match value {
        Value::Object(_) => value,

        Value::Array(items) => items
            .iter()
            .find(|item| item.get("testGroups").is_some())
            .expect("ACVP array did not contain a vector-set document"),

        _ => panic!("unexpected ACVP top-level JSON type"),
    }
}

fn get_str<'a>(value: &'a Value, field: &str) -> &'a str {
    value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing or invalid string field: {field}"))
}

fn get_u64(value: &Value, field: &str) -> u64 {
    value
        .get(field)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("missing or invalid integer field: {field}"))
}

fn get_bool(value: &Value, field: &str) -> bool {
    value
        .get(field)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("missing or invalid boolean field: {field}"))
}

fn decode_hex(input: &str) -> Vec<u8> {
    assert!(
        input.len() % 2 == 0,
        "hex string has odd number of characters: {}",
        input.len()
    );

    (0..input.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&input[i..i + 2], 16)
                .unwrap_or_else(|_| panic!("invalid hex byte: {}", &input[i..i + 2]))
        })
        .collect()
}

fn fixed_16(label: &str, input: &str) -> [u8; 16] {
    let bytes = decode_hex(input);
    let len = bytes.len();

    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("{label} must contain 16 bytes, found {len}"))
}

fn find_expected_case<'a>(expected: &'a Value, tg_id: u64, tc_id: u64) -> &'a Value {
    let groups = expected
        .get("testGroups")
        .and_then(Value::as_array)
        .expect("expectedResults.json has no testGroups array");

    let group = groups
        .iter()
        .find(|group| group.get("tgId").and_then(Value::as_u64) == Some(tg_id))
        .unwrap_or_else(|| panic!("expected results missing tgId={tg_id}"));

    group
        .get("tests")
        .and_then(Value::as_array)
        .expect("expected result group has no tests")
        .iter()
        .find(|test| test.get("tcId").and_then(Value::as_u64) == Some(tc_id))
        .unwrap_or_else(|| panic!("expected results missing tgId={tg_id}, tcId={tc_id}"))
}

fn profile_directory() -> PathBuf {
    env::var_os("ACVP_PROFILE_DIR").map(PathBuf::from).expect(
        "ACVP_PROFILE_DIR must point to the directory containing \
             prompt.json and expectedResults.json",
    )
}

#[test]
#[ignore = "requires locally generated NIST ACVP vectors"]
fn nist_acvp_ascon_aead128_profile() {
    let directory = profile_directory();

    let prompt_json = load_json(&directory.join("prompt.json"));
    let expected_json = load_json(&directory.join("expectedResults.json"));

    let prompt = acvp_document(&prompt_json);
    let expected = acvp_document(&expected_json);

    assert_eq!(
        get_str(prompt, "algorithm"),
        "Ascon",
        "unexpected ACVP algorithm"
    );

    assert_eq!(get_str(prompt, "mode"), "AEAD128", "unexpected ACVP mode");

    assert_eq!(
        get_str(prompt, "revision"),
        "SP800-232",
        "unexpected ACVP revision"
    );

    assert_eq!(
        get_u64(prompt, "vsId"),
        get_u64(expected, "vsId"),
        "vsId differs between prompt and expected results"
    );

    let groups = prompt
        .get("testGroups")
        .and_then(Value::as_array)
        .expect("prompt.json has no testGroups array");

    let mut total = 0usize;
    let mut encrypt_count = 0usize;
    let mut decrypt_count = 0usize;

    let mut decrypt_accepted = 0usize;
    let mut decrypt_rejected = 0usize;

    for group in groups {
        let tg_id = get_u64(group, "tgId");
        let direction = get_str(group, "direction");

        assert!(
            !get_bool(group, "supportsNonceMasking"),
            "tgId={tg_id}: nonce masking is outside the ASCON-IoT profile"
        );

        let tests = group
            .get("tests")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("tgId={tg_id} has no tests array"));

        for test in tests {
            total += 1;

            let tc_id = get_u64(test, "tcId");
            let payload_len = get_u64(test, "payloadLen");
            let ad_len = get_u64(test, "adLen");
            let tag_len = get_u64(test, "tagLen");

            assert_eq!(
                tag_len, 128,
                "tgId={tg_id}, tcId={tc_id}: unsupported tag length"
            );

            assert_eq!(
                payload_len % 8,
                0,
                "tgId={tg_id}, tcId={tc_id}: payload is not byte-aligned"
            );

            assert_eq!(
                ad_len % 8,
                0,
                "tgId={tg_id}, tcId={tc_id}: AD is not byte-aligned"
            );

            assert!(
                test.get("secondKey").is_none() || test.get("secondKey").unwrap().is_null(),
                "tgId={tg_id}, tcId={tc_id}: unexpected secondKey"
            );

            let key: KeyBytes = fixed_16("key", get_str(test, "key"));
            let nonce: NonceBytes = fixed_16("nonce", get_str(test, "nonce"));
            let associated_data = decode_hex(get_str(test, "ad"));

            assert_eq!(
                associated_data.len() * 8,
                ad_len as usize,
                "tgId={tg_id}, tcId={tc_id}: AD length mismatch"
            );

            let expected_case = find_expected_case(expected, tg_id, tc_id);

            let cipher = BaselineAsconAead128::new(&key);

            match direction {
                "encrypt" => {
                    encrypt_count += 1;

                    let mut buffer = decode_hex(get_str(test, "pt"));

                    assert_eq!(
                        buffer.len() * 8,
                        payload_len as usize,
                        "tgId={tg_id}, tcId={tc_id}: PT length mismatch"
                    );

                    let actual_tag = cipher
                        .encrypt_in_place(&nonce, &associated_data, &mut buffer)
                        .unwrap_or_else(|_| {
                            panic!(
                                "tgId={tg_id}, tcId={tc_id}: \
                                 encryption unexpectedly failed"
                            )
                        });

                    let expected_ciphertext = decode_hex(get_str(expected_case, "ct"));

                    let expected_tag: TagBytes =
                        fixed_16("expected tag", get_str(expected_case, "tag"));

                    assert_eq!(
                        buffer, expected_ciphertext,
                        "tgId={tg_id}, tcId={tc_id}: ciphertext mismatch"
                    );

                    assert_eq!(
                        actual_tag, expected_tag,
                        "tgId={tg_id}, tcId={tc_id}: tag mismatch"
                    );
                }

                "decrypt" => {
                    decrypt_count += 1;

                    let mut buffer = decode_hex(get_str(test, "ct"));

                    assert_eq!(
                        buffer.len() * 8,
                        payload_len as usize,
                        "tgId={tg_id}, tcId={tc_id}: CT length mismatch"
                    );

                    let tag: TagBytes = fixed_16("tag", get_str(test, "tag"));

                    let expected_passed = get_bool(expected_case, "testPassed");

                    let result =
                        cipher.decrypt_in_place(&nonce, &associated_data, &mut buffer, &tag);

                    if expected_passed {
                        decrypt_accepted += 1;

                        assert!(
                            result.is_ok(),
                            "tgId={tg_id}, tcId={tc_id}: \
                             valid NIST ciphertext was rejected"
                        );

                        let expected_plaintext = decode_hex(get_str(expected_case, "pt"));

                        assert_eq!(
                            buffer, expected_plaintext,
                            "tgId={tg_id}, tcId={tc_id}: plaintext mismatch"
                        );
                    } else {
                        decrypt_rejected += 1;

                        assert!(
                            result.is_err(),
                            "tgId={tg_id}, tcId={tc_id}: \
                             invalid NIST ciphertext/tag was accepted"
                        );
                    }
                }

                other => {
                    panic!("tgId={tg_id}: unsupported ACVP direction: {other}");
                }
            }
        }
    }

    assert!(total > 0, "ACVP prompt contained no test cases");
    assert!(encrypt_count > 0, "no encrypt tests were executed");
    assert!(decrypt_count > 0, "no decrypt tests were executed");

    println!();
    println!("=== NIST ACVP Ascon-AEAD128 SP800-232 ===");
    println!("Vector set:          {}", get_u64(prompt, "vsId"));
    println!("Total tests:         {total}");
    println!("Encrypt PASS:        {encrypt_count}");
    println!("Decrypt tests:       {decrypt_count}");
    println!("Decrypt accepted:    {decrypt_accepted}");
    println!("Decrypt rejected:    {decrypt_rejected}");
    println!("Ciphertext mismatch: 0");
    println!("Tag mismatch:        0");
    println!("Plaintext mismatch:  0");
    println!("Result:              PASS");
}
