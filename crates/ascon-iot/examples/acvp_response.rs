use std::{env, fs, path::Path, process};

use ascon_iot::{BaselineAsconAead128, KeyBytes, NonceBytes, TagBytes};
use serde_json::{Value, json};

fn load_json(path: &Path) -> Value {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()));

    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("invalid JSON in {}: {e}", path.display()))
}

fn extract_document(value: Value) -> Value {
    match value {
        Value::Object(_) => value,

        Value::Array(items) => items
            .into_iter()
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
        "hex string has odd number of characters"
    );

    (0..input.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&input[i..i + 2], 16)
                .unwrap_or_else(|_| panic!("invalid hex byte: {}", &input[i..i + 2]))
        })
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    let mut output = String::with_capacity(bytes.len() * 2);

    for &byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0F) as usize] as char);
    }

    output
}

fn fixed_16(label: &str, input: &str) -> [u8; 16] {
    let bytes = decode_hex(input);
    let len = bytes.len();

    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("{label} must contain 16 bytes, found {len}"))
}

fn usage(program: &str) -> ! {
    eprintln!("Usage:");
    eprintln!("  {program} <prompt.json> <response.json>");
    process::exit(2);
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        usage(&args[0]);
    }

    let prompt_path = Path::new(&args[1]);
    let response_path = Path::new(&args[2]);

    let prompt = extract_document(load_json(prompt_path));

    assert_eq!(get_str(&prompt, "algorithm"), "Ascon");
    assert_eq!(get_str(&prompt, "mode"), "AEAD128");
    assert_eq!(get_str(&prompt, "revision"), "SP800-232");

    let groups = prompt
        .get("testGroups")
        .and_then(Value::as_array)
        .expect("prompt.json has no testGroups array");

    let mut result_groups = Vec::new();

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
            .unwrap_or_else(|| panic!("tgId={tg_id}: missing tests array"));

        let mut result_tests = Vec::new();

        for test in tests {
            total += 1;

            let tc_id = get_u64(test, "tcId");
            let payload_len = get_u64(test, "payloadLen");
            let ad_len = get_u64(test, "adLen");
            let tag_len = get_u64(test, "tagLen");

            assert_eq!(tag_len, 128, "tgId={tg_id}, tcId={tc_id}: tagLen != 128");

            assert_eq!(
                payload_len % 8,
                0,
                "tgId={tg_id}, tcId={tc_id}: payload not byte-aligned"
            );

            assert_eq!(
                ad_len % 8,
                0,
                "tgId={tg_id}, tcId={tc_id}: AD not byte-aligned"
            );

            assert!(
                test.get("secondKey").is_none() || test.get("secondKey").unwrap().is_null(),
                "tgId={tg_id}, tcId={tc_id}: secondKey is unsupported"
            );

            let key: KeyBytes = fixed_16("key", get_str(test, "key"));

            let nonce: NonceBytes = fixed_16("nonce", get_str(test, "nonce"));

            let associated_data = decode_hex(get_str(test, "ad"));

            assert_eq!(
                associated_data.len() * 8,
                ad_len as usize,
                "tgId={tg_id}, tcId={tc_id}: AD length mismatch"
            );

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

                    let tag = cipher
                        .encrypt_in_place(&nonce, &associated_data, &mut buffer)
                        .unwrap_or_else(|_| {
                            panic!(
                                "tgId={tg_id}, tcId={tc_id}: \
                                 encryption failed"
                            )
                        });

                    result_tests.push(json!({
                        "tcId": tc_id,
                        "ct": encode_hex(&buffer),
                        "tag": encode_hex(&tag),
                    }));
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

                    let result =
                        cipher.decrypt_in_place(&nonce, &associated_data, &mut buffer, &tag);

                    match result {
                        Ok(()) => {
                            decrypt_accepted += 1;

                            result_tests.push(json!({
                                "tcId": tc_id,
                                "testPassed": true,
                                "pt": encode_hex(&buffer),
                            }));
                        }

                        Err(_) => {
                            decrypt_rejected += 1;

                            result_tests.push(json!({
                                "tcId": tc_id,
                                "testPassed": false,
                            }));
                        }
                    }
                }

                other => {
                    panic!("tgId={tg_id}: unsupported direction {other}");
                }
            }
        }

        result_groups.push(json!({
            "tgId": tg_id,
            "tests": result_tests,
        }));
    }

    /*
     * Preserve the ACVP vector-set metadata directly from prompt.json,
     * but replace all test groups with results produced by ASCON-IoT.
     *
     * expectedResults.json is deliberately NOT read by this program.
     */
    let mut response = prompt.clone();

    response
        .as_object_mut()
        .expect("ACVP document must be an object")
        .insert("testGroups".to_string(), Value::Array(result_groups));

    let output = serde_json::to_string_pretty(&response).expect("failed to serialize response");

    fs::write(response_path, format!("{output}\n"))
        .unwrap_or_else(|e| panic!("could not write {}: {e}", response_path.display()));

    println!("=== ASCON-IoT ACVP RESPONSE ===");
    println!("Vector set:       {}", get_u64(&prompt, "vsId"));
    println!("Total tests:      {total}");
    println!("Encrypt:          {encrypt_count}");
    println!("Decrypt:          {decrypt_count}");
    println!("Decrypt accepted: {decrypt_accepted}");
    println!("Decrypt rejected: {decrypt_rejected}");
    println!("Output:           {}", response_path.display());
}
