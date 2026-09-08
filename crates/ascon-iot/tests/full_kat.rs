use ascon_iot::{BaselineAsconAead128, TAG_SIZE};

const KAT: &str = include_str!("vectors/LWC_AEAD_KAT_128_128.txt");

const EXPECTED_VECTOR_COUNT: usize = 1089;
const KEY_SIZE: usize = 16;
const NONCE_SIZE: usize = 16;

#[derive(Debug)]
struct KatVector {
    count: usize,
    key: Vec<u8>,
    nonce: Vec<u8>,
    plaintext: Vec<u8>,
    associated_data: Vec<u8>,
    ciphertext_and_tag: Vec<u8>,
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let hex = hex.trim();

    assert!(
        hex.len().is_multiple_of(2),
        "hex string must contain an even number of characters: {hex:?}"
    );

    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = core::str::from_utf8(pair).expect("invalid UTF-8 in hexadecimal KAT field");

            u8::from_str_radix(pair, 16).unwrap_or_else(|_| {
                panic!("invalid hexadecimal value in KAT: {pair:?}");
            })
        })
        .collect()
}

fn parse_field(line: &str) -> (&str, &str) {
    let (name, value) = line
        .split_once('=')
        .unwrap_or_else(|| panic!("invalid KAT line, expected '=': {line}"));

    (name.trim(), value.trim())
}

fn parse_kat_vectors(input: &str) -> Vec<KatVector> {
    let mut vectors = Vec::new();

    let mut count: Option<usize> = None;
    let mut key: Option<Vec<u8>> = None;
    let mut nonce: Option<Vec<u8>> = None;
    let mut plaintext: Option<Vec<u8>> = None;
    let mut associated_data: Option<Vec<u8>> = None;
    let mut ciphertext_and_tag: Option<Vec<u8>> = None;

    for raw_line in input.lines().chain(core::iter::once("")) {
        let line = raw_line.trim();

        if line.is_empty() {
            if let Some(current_count) = count.take() {
                vectors.push(KatVector {
                    count: current_count,
                    key: key
                        .take()
                        .unwrap_or_else(|| panic!("Count {current_count}: missing Key")),
                    nonce: nonce
                        .take()
                        .unwrap_or_else(|| panic!("Count {current_count}: missing Nonce")),
                    plaintext: plaintext
                        .take()
                        .unwrap_or_else(|| panic!("Count {current_count}: missing PT")),
                    associated_data: associated_data
                        .take()
                        .unwrap_or_else(|| panic!("Count {current_count}: missing AD")),
                    ciphertext_and_tag: ciphertext_and_tag
                        .take()
                        .unwrap_or_else(|| panic!("Count {current_count}: missing CT")),
                });
            }

            continue;
        }

        let (field, value) = parse_field(line);

        match field {
            "Count" => {
                count = Some(
                    value
                        .parse::<usize>()
                        .unwrap_or_else(|_| panic!("invalid Count value: {value}")),
                );
            }

            "Key" => {
                key = Some(hex_to_bytes(value));
            }

            "Nonce" => {
                nonce = Some(hex_to_bytes(value));
            }

            "PT" => {
                plaintext = Some(hex_to_bytes(value));
            }

            "AD" => {
                associated_data = Some(hex_to_bytes(value));
            }

            "CT" => {
                ciphertext_and_tag = Some(hex_to_bytes(value));
            }

            _ => {
                panic!("unrecognized KAT field: {field}");
            }
        }
    }

    vectors
}

fn array_16(bytes: &[u8], label: &str, count: usize) -> [u8; 16] {
    bytes.try_into().unwrap_or_else(|_| {
        panic!(
            "Count {count}: {label} must contain exactly 16 bytes, got {}",
            bytes.len()
        )
    })
}

#[test]
fn complete_kat_structure_is_consistent() {
    let vectors = parse_kat_vectors(KAT);

    assert_eq!(
        vectors.len(),
        EXPECTED_VECTOR_COUNT,
        "expected complete 33 x 33 Ascon-AEAD128 KAT set"
    );

    for (index, vector) in vectors.iter().enumerate() {
        assert_eq!(
            vector.count,
            index + 1,
            "KAT Count sequence is not continuous"
        );

        assert_eq!(
            vector.key.len(),
            KEY_SIZE,
            "Count {}: Key length must be 128 bits",
            vector.count
        );

        assert_eq!(
            vector.nonce.len(),
            NONCE_SIZE,
            "Count {}: Nonce length must be 128 bits",
            vector.count
        );

        assert_eq!(
            vector.ciphertext_and_tag.len(),
            vector.plaintext.len() + TAG_SIZE,
            "Count {}: CT length must equal PT length + {}-byte tag",
            vector.count,
            TAG_SIZE
        );
    }
}

#[test]
fn all_official_ascon_aead128_kats_encrypt_correctly() {
    let vectors = parse_kat_vectors(KAT);

    assert_eq!(
        vectors.len(),
        EXPECTED_VECTOR_COUNT,
        "expected complete Ascon-AEAD128 KAT set"
    );

    for vector in &vectors {
        let key = array_16(&vector.key, "Key", vector.count);
        let nonce = array_16(&vector.nonce, "Nonce", vector.count);

        assert_eq!(
            vector.ciphertext_and_tag.len(),
            vector.plaintext.len() + TAG_SIZE,
            "Count {}: unexpected CT length",
            vector.count
        );

        let expected_ciphertext = &vector.ciphertext_and_tag[..vector.plaintext.len()];

        let expected_tag = &vector.ciphertext_and_tag[vector.plaintext.len()..];

        let cipher = BaselineAsconAead128::new(&key);

        let mut message = vector.plaintext.clone();

        let tag = cipher
            .encrypt_in_place(&nonce, &vector.associated_data, &mut message)
            .unwrap_or_else(|_| panic!("Count {}: encryption failed", vector.count));

        assert_eq!(
            message.as_slice(),
            expected_ciphertext,
            "Count {}: ciphertext mismatch",
            vector.count
        );

        assert_eq!(
            tag.as_slice(),
            expected_tag,
            "Count {}: authentication tag mismatch",
            vector.count
        );
    }
}

#[test]
fn all_official_ascon_aead128_kats_decrypt_correctly() {
    let vectors = parse_kat_vectors(KAT);

    assert_eq!(
        vectors.len(),
        EXPECTED_VECTOR_COUNT,
        "expected complete Ascon-AEAD128 KAT set"
    );

    for vector in &vectors {
        let key = array_16(&vector.key, "Key", vector.count);
        let nonce = array_16(&vector.nonce, "Nonce", vector.count);

        assert!(
            vector.ciphertext_and_tag.len() >= TAG_SIZE,
            "Count {}: CT is shorter than authentication tag",
            vector.count
        );

        let ciphertext_len = vector.ciphertext_and_tag.len() - TAG_SIZE;

        let mut ciphertext = vector.ciphertext_and_tag[..ciphertext_len].to_vec();

        let tag: [u8; TAG_SIZE] = vector.ciphertext_and_tag[ciphertext_len..]
            .try_into()
            .unwrap_or_else(|_| {
                panic!("Count {}: invalid authentication tag length", vector.count)
            });

        let cipher = BaselineAsconAead128::new(&key);

        cipher
            .decrypt_in_place(&nonce, &vector.associated_data, &mut ciphertext, &tag)
            .unwrap_or_else(|_| panic!("Count {}: authentication/decryption failed", vector.count));

        assert_eq!(
            ciphertext.as_slice(),
            vector.plaintext.as_slice(),
            "Count {}: recovered plaintext mismatch",
            vector.count
        );
    }
}
