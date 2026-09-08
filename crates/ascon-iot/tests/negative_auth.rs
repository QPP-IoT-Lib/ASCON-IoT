use ascon_iot::{BaselineAsconAead128, KeyBytes, NonceBytes};

const CASES: usize = 256;

const LENGTHS: &[usize] = &[
    0, 1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256,
];

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E3779B97F4A7C15);

    let mut z = *state;

    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);

    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);

    z ^ (z >> 31)
}

fn deterministic_bytes(case_id: usize, domain: u64, len: usize) -> Vec<u8> {
    let mut state =
        0x4153_434F_4E49_4F54u64 ^ (case_id as u64).wrapping_mul(0xD6E8FEB86659FD93) ^ domain;

    let mut output = vec![0u8; len];

    let mut i = 0usize;

    while i < len {
        let block = splitmix64(&mut state).to_le_bytes();

        for byte in block {
            if i == len {
                break;
            }

            output[i] = byte;
            i += 1;
        }
    }

    output
}

fn fixed_16(case_id: usize, domain: u64) -> [u8; 16] {
    deterministic_bytes(case_id, domain, 16).try_into().unwrap()
}

fn tamper_bytes(mut data: Vec<u8>) -> Vec<u8> {
    if data.is_empty() {
        data.push(0x80);
    } else {
        data[0] ^= 0x80;
    }

    data
}

#[test]
fn systematic_authentication_failures_are_rejected() {
    let mut valid_decrypts = 0usize;

    let mut rejected_tag = 0usize;
    let mut rejected_ciphertext = 0usize;
    let mut rejected_ad = 0usize;
    let mut rejected_nonce = 0usize;
    let mut rejected_key = 0usize;

    for case_id in 0..CASES {
        let pt_len = LENGTHS[case_id % LENGTHS.len()];

        let ad_len = LENGTHS[(case_id / LENGTHS.len()) % LENGTHS.len()];

        let key: KeyBytes = fixed_16(case_id, 0x4B4559);

        let nonce: NonceBytes = fixed_16(case_id, 0x4E4F4E4345);

        let ad = deterministic_bytes(case_id, 0x4144, ad_len);

        let plaintext = deterministic_bytes(case_id, 0x5054, pt_len);

        let cipher = BaselineAsconAead128::new(&key);

        let mut ciphertext = plaintext.clone();

        let tag = cipher
            .encrypt_in_place(&nonce, &ad, &mut ciphertext)
            .expect("encryption failed");

        /*
         * Control:
         * untouched ciphertext must authenticate.
         */
        let mut valid_buffer = ciphertext.clone();

        cipher
            .decrypt_in_place(&nonce, &ad, &mut valid_buffer, &tag)
            .unwrap_or_else(|_| {
                panic!(
                    "case {case_id}: \
                     valid ciphertext rejected"
                )
            });

        assert_eq!(
            valid_buffer, plaintext,
            "case {case_id}: \
             valid plaintext mismatch"
        );

        valid_decrypts += 1;

        /*
         * 1. Modified authentication tag.
         */
        let mut bad_tag = tag;
        bad_tag[0] ^= 0x80;

        let mut buffer = ciphertext.clone();

        assert!(
            cipher
                .decrypt_in_place(&nonce, &ad, &mut buffer, &bad_tag,)
                .is_err(),
            "case {case_id}: \
             modified tag was accepted"
        );

        rejected_tag += 1;

        /*
         * 2. Modified ciphertext.
         *
         * For zero-length plaintext, adding one byte
         * also constitutes a modified ciphertext.
         */
        let mut bad_ciphertext = tamper_bytes(ciphertext.clone());

        assert!(
            cipher
                .decrypt_in_place(&nonce, &ad, &mut bad_ciphertext, &tag,)
                .is_err(),
            "case {case_id}: \
             modified ciphertext was accepted"
        );

        rejected_ciphertext += 1;

        /*
         * 3. Modified associated data.
         */
        let bad_ad = tamper_bytes(ad.clone());

        let mut buffer = ciphertext.clone();

        assert!(
            cipher
                .decrypt_in_place(&nonce, &bad_ad, &mut buffer, &tag,)
                .is_err(),
            "case {case_id}: \
             modified AD was accepted"
        );

        rejected_ad += 1;

        /*
         * 4. Wrong nonce.
         */
        let mut bad_nonce = nonce;
        bad_nonce[0] ^= 0x80;

        let mut buffer = ciphertext.clone();

        assert!(
            cipher
                .decrypt_in_place(&bad_nonce, &ad, &mut buffer, &tag,)
                .is_err(),
            "case {case_id}: \
             wrong nonce was accepted"
        );

        rejected_nonce += 1;

        /*
         * 5. Wrong key.
         */
        let mut bad_key = key;
        bad_key[0] ^= 0x80;

        let bad_cipher = BaselineAsconAead128::new(&bad_key);

        let mut buffer = ciphertext.clone();

        assert!(
            bad_cipher
                .decrypt_in_place(&nonce, &ad, &mut buffer, &tag,)
                .is_err(),
            "case {case_id}: \
             wrong key was accepted"
        );

        rejected_key += 1;
    }

    println!();
    println!("=== ASCON NEGATIVE AUTH TESTS ===");
    println!("Cases:                   {CASES}");
    println!("Valid decryptions:       {valid_decrypts}");
    println!("Modified tag rejected:   {rejected_tag}");
    println!("Modified CT rejected:    {rejected_ciphertext}");
    println!("Modified AD rejected:    {rejected_ad}");
    println!("Wrong nonce rejected:    {rejected_nonce}");
    println!("Wrong key rejected:      {rejected_key}");
    println!(
        "Total negative checks:   {}",
        rejected_tag + rejected_ciphertext + rejected_ad + rejected_nonce + rejected_key
    );
    println!("Authentication failures: 0");
    println!("Result:                   PASS");
}
