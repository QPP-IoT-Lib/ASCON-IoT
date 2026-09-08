use std::{
    hint::black_box,
    time::{Duration, Instant},
};

use ascon_iot::{BaselineAsconAead128, KeyBytes, NonceBytes, TagBytes};

const AD_SIZES: &[usize] = &[0, 1, 15, 16, 17, 31, 32, 33, 64, 128, 256, 512, 1024];

const PT_SIZES: &[usize] = &[0, 64, 256];

const SAMPLES: usize = 7;

const CIPHER_CONSTRUCTION_ITERATIONS: usize = 2_000_000;

fn median(mut values: Vec<Duration>) -> Duration {
    values.sort_unstable();
    values[values.len() / 2]
}

fn ns_per_op(duration: Duration, iterations: usize) -> f64 {
    duration.as_secs_f64() * 1_000_000_000.0 / iterations as f64
}

fn iterations_for(pt_size: usize, ad_size: usize) -> usize {
    match pt_size + ad_size {
        0..=16 => 400_000,
        17..=64 => 200_000,
        65..=256 => 80_000,
        257..=512 => 40_000,
        513..=1024 => 20_000,
        _ => 10_000,
    }
}

fn deterministic_bytes(index: usize, len: usize) -> Vec<u8> {
    let mut state = 0x434F_4D50_4F4E_454Eu64 ^ (index as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);

    let mut out = vec![0u8; len];

    for byte in &mut out {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;

        state = state.wrapping_mul(0x2545_F491_4F6C_DD1D);

        *byte = state as u8;
    }

    out
}

fn deterministic_key(index: usize) -> KeyBytes {
    deterministic_bytes(index, 16).try_into().unwrap()
}

fn benchmark_cipher_construction() -> Duration {
    const KEY_POOL: usize = 4096;

    /*
     * Keys are generated before the timed region.
     *
     * This measures construction of BaselineAsconAead128
     * from an already available 128-bit key.
     *
     * It does NOT measure QPP-RNG generation and it does
     * NOT represent the complete cryptographic
     * initialization performed for each AEAD operation.
     */
    let keys: Vec<KeyBytes> = (0..KEY_POOL).map(deterministic_key).collect();

    let mut samples = Vec::with_capacity(SAMPLES);

    for _ in 0..SAMPLES {
        let start = Instant::now();

        for i in 0..CIPHER_CONSTRUCTION_ITERATIONS {
            let key = black_box(&keys[i % KEY_POOL]);

            let cipher = BaselineAsconAead128::new(key);

            black_box(cipher);
        }

        samples.push(start.elapsed());
    }

    median(samples)
}

fn prepare_plaintexts(count: usize, size: usize) -> Vec<Vec<u8>> {
    (0..count).map(|i| deterministic_bytes(i, size)).collect()
}

fn benchmark_encrypt(
    cipher: &BaselineAsconAead128,
    nonce: &NonceBytes,
    pt_size: usize,
    ad_size: usize,
    iterations: usize,
) -> Duration {
    let ad = deterministic_bytes(0xAD, ad_size);

    let mut samples = Vec::with_capacity(SAMPLES);

    for _ in 0..SAMPLES {
        /*
         * Plaintext creation is deliberately outside
         * the measured interval.
         */
        let mut buffers = prepare_plaintexts(iterations, pt_size);

        let mut checksum = 0u8;

        let start = Instant::now();

        for buffer in &mut buffers {
            let tag = cipher
                .encrypt_in_place(
                    nonce,
                    black_box(ad.as_slice()),
                    black_box(buffer.as_mut_slice()),
                )
                .expect("encryption failed");

            checksum ^= tag[0];
        }

        let elapsed = start.elapsed();

        black_box(checksum);
        black_box(&buffers);

        samples.push(elapsed);
    }

    median(samples)
}

fn prepare_ciphertexts(
    cipher: &BaselineAsconAead128,
    nonce: &NonceBytes,
    pt_size: usize,
    ad: &[u8],
    iterations: usize,
) -> (Vec<Vec<u8>>, Vec<TagBytes>) {
    let mut buffers = prepare_plaintexts(iterations, pt_size);

    let mut tags = Vec::with_capacity(iterations);

    for buffer in &mut buffers {
        let tag = cipher
            .encrypt_in_place(nonce, ad, buffer)
            .expect("ciphertext preparation failed");

        tags.push(tag);
    }

    (buffers, tags)
}

fn benchmark_decrypt(
    cipher: &BaselineAsconAead128,
    nonce: &NonceBytes,
    pt_size: usize,
    ad_size: usize,
    iterations: usize,
) -> Duration {
    let ad = deterministic_bytes(0xAD, ad_size);

    let mut samples = Vec::with_capacity(SAMPLES);

    for _ in 0..SAMPLES {
        /*
         * Ciphertext and tag preparation are deliberately
         * outside the measured interval.
         */
        let (mut buffers, tags) = prepare_ciphertexts(cipher, nonce, pt_size, &ad, iterations);

        let mut checksum = 0u8;

        let start = Instant::now();

        for (buffer, tag) in buffers.iter_mut().zip(tags.iter()) {
            cipher
                .decrypt_in_place(
                    nonce,
                    black_box(ad.as_slice()),
                    black_box(buffer.as_mut_slice()),
                    black_box(tag),
                )
                .expect("decryption failed");

            if let Some(first) = buffer.first() {
                checksum ^= *first;
            }
        }

        let elapsed = start.elapsed();

        black_box(checksum);
        black_box(&buffers);

        samples.push(elapsed);
    }

    median(samples)
}

fn warm_up(cipher: &BaselineAsconAead128, nonce: &NonceBytes) {
    let ad = [0xA5u8; 64];
    let mut buffer = [0x5Au8; 64];

    for _ in 0..5_000 {
        let tag = cipher
            .encrypt_in_place(nonce, &ad, &mut buffer)
            .expect("warm-up failed");

        black_box(tag);
        black_box(&buffer);
    }
}

fn main() {
    let key: KeyBytes = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];

    let nonce: NonceBytes = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F,
    ];

    let cipher = BaselineAsconAead128::new(&key);

    warm_up(&cipher, &nonce);

    println!("=== ASCON-IoT COMPONENT BENCHMARK ===");
    println!("Algorithm: Ascon-AEAD128");
    println!("Samples: {SAMPLES}");
    println!();

    let cipher_construction = benchmark_cipher_construction();

    println!(
        "cipher_construction,0,0,{CIPHER_CONSTRUCTION_ITERATIONS},{:.2}",
        ns_per_op(cipher_construction, CIPHER_CONSTRUCTION_ITERATIONS,)
    );

    println!();

    println!("operation,pt_bytes,ad_bytes,iterations,median_ns_op");

    for &pt_size in PT_SIZES {
        for &ad_size in AD_SIZES {
            let iterations = iterations_for(pt_size, ad_size);

            let enc = benchmark_encrypt(&cipher, &nonce, pt_size, ad_size, iterations);

            println!(
                "encrypt,{pt_size},{ad_size},{iterations},{:.2}",
                ns_per_op(enc, iterations,)
            );

            let dec = benchmark_decrypt(&cipher, &nonce, pt_size, ad_size, iterations);

            println!(
                "decrypt,{pt_size},{ad_size},{iterations},{:.2}",
                ns_per_op(dec, iterations,)
            );
        }
    }
}
