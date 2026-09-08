use std::{
    hint::black_box,
    time::{Duration, Instant},
};

use ascon_iot::{BaselineAsconAead128, KeyBytes, NonceBytes, TagBytes};

const SIZES: &[usize] = &[0, 16, 32, 64, 128, 256, 512, 1024, 4096];

const SAMPLES: usize = 7;

fn iterations_for(size: usize) -> usize {
    match size {
        0..=16 => 400_000,
        17..=64 => 200_000,
        65..=128 => 100_000,
        129..=256 => 80_000,
        257..=512 => 40_000,
        513..=1024 => 20_000,
        _ => 5_000,
    }
}

fn make_data(index: usize, len: usize) -> Vec<u8> {
    let mut state = 0x4153_434F_4E2D_494Fu64 ^ (index as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);

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

fn prepare_plaintexts(count: usize, size: usize) -> Vec<Vec<u8>> {
    (0..count).map(|i| make_data(i, size)).collect()
}

fn median(mut values: Vec<Duration>) -> Duration {
    values.sort_unstable();
    values[values.len() / 2]
}

fn warm_up(cipher: &BaselineAsconAead128, nonce: &NonceBytes) {
    let ad = [];
    let mut buffer = vec![0xA5; 256];

    for _ in 0..2_000 {
        let tag = cipher
            .encrypt_in_place(nonce, &ad, &mut buffer)
            .expect("warm-up encryption failed");

        black_box(tag);
        black_box(&buffer);
    }
}

fn benchmark_encrypt(
    cipher: &BaselineAsconAead128,
    nonce: &NonceBytes,
    size: usize,
    iterations: usize,
) -> Duration {
    let ad = [];
    let mut samples = Vec::with_capacity(SAMPLES);

    for _ in 0..SAMPLES {
        let mut buffers = prepare_plaintexts(iterations, size);

        let mut checksum = 0u8;

        let start = Instant::now();

        for buffer in &mut buffers {
            let tag = cipher
                .encrypt_in_place(nonce, &ad, black_box(buffer.as_mut_slice()))
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
    count: usize,
    size: usize,
) -> (Vec<Vec<u8>>, Vec<TagBytes>) {
    let ad = [];

    let mut buffers = prepare_plaintexts(count, size);

    let mut tags = Vec::with_capacity(count);

    for buffer in &mut buffers {
        let tag = cipher
            .encrypt_in_place(nonce, &ad, buffer)
            .expect("ciphertext preparation failed");

        tags.push(tag);
    }

    (buffers, tags)
}

fn benchmark_decrypt(
    cipher: &BaselineAsconAead128,
    nonce: &NonceBytes,
    size: usize,
    iterations: usize,
) -> Duration {
    let ad = [];
    let mut samples = Vec::with_capacity(SAMPLES);

    for _ in 0..SAMPLES {
        /*
         * Preparation occurs outside the measured
         * interval. Every ciphertext is decrypted
         * exactly once inside the benchmark.
         */
        let (mut buffers, tags) = prepare_ciphertexts(cipher, nonce, iterations, size);

        let mut checksum = 0u8;

        let start = Instant::now();

        for (buffer, tag) in buffers.iter_mut().zip(tags.iter()) {
            cipher
                .decrypt_in_place(nonce, &ad, black_box(buffer.as_mut_slice()), black_box(tag))
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

fn ns_per_op(duration: Duration, iterations: usize) -> f64 {
    duration.as_secs_f64() * 1_000_000_000.0 / iterations as f64
}

fn mib_per_second(size: usize, ns_op: f64) -> f64 {
    if size == 0 || ns_op == 0.0 {
        return 0.0;
    }

    let bytes_per_second = size as f64 / (ns_op / 1e9);

    bytes_per_second / (1024.0 * 1024.0)
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

    println!("=== ASCON-IoT HOST BASELINE BENCHMARK ===");
    println!("Algorithm: Ascon-AEAD128");
    println!("Associated data: 0 bytes");
    println!("Samples per measurement: {SAMPLES}");
    println!();
    println!("operation,size_bytes,iterations,median_ns_op,MiB_s");

    for &size in SIZES {
        let iterations = iterations_for(size);

        let enc = benchmark_encrypt(&cipher, &nonce, size, iterations);

        let enc_ns = ns_per_op(enc, iterations);

        println!(
            "encrypt,{size},{iterations},{enc_ns:.2},{:.3}",
            mib_per_second(size, enc_ns),
        );

        let dec = benchmark_decrypt(&cipher, &nonce, size, iterations);

        let dec_ns = ns_per_op(dec, iterations);

        println!(
            "decrypt,{size},{iterations},{dec_ns:.2},{:.3}",
            mib_per_second(size, dec_ns),
        );
    }
}
