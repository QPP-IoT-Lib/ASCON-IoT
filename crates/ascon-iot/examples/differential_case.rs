use std::{env, process};

use ascon_iot::{BaselineAsconAead128, KeyBytes, NonceBytes, TagBytes};

fn decode_hex(input: &str) -> Vec<u8> {
    assert!(input.len() % 2 == 0, "hex length must be even");

    (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16).unwrap_or_else(|_| panic!("invalid hex")))
        .collect()
}

fn fixed_16(name: &str, input: &str) -> [u8; 16] {
    let bytes = decode_hex(input);
    let len = bytes.len();

    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("{name} must be 16 bytes, found {len}"))
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

fn usage(program: &str) -> ! {
    eprintln!("usage:");
    eprintln!("  {program} enc KEY NONCE AD PT");
    eprintln!("  {program} dec KEY NONCE AD CT TAG");
    process::exit(2);
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        usage(&args[0]);
    }

    match args[1].as_str() {
        "enc" => {
            if args.len() != 6 {
                usage(&args[0]);
            }

            let key: KeyBytes = fixed_16("key", &args[2]);

            let nonce: NonceBytes = fixed_16("nonce", &args[3]);

            let ad = decode_hex(&args[4]);

            let mut buffer = decode_hex(&args[5]);

            let cipher = BaselineAsconAead128::new(&key);

            let tag = cipher
                .encrypt_in_place(&nonce, &ad, &mut buffer)
                .expect("encryption failed");

            println!("CT={}", encode_hex(&buffer));
            println!("TAG={}", encode_hex(&tag));
        }

        "dec" => {
            if args.len() != 7 {
                usage(&args[0]);
            }

            let key: KeyBytes = fixed_16("key", &args[2]);

            let nonce: NonceBytes = fixed_16("nonce", &args[3]);

            let ad = decode_hex(&args[4]);

            let mut buffer = decode_hex(&args[5]);

            let tag: TagBytes = fixed_16("tag", &args[6]);

            let cipher = BaselineAsconAead128::new(&key);

            match cipher.decrypt_in_place(&nonce, &ad, &mut buffer, &tag) {
                Ok(()) => {
                    println!("PT={}", encode_hex(&buffer));
                }

                Err(_) => {
                    println!("AUTHFAIL");
                    process::exit(3);
                }
            }
        }

        _ => usage(&args[0]),
    }
}
