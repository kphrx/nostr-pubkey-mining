#![feature(split_array)]
extern crate getopts;

use std::env;

use getopts::Options;

use libsecp256k1::{SecretKey, PublicKey};
use openssl::rand::rand_bytes;

use bech32::{self, ToBase32, Variant};
use hex::{FromHex, ToHex};

const CHARSET_REV: [i8; 128] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30, 7, 5, -1, -1, -1, -1, -1, -1, -1, 29, -1, 24, 13, 25, 9, 8, 23,
    -1, 18, 22, 31, 27, 19, -1, 1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1, -1, 29,
    -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1, 1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1,
    -1, -1, -1, -1,
];

fn do_work(hex: Option<String>, pre: Option<String>) -> (String, String, String, String) {
    let req_search: bool = hex.is_none() && pre.is_some();

    let prefix_bytes = if req_search {
        let p = pre.unwrap();

        let mut prefix5bit: Vec<u8> = vec![];
        for c in p.chars() {
            let num_value = CHARSET_REV[c as usize];
            if !(0..=31).contains(&num_value) {
                panic!("invalid pubkey characters");
            }
            prefix5bit.push(num_value as u8);
        }

        bech32::convert_bits(&prefix5bit, 5, 8, true).expect("Conver failed")
    } else {
        vec![]
    };
    let prefix_length = prefix_bytes.len();

    let bytes = if let Some(ref h) = hex {
        <[u8; 32]>::from_hex(h).expect("Decoding failed")
    } else {
        [0; 32]
    };

    let mut count = 0;
    print!("\x1B[?25l[{}]\r", count);
    'outer: loop {
        count = count+1;
        let skey_bytes = if hex.is_some() {
            bytes
        } else {
            let mut bytes: [u8; 32] = [0; 32];
            rand_bytes(&mut bytes).unwrap();

            bytes
        };

        let skey = SecretKey::parse(&skey_bytes).unwrap();
        let pkey = PublicKey::from_secret_key(&skey);
        let pkey_serialized = pkey.serialize_compressed();
        let (_, pkey_bytes) = pkey_serialized.rsplit_array_ref::<32>();

        for i in 0..prefix_length {
            let key_byte = pkey_bytes[i];
            let pre_byte = prefix_bytes[i];
            if i >= prefix_length - 1 && (key_byte < pre_byte || key_byte >= pre_byte + 32) {
                print!("[{}]\r", count);
                continue 'outer;
            }

            if key_byte != pre_byte {
                print!("[{}]\r", count);
                continue 'outer;
            }
        }

        println!("\x1B[?25h[{}]", count);

        let skey_bech32 = bech32::encode("nsec", skey_bytes.to_base32(), Variant::Bech32).unwrap();
        let pkey_bech32 = bech32::encode("npub", pkey_bytes.to_base32(), Variant::Bech32).unwrap();

        let skey_hex = skey_bytes.encode_hex::<String>();
        let pkey_hex = pkey_bytes.encode_hex::<String>();
        break (skey_bech32, skey_hex, pkey_bech32, pkey_hex)
    }
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} RANDOM_HEX [options]", program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optopt("p", "", "mining npub key", "PREFIX");
    opts.optopt("o", "", "set output filename", "FILENAME");
    opts.optflag("h", "help", "print this help menu");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(f) => { panic!("{}", f.to_string()) }
    };
    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }
    let prefix = matches.opt_str("p");
    let output = matches.opt_str("o");
    let hex = if !matches.free.is_empty() {
        Some(matches.free[0].clone())
    } else {
        None
    };
    let (skey_bech32, skey_hex, pkey_bech32, pkey_hex) = do_work(hex, prefix);

    match output {
        Some(x) => {
            println!("Output: {}", x);
            println!("");
            println!("secret nsec: {}", skey_bech32);
            println!("secret  hex: {}", skey_hex);
            println!("");
            println!("public npub: {}", pkey_bech32);
            println!("public  hex: {}", pkey_hex);
        },
        None => {
            println!("secret nsec: {}", skey_bech32);
            println!("secret  hex: {}", skey_hex);
            println!("");
            println!("public npub: {}", pkey_bech32);
            println!("public  hex: {}", pkey_hex);
        },
    }
}
