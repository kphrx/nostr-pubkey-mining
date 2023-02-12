#![feature(split_array)]
extern crate getopts;

use std::env;

use getopts::Options;

use libsecp256k1::{SecretKey, PublicKey};
use openssl::rand::rand_bytes;

use bech32::{self, ToBase32, Variant};
use hex::{FromHex, ToHex};

fn do_work(hex: Option<String>, pre: Option<String>) -> (String, String, String, String) {
    let req_search: bool = hex.is_none() && pre.is_some();

    let check_prefix = if req_search {
        let p = pre.unwrap();
        Some(move |npub: String| {
            let mut ncs = npub.chars();
            if Some('n') == ncs.next() && Some('p') == ncs.next() && Some('u') == ncs.next() && Some('b') == ncs.next() && Some('1') == ncs.next() {
                for pc in p.chars() {
                    if Some(pc) != ncs.next() {
                        return false
                    }
                }

                true
            } else {
                false
            }
        })
    } else {
        None
    };

    let byte = if let Some(ref h) = hex {
        <[u8; 32]>::from_hex(h).expect("Decoding failed")
    } else {
        [0; 32]
    };

    let mut count = 0;
    print!("\x1B[?25l[{}]\r", count);
    let (skey_hex, pkey_bech32, pkey_hex) = loop {
        let skey_byte = if hex.is_some() {
            byte
        } else {
            let mut byte: [u8; 32] = [0; 32];
            rand_bytes(&mut byte).unwrap();

            byte
        };

        let skey = SecretKey::parse(&skey_byte).unwrap();
        let pkey = PublicKey::from_secret_key(&skey);
        let pkey_serialized = pkey.serialize_compressed();
        let (_, pkey_byte) = pkey_serialized.rsplit_array_ref::<32>();

        let pkey_bech32 = bech32::encode("npub", pkey_byte.to_base32(), Variant::Bech32).unwrap();

        let end = if check_prefix.is_some() {
            check_prefix.clone().unwrap()(pkey_bech32.clone())
        } else {
            true
        };

        count = count+1;
        if end {
            println!("\x1B[?25h[{}]", count);
            let skey_hex = skey_byte.encode_hex::<String>();
            let pkey_hex = pkey_byte.encode_hex::<String>();
            break (skey_hex, pkey_bech32, pkey_hex)
        }
        print!("[{}]\r", count);
    };

    let skey_byte = <[u8; 32]>::from_hex(skey_hex.clone()).expect("Decoding failed");
    let skey_bech32 = bech32::encode("nsec", skey_byte.to_base32(), Variant::Bech32).unwrap();

    (skey_bech32, skey_hex, pkey_bech32, pkey_hex)
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
