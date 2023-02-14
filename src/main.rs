#![feature(split_array)]
extern crate getopts;
extern crate num_cpus;

use std::env;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc, Arc,
};
use std::thread::{self, JoinHandle};
use std::time;

use getopts::Options;

use bech32::{self, ToBase32, Variant};
use hex::{FromHex, ToHex};
use libsecp256k1::{PublicKey, SecretKey};
use openssl::rand::rand_bytes;

const CHARSET_REV: [i8; 128] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30, 7, 5, -1, -1, -1, -1, -1, -1, -1, 29, -1, 24, 13, 25, 9, 8, 23,
    -1, 18, 22, 31, 27, 19, -1, 1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1, -1, 29,
    -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1, 1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1,
    -1, -1, -1, -1,
];

fn gen_private_key(hex: Option<String>) -> [u8; 32] {
    if let Some(hex) = hex {
        <[u8; 32]>::from_hex(hex).expect("Decoding failed")
    } else {
        let mut bytes: [u8; 32] = [0; 32];
        rand_bytes(&mut bytes).unwrap();
        bytes
    }
}

fn gen_public_key(skey_bytes: [u8; 32]) -> [u8; 32] {
    let skey = SecretKey::parse(&skey_bytes).unwrap();
    let pkey = PublicKey::from_secret_key(&skey);
    let pkey_serialized = pkey.serialize_compressed();
    let (_, pkey_bytes) = pkey_serialized.rsplit_array_ref::<32>();

    *pkey_bytes
}

fn gen_keypair(hex: Option<String>) -> ([u8; 32], [u8; 32]) {
    let skey_bytes = gen_private_key(hex);
    let pkey_bytes = gen_public_key(skey_bytes);
    (skey_bytes, pkey_bytes)
}

fn do_work(hex: Option<String>, pre: Option<String>) -> (String, String, String, String) {
    let req_search: bool = hex.is_none() && pre.is_some();

    let (skey_bytes, pkey_bytes) = if !req_search {
        gen_keypair(hex)
    } else {
        let p = pre.unwrap();
        let mut prefix5bit: Vec<u8> = vec![];
        for c in p.chars() {
            let num_value = CHARSET_REV[c as usize];
            if !(0..=31).contains(&num_value) {
                panic!("invalid pubkey characters");
            }
            prefix5bit.push(num_value as u8);
        }
        let prefix_bytes = bech32::convert_bits(&prefix5bit, 5, 8, true).expect("Conver failed");
        let prefix_length = prefix_bytes.len();

        let wait = Arc::new(AtomicBool::new(false));
        let finish = Arc::new(AtomicBool::new(false));
        let queue = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = mpsc::channel();
        let num = num_cpus::get();
        let mut worker_threads: Vec<JoinHandle<()>> = Vec::with_capacity(num);
        for _ in 0..num {
            let wait = wait.clone();
            let finish = finish.clone();
            let queue = queue.clone();
            let tx = tx.clone();
            let thread = thread::spawn(move || loop {
                if wait.load(Ordering::Relaxed) {
                    thread::park();
                    thread::sleep(time::Duration::from_micros(500));
                }
                if finish.load(Ordering::Relaxed) {
                    break;
                }
                queue.fetch_add(1, Ordering::SeqCst);

                let keypair = gen_keypair(None);
                if let Err(_) = tx.send(keypair) {
                    continue;
                }

                thread::sleep(time::Duration::from_micros(5));
            });
            worker_threads.push(thread)
        }
        let mut counter = 0;
        print!("Checked: {:?} \x1B[?25l\r", counter);
        let (mut skey_bytes, mut pkey_bytes): ([u8; 32], [u8; 32]) = ([0u8; 32], [0u8; 32]);
        'outer: for (skey, pkey) in rx {
            queue.fetch_sub(1, Ordering::SeqCst);
            let queue_count = queue.load(Ordering::SeqCst);
            if queue_count > 10 {
                wait.store(true, Ordering::Relaxed);
            } else if wait.load(Ordering::Relaxed) && queue_count > 5 {
                wait.store(false, Ordering::Relaxed);
                for thread in &worker_threads {
                    thread.thread().unpark();
                }
            }

            counter += 1;
            for i in 0..prefix_length {
                let key_byte = pkey[i];
                let pre_byte = prefix_bytes[i];

                if i >= prefix_length - 1 && (key_byte < pre_byte || key_byte >= pre_byte + 32) {
                    print!("Checked: {:?} \r", counter);
                    continue 'outer;
                }
                if key_byte != pre_byte {
                    print!("Checked: {:?} \r", counter);
                    continue 'outer;
                }
            }
            println!("Checked: {:?} \x1B[?25h", counter);
            skey_bytes = skey;
            pkey_bytes = pkey;
            finish.store(true, Ordering::Relaxed);
            for thread in &worker_threads {
                thread.thread().unpark();
            }
            break;
        }
        (skey_bytes, pkey_bytes)
    };
    let skey_bech32 = bech32::encode("nsec", skey_bytes.to_base32(), Variant::Bech32).unwrap();
    let pkey_bech32 = bech32::encode("npub", pkey_bytes.to_base32(), Variant::Bech32).unwrap();
    let skey_hex = skey_bytes.encode_hex::<String>();
    let pkey_hex = pkey_bytes.encode_hex::<String>();
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
        Ok(m) => m,
        Err(f) => {
            panic!("{}", f.to_string())
        }
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
        }
        None => {
            println!("secret nsec: {}", skey_bech32);
            println!("secret  hex: {}", skey_hex);
            println!("");
            println!("public npub: {}", pkey_bech32);
            println!("public  hex: {}", pkey_hex);
        }
    }
}
