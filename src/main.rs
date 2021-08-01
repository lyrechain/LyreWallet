#![deny(unsafe_code)]

mod keypair;
use keypair::*;
mod global;
use global::*;

fn main() {
    let mut keys = LyreKeyPair::default();
    println!("{:?}", &keys);
    keys.new_key();

    println!("{:?}", &keys);
    &keys.dangerous_debug();

    dbg!(keys.zero_privkey());
    &keys.dangerous_debug();
}
