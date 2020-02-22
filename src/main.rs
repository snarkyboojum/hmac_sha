extern crate sha_hash;

use sha_hash::sha512_hash;

enum HASH_BLOCK_SIZE {
    FiveTwelve = 1024,
}

fn key_length_bits(key: &[u32]) -> usize {
    let key_length = key.len();

    key_length * 32
}

fn main() {
    println!("Welcome to the HMAC-SHA512 implementation!");

    let text: &[u8] = &[
        0x53, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20,
        0x66, 0x6F, 0x72, 0x20, 0x6B, 0x65, 0x79, 0x6C, 0x65, 0x6E, 0x3D, 0x62, 0x6C, 0x6F, 0x63,
        0x6B, 0x6C, 0x65, 0x6E,
    ];

    let key: &[u32] = &[
        0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F, 0x10111213, 0x14151617, 0x18191A1B,
        0x1C1D1E1F, 0x20212223, 0x24252627, 0x28292A2B, 0x2C2D2E2F, 0x30313233, 0x34353637,
        0x38393A3B, 0x3C3D3E3F, 0x40414243, 0x44454647, 0x48494A4B, 0x4C4D4E4F, 0x50515253,
        0x54555657, 0x58595A5B, 0x5C5D5E5F, 0x60616263, 0x64656667, 0x68696A6B, 0x6C6D6E6F,
        0x70717273, 0x74757677, 0x78797A7B, 0x7C7D7E7F,
    ];

    // See https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf
    // for HMAC construction algorithm and implementation details

    // determine K0
    use std::cmp::Ordering;
    match key_length_bits(key).cmp(&1024) {
        Ordering::Equal => {}
        Ordering::Greater => {}
        Ordering::Less => {}
    }
}
