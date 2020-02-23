extern crate sha_hash;

use sha_hash::sha512_hash;

enum HASH_BLOCK_SIZE {
    FiveTwelve = 1024,
}

fn key_length_bits(key: &[u32]) -> usize {
    let key_length = key.len();

    key_length * 32
}

// See https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf
// for HMAC construction algorithm and implementation details

// TODO: this currently only works for SHA-512 where the block size is 1024 bits
fn hmac_sha512(key: &[u32], text: &[u32]) -> [u32; 16] {
    // determine K0
    use byteorder::{BigEndian, ByteOrder};
    use std::cmp::Ordering;

    println!("text is: {:2x?}\n", text);
    println!("key is: {:2x?}\n", key);
    println!("------");

    let mut text_bytes = vec![0u8; text.len() * 4];
    BigEndian::write_u32_into(&text, &mut text_bytes);
    let mut key_bytes = vec![0u8; key.len() * 4];
    BigEndian::write_u32_into(&key, &mut key_bytes);

    match key_length_bits(key).cmp(&1024) {
        Ordering::Equal => {
            let ipad = vec![0x36; 128];
            let opad = vec![0x5c; 128];

            let mut k0_ipad = vec![0u8; 128];
            let mut k0_opad = vec![0u8; 128];
            assert_eq!(key.len() * 4, ipad.len());
            assert_eq!(key.len() * 4, opad.len());

            for (i, item) in key_bytes.iter().enumerate() {
                k0_ipad[i] = ipad[i] ^ item;
                k0_opad[i] = opad[i] ^ item;
            }
            println!("k0^ipad is: {:2x?}\n", k0_ipad);

            // concat k0 + ipad + text
            k0_ipad.extend(&text_bytes);
            println!("(k0^ipad)||text is: {:2x?}\n", k0_ipad);

            // hash and convert to bytes
            let hash = sha512_hash(&k0_ipad).expect("Couldn't hash k0 + ipad + text");
            let mut hash_bytes = vec![0u8; hash.len() * 8];
            BigEndian::write_u64_into(&hash, &mut hash_bytes);
            println!("hash((k0^ipad)||text) is: {:2x?}\n", hash);

            println!("k0^opad is: {:2x?}\n", k0_opad);
            // concat (k0 ^ opad) and hash bytes
            k0_opad.extend(&hash_bytes);
            let hmac = sha512_hash(&k0_opad).expect("Couldn't do final hash for mac");

            println!("mac is: {:2x?}", hmac);

            // return hmac;
        }

        Ordering::Greater => {}
        Ordering::Less => {}
    }

    [0u32; 16]
}

fn main() {
    println!("Welcome to the HMAC-SHA512 implementation!");

    let text: &[u32] = &[
        0x00005361, 0x6D706C65, 0x206D6573, 0x73616765, 0x20666F72, 0x206B6579, 0x6C656E3D,
        0x626C6F63, 0x6B6C656E,
    ];

    let key: &[u32] = &[
        0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F, 0x10111213, 0x14151617, 0x18191A1B,
        0x1C1D1E1F, 0x20212223, 0x24252627, 0x28292A2B, 0x2C2D2E2F, 0x30313233, 0x34353637,
        0x38393A3B, 0x3C3D3E3F, 0x40414243, 0x44454647, 0x48494A4B, 0x4C4D4E4F, 0x50515253,
        0x54555657, 0x58595A5B, 0x5C5D5E5F, 0x60616263, 0x64656667, 0x68696A6B, 0x6C6D6E6F,
        0x70717273, 0x74757677, 0x78797A7B, 0x7C7D7E7F,
    ];

    let mac = hmac_sha512(key, text);
}
