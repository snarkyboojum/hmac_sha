extern crate hmac_sha;

use hmac_sha::hmac_sha512;
use byteorder::{BigEndian, ByteOrder};


fn main() {
    println!("Welcome to the HMAC-SHA512 implementation!");

    let message = "Sample message for keylen<blocklen";

    let key: &[u32] = &[
        0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F, 0x10111213, 0x14151617, 0x18191A1B,
        0x1C1D1E1F, 0x20212223, 0x24252627, 0x28292A2B, 0x2C2D2E2F, 0x30313233, 0x34353637,
        0x38393A3B, 0x3C3D3E3F,
    ];

    let mut key_bytes = vec![0u8; key.len() * 4];
    BigEndian::write_u32_into(&key, &mut key_bytes);

    let hmac = hmac_sha512(&key_bytes, &message.as_bytes());
    println!("mac is: {:2x?}", hmac);
}