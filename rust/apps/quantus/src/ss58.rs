extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::vec;
use blake2::{Blake2b512, Digest};
use bitcoin::base58;

/// Convert a fixed-length u8 array (public key) to SS58-encoded address
pub fn encode(pubkey: &[u8; 32], version: u16) -> String {
    // Encode version prefix
    let ident: u16 = version & 0b0011_1111_1111_1111;
    let mut v = match ident {
        0..=63 => vec![ident as u8],
        64..=16_383 => {
            let first = ((ident & 0b0000_0000_1111_1100) as u8) >> 2;
            let second = ((ident >> 8) as u8) | (((ident & 0b11) as u8) << 6);
            vec![first | 0b0100_0000, second]
        }
        _ => panic!("Invalid SS58 prefix range"),
    };

    v.extend_from_slice(pubkey);

    // Compute the checksum using the provided ss58hash utility
    let hash = ss58hash(&v);
    v.extend_from_slice(&hash[..2]);

    // Base58 encode the result
    base58::encode(&v)
}

const PREFIX: &[u8] = b"SS58PRE";

fn ss58hash(data: &[u8]) -> Vec<u8> {
    let mut ctx = Blake2b512::new();
    ctx.update(PREFIX);
    ctx.update(data);
    ctx.finalize().to_vec()
}

const BS58_MIN_LEN: usize = 35; // Prefix (1) + ID (32) + Checksum (2)

/// Decode an SS58-encoded address string back to a 32-byte public key
pub fn decode(address: &str) -> [u8; 32] {
    let decoded = base58::decode(address).expect("get valid base58");
    let len = decoded.len();
    if len < BS58_MIN_LEN {
        panic!("Unable to decode bs58 address");
    }
    let slice: [u8; 32] = decoded[len - 34..len - 2]
        .try_into()
        .expect("get array length of 32");
    slice
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
