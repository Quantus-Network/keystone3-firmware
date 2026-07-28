extern crate alloc;
use alloc::format;
use alloc::string::{String, ToString};
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

/// Decode an SS58-encoded address string back to a 32-byte public key, validating the
/// network prefix and checksum. Returns an error on malformed input instead of panicking
/// (audit L-1/L-2).
pub fn decode(address: &str, version: u16) -> Result<[u8; 32], String> {
    let decoded = base58::decode(address).map_err(|e| format!("invalid base58: {}", e))?;
    let len = decoded.len();
    if len < BS58_MIN_LEN {
        return Err(format!("address too short: {} bytes", len));
    }
    // Prefix: 1 byte for 0..=63, 2 bytes for 64..=16383 (inverse of `encode`).
    let (prefix, prefix_len) = match decoded[0] {
        first @ 0..=63 => (first as u16, 1usize),
        first @ 0b0100_0000..=0b0111_1111 => {
            let second = decoded[1] as u16;
            (
                (((first as u16) & 0b0011_1111) << 2) | (second >> 6) | ((second & 0b0011_1111) << 8),
                2usize,
            )
        }
        other => return Err(format!("invalid SS58 prefix byte {:#x}", other)),
    };
    let expected = version & 0b0011_1111_1111_1111;
    if prefix != expected {
        return Err(format!("SS58 prefix {} does not match expected {}", prefix, expected));
    }
    if len != prefix_len + 32 + 2 {
        return Err(format!("unexpected address length: {} bytes", len));
    }
    let hash = ss58hash(&decoded[..len - 2]);
    if decoded[len - 2..] != hash[..2] {
        return Err("SS58 checksum mismatch".to_string());
    }
    decoded[prefix_len..prefix_len + 32]
        .try_into()
        .map_err(|_| "account id not 32 bytes".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const QUANTUS_PREFIX: u16 = 189;

    #[test]
    fn encode_decode_roundtrip() {
        let pubkey = [0xab; 32];
        let address = encode(&pubkey, QUANTUS_PREFIX);
        assert_eq!(decode(&address, QUANTUS_PREFIX).unwrap(), pubkey);
    }

    #[test]
    fn rejects_wrong_prefix() {
        let address = encode(&[0xab; 32], QUANTUS_PREFIX);
        let err = decode(&address, 42).unwrap_err();
        assert!(err.contains("prefix"), "{}", err);
    }

    #[test]
    fn rejects_bad_checksum() {
        let mut address = encode(&[0xab; 32], QUANTUS_PREFIX);
        let last = address.len() - 1;
        let c = address.as_bytes()[last];
        // Flip the final base58 character to corrupt the checksum.
        address.replace_range(last.., if c == b'1' { "2" } else { "1" });
        assert!(decode(&address, QUANTUS_PREFIX).is_err());
    }

    #[test]
    fn rejects_malformed_input() {
        assert!(decode("not-base58!!!", QUANTUS_PREFIX).is_err());
        assert!(decode("1", QUANTUS_PREFIX).is_err());
        assert!(decode("", QUANTUS_PREFIX).is_err());
    }
}
