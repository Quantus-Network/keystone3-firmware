#![no_std]
extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use crate::errors::{QuantusError, Result};
use crate::structs::ParsedQuantusTx;
use crate::parser::QuantusTx;
use qp_rusty_crystals_dilithium::ml_dsa_87::Keypair;
use qp_poseidon_core::hash_bytes;
#[cfg(not(test))]
use rust_tools::debug;
use cryptoxide::hashing::blake2b_256;

pub fn decode_ur_qr_parts(ur_parts: &[String]) -> Result<Vec<u8>> {
    use quantus_ur::decode_bytes;
    
    match decode_bytes(ur_parts) {
        Ok(bytes) => Ok(bytes),
        Err(_) => {
            #[cfg(not(test))]
            debug!("decode_bytes failed, trying decode (hex)".to_string());
            use quantus_ur::decode_hex;
            let hex_str = decode_hex(ur_parts)
                .map_err(|_| QuantusError::InvalidTransaction)?;
            hex::decode(&hex_str)
                .map_err(|_| QuantusError::InvalidTransaction)
        }
    }
}

pub mod errors;
pub mod structs;
pub mod parser;
pub mod ss58;
pub mod checkphrase;

fn get_keys(mnemonic: &str, passphrase: &str, path: &str) -> Result<Keypair> {
    qp_rusty_crystals_hdwallet::derive_key_from_mnemonic(mnemonic, Some(passphrase), path)
        .map_err(|e| QuantusError::SignFailure(alloc::format!("{:?}", e)))
}

pub fn get_address(mnemonic: &str, passphrase: &str, path: &str) -> Result<String> {
    let keys = get_keys(mnemonic, passphrase, path)?;
        
    let pub_key_bytes = keys.public.to_bytes();
    
    let account_id = hash_bytes(&pub_key_bytes);
    
    // Use custom ss58 encoding
    Ok(ss58::encode(&account_id, 189))
}

fn format_amount(amount: u128) -> String {
    const DECIMALS: u128 = 1_000_000_000_000; // 10^12
    
    let integer_part = amount / DECIMALS;
    let fractional_part = amount % DECIMALS;
    
    if fractional_part == 0 {
        alloc::format!("{}", integer_part)
    } else {
        let formatted = alloc::format!("{}.{:012}", integer_part, fractional_part);
        let trimmed = formatted.trim_end_matches('0');
        String::from(trimmed.trim_end_matches('.'))
    }
}

fn format_duration(ms: u64) -> String {
    let seconds = ms / 1000;
    if seconds == 0 {
        // Defense-in-depth: a non-zero sub-second duration must never render as a blank
        // string and hide the reversal window (audit H-1). The parser already rejects
        // delays below the on-chain minimum, so this only guards future call paths.
        return if ms == 0 { String::new() } else { "< 1s".to_string() };
    }
    
    let days = seconds / 86400;
    let remainder_d = seconds % 86400;
    let hours = remainder_d / 3600;
    let remainder_h = remainder_d % 3600;
    let minutes = remainder_h / 60;
    let sec = remainder_h % 60;

    let mut result = String::new();
    if days > 0 { result.push_str(&alloc::format!("{}d ", days)); }
    if hours > 0 { result.push_str(&alloc::format!("{}h ", hours)); }
    if minutes > 0 { result.push_str(&alloc::format!("{}m ", minutes)); }
    if sec > 0 { result.push_str(&alloc::format!("{}s", sec)); }
    
    String::from(result.trim())
}

fn tx_type_title(tx: &QuantusTx) -> &'static str {
    match tx {
        QuantusTx::Transfer { is_reversible: true, .. } => "Reversible Transfer",
        QuantusTx::Transfer { .. } => "Transfer",
        QuantusTx::MultisigCreate { .. } => "Create Multisig",
        QuantusTx::MultisigPropose { .. } => "Multisig Propose",
        QuantusTx::MultisigApprove { .. } => "Multisig Approve",
        QuantusTx::MultisigExecute { .. } => "Multisig Execute",
    }
}

fn push_row(labels: &mut Vec<String>, values: &mut Vec<String>, label: &str, value: String) {
    labels.push(label.to_string());
    values.push(value);
}

// Flatten a call into ordered (label, value) rows for the per-type detail view. Recurses into the
// inner call of a multisig proposal so the user sees exactly what is being proposed (no blind signing).
fn push_address_row(labels: &mut Vec<String>, values: &mut Vec<String>, label: &str, address: &str, with_checkphrase: bool) {
    push_row(labels, values, label, address.to_string());
    let phrase = if with_checkphrase {
        checkphrase::from_address(address)
    } else {
        String::new()
    };
    push_row(labels, values, "Checkphrase", phrase);
}

fn append_rows(tx: &QuantusTx, labels: &mut Vec<String>, values: &mut Vec<String>, with_checkphrase: bool) {
    match tx {
        QuantusTx::Transfer { to, amount, is_reversible, reversible_timeframe } => {
            push_row(labels, values, "Amount", alloc::format!("{} QUAN", format_amount(*amount)));
            push_address_row(labels, values, "To", to, with_checkphrase);
            if *is_reversible {
                push_row(labels, values, "Reversible", "Yes".to_string());
                if let Some(ms) = reversible_timeframe {
                    push_row(labels, values, "Reversal Window", format_duration(*ms));
                }
            }
        }
        QuantusTx::MultisigCreate { signers, threshold, nonce } => {
            push_row(labels, values, "Threshold", alloc::format!("{} of {}", threshold, signers.len()));
            push_row(labels, values, "Nonce", nonce.to_string());
            for (i, signer) in signers.iter().enumerate() {
                push_address_row(labels, values, &alloc::format!("Signer {}", i + 1), signer, with_checkphrase);
            }
        }
        QuantusTx::MultisigPropose { multisig, expiry, inner } => {
            push_address_row(labels, values, "Multisig", multisig, with_checkphrase);
            push_row(labels, values, "Expiry Block", expiry.to_string());
            push_row(labels, values, "Proposed Call", tx_type_title(inner).to_string());
            append_rows(inner, labels, values, with_checkphrase);
        }
        QuantusTx::MultisigApprove { multisig, proposal_id, inner } => {
            push_address_row(labels, values, "Multisig", multisig, with_checkphrase);
            push_row(labels, values, "Proposal ID", proposal_id.to_string());
            // The chain binds approvals to the proposal's call bytes; render the contained
            // call so the signer never blind-approves (audit H-2).
            push_row(labels, values, "Proposed Call", tx_type_title(inner).to_string());
            append_rows(inner, labels, values, with_checkphrase);
        }
        QuantusTx::MultisigExecute { multisig, proposal_id } => {
            push_address_row(labels, values, "Multisig", multisig, with_checkphrase);
            push_row(labels, values, "Proposal ID", proposal_id.to_string());
            // Execute carries no call bytes, so the proposal contents cannot be verified
            // on-device; say so instead of implying a verifiable review (audit H-2).
            push_row(labels, values, "Warning", "Proposal contents not verifiable on-device".to_string());
        }
    }
}

fn build_parsed_tx(parsed: &parser::ParsedPayload, with_checkphrase: bool) -> ParsedQuantusTx {
    let tx = &parsed.call;
    let tx_type = tx_type_title(tx).to_string();
    let nonce = parsed.extensions.nonce.to_string();
    let tip = format_amount(parsed.extensions.tip);
    let network = parsed.network.to_string();
    let era = parsed.extensions.era.to_string();

    // Plain transfers keep the existing curated card layout (to/amount/tip/nonce fields).
    if let QuantusTx::Transfer { to, amount, is_reversible, reversible_timeframe } = tx {
        let timeframe_str = match reversible_timeframe {
            Some(ms) => format_duration(*ms),
            None => String::new(),
        };
        let to_checkphrase = if with_checkphrase && !to.is_empty() {
            checkphrase::from_address(to)
        } else {
            String::new()
        };
        return ParsedQuantusTx::new(
            tx_type,
            false,
            to.clone(),
            to_checkphrase,
            format_amount(*amount),
            nonce,
            tip,
            *is_reversible,
            timeframe_str,
            network,
            era,
            Vec::new(),
            Vec::new(),
        );
    }

    // Everything else renders as a generic per-type labeled list, followed by the signed
    // extensions so nothing that is signed goes undisplayed.
    let mut labels = Vec::new();
    let mut values = Vec::new();
    append_rows(tx, &mut labels, &mut values, with_checkphrase);
    push_row(&mut labels, &mut values, "Network", network.clone());
    push_row(&mut labels, &mut values, "Signer Nonce", nonce.clone());
    push_row(&mut labels, &mut values, "Tip", alloc::format!("{} QUAN", tip));
    push_row(&mut labels, &mut values, "Valid For", era.clone());
    ParsedQuantusTx::new(
        tx_type,
        true,
        String::new(),
        String::new(),
        String::new(),
        nonce,
        tip,
        false,
        String::new(),
        network,
        era,
        labels,
        values,
    )
}

pub fn parse_quantus_tx(data: &[u8]) -> Result<ParsedQuantusTx> {
    parse_quantus_tx_impl(data, true)
}

pub fn parse_quantus_tx_light(data: &[u8]) -> Result<ParsedQuantusTx> {
    parse_quantus_tx_impl(data, false)
}

fn parse_quantus_tx_impl(data: &[u8], with_checkphrase: bool) -> Result<ParsedQuantusTx> {
    #[cfg(not(test))]
    debug!(alloc::format!("parse_quantus_tx input len: {}", data.len()));

    match parser::parse_payload(data) {
        Ok(parsed) => {
            #[cfg(not(test))]
            debug!(alloc::format!("parse_payload success: {}", parsed.call));
            Ok(build_parsed_tx(&parsed, with_checkphrase))
        }
        Err(_e) => {
            #[cfg(not(test))]
            debug!(alloc::format!("parse_payload failed: {}", _e));
            Err(QuantusError::InvalidTransaction)
        }
    }
}

/// `hedge` is fresh device randomness for FIPS 204 hedged signing: it is folded into the
/// signature's internal nonce so a fault-injection attack on a stolen device cannot use the
/// deterministic two-signature trick to recover key material (audit M-1).
pub fn sign_raw_tx(
    payload_to_sign: Vec<u8>,
    path: &str,
    mnemonic: &str,
    passphrase: &str,
    hedge: [u8; 32],
) -> Result<Vec<u8>> {
    #[cfg(not(test))]
    debug!(alloc::format!("sign_raw_tx payload len: {}", payload_to_sign.len()));

    // 1. Derive keys
    let keys = get_keys(mnemonic, passphrase, path)?;

    // 2. Handle payload > 256 bytes
    let msg_to_sign = if payload_to_sign.len() > 256 {
        #[cfg(not(test))]
        debug!("Payload > 256 bytes, hashing with Blake2b-256".to_string());
        blake2b_256(&payload_to_sign).to_vec()
    } else {
        payload_to_sign
    };

    // 3. Sign
    let signature = keys.secret.sign(&msg_to_sign, None, Some(hedge))
        .map_err(|e| QuantusError::SignFailure(alloc::format!("{:?}", e)))?;

    #[cfg(not(test))]
    debug!(alloc::format!("Quantus signature hash: {}", hex::encode(blake2b_256(&signature))));

    // 4. Concatenate Signature + Public Key
    let mut signature_with_pubkey = signature.to_vec();
    signature_with_pubkey.extend_from_slice(&keys.public.to_bytes());

    #[cfg(not(test))]
    debug!(alloc::format!("signature_with_pubkey len: {}", signature_with_pubkey.len()));

    Ok(signature_with_pubkey)
}

pub fn check_raw_tx(data: Vec<u8>) -> Result<()> {
    match parser::parse_payload(&data) {
        Ok(_) => Ok(()),
        Err(_e) => {
            #[cfg(not(test))]
            debug!(alloc::format!("check_raw_tx failed: {}", _e));
            Err(QuantusError::InvalidTransaction)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quantus_ur::{encode_bytes, decode_bytes};

    const TEST_HEDGE: [u8; 32] = [0x42; 32];

    #[test]
    fn test_format_duration_subsecond() {
        assert_eq!(format_duration(0), "");
        assert_eq!(format_duration(500), "< 1s");
        assert_eq!(format_duration(1_000), "1s");
        assert_eq!(format_duration(90_000), "1m 30s");
    }

    #[test]
    fn test_sign_encode_decode_roundtrip() {
        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let test_passphrase = "";
        let test_path = "m/44'/189'/0'/0'/0'";
        
        let test_payload = b"test payload for signing";
        
        let signature = sign_raw_tx(
            test_payload.to_vec(),
            test_path,
            test_mnemonic,
            test_passphrase,
            TEST_HEDGE
        ).expect("Signing should succeed");
        
        assert!(!signature.is_empty(), "Signature should not be empty");
        
        let ur_parts = encode_bytes(&signature).expect("Encoding should succeed");
        assert!(!ur_parts.is_empty(), "Should have at least one UR part");
        
        let decoded_signature = decode_bytes(&ur_parts).expect("Decoding should succeed");
        
        assert_eq!(signature, decoded_signature, "Decoded signature should match original");
    }

    #[test]
    fn test_sign_encode_decode_large_payload() {
        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let test_passphrase = "";
        let test_path = "m/44'/189'/0'/0'/0'";
        
        let mut large_payload = Vec::with_capacity(300);
        for i in 0..300 {
            large_payload.push(i as u8);
        }
        
        let signature = sign_raw_tx(
            large_payload.clone(),
            test_path,
            test_mnemonic,
            test_passphrase,
            TEST_HEDGE
        ).expect("Signing should succeed");
        
        let ur_parts = encode_bytes(&signature).expect("Encoding should succeed");
        
        assert!(ur_parts.len() > 1, "Large payload should produce multiple UR parts");
        
        let decoded_signature = decode_bytes(&ur_parts).expect("Decoding should succeed");
        
        assert_eq!(signature, decoded_signature, "Decoded signature should match original");
    }

    #[test]
    fn test_ur_parts_format() {
        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let test_passphrase = "";
        let test_path = "m/44'/189'/0'/0'/0'";
        
        let test_payload = b"test";
        let signature = sign_raw_tx(
            test_payload.to_vec(),
            test_path,
            test_mnemonic,
            test_passphrase,
            TEST_HEDGE
        ).expect("Signing should succeed");
        
        let ur_parts = encode_bytes(&signature).expect("Encoding should succeed");
        
        for part in &ur_parts {
            assert!(part.starts_with("UR:QUANTUS-SIGN-REQUEST"), 
                "UR part should start with UR:QUANTUS-SIGN-REQUEST, got: {}", part);
        }
    }

    #[test]
    fn test_production_encode_decode_roundtrip() {
        use ur_parse_lib::keystone_ur_encoder::probe_encode;
        use minicbor::bytes::ByteVec;
        
        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let test_passphrase = "";
        let test_path = "m/44'/189'/0'/0'/0'";
        
        let test_payload = b"test payload for signing";
        let signature = sign_raw_tx(
            test_payload.to_vec(),
            test_path,
            test_mnemonic,
            test_passphrase,
            TEST_HEDGE
        ).expect("Signing should succeed");
        
        let cbor_wrapped = minicbor::to_vec(ByteVec::from(signature.clone()))
            .expect("CBOR encoding should succeed");
        
        const FRAGMENT_MAX_LENGTH_DEFAULT: usize = 200;
        let encode_result = probe_encode(
            &cbor_wrapped,
            FRAGMENT_MAX_LENGTH_DEFAULT,
            "quantus-sign-request".to_string()
        ).expect("probe_encode should succeed");
        
        let mut ur_parts = Vec::new();
        ur_parts.push(encode_result.data.clone());
        
        if encode_result.is_multi_part {
            if let Some(mut encoder) = encode_result.encoder {
                let count = encoder.fragment_count();
                while ur_parts.len() < count {
                    let part = encoder.next_part().expect("next_part should succeed");
                    ur_parts.push(part);
                }
            }
        }
        
        assert!(!ur_parts.is_empty(), "Should have at least one UR part");
        
        for part in &ur_parts {
            assert!(part.starts_with("ur:quantus-sign-request") || part.starts_with("UR:QUANTUS-SIGN-REQUEST"),
                "UR part should start with ur:quantus-sign-request, got: {}", part);
        }
        
        let decoded_signature = decode_bytes(&ur_parts).expect("Decoding should succeed");
        
        assert_eq!(signature, decoded_signature, "Decoded signature should match original");
    }

    #[test]
    fn test_production_encode_decode_large_signature() {
        use ur_parse_lib::keystone_ur_encoder::probe_encode;
        use minicbor::bytes::ByteVec;
        
        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let test_passphrase = "";
        let test_path = "m/44'/189'/0'/0'/0'";
        
        let mut large_payload = Vec::with_capacity(300);
        for i in 0..300 {
            large_payload.push(i as u8);
        }
        
        let signature = sign_raw_tx(
            large_payload,
            test_path,
            test_mnemonic,
            test_passphrase,
            TEST_HEDGE
        ).expect("Signing should succeed");
        
        let cbor_wrapped = minicbor::to_vec(ByteVec::from(signature.clone()))
            .expect("CBOR encoding should succeed");
        
        const FRAGMENT_MAX_LENGTH_DEFAULT: usize = 200;
        let encode_result = probe_encode(
            &cbor_wrapped,
            FRAGMENT_MAX_LENGTH_DEFAULT,
            "quantus-sign-request".to_string()
        ).expect("probe_encode should succeed");
        
        let mut ur_parts = Vec::new();
        ur_parts.push(encode_result.data.clone());
        
        if encode_result.is_multi_part {
            if let Some(mut encoder) = encode_result.encoder {
                let count = encoder.fragment_count();
                while ur_parts.len() < count {
                    let part = encoder.next_part().expect("next_part should succeed");
                    ur_parts.push(part);
                }
            }
        }
        
        assert!(ur_parts.len() > 1, "Large signature should produce multiple UR parts");
        
        let decoded_signature = decode_bytes(&ur_parts).expect("Decoding should succeed");
        
        assert_eq!(signature, decoded_signature, "Decoded signature should match original");
    }

extern crate std;
use std::println;
#[test]
fn known_value_test() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let passphrase = "";
        let path = "m/44'/189189'/0'/0'/0'";
        let known_account_id = "qzpKmxWGG2prrAtgYsBT99eiPYz2teMDnMqAXNgEJqZh4DFty";

        // 1. Verify Address
        let address = get_address(mnemonic, passphrase, path).expect("get_address failed");
        assert_eq!(address, known_account_id, "Address does not match known value");
        
        // 2. Verify Signing
        let hex_payload = "0200007416854906f03a9dff66e3270a736c44e15970ac03a638471523a03069f276ca0700e876481755010000007400000002000000826beefbe2be72645ff376f18de745ac196dc77637436090de4174180706118e5a77ae1c95817ee664cf733fafa7baa8e6244b396a54e57a5bc414b24c52800600";
        let payload = hex::decode(hex_payload).expect("hex decode failed");
        
        // std::println!("Quantus Payload (Hex): {}", hex_payload);
        println!("Quantus Payload (Hex): {}", hex_payload);
        
        let payload_hash = blake2b_256(&payload);
        println!("Quantus Payload Hash (Blake2b-256): {}", hex::encode(payload_hash));

        // let keys = get_keys(mnemonic, passphrase, path).expect("get_keys failed");
        // let signature = keys.secret.sign(&payload, None, None); 
    
        let signature = sign_raw_tx(
            payload.clone(),
            path,
            mnemonic,
            passphrase,
            TEST_HEDGE
        ).expect("sign_raw_tx failed");

        println!("Quantus signature (Hex): {}", hex::encode(&signature));
        let sig_hash = blake2b_256(&signature);
        println!("Quantus signature Hash (Blake2b-256): {}", hex::encode(sig_hash));
    }
}
