#![no_std]
extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use crate::errors::{QuantusError, Result};
use crate::structs::ParsedQuantusTx;
use qp_rusty_crystals_dilithium::ml_dsa_87::Keypair;
use qp_rusty_crystals_hdwallet::HDLattice;
use qp_poseidon_core::{hash_padded_bytes, FIELD_ELEMENT_PREIMAGE_PADDING_LEN};
use rust_tools::debug;
use cryptoxide::hashing::blake2b_256;

pub mod errors;
pub mod structs;
pub mod metadata;
pub mod parser;

fn poseidon_hash(data: &[u8]) -> [u8; 32] {
    hash_padded_bytes::<FIELD_ELEMENT_PREIMAGE_PADDING_LEN>(data)
}

fn get_keys(mnemonic: &str, passphrase: &str, path: &str) -> Result<Keypair> {
    let hd_wallet = HDLattice::from_mnemonic(mnemonic, Some(passphrase))
        .map_err(|e| QuantusError::SignFailure(alloc::format!("{:?}", e)))?;
    
    hd_wallet.generate_derived_keys(path)
        .map_err(|e| QuantusError::SignFailure(alloc::format!("{:?}", e)))
}

pub fn get_address(mnemonic: &str, passphrase: &str, path: &str) -> Result<String> {
    let keys = get_keys(mnemonic, passphrase, path)?;
        
    let pub_key_bytes = keys.public.to_bytes();
    
    let account_id = poseidon_hash(&pub_key_bytes);
    
    // Use ss58 crate to encode. 
    Ok(ss58::encode(&account_id, ss58::Ss58AddressFormat::Custom(189)))
}

fn format_duration(ms: u64) -> String {
    let seconds = ms / 1000;
    if seconds == 0 {
        return "".to_string();
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

pub fn parse_quantus_tx(data: &[u8]) -> Result<ParsedQuantusTx> {
    use crate::parser::QuantusPayloadParser;
    
    debug!(alloc::format!("parse_quantus_tx input len: {}", data.len()));
    
    match QuantusPayloadParser::parse_payload(data) {
        Ok(info) => {
            debug!(alloc::format!("QuantusPayloadParser success: {}", info));
            let reversible_timeframe_str = if let Some(ms) = info.reversible_timeframe {
                format_duration(ms)
            } else {
                String::new()
            };

            Ok(ParsedQuantusTx::new(
                info.to_address,
                alloc::format!("{}", info.amount),
                "0".to_string(), // Nonce not available in new format
                "0".to_string(), // Fee not available in new format
                info.is_reversible,
                reversible_timeframe_str
            ))
        }
        Err(e) => {
            debug!(alloc::format!("QuantusPayloadParser failed: {}", e));
            Err(QuantusError::InvalidTransaction)
        }
    }
}

pub fn sign_raw_tx(
    payload_to_sign: Vec<u8>,
    path: &str,
    mnemonic: &str,
    passphrase: &str,
) -> Result<(Vec<u8>, String)> {
    debug!(alloc::format!("sign_raw_tx payload len: {}", payload_to_sign.len()));

    // 1. Derive keys
    let keys = get_keys(mnemonic, passphrase, path)?;

    // 2. Handle payload > 256 bytes
    let msg_to_sign = if payload_to_sign.len() > 256 {
        debug!("Payload > 256 bytes, hashing with Blake2b-256".to_string());
        blake2b_256(&payload_to_sign).to_vec()
    } else {
        payload_to_sign
    };

    // 3. Sign
    // Dilithium sign signature: fn sign(&self, msg: &[u8], ctx: Option<&[u8]>, rnd: Option<[u8; 32]>) -> [u8; SIG_BYTES]
    let signature = keys.secret.sign(&msg_to_sign, None, None); 
    
    // 4. Concatenate Signature + Public Key
    let mut signature_with_pubkey = signature.to_vec();
    signature_with_pubkey.extend_from_slice(&keys.public.to_bytes());
    
    let tx_hash = hex::encode(blake2b_256(&msg_to_sign)); // Return hash of signed message as tx_hash?
    Ok((signature_with_pubkey, tx_hash))
}

pub fn check_raw_tx(data: Vec<u8>) -> Result<()> {
    use crate::parser::QuantusPayloadParser;
    QuantusPayloadParser::parse_payload(&data)
        .map(|_| ())
        .map_err(|_| QuantusError::InvalidTransaction)
}
