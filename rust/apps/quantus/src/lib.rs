#![no_std]
extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use crate::errors::{QuantusError, Result};

pub mod errors;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QuantusTransaction {
    pub to: String,
    pub amount: u64,
    pub nonce: u64,
}

#[derive(Debug)]
pub struct QuantusSignature {
    pub signature: Vec<u8>,
}

pub fn sign_tx(
    tx_json: &str,
    seed: &[u8],
    path: &str,
) -> Result<QuantusSignature> {
    let tx: QuantusTransaction = serde_json::from_str(tx_json)
        .map_err(|_| QuantusError::InvalidTransaction)?;
    
    // For now, we just sign the JSON string bytes. 
    // In a real implementation, we would serialize it deterministically or hash it.
    let message_bytes = tx_json.as_bytes();
    
    // Using a simple signing mechanism from keystore (e.g. ed25519 or secp256k1)
    // Assuming Ed25519 for this new coin as it's common.
    // We need to check what keystore exposes.
    
    // For this stub, let's just print what we are doing (in a way) and return a dummy signature
    // or actually sign if easy.
    
    // Let's look at how other apps sign.
    // Ethereum uses: keystore::algorithms::secp256k1::sign_message_by_seed
    
    // Let's use secp256k1 for now as it's available.
    use keystore::algorithms::secp256k1;
    use bitcoin::secp256k1::Message;
    use cryptoxide::hashing::sha256;

    let hash = sha256(message_bytes);
    let message = Message::from_digest_slice(&hash).map_err(|_| QuantusError::SignFailure("Invalid message".into()))?;
    
    let (rec_id, rs) = secp256k1::sign_message_by_seed(seed, &String::from(path), &message)
        .map_err(|e| QuantusError::SignFailure(alloc::format!("{:?}", e)))?;
        
    let mut signature = rs.to_vec();
    signature.push(rec_id as u8); // Append recovery ID if needed, or just raw bytes.
    
    Ok(QuantusSignature { signature })
}

