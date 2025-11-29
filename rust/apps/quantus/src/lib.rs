#![no_std]
extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use crate::errors::{QuantusError, Result};
use qp_rusty_crystals_hdwallet::HDLattice;
use qp_poseidon_core::{hash_padded_bytes, FIELD_ELEMENT_PREIMAGE_PADDING_LEN};

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

fn poseidon_hash(data: &[u8]) -> [u8; 32] {
    hash_padded_bytes::<FIELD_ELEMENT_PREIMAGE_PADDING_LEN>(data)
}

pub fn get_address(mnemonic: &str, path: &str) -> Result<String> {
    let hd_wallet = HDLattice::from_mnemonic(mnemonic, None)
        .map_err(|e| QuantusError::SignFailure(alloc::format!("{:?}", e)))?;
    
    let keys = hd_wallet.generate_derived_keys(path)
        .map_err(|e| QuantusError::SignFailure(alloc::format!("{:?}", e)))?;
        
    let pub_key_bytes = keys.public.to_bytes();
    
    let account_id = poseidon_hash(&pub_key_bytes);
    
    // Use ss58 crate to encode. 
    Ok(ss58::encode(&account_id, ss58::Ss58AddressFormat::Custom(189)))
}

pub fn sign_tx(
    tx_json: &str,
    mnemonic: &str,
    path: &str,
) -> Result<QuantusSignature> {
    let _tx: QuantusTransaction = serde_json::from_str(tx_json)
        .map_err(|_| QuantusError::InvalidTransaction)?;
    
    let hd_wallet = HDLattice::from_mnemonic(mnemonic, None)
        .map_err(|e| QuantusError::SignFailure(alloc::format!("HD Wallet error: {:?}", e)))?;
        
    let keys = hd_wallet.generate_derived_keys(path)
        .map_err(|e| QuantusError::SignFailure(alloc::format!("Key derivation error: {:?}", e)))?;
        
    // Sign the JSON string bytes directly for now
    let message_bytes = tx_json.as_bytes();
    // sign(message, ctx, randomized_signing)
    let signature = keys.sign(message_bytes, None, None);
    
    Ok(QuantusSignature { signature: signature.to_vec() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_values() {
        let mnemonic = "orchard answer curve patient visual flower maze noise retreat penalty cage small earth domain scan pitch bottom crunch theme club client swap slice raven";
        
        // qznMJss7Ls1SWBhvvL2CSHVbgTxEfnL9GgpvMTq5CWMEwfCoe
                
        // let path = format!("m/44'/189189'/{index}'/0/0", index = wallet_index);

        let path0 = "m/44'/189189'/0'/0/0";
        let addr0 = get_address(mnemonic, path0).unwrap();
        
        // Commenting out assertion until path is confirmed to avoid CI failure
        assert_eq!(addr0, "qznMJss7Ls1SWBhvvL2CSHVbgTxEfnL9GgpvMTq5CWMEwfCoe", "Got address: {}", addr0);
        
        assert!(addr0.starts_with("qz"), "Address should start with qz prefix (for 189/Quantus)");
    }
}
