#![no_std]
extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use crate::errors::{QuantusError, Result};
use crate::structs::ParsedQuantusTx;
use qp_rusty_crystals_hdwallet::HDLattice;
use qp_poseidon_core::{hash_padded_bytes, FIELD_ELEMENT_PREIMAGE_PADDING_LEN};
use parity_scale_codec::{Encode, Decode};
use app_utils::keystone;
use rust_tools::debug;

pub mod errors;
pub mod structs;
pub mod substrate;
pub mod metadata;

#[derive(Serialize, Deserialize, Debug, Clone, Encode, Decode)]
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

pub fn get_address(mnemonic: &str, passphrase: &str, path: &str) -> Result<String> {
    let hd_wallet = HDLattice::from_mnemonic(mnemonic, Some(passphrase))
        .map_err(|e| QuantusError::SignFailure(alloc::format!("{:?}", e)))?;
    
    let keys = hd_wallet.generate_derived_keys(path)
        .map_err(|e| QuantusError::SignFailure(alloc::format!("{:?}", e)))?;
        
    let pub_key_bytes = keys.public.to_bytes();
    
    let account_id = poseidon_hash(&pub_key_bytes);
    
    // Use ss58 crate to encode. 
    Ok(ss58::encode(&account_id, ss58::Ss58AddressFormat::Custom(189)))
}

pub fn parse_quantus_tx(data: &[u8]) -> Result<ParsedQuantusTx> {
    use crate::substrate::{SubstrateSignerPayload, BalancesTransferCall};
    use crate::metadata::get_quantus_metadata;
    
    debug!(alloc::format!("parse_quantus_tx input len: {}", data.len()));
    
    let metadata = get_quantus_metadata();
    
    match SubstrateSignerPayload::decode(data, &metadata) {
        Ok(payload) => {
            debug!("SubstrateSignerPayload decoded successfully".to_string());
            let transfer_call = payload.call.parse_balances_transfer(&metadata)?;
            let to_address = transfer_call.to_ss58_address()?;
            let amount_str = alloc::format!("{}", transfer_call.amount);
            let nonce_str = alloc::format!("{}", payload.params.nonce);
            let fee_str = alloc::format!("{}", payload.params.tip);
            
            debug!(alloc::format!("To: {}, Amount: {}, Nonce: {}, Fee: {}", to_address, amount_str, nonce_str, fee_str));
            
            Ok(ParsedQuantusTx::new(
                to_address,
                amount_str,
                nonce_str,
                fee_str,
            ))
        }
        Err(e) => {
            debug!(alloc::format!("SubstrateSignerPayload decode failed: {:?}", e));
            debug!("Falling back to QuantusTransaction decode".to_string());
            let tx = QuantusTransaction::decode(&mut &data[..])
                .map_err(|_| QuantusError::InvalidTransaction)?;
                
            Ok(ParsedQuantusTx::new(
                tx.to,
                alloc::format!("{}", tx.amount),
                alloc::format!("{}", tx.nonce),
                "0".to_string(),
            ))
        }
    }
}

pub fn sign_raw_tx(
    data: Vec<u8>,
    _context: keystone::ParseContext,
    _seed: &[u8],
) -> Result<(String, String)> {
    // 2. Decode SCALE bytes to QuantusTransaction
    let _tx = QuantusTransaction::decode(&mut &data[..])
        .map_err(|_| QuantusError::InvalidTransaction)?;

    // 3. Sign
    // TODO: Use the seed to derive keys and sign
    // For now, we just return a placeholder signature to compile
    let signature_hex = "placeholder_signature".to_string();
    let tx_hash = "placeholder_hash".to_string();
    
    Ok((signature_hex, tx_hash))
}

pub fn check_raw_tx(data: Vec<u8>, _context: keystone::ParseContext) -> Result<()> {
    let _tx = QuantusTransaction::decode(&mut &data[..])
        .map_err(|_| QuantusError::InvalidTransaction)?;
        
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_scale_decode() {
        let tx = QuantusTransaction {
            to: "qznMJss7Ls1SWBhvvL2CSHVbgTxEfnL9GgpvMTq5CWMEwfCoe".to_string(),
            amount: 1000,
            nonce: 1,
        };
        let encoded = tx.encode();
        let decoded = QuantusTransaction::decode(&mut &encoded[..]).unwrap();
        assert_eq!(tx.to, decoded.to);
        assert_eq!(tx.amount, decoded.amount);
        assert_eq!(tx.nonce, decoded.nonce);
    }
}
