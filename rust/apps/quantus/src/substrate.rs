use alloc::string::{String, ToString};
use alloc::vec::Vec;
use parity_scale_codec::{Decode, Encode, Compact};
use crate::errors::{QuantusError, Result};
use crate::metadata::{get_quantus_metadata, ChainMetadata};
use rust_tools::debug;

#[derive(Debug, Clone)]
pub struct SubstrateExtrinsicParams {
    pub era: Era,
    pub nonce: u64,
    pub tip: u128,
}

#[derive(Debug, Clone)]
pub enum Era {
    Immortal,
    Mortal { period: u64, phase: u64 },
}

#[derive(Debug, Clone)]
pub struct BalancesTransferCall {
    pub destination: Vec<u8>,
    pub amount: u128,
}

#[derive(Debug, Clone)]
pub struct SubstrateCall {
    pub pallet_index: u8,
    pub call_index: u8,
    pub call_data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SubstrateSignerPayload {
    pub call: SubstrateCall,
    pub params: SubstrateExtrinsicParams,
    // We ignore the "Additional" params (Genesis Hash, etc) for parsing 
    // as they are at the end and we don't display them.
}

impl Era {
    fn decode(data: &mut &[u8]) -> Result<Self> {
        debug!(alloc::format!("Era::decode input len: {}", data.len()));
        let first_byte = u8::decode(data).map_err(|_| QuantusError::InvalidTransaction)?;
        
        if first_byte == 0 {
            debug!("Era::Immortal".to_string());
            Ok(Era::Immortal)
        } else {
            let second_byte = u8::decode(data).map_err(|_| QuantusError::InvalidTransaction)?;
            let encoded = ((first_byte as u64) << 8) | (second_byte as u64);
            let period = 2u64.pow((encoded % (1 << 4)) as u32);
            let phase = encoded >> 4;
            debug!(alloc::format!("Era::Mortal period: {}, phase: {}", period, phase));
            Ok(Era::Mortal { period, phase })
        }
    }
}

impl SubstrateExtrinsicParams {
    pub fn decode(data: &mut &[u8]) -> Result<Self> {
        debug!(alloc::format!("SubstrateExtrinsicParams::decode input len: {}", data.len()));
        
        // Standard Substrate SignedExtension order for "Extra" (included in tx):
        // 1. CheckEra (Era)
        // 2. CheckNonce (Compact<Index>)
        // 3. ChargeTransactionPayment (Compact<Balance>)
        
        let era = Era::decode(data)?;
        
        let Compact(nonce) = Compact::<u64>::decode(data)
            .map_err(|_| QuantusError::InvalidTransaction)?;
        debug!(alloc::format!("Nonce decoded: {}", nonce));
            
        let Compact(tip) = Compact::<u128>::decode(data)
            .map_err(|_| QuantusError::InvalidTransaction)?;
        debug!(alloc::format!("Tip decoded: {}", tip));
        
        Ok(SubstrateExtrinsicParams { nonce, era, tip })
    }
}

impl BalancesTransferCall {
    pub fn decode(data: &mut &[u8]) -> Result<Self> {
        debug!(alloc::format!("BalancesTransferCall::decode input len: {}", data.len()));
        // Balances::transfer arguments:
        // 1. dest: MultiAddress (usually Id(AccountId))
        // 2. amount: Compact<Balance>
        
        // Handle MultiAddress enum. 
        // 0x00 = Id (AccountId, 32 bytes)
        // 0x01 = Index (Compact, rarely used in modern chains)
        // 0x02 = Raw (Bytes)
        // 0x03 = Address32 (32 bytes)
        // 0x04 = Address20 (20 bytes)
        
        let address_type = u8::decode(data).map_err(|_| QuantusError::InvalidTransaction)?;
        debug!(alloc::format!("MultiAddress Type: {}", address_type));
        
        let destination = match address_type {
            0x00 | 0x03 => { // Id or Address32
                let mut dest = Vec::new();
                for _ in 0..32 {
                    let byte = u8::decode(data).map_err(|_| QuantusError::InvalidTransaction)?;
                    dest.push(byte);
                }
                debug!(alloc::format!("Destination: {}", hex::encode(&dest)));
                dest
            },
            _ => {
                debug!("Unsupported Address Type".to_string());
                return Err(QuantusError::InvalidTransaction); // We only support standard AccountId for now
            }
        };

        let Compact(amount) = Compact::<u128>::decode(data)
            .map_err(|_| QuantusError::InvalidTransaction)?;
        debug!(alloc::format!("Amount decoded: {}", amount));
        
        Ok(BalancesTransferCall { destination, amount })
    }
    
    pub fn to_ss58_address(&self) -> Result<String> {
        let account_id: [u8; 32] = self.destination[..32]
            .try_into()
            .map_err(|_| QuantusError::InvalidTransaction)?;
        // Quantus prefix 189
        Ok(ss58::encode(&account_id, ss58::Ss58AddressFormat::Custom(189)))
    }
}

impl SubstrateCall {
    pub fn decode(data: &mut &[u8], metadata: &ChainMetadata) -> Result<Self> {
        debug!(alloc::format!("SubstrateCall::decode input len: {}, hex: {}", data.len(), hex::encode(&data[..core::cmp::min(data.len(), 20)])));
        
        let pallet_index = u8::decode(data).map_err(|_| QuantusError::InvalidTransaction)?;
        let call_index = u8::decode(data).map_err(|_| QuantusError::InvalidTransaction)?;
        
        debug!(alloc::format!("Pallet: {}, Call: {}", pallet_index, call_index));
        
        let start_len = data.len();
        
        let call_data = if metadata.is_balances_transfer(pallet_index, call_index) ||
                          metadata.is_balances_transfer_keep_alive(pallet_index, call_index) ||
                          metadata.is_balances_force_transfer(pallet_index, call_index) {
            debug!("Identified as Balances Transfer".to_string());
            let mut temp_data = *data;
            let _transfer = BalancesTransferCall::decode(&mut temp_data)?;
            let consumed = start_len - temp_data.len();
            let result = data[..consumed].to_vec();
            *data = &data[consumed..];
            result
        } else {
            // For unknown calls, we can't safely decode because we don't know the length.
            // In a full implementation, we might try to heuristic it or just fail.
            // For now, we fail, triggering the "Blind Sign" fallback in the main lib.
            debug!("Unknown Call - Failing decode".to_string());
            return Err(QuantusError::InvalidTransaction);
        };
        
        Ok(SubstrateCall {
            pallet_index,
            call_index,
            call_data,
        })
    }
    
    pub fn parse_balances_transfer(&self, metadata: &ChainMetadata) -> Result<BalancesTransferCall> {
        // We allow parsing any of the balance transfer variants
        if !metadata.is_balances_transfer(self.pallet_index, self.call_index) &&
           !metadata.is_balances_transfer_keep_alive(self.pallet_index, self.call_index) &&
           !metadata.is_balances_force_transfer(self.pallet_index, self.call_index) {
            return Err(QuantusError::InvalidTransaction);
        }
        
        let mut call_data = self.call_data.as_slice();
        // Since we already sliced the data during decode, we can decode without worrying about over-consuming
        // But BalancesTransferCall::decode expects the leading byte for MultiAddress
        BalancesTransferCall::decode(&mut call_data)
    }
}

impl SubstrateSignerPayload {
    pub fn decode(data: &[u8], metadata: &ChainMetadata) -> Result<Self> {
        debug!(alloc::format!("SubstrateSignerPayload::decode total len: {}", data.len()));
        let mut remaining = data;
        
        // 1. Call
        let call = SubstrateCall::decode(&mut remaining, metadata)?;
        
        // 2. Extra (Era, Nonce, Tip)
        let params = SubstrateExtrinsicParams::decode(&mut remaining)?;
        
        // 3. Additional (SpecVersion, GenesisHash, etc.) - We ignore these for display
        
        Ok(SubstrateSignerPayload { call, params })
    }
}
