use alloc::collections::BTreeMap;
use alloc::string::String;
use crate::errors::{QuantusError, Result};

pub struct PalletMetadata {
    pub index: u8,
    pub name: &'static str,
    pub calls: BTreeMap<u8, &'static str>,
}

pub struct ChainMetadata {
    pub pallets: BTreeMap<&'static str, PalletMetadata>,
    pub pallet_by_index: BTreeMap<u8, &'static str>,
}

impl ChainMetadata {
    pub fn get_pallet_index(&self, pallet_name: &str) -> Option<u8> {
        self.pallets.get(pallet_name).map(|p| p.index)
    }
    
    pub fn get_call_index(&self, pallet_name: &str, call_name: &str) -> Option<u8> {
        self.pallets
            .get(pallet_name)
            .and_then(|p| {
                p.calls.iter()
                    .find(|(_, name)| **name == call_name)
                    .map(|(idx, _)| *idx)
            })
    }
    
    pub fn get_pallet_name(&self, pallet_index: u8) -> Option<&'static str> {
        self.pallet_by_index.get(&pallet_index).copied()
    }
    
    pub fn is_balances_transfer(&self, pallet_index: u8, call_index: u8) -> bool {
        self.get_pallet_name(pallet_index)
            .and_then(|name| {
                if name == "Balances" {
                    self.get_call_index("Balances", "transfer_allow_death")
                        .map(|idx| idx == call_index)
                } else {
                    None
                }
            })
            .unwrap_or(false)
    }
    
    pub fn is_balances_transfer_keep_alive(&self, pallet_index: u8, call_index: u8) -> bool {
        self.get_pallet_name(pallet_index)
            .and_then(|name| {
                if name == "Balances" {
                    self.get_call_index("Balances", "transfer_keep_alive")
                        .map(|idx| idx == call_index)
                } else {
                    None
                }
            })
            .unwrap_or(false)
    }
    
    pub fn is_balances_force_transfer(&self, pallet_index: u8, call_index: u8) -> bool {
        self.get_pallet_name(pallet_index)
            .and_then(|name| {
                if name == "Balances" {
                    self.get_call_index("Balances", "force_transfer")
                        .map(|idx| idx == call_index)
                } else {
                    None
                }
            })
            .unwrap_or(false)
    }
}

pub fn get_quantus_metadata() -> ChainMetadata {
    let mut pallets = BTreeMap::new();
    let mut pallet_by_index = BTreeMap::new();
    
    let mut balances_calls = BTreeMap::new();
    balances_calls.insert(0x00, "transfer_allow_death");
    balances_calls.insert(0x02, "force_transfer");
    balances_calls.insert(0x03, "transfer_keep_alive");
    
    let balances = PalletMetadata {
        index: 0x02,
        name: "Balances",
        calls: balances_calls,
    };
    
    let mut reversible_transfers_calls = BTreeMap::new();
    reversible_transfers_calls.insert(0x00, "set_high_security");
    reversible_transfers_calls.insert(0x01, "cancel");
    reversible_transfers_calls.insert(0x02, "execute_transfer");
    reversible_transfers_calls.insert(0x03, "schedule_transfer");
    reversible_transfers_calls.insert(0x04, "schedule_transfer_with_delay");
    reversible_transfers_calls.insert(0x05, "schedule_asset_transfer");
    reversible_transfers_calls.insert(0x06, "schedule_asset_transfer_with_delay");
    
    let reversible_transfers = PalletMetadata {
        index: 0x0D,
        name: "ReversibleTransfers",
        calls: reversible_transfers_calls,
    };
    
    pallets.insert("Balances", balances);
    pallets.insert("ReversibleTransfers", reversible_transfers);
    
    pallet_by_index.insert(0x00, "System");
    pallet_by_index.insert(0x01, "Timestamp");
    pallet_by_index.insert(0x02, "Balances");
    pallet_by_index.insert(0x03, "TransactionPayment");
    pallet_by_index.insert(0x04, "Sudo");
    pallet_by_index.insert(0x05, "QPoW");
    pallet_by_index.insert(0x07, "MiningRewards");
    pallet_by_index.insert(0x08, "Vesting");
    pallet_by_index.insert(0x09, "Preimage");
    pallet_by_index.insert(0x0A, "Scheduler");
    pallet_by_index.insert(0x0B, "Utility");
    pallet_by_index.insert(0x0C, "Referenda");
    pallet_by_index.insert(0x0D, "ReversibleTransfers");
    pallet_by_index.insert(0x0E, "ConvictionVoting");
    pallet_by_index.insert(0x0F, "TechCollective");
    pallet_by_index.insert(0x10, "TechReferenda");
    pallet_by_index.insert(0x11, "MerkleAirdrop");
    pallet_by_index.insert(0x12, "TreasuryPallet");
    pallet_by_index.insert(0x13, "Origins");
    pallet_by_index.insert(0x14, "Recovery");
    pallet_by_index.insert(0x15, "Assets");
    pallet_by_index.insert(0x16, "AssetsHolder");
    
    ChainMetadata {
        pallets,
        pallet_by_index,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_metadata_lookup() {
        let metadata = get_quantus_metadata();
        
        assert_eq!(metadata.get_pallet_index("Balances"), Some(0x02));
        assert_eq!(metadata.get_call_index("Balances", "transfer_allow_death"), Some(0x00));
        assert_eq!(metadata.get_call_index("Balances", "transfer_keep_alive"), Some(0x03));
        assert_eq!(metadata.get_call_index("Balances", "force_transfer"), Some(0x02));
        assert_eq!(metadata.get_pallet_name(0x02), Some("Balances"));
        assert_eq!(metadata.get_pallet_name(0x0D), Some("ReversibleTransfers"));
        assert!(metadata.is_balances_transfer(0x02, 0x00));
        assert!(metadata.is_balances_transfer_keep_alive(0x02, 0x03));
        assert!(metadata.is_balances_force_transfer(0x02, 0x02));
    }
}
