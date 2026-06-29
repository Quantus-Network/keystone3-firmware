use parity_scale_codec::{Decode, Compact};
use core::fmt;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::format;

// Runtime pallet indices (chain `main`, spec >= 133). Must match the connected network.
const PALLET_BALANCES: u8 = 2;
const PALLET_REVERSIBLE_TRANSFERS: u8 = 11;
const PALLET_MULTISIG: u8 = 19;

/// A decoded Quantus call. Display-only: the device never blind-signs, it shows what it parses.
#[derive(Debug, PartialEq)]
pub enum QuantusTx {
    Transfer {
        to: String,
        amount: u128,
        is_reversible: bool,
        reversible_timeframe: Option<u64>,
    },
    MultisigCreate {
        signers: Vec<String>,
        threshold: u32,
        nonce: u64,
    },
    MultisigPropose {
        multisig: String,
        expiry: u32,
        inner: Box<QuantusTx>,
    },
    MultisigApprove {
        multisig: String,
        proposal_id: u32,
    },
    MultisigExecute {
        multisig: String,
        proposal_id: u32,
    },
}

impl QuantusTx {
    pub fn is_transfer(&self) -> bool {
        matches!(self, QuantusTx::Transfer { .. })
    }
}

impl fmt::Display for QuantusTx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QuantusTx::Transfer { to, amount, is_reversible, reversible_timeframe } => {
                let amount_f64 = *amount as f64 / 10_000_000_000.0;
                write!(f, "Transfer to {} amount {:.4} reversible {}", to, amount_f64, is_reversible)?;
                if let Some(t) = reversible_timeframe {
                    write!(f, " timeframe {}ms", t)?;
                }
                Ok(())
            }
            QuantusTx::MultisigCreate { signers, threshold, nonce } => {
                write!(f, "Create multisig {} of {} nonce {}", threshold, signers.len(), nonce)
            }
            QuantusTx::MultisigPropose { multisig, expiry, inner } => {
                write!(f, "Multisig propose on {} expiry {} call [{}]", multisig, expiry, inner)
            }
            QuantusTx::MultisigApprove { multisig, proposal_id } => {
                write!(f, "Multisig approve on {} proposal {}", multisig, proposal_id)
            }
            QuantusTx::MultisigExecute { multisig, proposal_id } => {
                write!(f, "Multisig execute on {} proposal {}", multisig, proposal_id)
            }
        }
    }
}

pub struct QuantusPayloadParser;

impl QuantusPayloadParser {
    pub fn bytes_to_ss58(bytes: &[u8]) -> String {
        const SS58_PREFIX: u16 = 189; // Quantus SS58 prefix

        if bytes.len() != 32 {
            panic!("AccountId32 must be 32 bytes");
        }

        let mut account_id_bytes = [0u8; 32];
        account_id_bytes.copy_from_slice(bytes);

        crate::ss58::encode(&account_id_bytes, SS58_PREFIX)
    }

    pub fn parse_payload(payload: &[u8]) -> Result<QuantusTx, String> {
        let mut input = &payload[..];

        let pallet_index: u8 = Decode::decode(&mut input).map_err(|e| e.to_string())?;
        let call_data = input;

        match pallet_index {
            PALLET_BALANCES => Self::parse_balances_call(call_data),
            PALLET_REVERSIBLE_TRANSFERS => Self::parse_reversible_transfers_call(call_data),
            PALLET_MULTISIG => Self::parse_multisig_call(call_data),
            _ => Err(format!("Unknown pallet {}", pallet_index)),
        }
    }

    fn parse_balances_call(call_data: &[u8]) -> Result<QuantusTx, String> {
        let mut input = call_data;
        let call_index: u8 = Decode::decode(&mut input).map_err(|e| e.to_string())?;

        match call_index {
            0 | 3 => { // transfer_allow_death or transfer_keep_alive
                let dest = Self::parse_multi_address(&mut input)?;
                let amount: Compact<u128> = Decode::decode(&mut input).map_err(|e| e.to_string())?;
                Ok(QuantusTx::Transfer {
                    to: dest,
                    amount: amount.0,
                    is_reversible: false,
                    reversible_timeframe: None,
                })
            }
            _ => Err(format!("Balances: Unsupported call index {}", call_index)),
        }
    }

    fn parse_reversible_transfers_call(call_data: &[u8]) -> Result<QuantusTx, String> {
        let mut input = call_data;
        let call_index: u8 = Decode::decode(&mut input).map_err(|e| e.to_string())?;

        match call_index {
            3 => { // schedule_transfer
                let dest = Self::parse_multi_address(&mut input)?;
                let amount: u128 = Decode::decode(&mut input).map_err(|e| e.to_string())?;
                Ok(QuantusTx::Transfer {
                    to: dest,
                    amount,
                    is_reversible: true,
                    reversible_timeframe: None, // Uses configured delay
                })
            }
            4 => { // schedule_transfer_with_delay
                let dest = Self::parse_multi_address(&mut input)?;
                let amount: u128 = Decode::decode(&mut input).map_err(|e| e.to_string())?;
                let delay = Self::parse_block_number_or_timestamp(&mut input)?;
                Ok(QuantusTx::Transfer {
                    to: dest,
                    amount,
                    is_reversible: true,
                    reversible_timeframe: Some(delay),
                })
            }
            _ => Err(format!("ReversibleTransfers: Unsupported call index {}", call_index)),
        }
    }

    fn parse_multisig_call(call_data: &[u8]) -> Result<QuantusTx, String> {
        let mut input = call_data;
        let call_index: u8 = Decode::decode(&mut input).map_err(|e| e.to_string())?;

        match call_index {
            0 => { // create_multisig(signers, threshold, nonce)
                let signers: Vec<[u8; 32]> = Decode::decode(&mut input).map_err(|e| e.to_string())?;
                let threshold: u32 = Decode::decode(&mut input).map_err(|e| e.to_string())?;
                let nonce: u64 = Decode::decode(&mut input).map_err(|e| e.to_string())?;
                let signers = signers.iter().map(|s| Self::bytes_to_ss58(s)).collect();
                Ok(QuantusTx::MultisigCreate { signers, threshold, nonce })
            }
            1 => { // propose(multisig_address, call, expiry)
                let multisig = Self::parse_account_id32(&mut input)?;
                let call_bytes: Vec<u8> = Decode::decode(&mut input).map_err(|e| e.to_string())?;
                let expiry: u32 = Decode::decode(&mut input).map_err(|e| e.to_string())?;
                let inner = Self::parse_payload(&call_bytes)?;
                Ok(QuantusTx::MultisigPropose { multisig, expiry, inner: Box::new(inner) })
            }
            2 => { // approve(multisig_address, proposal_id)
                let multisig = Self::parse_account_id32(&mut input)?;
                let proposal_id: u32 = Decode::decode(&mut input).map_err(|e| e.to_string())?;
                Ok(QuantusTx::MultisigApprove { multisig, proposal_id })
            }
            6 => { // execute(multisig_address, proposal_id)
                let multisig = Self::parse_account_id32(&mut input)?;
                let proposal_id: u32 = Decode::decode(&mut input).map_err(|e| e.to_string())?;
                Ok(QuantusTx::MultisigExecute { multisig, proposal_id })
            }
            _ => Err(format!("Multisig: Unsupported call index {}", call_index)),
        }
    }

    fn parse_account_id32(input: &mut &[u8]) -> Result<String, String> {
        let account_id: [u8; 32] = Decode::decode(input).map_err(|e| e.to_string())?;
        Ok(Self::bytes_to_ss58(&account_id))
    }

    fn parse_multi_address(input: &mut &[u8]) -> Result<String, String> {
        let address_type: u8 = Decode::decode(input).map_err(|e| e.to_string())?;

        match address_type {
            0 => { // Id(AccountId)
                let account_id: [u8; 32] = Decode::decode(input).map_err(|e| e.to_string())?;
                Ok(Self::bytes_to_ss58(&account_id))
            }
            1 => Err("Index(Compact<u32>) MultiAddress type 1 is not supported".to_string()),
            2 => Err("Raw(Vec<u8>) MultiAddress type 2 is not supported".to_string()),
            3 => Err("Address32([u8; 32]) MultiAddress type 3 is not supported".to_string()),
            4 => Err("Address20([u8; 20]) MultiAddress type 4 is not supported".to_string()),
            _ => Err(format!("Unknown multi address type: {}", address_type)),
        }
    }

    fn parse_block_number_or_timestamp(input: &mut &[u8]) -> Result<u64, String> {
        let variant: u8 = Decode::decode(input).map_err(|e| e.to_string())?;

        match variant {
            0 => Err("Block numbers are not supported for delayed transactions".to_string()),
            1 => { // Timestamp(u64)
                let timestamp: u64 = Decode::decode(input).map_err(|e| e.to_string())?;
                Ok(timestamp)
            }
            _ => Err(format!("Unknown time variant: {}", variant)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    fn assert_transfer(tx: &QuantusTx, address: &str, amount: u128, reversible: bool, timeframe: Option<u64>) {
        match tx {
            QuantusTx::Transfer { to, amount: a, is_reversible, reversible_timeframe } => {
                assert_eq!(to, address);
                assert_eq!(*a, amount);
                assert_eq!(*is_reversible, reversible);
                assert_eq!(*reversible_timeframe, timeframe);
            }
            other => panic!("expected Transfer, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_real_world_balance_transfer() {
        let hex_payload = "020000ef5f320156894f0fde742921c6990bf446e82c89fae5a23e701900abcd92dfb40700282e8cd185012800007400000002000000826beefbe2be72645ff376f18de745ac196dc77637436090de4174180706118e3d3e081c6e3599f8ae31d404d9f087f50c25b4e08c35712e23470a60da5799ca00";
        let payload = hex::decode(hex_payload).unwrap();
        let tx = QuantusPayloadParser::parse_payload(&payload).unwrap();
        assert_transfer(&tx, "qzps6MnSixszZAWiwcpjtw6uXBjWg2aEyrXBdp9thijzY1g86", 900000000000u128, false, None);
    }

    #[test]
    fn test_parse_real_world_balance_transfer_2() {
        let hex_payload = "0200007416854906f03a9dff66e3270a736c44e15970ac03a638471523a03069f276ca0700e876481755010000007400000002000000826beefbe2be72645ff376f18de745ac196dc77637436090de4174180706118e5a77ae1c95817ee664cf733fafa7baa8e6244b396a54e57a5bc414b24c52800600";
        let payload = hex::decode(hex_payload).unwrap();
        let tx = QuantusPayloadParser::parse_payload(&payload).unwrap();
        assert_transfer(&tx, "qzn5St24cMsjE4JKYdXLBctusWj5zom67dnrW22SweAahLGeG", 100000000000u128, false, None);
    }

    #[test]
    fn test_parse_reversible_transfer_with_delay() {
        // schedule_transfer_with_delay on the reversible-transfers pallet (index 11, call 4):
        // 0b 04 <MultiAddress::Id 00><32-byte dest><u128 amount><DispatchTime::Timestamp(u64)>
        let hex_payload = "0b04007416854906f03a9dff66e3270a736c44e15970ac03a638471523a03069f276ca0040b0464f010000000000000000000001e093040000000000";
        let payload = hex::decode(hex_payload).unwrap();
        let tx = QuantusPayloadParser::parse_payload(&payload).unwrap();
        assert_transfer(&tx, "qzn5St24cMsjE4JKYdXLBctusWj5zom67dnrW22SweAahLGeG", 1440000000000u128, true, Some(300000u64));
    }

    // Authoritative multisig vectors: SCALE-encoded offline from the live chain
    // metadata via subxt (quantus-cli example `encode_multisig_vectors`).
    // SS58 strings below are sp_core-encoded (network 189) and cross-check our ss58 module.
    const SS58_A: &str = "qzoK1UVQSssYHuTWxAN1U8egoJWRjTzF1LBcRubYp5a19ium3";
    const SS58_B: &str = "qzohPMkqjuMjQajDBZCU52NqZUjuMQLHSYWiSR3PhWZSegGEF";
    const SS58_C: &str = "qzp5mF2H2vqvXFzuQx2vfv6zKeyNyLgKskqpSvVEawYt9dJPY";
    const SS58_MULTISIG: &str = "qznvdbDy9rPMBEBpimXYsEvY38Gx7XeCa7rWRQ9hveaZemr8U";
    const SS58_DEST: &str = "qzn9sph6ZoQxwseSFyrdfTUEWmozsex7hhCJQPG29nbgesGei";

    fn parse_hex(hex_payload: &str) -> QuantusTx {
        let payload = hex::decode(hex_payload).unwrap();
        QuantusPayloadParser::parse_payload(&payload).unwrap()
    }

    #[test]
    fn test_parse_real_multisig_create() {
        let tx = parse_hex("13000caaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc020000000000000000000000");
        match tx {
            QuantusTx::MultisigCreate { signers, threshold, nonce } => {
                assert_eq!(signers, [SS58_A, SS58_B, SS58_C]);
                assert_eq!(threshold, 2);
                assert_eq!(nonce, 0);
            }
            other => panic!("expected MultisigCreate, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_real_multisig_approve() {
        match parse_hex("1302999999999999999999999999999999999999999999999999999999999999999907000000") {
            QuantusTx::MultisigApprove { multisig, proposal_id } => {
                assert_eq!(multisig, SS58_MULTISIG);
                assert_eq!(proposal_id, 7);
            }
            other => panic!("expected MultisigApprove, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_real_multisig_execute() {
        match parse_hex("1306999999999999999999999999999999999999999999999999999999999999999907000000") {
            QuantusTx::MultisigExecute { multisig, proposal_id } => {
                assert_eq!(multisig, SS58_MULTISIG);
                assert_eq!(proposal_id, 7);
            }
            other => panic!("expected MultisigExecute, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_real_multisig_propose_transfer() {
        // propose wrapping Balances::transfer_allow_death(dest, 42_000_000_000), expiry 5000
        match parse_hex("13019999999999999999999999999999999999999999999999999999999999999999a4020000777777777777777777777777777777777777777777777777777777777777777707002465c70988130000") {
            QuantusTx::MultisigPropose { multisig, expiry, inner } => {
                assert_eq!(multisig, SS58_MULTISIG);
                assert_eq!(expiry, 5000);
                assert_transfer(&inner, SS58_DEST, 42_000_000_000u128, false, None);
            }
            other => panic!("expected MultisigPropose, got {:?}", other),
        }
    }
}
