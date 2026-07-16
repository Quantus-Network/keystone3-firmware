use alloc::string::String;
use alloc::vec::Vec;
use app_utils::impl_public_struct;

impl_public_struct!(ParsedQuantusTx {
    tx_type: String,
    is_multisig: bool,
    to: String,
    to_checkphrase: String,
    amount: String,
    nonce: String,
    tip: String,
    is_reversible: bool,
    reversible_timeframe: String,
    network: String,
    era: String,
    detail_labels: Vec<String>,
    detail_values: Vec<String>
});
