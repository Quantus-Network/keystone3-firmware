use alloc::string::String;
use app_utils::impl_public_struct;

impl_public_struct!(ParsedQuantusTx {
    to: String,
    amount: String,
    nonce: String,
    fee: String
});

