use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::string::String;
use cty::c_char;

use app_quantus::{sign_tx, get_address};

use crate::common::errors::{KeystoneError, RustCError};
use crate::common::types::{PtrBytes, PtrString, PtrT, PtrUR};
use crate::common::structs::SimpleResponse;
use crate::common::ur::{UREncodeResult, FRAGMENT_MAX_LENGTH_DEFAULT};
use crate::common::utils::{convert_c_char, recover_c_char};
use crate::{extract_array, extract_ptr_with_type};
use ur_registry::bytes::Bytes;
use ur_registry::traits::RegistryItem;

#[no_mangle]
pub unsafe extern "C" fn quantus_get_address(
    mnemonic: PtrString,
    path: PtrString,
) -> *mut SimpleResponse<c_char> {
    let mnemonic = recover_c_char(mnemonic);
    let path = recover_c_char(path);
    
    match get_address(&mnemonic, &path) {
        Ok(addr) => SimpleResponse::success(convert_c_char(addr) as *mut c_char).simple_c_ptr(),
        Err(e) => SimpleResponse::from(RustCError::UnexpectedError(e.to_string())).simple_c_ptr(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn quantus_sign_tx(
    tx_json: PtrString,
    mnemonic: PtrString,
) -> PtrT<UREncodeResult> {
    // 1. Get JSON string directly
    let tx_json_str = recover_c_char(tx_json);
    let mnemonic_str = recover_c_char(mnemonic);

    // 3. Sign the transaction
    // Note: Passing hardcoded path for now as before.
    let signature = match sign_tx(&tx_json_str, &mnemonic_str, "m/44'/189189'/0'/0/0") {
        Ok(s) => s,
        Err(e) => return UREncodeResult::from(KeystoneError::SignTxFailed(e.to_string())).c_ptr(),
    };

    // 4. Encode the signature as a UR Bytes
    let sig_vec = signature.signature.to_vec();
    UREncodeResult::encode(
        sig_vec, 
        "bytes".to_string(), 
        FRAGMENT_MAX_LENGTH_DEFAULT
    ).c_ptr()
}
