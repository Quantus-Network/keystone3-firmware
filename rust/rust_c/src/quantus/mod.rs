use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::string::String;

use app_quantus::sign_tx;

use crate::common::errors::{KeystoneError, RustCError};
use crate::common::types::{PtrBytes, PtrT, PtrUR};
use crate::common::ur::{UREncodeResult, FRAGMENT_MAX_LENGTH_DEFAULT};
use crate::{extract_array, extract_ptr_with_type};
use ur_registry::bytes::Bytes;
use ur_registry::traits::RegistryItem;

#[no_mangle]
pub unsafe extern "C" fn quantus_sign_tx(
    ptr: PtrUR,
    seed: PtrBytes,
    seed_len: u32,
) -> PtrT<UREncodeResult> {
    // 1. Extract payload directly from UR Bytes
    // We bypass build_payload because we are just passing raw JSON bytes, 
    // not a Keystone Protobuf envelope.
    let bytes_item = extract_ptr_with_type!(ptr, Bytes);
    let bytes = bytes_item.get_bytes();

    // 2. Parse JSON string from bytes
    let tx_json = match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return UREncodeResult::from(RustCError::InvalidData("Invalid UTF-8".to_string())).c_ptr(),
    };

    // 3. Extract seed
    let seed = extract_array!(seed, u8, seed_len as usize);
    
    // 4. Sign
    // Using a dummy path for now as it's not provided in the simple UR
    let path = "m/44'/999'/0'"; 

    match sign_tx(&tx_json, seed, path) {
        Ok(sig) => {
            // 5. Return result
            // Wrap the signature bytes in a UR (Bytes type)
            let sig_bytes = sig.signature;
            match ur_registry::bytes::Bytes::new(sig_bytes).try_into() {
                Ok(ur_bytes) => {
                     UREncodeResult::encode(
                        ur_bytes,
                        ur_registry::bytes::Bytes::get_registry_type().get_type(),
                        FRAGMENT_MAX_LENGTH_DEFAULT,
                    ).c_ptr()
                },
                Err(e) => UREncodeResult::from(RustCError::UnexpectedError(e.to_string())).c_ptr(),
            }
        },
        Err(e) => UREncodeResult::from(RustCError::UnexpectedError(format!("{:?}", e))).c_ptr(),
    }
}
