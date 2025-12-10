use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::str::FromStr;
use app_quantus::{check_raw_tx, sign_raw_tx, parse_quantus_tx};
use app_utils::keystone::ParseContext;
use cty::{c_char, c_int, c_void};
use ur_registry::bytes::Bytes;
use ur_registry::traits::RegistryItem;

use crate::common::errors::{ErrorCodes, RustCError};
use crate::common::structs::{TransactionCheckResult, TransactionParseResult, SimpleResponse};
use crate::common::types::{PtrBytes, PtrString, PtrT, PtrUR, Ptr};
use crate::common::ur::{UREncodeResult, ViewType};
use crate::common::utils::{convert_c_char, recover_c_char};
use crate::{
    extract_array, extract_ptr_with_type, impl_c_ptr, impl_new_error,
    impl_response, make_free_method, free_str_ptr
};
use crate::common::free::Free;
use crate::quantus::structs::DisplayQuantusTx;

pub mod structs;

impl_c_ptr!(DisplayQuantusTx);

#[no_mangle]
pub unsafe extern "C" fn quantus_sign_tx(
    data: PtrUR,
    seed: PtrBytes,
    seed_len: c_int,
    master_fingerprint: PtrBytes,
    master_fingerprint_len: c_int,
) -> *mut UREncodeResult {
    let seed = extract_array!(seed, u8, seed_len);
    let mfp = extract_array!(master_fingerprint, u8, master_fingerprint_len);
    
    // Expect Bytes type from UR decoder because we mapped ur:quantus-sign-request to Bytes
    let bytes_ur = extract_ptr_with_type!(data, Bytes);
    let raw_bytes = bytes_ur.get_bytes();

    let context = ParseContext {
        master_fingerprint: bitcoin::bip32::Fingerprint::default(),
        extended_public_key: bitcoin::bip32::Xpub::from_str("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8").unwrap(),
    };

    match sign_raw_tx(raw_bytes, context, seed) {
        Ok((sign_result, _tx_hash)) => UREncodeResult::single(sign_result).c_ptr(),
        Err(e) => UREncodeResult::from(e).c_ptr(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn quantus_check_tx(
    data: PtrUR,
    master_fingerprint: PtrBytes,
    master_fingerprint_len: c_int,
) -> *mut TransactionCheckResult {
    let bytes_ur = extract_ptr_with_type!(data, Bytes);
    let raw_bytes = bytes_ur.get_bytes();

    let context = ParseContext {
        master_fingerprint: bitcoin::bip32::Fingerprint::default(),
        extended_public_key: bitcoin::bip32::Xpub::from_str("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8").unwrap(),
    };

    match check_raw_tx(raw_bytes, context) {
        Ok(_) => TransactionCheckResult::new().c_ptr(),
        Err(e) => TransactionCheckResult::from(e).c_ptr(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn quantus_parse_tx(data: PtrUR) -> Ptr<TransactionParseResult<DisplayQuantusTx>> {
    let bytes_ur = extract_ptr_with_type!(data, Bytes);
    let raw_bytes = bytes_ur.get_bytes();

    match parse_quantus_tx(raw_bytes.as_slice()) {
        Ok(tx) => TransactionParseResult::success(DisplayQuantusTx::from(&tx).c_ptr()).c_ptr(),
        Err(e) => TransactionParseResult::from(e).c_ptr(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn quantus_get_address(
    mnemonic: PtrString,
    passphrase: PtrString,
    path: PtrString,
) -> *mut SimpleResponse<c_char> {
    let mnemonic = recover_c_char(mnemonic);
    let passphrase = recover_c_char(passphrase);
    let path = recover_c_char(path);
    
    match app_quantus::get_address(&mnemonic, &passphrase, &path) {
        Ok(result) => SimpleResponse::success(convert_c_char(result) as *mut c_char).simple_c_ptr(),
        Err(e) => SimpleResponse::from(e).simple_c_ptr(),
    }
}

make_free_method!(TransactionParseResult<DisplayQuantusTx>);
