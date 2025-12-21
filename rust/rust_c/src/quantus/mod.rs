use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::str::FromStr;
use app_quantus::{check_raw_tx, sign_raw_tx, parse_quantus_tx};
use cty::{c_char, c_int, c_void};
use ur_registry::bytes::Bytes;
use ur_registry::traits::RegistryItem;
use hex;

use crate::common::errors::{ErrorCodes, RustCError};
use crate::common::structs::{TransactionCheckResult, TransactionParseResult, SimpleResponse};
use crate::common::types::{PtrBytes, PtrString, PtrT, PtrUR, Ptr};
use crate::common::ur::{UREncodeResult, ViewType, FRAGMENT_MAX_LENGTH_DEFAULT};
use ur_parse_lib::keystone_ur_encoder;
use crate::common::utils::{convert_c_char, recover_c_char};
use crate::{
    extract_array, extract_ptr_with_type, impl_c_ptr, impl_new_error,
    impl_response, make_free_method, free_str_ptr
};
use crate::common::free::Free;
use crate::quantus::structs::DisplayQuantusTx;

#[cfg(feature = "quantus")]
use quantus_ur::encode_bytes;

pub mod structs;

impl_c_ptr!(DisplayQuantusTx);

#[no_mangle]
pub unsafe extern "C" fn quantus_sign_tx(
    data: PtrUR,
    mnemonic: PtrString,
    passphrase: PtrString,
    path: PtrString,
    master_fingerprint: PtrBytes,
    master_fingerprint_len: c_int,
) -> *mut UREncodeResult {
    let mnemonic = recover_c_char(mnemonic);
    let passphrase = recover_c_char(passphrase);
    let path = recover_c_char(path);
    let mfp = extract_array!(master_fingerprint, u8, master_fingerprint_len);
    
    // Expect Bytes type from UR decoder because we mapped ur:quantus-sign-request to Bytes
    let bytes_ur = extract_ptr_with_type!(data, Bytes);
    let raw_bytes = bytes_ur.get_bytes();

    match sign_raw_tx(raw_bytes, &path, &mnemonic, &passphrase) {
        Ok(sign_result) => {
            match encode_bytes(&sign_result) {
                Ok(ur_parts) => {
                    if ur_parts.is_empty() {
                        return UREncodeResult::from(RustCError::UnexpectedError(
                            "quantus_ur encode_bytes returned empty parts".to_string()
                        )).c_ptr();
                    }
                    if ur_parts.len() == 1 {
                        UREncodeResult::single(ur_parts[0].clone()).c_ptr()
                    } else {
                        use minicbor::bytes::ByteVec;
                        let cbor_wrapped = match minicbor::to_vec(ByteVec::from(sign_result.clone())) {
                            Ok(cbor) => cbor,
                            Err(e) => {
                                return UREncodeResult::from(RustCError::UnexpectedError(
                                    alloc::format!("CBOR encoding failed: {}", e)
                                )).c_ptr();
                            }
                        };
                        let result = ur_parse_lib::keystone_ur_encoder::probe_encode(
                            &cbor_wrapped,
                            FRAGMENT_MAX_LENGTH_DEFAULT,
                            "quantus-sign-request".to_string()
                        );
                        match result {
                            Ok(encode_result) => {
                                if encode_result.is_multi_part {
                                    match encode_result.encoder {
                                        Some(encoder) => UREncodeResult::multi(ur_parts[0].clone(), encoder).c_ptr(),
                                        None => UREncodeResult::from(RustCError::UnexpectedError(
                                            "encoder is none".to_string()
                                        )).c_ptr(),
                                    }
                                } else {
                                    UREncodeResult::single(ur_parts[0].clone()).c_ptr()
                                }
                            }
                            Err(e) => UREncodeResult::from(RustCError::UnexpectedError(
                                alloc::format!("encoder creation failed: {}", e)
                            )).c_ptr(),
                        }
                    }
                }
                Err(e) => UREncodeResult::from(RustCError::UnexpectedError(
                    alloc::format!("quantus_ur encode failed: {}", e)
                )).c_ptr(),
            }
        }
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

    match check_raw_tx(raw_bytes) {
        Ok(_) => TransactionCheckResult::new().c_ptr(),
        Err(e) => TransactionCheckResult::from(e).c_ptr(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn quantus_parse_tx(data: PtrUR) -> Ptr<TransactionParseResult<DisplayQuantusTx>> {
    rust_tools::debug!(alloc::format!("Quantus: quantus_parse_tx called"));
    
    let bytes_ur = extract_ptr_with_type!(data, Bytes);
    let raw_bytes = bytes_ur.get_bytes();
    
    rust_tools::debug!(alloc::format!("Quantus: Encoded transaction (hex): {}", hex::encode(&raw_bytes)));
    rust_tools::debug!(alloc::format!("Quantus: Encoded transaction length: {} bytes", raw_bytes.len()));

    match parse_quantus_tx(raw_bytes.as_slice()) {
        Ok(tx) => {
            rust_tools::debug!(alloc::format!("Quantus: Transaction decoded successfully"));
            rust_tools::debug!(alloc::format!("Quantus: To: {}", tx.get_to()));
            rust_tools::debug!(alloc::format!("Quantus: Amount: {}", tx.get_amount()));
            rust_tools::debug!(alloc::format!("Quantus: Reversible: {}", tx.get_is_reversible()));
            rust_tools::debug!(alloc::format!("Quantus: Timeframe: {}", tx.get_reversible_timeframe()));
            rust_tools::debug!(alloc::format!("Quantus: Nonce: {}", tx.get_nonce()));
            rust_tools::debug!(alloc::format!("Quantus: Fee: {}", tx.get_fee()));
            TransactionParseResult::success(DisplayQuantusTx::from(&tx).c_ptr()).c_ptr()
        },
        Err(e) => {
            rust_tools::debug!(alloc::format!("Quantus: Parse error: {:?}", e));
            TransactionParseResult::from(e).c_ptr()
        },
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::ur::get_next_part;
    use crate::common::free::{free_ur_encode_result, free_ur_encode_muilt_result};
    use crate::common::utils::recover_c_char;
    use crate::common::types::PtrEncoder;
    use quantus_ur::decode_bytes;
    use alloc::string::String;
    use alloc::vec::Vec;
    use crate::{free_ptr_with_type};
    use cty::c_char;
    
    #[no_mangle]
    extern "C" fn PrintString(_: *mut c_char) {
    }
    
    fn extract_ur_parts_from_result(result: *mut UREncodeResult) -> Vec<String> {
        unsafe {
            #[repr(C)]
            struct UREncodeResultLayout {
                is_multi_part: bool,
                data: *mut c_char,
                encoder: PtrEncoder,
                error_code: u32,
                error_message: *mut c_char,
            }
            
            #[repr(C)]
            struct UREncodeMultiResultLayout {
                data: *mut c_char,
                error_code: u32,
                error_message: *mut c_char,
            }
            
            let layout = &*(result as *const UREncodeResultLayout);
            
            if layout.error_code != 0 {
                panic!("UREncodeResult has error: {}", 
                    recover_c_char(layout.error_message));
            }
            
            let mut parts = Vec::new();
            let first_part = recover_c_char(layout.data);
            parts.push(first_part);
            
            if layout.is_multi_part && !layout.encoder.is_null() {
                let encoder_ref = &*(layout.encoder as *mut ur_parse_lib::keystone_ur_encoder::KeystoneUREncoder);
                let count = encoder_ref.fragment_count();
                
                if count > 1 && count < 1000 {
                    for _ in 1..count {
                        let multi_result = get_next_part(layout.encoder);
                        let multi_layout = &*(multi_result as *const UREncodeMultiResultLayout);
                        if multi_layout.error_code != 0 {
                            free_ur_encode_muilt_result(multi_result);
                            break;
                        }
                        let part = recover_c_char(multi_layout.data);
                        parts.push(part);
                        free_ur_encode_muilt_result(multi_result);
                    }
                }
            }
            
            parts
        }
    }
    
    #[test]
    fn test_quantus_sign_tx_encode_decode_roundtrip() {
        let test_payload = b"test payload for signing";
        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let test_passphrase = "";
        let test_path = "m/44'/189'/0'/0/0";
        let mfp = [0u8; 4];
        
        let bytes_ur = Bytes::new(test_payload.to_vec());
        let bytes_ptr = Box::into_raw(Box::new(bytes_ur)) as PtrUR;
        
        let mnemonic_cstr = cstr_core::CString::new(test_mnemonic).unwrap();
        let passphrase_cstr = cstr_core::CString::new(test_passphrase).unwrap();
        let path_cstr = cstr_core::CString::new(test_path).unwrap();
        
        let mnemonic_ptr = mnemonic_cstr.as_ptr() as PtrString;
        let passphrase_ptr = passphrase_cstr.as_ptr() as PtrString;
        let path_ptr = path_cstr.as_ptr() as PtrString;
        let mfp_ptr = mfp.as_ptr() as PtrBytes;
        
        let result = unsafe {
            quantus_sign_tx(
                bytes_ptr,
                mnemonic_ptr,
                passphrase_ptr,
                path_ptr,
                mfp_ptr,
                mfp.len() as c_int
            )
        };
        
        let ur_parts = extract_ur_parts_from_result(result);
        assert!(!ur_parts.is_empty(), "Should have at least one UR part");
        
        for part in &ur_parts {
            assert!(part.to_lowercase().starts_with("ur:quantus-sign-request"), 
                "UR part should start with ur:quantus-sign-request, got: {}", part);
        }
        
        let decoded_signature = decode_bytes(&ur_parts)
            .expect("quantus_ur::decode_bytes should succeed");
        
        let expected_signature = sign_raw_tx(
            test_payload.to_vec(),
            test_path,
            test_mnemonic,
            test_passphrase
        ).expect("Signing should succeed");
        
        assert_eq!(decoded_signature, expected_signature, 
            "Decoded signature should match expected signature");
        
        unsafe {
            free_ur_encode_result(result);
            free_ptr_with_type!(bytes_ptr, Bytes);
        }
    }
}
