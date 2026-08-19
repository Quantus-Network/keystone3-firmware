//! Audit H-2: verify device-produced signatures with the chain's own verifier instead of
//! only round-tripping through the signing library. `qp-dilithium-crypto` is the crate the
//! Quantus runtime uses as its `Signature` type, so `DilithiumSignatureScheme::verify` here
//! is byte-for-byte the check a node performs on a submitted extrinsic, including the
//! poseidon-hash binding of the public key to the signer's AccountId32.

use app_quantus::parser::{self, QuantusTx};
use app_quantus::{get_address, sign_raw_tx};
use qp_dilithium_crypto::types::{Dilithium87SignatureWithPublic, DilithiumSignatureScheme};
use qp_dilithium_crypto::DilithiumSigner;
use sp_runtime::traits::{IdentifyAccount, Verify};
use sp_runtime::AccountId32;

// The lib's debug logging prints through this firmware symbol; stub it for host tests.
#[no_mangle]
pub extern "C" fn PrintString(_: *mut core::ffi::c_char) {}

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PATH: &str = "m/44'/189'/0'/0'/0'";

/// Planck transfer_keep_alive signing payload with full extensions, 119 bytes (< 256, so the
/// runtime verifies the signature over the raw payload). Same vector as `ur_gen`'s default.
const SHORT_PAYLOAD: &str = "0200007416854906f03a9dff66e3270a736c44e15970ac03a638471523a03069f276ca0700e8764817550100000083000000020000004901bf5c57fd3f9e726af399c763de6670dbdb115a91c0237e173f16eef65e725a77ae1c95817ee664cf733fafa7baa8e6244b396a54e57a5bc414b24c52800600";

/// Planck create_multisig (8 signers, threshold 3) signing payload with full extensions,
/// 348 bytes (> 256, so both signer and verifier operate on blake2_256 of the payload).
const LONG_PAYLOAD: &str = "130020a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a70300000007000000000000000014000083000000020000004901bf5c57fd3f9e726af399c763de6670dbdb115a91c0237e173f16eef65e72111111111111111111111111111111111111111111111111111111111111111100";

fn device_sign(payload: &[u8]) -> (DilithiumSignatureScheme, AccountId32) {
    let sig_with_pubkey =
        sign_raw_tx(payload.to_vec(), PATH, MNEMONIC, "", [0x42; 32]).expect("sign");
    let sig_with_public =
        Dilithium87SignatureWithPublic::from_bytes(&sig_with_pubkey).expect("sig||pubkey layout");
    let signer = DilithiumSigner::Dilithium87(sig_with_public.public()).into_account();
    (DilithiumSignatureScheme::Dilithium87(sig_with_public), signer)
}

/// The verification a Quantus node runs on a signed extrinsic: sp_runtime's `SignedPayload`
/// hashes payloads longer than 256 bytes with blake2_256 before the signature check.
fn chain_verifies(payload: &[u8], signature: &DilithiumSignatureScheme, signer: &AccountId32) -> bool {
    if payload.len() > 256 {
        signature.verify(&sp_core::hashing::blake2_256(payload)[..], signer)
    } else {
        signature.verify(payload, signer)
    }
}

#[test]
fn device_signature_verifies_under_chain_scheme_raw_payload() {
    let payload = hex::decode(SHORT_PAYLOAD).unwrap();
    assert!(payload.len() <= 256);
    let parsed = parser::parse_payload(&payload).expect("device-displayable payload");
    assert!(parsed.call.is_transfer());

    let (signature, signer) = device_sign(&payload);
    assert!(chain_verifies(&payload, &signature, &signer));
}

#[test]
fn device_signature_verifies_under_chain_scheme_hashed_payload() {
    let payload = hex::decode(LONG_PAYLOAD).unwrap();
    assert!(payload.len() > 256);
    // Also proves the device's blake2b_256 (cryptoxide) matches the runtime's blake2_256.
    let parsed = parser::parse_payload(&payload).expect("device-displayable payload");
    match parsed.call {
        QuantusTx::MultisigCreate { signers, threshold, nonce } => {
            assert_eq!(signers.len(), 8);
            assert_eq!(threshold, 3);
            assert_eq!(nonce, 7);
        }
        other => panic!("expected MultisigCreate, got {:?}", other),
    }

    let (signature, signer) = device_sign(&payload);
    assert!(chain_verifies(&payload, &signature, &signer));
}

#[test]
fn tampered_payload_fails_chain_verification() {
    let payload = hex::decode(SHORT_PAYLOAD).unwrap();
    let (signature, signer) = device_sign(&payload);

    let mut tampered = payload.clone();
    tampered[40] ^= 0x01; // flip one bit in the transfer amount
    assert!(!chain_verifies(&tampered, &signature, &signer));

    let wrong_signer = AccountId32::new([0x42; 32]);
    assert!(!chain_verifies(&payload, &signature, &wrong_signer));
}

#[test]
fn device_address_is_the_chain_account_identity() {
    let payload = hex::decode(SHORT_PAYLOAD).unwrap();
    let (_, signer) = device_sign(&payload);
    let signer_bytes: &[u8; 32] = signer.as_ref();

    let device_address = get_address(MNEMONIC, "", PATH).expect("address");
    assert_eq!(device_address, parser::bytes_to_ss58(signer_bytes));
}

const ACCOUNT_PATH: &str = "m/44'/189189'/0'/0'/0'";

fn envelope_for(signer: &str) -> String {
    format!(r#"{{"v":1,"signer":"{}","payload":"0x{}"}}"#, signer, SHORT_PAYLOAD)
}

#[test]
fn sign_request_signs_only_for_the_envelope_signer() {
    use app_quantus::errors::QuantusError;

    let payload = hex::decode(SHORT_PAYLOAD).unwrap();
    let signer = get_address(MNEMONIC, "", ACCOUNT_PATH).expect("address");
    let envelope = envelope_for(&signer);

    let sig_with_pubkey =
        app_quantus::sign_request(envelope.as_bytes(), ACCOUNT_PATH, MNEMONIC, "", [0x42; 32])
            .expect("sign");
    let sig_with_public =
        Dilithium87SignatureWithPublic::from_bytes(&sig_with_pubkey).expect("sig||pubkey layout");
    let account = DilithiumSigner::Dilithium87(sig_with_public.public()).into_account();
    let account_bytes: &[u8; 32] = account.as_ref();
    assert_eq!(parser::bytes_to_ss58(account_bytes), signer);
    assert!(chain_verifies(
        &payload,
        &DilithiumSignatureScheme::Dilithium87(sig_with_public),
        &account
    ));

    // The same envelope signed at a different account index must be refused: the derived
    // address no longer matches the envelope's signer.
    let err = app_quantus::sign_request(
        envelope.as_bytes(),
        "m/44'/189189'/1'/0'/0'",
        MNEMONIC,
        "",
        [0x42; 32],
    )
    .unwrap_err();
    assert!(matches!(err, QuantusError::SignerMismatch(_)), "{:?}", err);
}

#[test]
fn parse_request_exposes_the_envelope_signer() {
    let signer = get_address(MNEMONIC, "", ACCOUNT_PATH).expect("address");
    let parsed = app_quantus::parse_request_light(envelope_for(&signer).as_bytes()).expect("parse");
    assert_eq!(parsed.get_signer(), signer);
    assert!(!parsed.get_is_multisig());

    assert!(app_quantus::check_request(envelope_for(&signer).as_bytes()).is_ok());
    assert!(app_quantus::check_request(&hex::decode(SHORT_PAYLOAD).unwrap()).is_err());
}
