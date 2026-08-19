extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::errors::{QuantusError, Result};
use crate::parser::MAX_PAYLOAD_BYTES;
use crate::ss58;

pub const VERSION: u64 = 1;
pub const QUANTUS_SS58_PREFIX: u16 = 189;

pub struct SigningRequest {
    pub signer: String,
    pub payload: Vec<u8>,
}

/// Mirrors the companion apps' `SigningRequest.decode` (quantus_sdk): a strict, versioned
/// JSON envelope `{"v":1,"signer":"<ss58>","payload":"0x<hex>"}` carried inside the UR.
/// Anything that is not exactly this envelope fails closed; naked payloads are rejected.
pub fn decode(bytes: &[u8]) -> Result<SigningRequest> {
    let text = core::str::from_utf8(bytes)
        .map_err(|_| invalid("not UTF-8"))?;
    let value: serde_json::Value = serde_json::from_str(text)
        .map_err(|_| invalid("not JSON"))?;
    let obj = value.as_object().ok_or_else(|| invalid("not a JSON object"))?;
    if obj.len() != 3 || !obj.contains_key("v") || !obj.contains_key("signer") || !obj.contains_key("payload") {
        return Err(invalid("keys are not exactly v/signer/payload"));
    }
    if obj.get("v").and_then(|v| v.as_u64()) != Some(VERSION) {
        return Err(invalid("unsupported version"));
    }

    let signer = obj
        .get("signer")
        .and_then(|v| v.as_str())
        .ok_or_else(|| invalid("signer is not a string"))?;
    ss58::decode(signer, QUANTUS_SS58_PREFIX)
        .map_err(|e| invalid(&alloc::format!("signer is not a valid address: {}", e)))?;

    let payload_hex = obj
        .get("payload")
        .and_then(|v| v.as_str())
        .ok_or_else(|| invalid("payload is not a string"))?;
    let hex_body = payload_hex
        .strip_prefix("0x")
        .ok_or_else(|| invalid("payload is not 0x hex"))?;
    let payload = hex::decode(hex_body).map_err(|_| invalid("payload is not hex"))?;
    if payload.is_empty() {
        return Err(invalid("payload is empty"));
    }
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(invalid("payload too large"));
    }

    Ok(SigningRequest {
        signer: signer.to_string(),
        payload,
    })
}

fn invalid(reason: &str) -> QuantusError {
    QuantusError::InvalidEnvelope(reason.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    const SIGNER: &str = "qzpKmxWGG2prrAtgYsBT99eiPYz2teMDnMqAXNgEJqZh4DFty";

    fn envelope(v: &str, signer: &str, payload: &str) -> Vec<u8> {
        format!(r#"{{"v":{},"signer":"{}","payload":"{}"}}"#, v, signer, payload).into_bytes()
    }

    #[test]
    fn accepts_valid_envelope() {
        let req = decode(&envelope("1", SIGNER, "0x0200ab")).unwrap();
        assert_eq!(req.signer, SIGNER);
        assert_eq!(req.payload, alloc::vec![0x02, 0x00, 0xab]);
    }

    #[test]
    fn accepts_the_companion_apps_exact_wire_bytes() {
        // Byte-for-byte what quantus_sdk's `SigningRequest(signer, [0,0,1,2,3]).encode()`
        // emits (mirrors quantus_sdk/test/models/signing_request_test.dart).
        let wire = br#"{"v":1,"signer":"qznQKhufTDfU3szAzfgCny7wMhxUN3qjEqneiRUNgC7MjSDyG","payload":"0x0000010203"}"#;
        let req = decode(wire).unwrap();
        assert_eq!(req.signer, "qznQKhufTDfU3szAzfgCny7wMhxUN3qjEqneiRUNgC7MjSDyG");
        assert_eq!(req.payload, alloc::vec![0x00, 0x00, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn rejects_naked_payload() {
        assert!(decode(&[0x02, 0x00, 0xab]).is_err());
    }

    #[test]
    fn rejects_non_utf8_and_non_object() {
        assert!(decode(&[0xC3, 0x28]).is_err());
        assert!(decode(b"[1,2,3]").is_err());
    }

    #[test]
    fn rejects_extra_or_missing_keys() {
        let extra = format!(r#"{{"v":1,"signer":"{}","payload":"0x00","x":1}}"#, SIGNER);
        assert!(decode(extra.as_bytes()).is_err());
        let missing = format!(r#"{{"v":1,"signer":"{}"}}"#, SIGNER);
        assert!(decode(missing.as_bytes()).is_err());
    }

    #[test]
    fn rejects_wrong_version() {
        assert!(decode(&envelope("2", SIGNER, "0x00")).is_err());
        assert!(decode(&envelope("\"1\"", SIGNER, "0x00")).is_err());
    }

    #[test]
    fn rejects_invalid_signer() {
        assert!(decode(&envelope("1", "not-an-address", "0x00")).is_err());
        // Valid SS58 but a foreign network prefix (Polkadot, prefix 0).
        let foreign = ss58::encode(&[0xab; 32], 0);
        assert!(decode(&envelope("1", &foreign, "0x00")).is_err());
    }

    #[test]
    fn rejects_bad_payload() {
        assert!(decode(&envelope("1", SIGNER, "00ab")).is_err());
        assert!(decode(&envelope("1", SIGNER, "0xzz")).is_err());
        assert!(decode(&envelope("1", SIGNER, "0x")).is_err());
        let huge = format!("0x{}", "ab".repeat(MAX_PAYLOAD_BYTES + 1));
        assert!(decode(&envelope("1", SIGNER, &huge)).is_err());
    }
}
