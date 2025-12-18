use hex;
use ur_registry::bytes::Bytes;
use ur_registry::traits::UR;
use ur_parse_lib::keystone_ur_decoder::probe_decode;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum QuantusUrError {
    #[error("Hex decoding error: {0}")]
    HexError(hex::FromHexError),
    #[error("UR error: {0}")]
    UrError(String),
    #[error("Decoding incomplete")]
    Incomplete,
}

/// Encodes a hex string into a UR string (or sequence of UR strings).
/// Returns a Vector of strings. If the payload fits in one part (<= 200 bytes), returns a single element.
/// Replaces "UR:BYTES" with "UR:QUANTUS-SIGN-REQUEST".
pub fn encode(hex_payload: &str) -> Result<Vec<String>, QuantusUrError> {
    let payload = hex::decode(hex_payload).map_err(QuantusUrError::HexError)?;
    let ur_payload = Bytes::new(payload);
    // 200 is the max fragment length used in the original code
    let mut ur_encoder = ur_payload.to_ur_encoder(200);
    
    let count = ur_encoder.fragment_count();
    let mut parts = Vec::with_capacity(count);

    for _ in 0..count {
        let part = ur_encoder.next_part().map_err(|e| QuantusUrError::UrError(e.to_string()))?;
        let part_modified = part.to_uppercase().replace("UR:BYTES", "UR:QUANTUS-SIGN-REQUEST");
        parts.push(part_modified);
    }
    
    Ok(parts)
}

/// Decodes a sequence of UR parts into a hex string.
/// Handles the "UR:QUANTUS-SIGN-REQUEST" type by substituting it back to "UR:BYTES".
pub fn decode(ur_parts: &[String]) -> Result<String, QuantusUrError> {
    if ur_parts.is_empty() {
        return Err(QuantusUrError::UrError("No UR parts provided".to_string()));
    }
    
    // Process first part to initialize decoder or get single part result
    let first_part = ur_parts[0].to_lowercase().replace("ur:quantus-sign-request", "ur:bytes");
    
    let result = probe_decode::<Bytes>(first_part).map_err(|e| QuantusUrError::UrError(e.to_string()))?;
    
    if !result.is_multi_part {
        if let Some(bytes_item) = result.data {
             return Ok(hex::encode(bytes_item.get_bytes()));
        } else {
             return Err(QuantusUrError::UrError("Single part decode failed to return data".to_string()));
        }
    }
    
    // Multi-part handling
    let mut decoder = result.decoder.ok_or_else(|| QuantusUrError::UrError("Multi-part but no decoder returned".to_string()))?;
    
    // Iterate ALL parts, including the first one, to ensure we trigger completion check and data extraction.
    // Re-processing the first part is harmless for fountain codes.
    for part in ur_parts {
        let restored = part.to_lowercase().replace("ur:quantus-sign-request", "ur:bytes");
        let parse_res = decoder.parse_ur::<Bytes>(restored).map_err(|e| QuantusUrError::UrError(e.to_string()))?;
        
        if parse_res.is_complete {
            if let Some(bytes_item) = parse_res.data {
                return Ok(hex::encode(bytes_item.get_bytes()));
            } else {
                return Err(QuantusUrError::UrError("Multi-part complete but no data".to_string()));
            }
        }
    }
    
    Err(QuantusUrError::Incomplete)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_part_roundtrip() {
        // Small payload that fits in 200 bytes
        let hex_payload = "0200007416854906f03a9dff66e3270a736c44e15970ac03a638471523a03069f276ca0700e876481755010000007400000002000000";
        
        let encoded_parts = encode(hex_payload).expect("Encoding failed");
        assert_eq!(encoded_parts.len(), 1, "Should be single part");
        
        let decoded_hex = decode(&encoded_parts).expect("Decoding failed");
        assert_eq!(decoded_hex.to_lowercase(), hex_payload.to_lowercase());
    }

    #[test]
    fn test_multi_part_roundtrip() {
        // Create a large payload (> 200 bytes)
        // 250 bytes of data
        let mut large_payload = String::with_capacity(500);
        for i in 0..250 {
            large_payload.push_str(&format!("{:02x}", i));
        }
        
        let encoded_parts = encode(&large_payload).expect("Encoding failed");
        assert!(encoded_parts.len() > 1, "Should be multi-part");
        
        // Print parts for debug
        // for (i, part) in encoded_parts.iter().enumerate() {
        //     println!("Part {}: {}", i, part);
        // }

        let decoded_hex = decode(&encoded_parts).expect("Decoding failed");
        assert_eq!(decoded_hex.to_lowercase(), large_payload.to_lowercase());
    }
}
