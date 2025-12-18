use ur_registry::bytes::Bytes;
use ur_registry::traits::UR;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: ur_gen <hex_payload>");
        println!("Defaulting to test quantus transaction payload");
    }
    // Use the hex payload from quantus parser tests (balance transfer)
    let hex_payload = if args.len() > 1 {
        args[1].clone()
    } else {
        "0200007416854906f03a9dff66e3270a736c44e15970ac03a638471523a03069f276ca0700e876481755010000007400000002000000826beefbe2be72645ff376f18de745ac196dc77637436090de4174180706118e5a77ae1c95817ee664cf733fafa7baa8e6244b396a54e57a5bc414b24c52800600".to_string()
    };

    let payload = hex::decode(&hex_payload).unwrap();
    println!("Hex payload: {}", hex_payload);
    println!("Payload length: {} bytes", payload.len());

    let ur_payload = Bytes::new(payload);
    let mut ur_encoder = ur_payload.to_ur_encoder(200);

    // Generate the UR string and replace ur:bytes with ur:quantus-sign-request
    let ur_str = ur_encoder.next_part().unwrap();
    let quantus_ur_upper = ur_str.to_uppercase().replace("UR:BYTES", "UR:QUANTUS-SIGN-REQUEST");
    let quantus_ur_lower = ur_str.to_lowercase().replace("ur:bytes", "ur:quantus-sign-request");

    println!("\nUR String (uppercase - traditional):");
    println!("{}", quantus_ur_upper);
    println!("\nUR String (lowercase - also valid):");
    println!("{}", quantus_ur_lower);

    println!("\nThis UR represents a quantus transaction that:");
    println!("- Sends 90.0 QUS to qzps6MnSixszZAWiwcpjtw6uXBjWg2aEyrXBdp9thijzY1g86");
    println!("- Is a regular (non-reversible) transfer");

    println!("\nTo generate QR code in terminal (if qrrs is installed):");
    println!("qrrs \"{}\"", quantus_ur_upper);
}

