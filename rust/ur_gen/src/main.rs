use std::env;
use quantus_ur;

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

    println!("Hex payload: {}", hex_payload);
    // Rough estimate of bytes if valid hex
    println!("Payload length: {} bytes", hex_payload.len() / 2);

    match quantus_ur::encode(&hex_payload) {
        Ok(ur_parts) => {
            let ur_str = &ur_parts[0]; // For display, just show the first part if single
            
            println!("\nUR String(s):");
            for part in &ur_parts {
                 println!("{}", part);
            }
            
            println!("\nThis UR represents a quantus transaction that:");
            println!("- Sends 90.0 QUS to qzps6MnSixszZAWiwcpjtw6uXBjWg2aEyrXBdp9thijzY1g86");
            println!("- Is a regular (non-reversible) transfer");

            println!("\nTo generate QR code in terminal (if qrrs is installed):");
            println!("qrrs \"{}\"", ur_str);
            
            // Verify decoding logic
            match quantus_ur::decode(&ur_parts) {
                Ok(decoded) => {
                    if decoded == hex_payload.to_lowercase() || decoded == hex_payload.to_uppercase() {
                         println!("\nDecode check passed.");
                    } else {
                        println!("\nWarning: Round-trip decode check returned different hex: {}", decoded);
                    }
                },
                Err(e) => println!("\nWarning: Round-trip decode check failed: {}", e),
            }
        },
        Err(e) => {
            eprintln!("Error encoding UR: {}", e);
            std::process::exit(1);
        }
    }
}
