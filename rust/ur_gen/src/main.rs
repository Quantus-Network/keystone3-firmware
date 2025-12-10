use app_quantus::QuantusTransaction;
use parity_scale_codec::Encode;
use ur_registry::bytes::Bytes;
use ur_registry::traits::UR;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: ur_gen <to_address> <amount> <nonce>");
        println!("Defaulting to test values: 'Alice', 1000, 1");
    }

    let to = if args.len() > 1 { args[1].clone() } else { "Alice".to_string() };
    let amount = if args.len() > 2 { args[2].parse().unwrap_or(1000) } else { 1000 };
    let nonce = if args.len() > 3 { args[3].parse().unwrap_or(1) } else { 1 };

    let tx = QuantusTransaction {
        to,
        amount,
        nonce,
    };

    println!("Transaction: {:?}", tx);
    let encoded = tx.encode();
    println!("SCALE encoded hex: {}", hex::encode(&encoded));

    let ur_payload = Bytes::new(encoded);
    let mut ur_encoder = ur_payload.to_ur_encoder(200);
    
    // We want to replace ur:bytes with ur:quantus-sign-request
    // But RegistryItem trait doesn't easily allow changing type for encoder?
    // Actually `Bytes::get_registry_type()` returns "bytes".
    // We can generate the string and replace it.
    
    let ur_str = ur_encoder.next_part().unwrap();
    let quantus_ur = ur_str.to_uppercase().replace("UR:BYTES", "UR:QUANTUS-SIGN-REQUEST");
    
    println!("\nUR String:");
    println!("{}", quantus_ur);
    
    println!("\nTo generate QR code in terminal (if qrrs is installed):");
    println!("qrrs \"{}\"", quantus_ur);
}

