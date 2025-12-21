use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    // Default payload from quantus parser tests
    let default_payload = "0200007416854906f03a9dff66e3270a736c44e15970ac03a638471523a03069f276ca0700e876481755010000007400000002000000826beefbe2be72645ff376f18de745ac196dc77637436090de4174180706118e5a77ae1c95817ee664cf733fafa7baa8e6244b396a54e57a5bc414b24c52800600";
    
    let hex_payload = if args.len() > 1 {
        args[1].clone()
    } else {
        default_payload.to_string()
    };

    println!("Hex payload: {}", hex_payload);

    match quantus_ur::encode_hex(&hex_payload) {
        Ok(ur_parts) => {
            let ur_str = &ur_parts[0];
            println!("\nUR String: {}", ur_str);
            println!("\nGenerate QR with: qrrs \"{}\"", ur_str);
        },
        Err(e) => {
            eprintln!("Error encoding UR: {}", e);
            std::process::exit(1);
        }
    }
}
