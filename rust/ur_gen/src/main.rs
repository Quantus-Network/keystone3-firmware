use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    // Default payload from quantus parser tests: transfer_keep_alive with Planck genesis hash
    let default_payload = "0200007416854906f03a9dff66e3270a736c44e15970ac03a638471523a03069f276ca0700e8764817550100000083000000020000004901bf5c57fd3f9e726af399c763de6670dbdb115a91c0237e173f16eef65e725a77ae1c95817ee664cf733fafa7baa8e6244b396a54e57a5bc414b24c52800600";
    
    let hex_payload = if args.len() > 1 {
        args[1].clone()
    } else {
        default_payload.to_string()
    };

    println!("Hex payload: {}", hex_payload);

    let binary_payload = hex::decode(&hex_payload).unwrap();

    match quantus_ur::encode_bytes(&binary_payload) {
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
