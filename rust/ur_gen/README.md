# Quantus UR Generator

This utility generates `ur:quantus-sign-request` UR strings from transaction data for testing the Keystone Quantus integration.

## Usage

Run the tool from the `rust` directory using `cargo`:

```bash
cd rust
# Default values (Alice, 1000, 1)
cargo run -p ur_gen

# Custom values: <address> <amount> <nonce>
cargo run -p ur_gen -- "Bob" 5000 2
```

## Output

The tool outputs:
1. The transaction details.
2. The SCALE-encoded hex.
3. The full UR string (e.g., `UR:QUANTUS-SIGN-REQUEST/...`).
4. A command to generate a QR code in your terminal using `qrrs`.

**Note:** To display QR codes in the terminal, install `qrrs`:
```bash
cargo install qrrs
```
