# Quantus UR Generator

This utility generates `ur:quantus-sign-request` UR strings from transaction data for testing the Keystone Quantus integration.

## Usage

Run the tool from the `rust` directory using `cargo`:

```bash
cd rust
# Default: built-in Planck transfer payload, signed by the standard test mnemonic's account 0
cargo run -p ur_gen

# Custom values: <scale-payload-hex> [signer-ss58-address]
cargo run -p ur_gen -- 0200007416... qzna4bUiEiZdXQpwvSQDmM2y9rBPyJRS9iNm85jPgicM76kA8
```

The payload is wrapped in the v1 signing-request envelope
(`{"v":1,"signer":...,"payload":"0x..."}`) shared with the companion apps, then UR-encoded.

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
