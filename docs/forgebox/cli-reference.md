# `forgebox-cli` Command Reference

The CLI is published on npm as **`forgebox-cli`**; the installed command is
**`forgebox`**. This reference combines the official README
(<https://github.com/KeystoneHQ/forgebox-cli>) with the **actual `--help` output
captured from the locally installed CLI (v1.1.0)**.

> Legend: **[VERIFIED-LOCAL]** = captured from the installed `forgebox` binary on
> this machine. **[VERIFIED-DOCS]** = from the official README. **[UNVERIFIED]** =
> inferred / unconfirmed.

## Installation

```bash
# Install globally (npm package is "forgebox-cli", command is "forgebox")
npm install -g forgebox-cli

# Verify
forgebox --version
forgebox --help
```

Or run without global install: `npx forgebox-cli --help`. [VERIFIED-DOCS]

### Local install status (this machine) [VERIFIED-LOCAL]

| Item | Value |
| --- | --- |
| Command on PATH | `forgebox` |
| Path | `/Users/elohim/.nvm/versions/node/v22.19.0/bin/forgebox` |
| `forgebox --version` | `1.1.0` |
| npm global package | `forgebox-cli@1.1.0` |
| npm `bin` mapping | `{ "forgebox": "bin/forgebox" }` |
| `forgebox-cli` on PATH | not found (expected — binary is `forgebox`) |

## Command summary [VERIFIED-LOCAL]

| Command | Purpose |
| --- | --- |
| `list-devices` | List all connected USB devices |
| `status` | Get ForgeBox device status (model, fw version, hw version, serial) |
| `keygen` | Generate a new secp256k1 key pair (PEM) |
| `register [directory]` | Register a public key to the hardware device |
| `sign` | Sign firmware into an OTA package |
| `interactive` / `i` | Start interactive menu mode |
| `help [command]` | Display help for a command |

## Captured local `--help` output

All output below was produced by running the installed CLI with help/version
flags only (no device-mutating commands were executed). [VERIFIED-LOCAL]

### `forgebox --version`

```text
1.1.0
```

### `forgebox --help`

```text
Usage: forgebox [options] [command]

CLI tool for ForgeBox Hardware Wallet management

Options:
  -V, --version                   output the version number
  -h, --help                      display help for command

Commands:
  list-devices                    List all connected USB devices
  status                          Get ForgeBox device status
  keygen [options]                Generate a new secp256k1 key pair
  register [options] [directory]  Register a public key to the hardware device
  sign [options]                  Sign firmware into OTA package
  interactive|i                   Start interactive mode
  help [command]                  display help for command
```

### `forgebox list-devices --help`

```text
Usage: forgebox list-devices [options]

List all connected USB devices

Options:
  -h, --help  display help for command
```

### `forgebox status --help`

```text
Usage: forgebox status [options]

Get ForgeBox device status

Options:
  -h, --help  display help for command
```

### `forgebox keygen --help`

```text
Usage: forgebox keygen [options]

Generate a new secp256k1 key pair

Options:
  -o, --out <directory>  Output directory for keys (default:
                         "/Users/elohim/.forgebox/keys")
  -f, --force            Allow writing keys into a git working tree (not
                         recommended)
  -h, --help             display help for command


Examples:
  $ forgebox keygen                        # writes to ~/.forgebox/keys
  $ forgebox keygen --out ./secure-storage
```

### `forgebox register --help`

```text
Usage: forgebox register [options] [directory]

Register a public key to the hardware device

Options:
  -p, --pubkey <file>  Path to public key file (PEM format)
  -k, --key <file>     Path to private key file (for proof of possession)
  -h, --help           display help for command


Examples:
  $ forgebox register --pubkey ./my-keys/pubkey.pem --key ./my-keys/private.pem
  $ forgebox register ./my-keys
```

### `forgebox sign --help`

```text
Usage: forgebox sign [options]

Sign firmware into OTA package

Options:
  -s, --s <path>    Source firmware file path
  -d, --d <path>    Destination signed file path
  -k, --key <path>  Private key PEM file path
  -h, --help        display help for command


Examples:
  $ forgebox sign --s firmware.bin --d update.bin --key ./my-keys/private.pem
```

### `forgebox interactive --help`

```text
Usage: forgebox interactive|i [options]

Start interactive mode

Options:
  -h, --help  display help for command
```

## Command details

### `keygen` — generate a signing key pair [VERIFIED-DOCS]

Generates a secp256k1 key pair in PEM format. By default writes to
`~/.forgebox/keys/`:

- `~/.forgebox/keys/private.pem` (mode `0600`)
- `~/.forgebox/keys/pubkey.pem` (mode `0644`)
- containing dir created mode `0700`

Flags: `-o, --out <dir>` (override output dir), `-f, --force` (allow writing into
a git working tree — **not recommended**).

Safety (from README): refuses to write into a git working tree unless `--force`;
back up **both** `private.pem` and `pubkey.pem` offline **before** `register`,
because the device accepts **one** public-key registration per lifetime — losing
the private key means you can no longer sign firmware for that device.

### `register` — establish the device Root of Trust [VERIFIED-DOCS]

Registers a public key on the device. The CLI uses the matching private key to
generate a proof-of-possession signature.

Two invocation forms:

```bash
forgebox register ~/.forgebox/keys          # pass the key directory
# or
forgebox register --pubkey <pubkey.pem> --key <private.pem>
```

Registration flow:
1. CLI verifies the key pair matches and creates a proof-of-possession signature.
2. CLI discovers and connects to the device over USB.
3. CLI prints the public key fingerprint (SHA-256).
4. You compare it with the fingerprint shown on the device.
5. If they match, confirm on the device (swipe).
6. The device validates the signature and stores the public key.

> One-time only: after registration the device verifies firmware **only** from
> the matching private key.

### `sign` — produce a signed OTA package [VERIFIED-DOCS]

```bash
forgebox sign --s <source_firmware_file> --d <signed_output> --key <private_key.pem>
```

Parameters:
- `--s` / `-s`: source firmware file (e.g. `mh1903_full.bin`).
- `--d` / `-d`: output OTA package path (e.g. `forgebox.bin`).
- `--key` / `-k`: private key file in PEM format (required). `sign` only accepts a
  PEM private-key **file path** (never inline key material).

What `sign` does:
1. Compresses and chunks the firmware per the OTA format.
2. Computes SHA-256 hashes of the compressed data and the original firmware.
3. Signs the required hash with the private key and writes the signature into the
   OTA header.
4. Writes an OTA package usable directly for device upgrades.

### `interactive` / `i` — menu mode [VERIFIED-DOCS]

Launches an interactive menu for common actions: List Devices, Get Device Status,
Generate Key Pair, Register Public Key.

## Notes / uncertainties

- The local `--help` for `list-devices`, `status`, and `interactive` exposes only
  `-h, --help` (no extra flags in v1.1.0). [VERIFIED-LOCAL]
- The `sign` command's `--help` does not document the OTA/output filename
  convention; the official examples use `forgebox.bin`, but `--d` accepts any
  path. The exact filename the device expects on an SD card is **not** stated in
  the CLI help. [UNVERIFIED — see `install-workflow.md`]
