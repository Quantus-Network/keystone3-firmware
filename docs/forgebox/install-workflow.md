# Install Workflow: Build → Sign → Load Custom Firmware via ForgeBox

This is the concrete, end-to-end procedure to take firmware built from **this
repo** (`Quantus-Network/keystone3-firmware`) and install it onto a ForgeBox
device using `forgebox` (the `forgebox-cli` package).

> Legend: **[VERIFIED]** = confirmed from an official source / this repo / the
> installed CLI. **[UNVERIFIED]** = inferred or from an unsourced search summary;
> confirm before relying on it.
>
> Assumption from the task: you have **already** run `forgebox keygen` and
> `forgebox register` — i.e. your public key is the device Root of Trust and your
> `private.pem` exists (default `~/.forgebox/keys/private.pem`). Steps 0–1 below
> are included for completeness; **skip them if already done.**

---

## Prerequisites [VERIFIED]

- A ForgeBox device + a data-capable USB-C cable.
- `forgebox` CLI installed (`forgebox --version` → `1.1.0` on this machine).
- Your signing key pair already generated and **registered** on the device
  (`~/.forgebox/keys/private.pem` + `pubkey.pem`).
- A toolchain to build this repo's firmware: `python3`, plus the ARM toolchain
  (`arm-none-eabi-gcc`) and Rust nightly **or** Docker. (See repo `README.md` /
  `docs/verify.md`.)
- A MicroSD card (FAT32) for loading the signed image. [VERIFIED — forgebox README]

---

## Step 0 (one-time, skip if done): generate your key pair [VERIFIED]

```bash
forgebox keygen          # writes ~/.forgebox/keys/{private.pem,pubkey.pem}
```

Back up **both** PEM files to offline storage before registering.

## Step 1 (one-time, skip if done): register your public key [VERIFIED]

```bash
forgebox register ~/.forgebox/keys
```

Compare the SHA-256 fingerprint shown in the terminal with the one on the device,
then confirm on the device.

> The device accepts **one** public-key registration for its lifetime. After
> this, it will only run firmware signed by the matching `private.pem`.

You can sanity-check connectivity any time with:

```bash
forgebox list-devices
forgebox status
```

---

## Step 2: build the firmware (this repo) [VERIFIED]

### Shortcut: `build_release.sh` (build + optional sign) — recommended

This repo ships `build_release.sh`, which wraps Steps 2–3 into one command and
builds the **production multi-coin** firmware (Quantus is included in the
multi-coin set, matching the simulator build):

```bash
# From the repo root.

# Build only -> build/mh1903_full.bin (+ build/keystone3.bin, official key).
# Does NOT produce forgebox.bin.
./build_release.sh

# Build AND sign with your registered key -> build/forgebox.bin (ready for SD card).
./build_release.sh --sign

# Use a different signing key (default: ~/.forgebox/keys/private.pem):
FORGEBOX_KEY=/path/to/private.pem ./build_release.sh --sign
```

> **Why a plain build has no `forgebox.bin`:** signing is opt-in. `build_release.sh`
> (and `build.py`) only produce the unsigned padded image `mh1903_full.bin` plus
> `keystone3.bin` (signed with Keystone's *official* key — not valid for your
> ForgeBox). `forgebox.bin` is `mh1903_full.bin` re-signed with *your* key, which
> only happens with `--sign` (it requires your `private.pem` and the `forgebox`
> CLI). The manual equivalent is Step 3 below.

### Manual build (underlying `build.py`)

Run the build at the repo root. This fork also supports a **`quantus`** build type
(added in `build.py`: `-DQUANTUS=true`), alongside `general`, `btc_only`, and
`cypherpunk`.

```bash
# From the repo root: /Users/elohim/play/quantus-network/keystone/keystone3-firmware

# Production multi-coin (incl. Quantus) — what build_release.sh runs:
python3 build.py -e production

# (other types, for reference)
# python3 build.py                       # general / multi-coin (dev)
# python3 build.py -t btc_only -e production
```

Or build via Docker (reproducible env — see `docs/verify.md`):

```bash
docker run -v $(pwd):/keystone3-firmware keystonehq/keystone3_baker:1.0.2 \
  python3 build.py -e production
```

### Build artifacts [VERIFIED — `build.py`, `tools/padding_bin_file/padding_bin_file.py`, `docs/verify.md`]

| File | What it is | Use for ForgeBox? |
| --- | --- | --- |
| `build/mh1903.bin` | Raw compiled firmware | No (intermediate) |
| `build/mh1903_full.bin` | **Padded full image + update metadata** (`mh1903append` marker, optional boot sig) | **Yes — this is the `forgebox sign` input** |
| `build/keystone3.bin` | OTA signed with **Keystone's official** key (macOS `ota_maker()` step) | **No — official key, not yours** |

> Why `mh1903_full.bin`: `build.py` runs
> `python3 padding_bin_file.py mh1903.bin`, and `padding_bin_file.py` writes the
> output to the fixed name **`mh1903_full.bin`**. The official forgebox examples
> also sign `mh1903_full.bin`. [VERIFIED]
>
> Do **not** load `keystone3.bin` onto ForgeBox: it is signed with Keystone's
> official key, not the key you registered. Re-sign `mh1903_full.bin` yourself in
> Step 3. [VERIFIED]

---

## Step 3: sign the firmware with YOUR key [VERIFIED]

Convert the padded image into a signed OTA package using your registered private
key:

```bash
forgebox sign \
  --s ./build/mh1903_full.bin \
  --d ./build/forgebox.bin \
  --key ~/.forgebox/keys/private.pem
```

- `--s` source = `build/mh1903_full.bin` (from Step 2).
- `--d` destination = `build/forgebox.bin` (the signed OTA you will load). The
  name `forgebox.bin` is the convention used by the official example; `--d`
  accepts any path. [VERIFIED-convention]
- `--key` = your PEM **private key file** (the one whose public key is registered
  on the device). `sign` only accepts a PEM file path. [VERIFIED]

This produces `build/forgebox.bin`, the file you load onto the device. The device
will accept it **only** because it is signed by the private key matching the
registered public key. [VERIFIED]

---

## Step 4: load the signed OTA onto the device [VERIFIED — forgebox README]

Per the official ForgeBox 101 guide, load via SD card:

1. Copy `build/forgebox.bin` to a MicroSD card (FAT32).
2. Insert the SD card into the ForgeBox device.
3. Start the firmware upgrade flow on the device.
4. Select the signed firmware package and confirm the upgrade.

After the upgrade completes, the device boots into your firmware.

### Recovery / reflashing [VERIFIED — forgebox README]

To erase or flash a different image, hold the **power button for 6+ seconds** to
enter **ForgeBox Recovery Mode**, then flash another firmware image from there.

---

## Quick reference (copy/paste, assuming key already registered)

```bash
# 1. Build AND sign in one step (production multi-coin, incl. Quantus).
#    Produces build/forgebox.bin signed with ~/.forgebox/keys/private.pem.
./build_release.sh --sign

# 2. Copy build/forgebox.bin to a FAT32 MicroSD card, insert into ForgeBox,
#    and run the on-device firmware upgrade flow.
```

Or the manual equivalent (build, then sign):

```bash
python3 build.py -e production
forgebox sign \
  --s ./build/mh1903_full.bin \
  --d ./build/forgebox.bin \
  --key ~/.forgebox/keys/private.pem
```

---

## Troubleshooting [VERIFIED — forgebox README]

1. `forgebox list-devices` — confirm the device is visible.
2. `forgebox status` — confirm it returns device info.
3. Confirm `build/mh1903_full.bin` exists before running `forgebox sign`.
4. If signing/verification fails, regenerate a clean key pair and re-register
   (subject to the one-time registration constraint).

Support contact (official): `eng@keyst.one`.

---

## Critical safety constraints [VERIFIED — forgebox README "Important Notes"]

- **Boot write area `0x01000000 ~ 0x01080FFF` — do not modify.** Corrupting the
  boot area can brick the device.
- **Fingerprint comms key page `DS28S60 PAGE_PF_AES_KEY = 82` — do not modify.**
  Overwriting it can break the fingerprint module.
- Store your signing key pair securely; anyone with `private.pem` can sign
  firmware as you. You are fully responsible for code you sign.

---

## Open questions / things NOT verified

These could not be confirmed from a primary source during research. **Do not
treat as fact** — verify against the device UI or Keystone before relying on them:

- **Exact on-device upgrade UI steps / menu labels** for ForgeBox. The README
  says "start the firmware upgrade flow … select the signed firmware package",
  but does not show the exact menu path. [UNVERIFIED]
- **Required SD-card filename.** The guide copies `build/forgebox.bin` to the SD
  card; whether the device requires a specific filename (e.g. the official
  Keystone path uses `keystone3.bin`) is not stated for ForgeBox. [UNVERIFIED]
- **WebUSB / cable-based loading for ForgeBox.** `keyst.one/firmware` documents a
  WebUSB upgrade path for the consumer **Keystone 3 Pro**; it is **not** confirmed
  to apply to ForgeBox, whose guide only documents the SD-card method. [UNVERIFIED]
- **Firmware version / anti-rollback check.** One search summary claimed a
  bootloader version check requiring a higher version than currently installed.
  No primary source was found and the ForgeBox README does not mention it for
  self-signed firmware. [UNVERIFIED]

---

## Sources

- ForgeBox 101 (device setup, build/sign/load, safety notes):
  <https://github.com/KeystoneHQ/forgebox>
- forgebox-cli README (commands, `sign` behavior, key safety):
  <https://github.com/KeystoneHQ/forgebox-cli>
- forgebox-helloworld (example firmware project):
  <https://github.com/KeystoneHQ/forgebox-helloworld>
- This repo: `build.py`, `tools/padding_bin_file/padding_bin_file.py`,
  `docs/verify.md`.
- Keystone firmware update page (consumer Keystone 3 Pro, for contrast):
  <https://keyst.one/firmware>
