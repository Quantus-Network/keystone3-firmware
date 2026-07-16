# ForgeBox Firmware Install

## Prerequisites

- `forgebox` CLI installed
- Key pair generated (`forgebox keygen`) and registered on device (`forgebox register ~/.forgebox/keys`)
- FAT32 MicroSD card

## Build & Sign (one command)

```bash
./build_release.sh --sign
```

Produces `build/forgebox.bin` signed with `~/.forgebox/keys/private.pem`.

## Install

1. Copy `build/forgebox.bin` to MicroSD
2. Insert into ForgeBox
3. Run firmware upgrade flow on device

## Recovery

Hold power 6+ seconds → ForgeBox Recovery Mode.
