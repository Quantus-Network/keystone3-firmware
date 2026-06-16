# Keystone ForgeBox — Overview

This directory documents how to install custom Keystone3 firmware (this fork:
`github.com/Quantus-Network/keystone3-firmware`) onto a Keystone device using
**ForgeBox** and the **`forgebox-cli`** tool.

> Verification legend used throughout these docs:
> - **[VERIFIED]** — confirmed from an official source (URL cited) or from the
>   locally installed CLI / this repo's source.
> - **[UNVERIFIED]** — inferred, or stated in a search summary without a primary
>   source. Treat with caution and confirm against the device/docs before relying on it.

## What is ForgeBox?

ForgeBox is an open, developer-focused hardware platform from Keystone, built on
the **Keystone 3 hardware wallet architecture**. Unlike the consumer Keystone 3
Pro (which ships ready-to-use official firmware), ForgeBox ships with **no
pre-installed wallet features** and is meant to run **your own code**. [VERIFIED]

Key properties (from the official product page and `forgebox` repo):

- **Open / customizable** hardware platform, not a sealed black box. [VERIFIED]
- **Secure by design**: built on hardened wallet architecture with triple Secure
  Elements and PCI-level self-destruct / anti-tamper protection. [VERIFIED]
- **Root of Trust you control**: you register *your own* public key on the
  device **once**. Afterwards the device will only execute firmware signed by the
  matching private key. [VERIFIED]

Sources:
- ForgeBox 101 guide / repo: <https://github.com/KeystoneHQ/forgebox>
- Product page: <https://keyst.one/shop/products/keystone-3-forge-box>

## What is `forgebox-cli`?

`forgebox-cli` is the official developer CLI for managing ForgeBox devices,
generating signing keys, registering the device public key, and producing signed
OTA (firmware update) packages. [VERIFIED]

- npm package name: **`forgebox-cli`**
- Installed command (binary): **`forgebox`** (the npm `bin` maps
  `forgebox -> bin/forgebox`) [VERIFIED]
- Latest published version: **1.1.0** (published versions: 1.0.0, 1.1.0) [VERIFIED]
- Source / docs: <https://github.com/KeystoneHQ/forgebox-cli>

> Naming note: the user refers to "forgebox-cli", but the actual command you type
> is **`forgebox`** (no `-cli` suffix). `forgebox-cli` is only the package name.

### Local install status (this machine) [VERIFIED]

- `forgebox` is installed at: `/Users/elohim/.nvm/versions/node/v22.19.0/bin/forgebox`
- `forgebox --version` → `1.1.0`
- npm global package: `forgebox-cli@1.1.0`
- `forgebox-cli` / `forgeboxcli` are **not** on PATH (expected — the binary is `forgebox`).

See [`cli-reference.md`](./cli-reference.md) for the full captured `--help` output.

## How ForgeBox relates to building/installing Keystone3 firmware

The end-to-end loop has three stages. This repo (the Quantus fork of
`keystone3-firmware`) covers **Stage 1**; `forgebox-cli` covers **Stages 2–3**.

1. **Build** the firmware from this repo → produces an unsigned firmware image
   (`build/mh1903.bin`) and a padded full image (`build/mh1903_full.bin`).
   [VERIFIED — see `build.py` and `docs/verify.md` in this repo]
2. **Sign** the padded image with *your* private key using `forgebox sign`,
   producing a signed OTA package (e.g. `forgebox.bin`). [VERIFIED]
3. **Load** the signed OTA package onto the ForgeBox device (SD card / on-device
   upgrade flow). [VERIFIED]

```
this repo (build.py)              forgebox-cli                 device
┌──────────────────┐   sign with  ┌───────────────┐   load    ┌──────────┐
│ mh1903_full.bin  │ ───────────► │  forgebox.bin │ ────────► │ ForgeBox │
│ (padded image)   │  your key    │ (signed OTA)  │  SD card  │  runs it │
└──────────────────┘              └───────────────┘           └──────────┘
```

> Important distinction: this repo's `build.py` on macOS also runs an `ota-maker`
> step that produces `build/keystone3.bin` signed with **Keystone's official**
> key. That official artifact is **not** what you load on ForgeBox. For ForgeBox
> you must re-sign `mh1903_full.bin` with **your own** key via `forgebox sign`.
> [VERIFIED — `ota_maker()` in `build.py`; ForgeBox signing in forgebox README]

The full, concrete, step-by-step procedure (including signing and loading) is in
[`install-workflow.md`](./install-workflow.md).

## Document index

- [`README.md`](./README.md) — this overview.
- [`cli-reference.md`](./cli-reference.md) — `forgebox` commands, flags, and the
  local `--help` output captured from the installed CLI.
- [`install-workflow.md`](./install-workflow.md) — step-by-step: build → sign →
  load a freshly built Keystone3 firmware onto a device via ForgeBox.

## Primary sources

- forgebox-cli (CLI source + README): <https://github.com/KeystoneHQ/forgebox-cli>
- forgebox (ForgeBox 101 / device guide): <https://github.com/KeystoneHQ/forgebox>
- forgebox-helloworld (example firmware project referenced by the guide):
  <https://github.com/KeystoneHQ/forgebox-helloworld>
- Keystone3 firmware (upstream): <https://github.com/KeystoneHQ/keystone3-firmware>
- ForgeBox product page: <https://keyst.one/shop/products/keystone-3-forge-box>
- npm package: <https://www.npmjs.com/package/forgebox-cli>
- This repo's build/verify guide: `docs/verify.md`
