#!/usr/bin/env bash
# Build the production multi-coin firmware (includes Quantus) for Keystone3 / ForgeBox.
#
# Usage:
#   ./build_release.sh           build production firmware (multi-coin, incl. Quantus)
#   ./build_release.sh --sign    also sign it into build/forgebox.bin with your
#                                registered ForgeBox key (forgebox sign)
#
# Outputs (in build/):
#   mh1903_full.bin   padded image -> input to `forgebox sign`
#   keystone3.bin     OTA signed with Keystone's OFFICIAL key (NOT for ForgeBox)
#   forgebox.bin      (only with --sign) signed with YOUR key -> load on ForgeBox
#
# Override the signing key with: FORGEBOX_KEY=/path/to/private.pem ./build_release.sh --sign
set -euo pipefail
cd "$(dirname "$0")"

SIGN=false
FORGEBOX_KEY="${FORGEBOX_KEY:-$HOME/.forgebox/keys/private.pem}"
case "${1:-}" in
    --sign|-s) SIGN=true ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    "")        ;;
    *)         echo "unknown option: $1" >&2; exit 1 ;;
esac

echo "==> Building production firmware: multi-coin incl. Quantus (python3 build.py -e production)"
echo "    (same coin set as the simulator-multi-coins build you run in the simulator)"
python3 build.py -e production

FULL_IMG="build/mh1903_full.bin"
if [ ! -f "$FULL_IMG" ]; then
    echo "error: $FULL_IMG not produced; build failed" >&2
    exit 1
fi

report() { printf "  %-22s %9s bytes  sha256=%s\n" "$1" "$(wc -c < "$1" | tr -d ' ')" "$(shasum -a 256 "$1" | cut -d' ' -f1)"; }

echo
echo "==> Release artifacts:"
for f in build/mh1903.bin build/mh1903_full.bin build/keystone3.bin; do
    [ -f "$f" ] && report "$f"
done

if [ "$SIGN" = true ]; then
    echo
    command -v forgebox >/dev/null 2>&1 || { echo "error: 'forgebox' CLI not found in PATH" >&2; exit 1; }
    [ -f "$FORGEBOX_KEY" ] || { echo "error: signing key not found: $FORGEBOX_KEY (set FORGEBOX_KEY=...)" >&2; exit 1; }
    echo "==> Signing into build/forgebox.bin with $FORGEBOX_KEY"
    forgebox sign --s "$FULL_IMG" --d ./build/forgebox.bin --key "$FORGEBOX_KEY"
    report "build/forgebox.bin"
    echo "==> Ready: copy build/forgebox.bin to a FAT32 SD card and run the ForgeBox upgrade flow."
fi
