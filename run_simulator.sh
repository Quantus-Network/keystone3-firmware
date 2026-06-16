#!/usr/bin/env bash
# Launch the Keystone3 simulator built from this repo (custom Quantus firmware).
#
# Usage:
#   ./run_simulator.sh          run the existing build/simulator (build it if missing)
#   ./run_simulator.sh -b       incremental rebuild (make -j) then run
#   ./run_simulator.sh -c       full clean rebuild (python3 build.py -o simulator) then run
#
# Unlock PIN: 111111
set -euo pipefail
cd "$(dirname "$0")"

REBUILD="none"
case "${1:-}" in
    -b|--build) REBUILD="incremental" ;;
    -c|--clean) REBUILD="clean" ;;
    -h|--help)  sed -n '2,9p' "$0"; exit 0 ;;
    "")         ;;
    *)          echo "unknown option: $1" >&2; exit 1 ;;
esac

# build.py exits non-zero on the cosmetic mh1903.bin padding step for simulator
# builds, so we tolerate that and verify the binary exists afterwards instead.
if [ "$REBUILD" = "clean" ] || [ ! -x build/simulator ]; then
    python3 build.py -o simulator || true
elif [ "$REBUILD" = "incremental" ]; then
    if [ -f build/Makefile ]; then
        ( cd build && make -j )
    else
        python3 build.py -o simulator || true
    fi
fi

if [ ! -x build/simulator ]; then
    echo "error: build/simulator not found (build failed)" >&2
    exit 1
fi

# Stop any running instance (match exact process name so we never kill this script).
pkill -x simulator 2>/dev/null || true
sleep 0.5

echo "Starting simulator (unlock PIN 111111). Press Ctrl+C to quit."
exec ./build/simulator
