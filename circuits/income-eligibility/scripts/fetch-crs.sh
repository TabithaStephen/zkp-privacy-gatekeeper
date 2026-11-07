#!/usr/bin/env bash
# Pre-download the Barretenberg BN254 CRS (structured reference string) over HTTPS.
#
# WHY: `bb` normally downloads the CRS itself on first use, but over plain HTTP.
# Some networks (e.g. HTTPS-only proxies in cloud sandboxes) block that. This
# script fetches the SAME official file from the SAME host over HTTPS and stores
# it where `bb` looks first (~/.bb-crs). On a normal laptop you don't need this.
#
# WHAT: the CRS is PUBLIC data from Aztec's Ignition trusted-setup ceremony.
# It contains no secrets. UltraHonk uses it as a universal setup for all circuits.
#
# Usage: ./scripts/fetch-crs.sh [num_points]   (default 2^20 = 1,048,576 points)
set -euo pipefail
POINTS="${1:-1048576}"
BYTES=$((POINTS * 32))                    # compressed BN254 G1 point = 32 bytes
DIR="${CRS_DIR:-$HOME/.bb-crs}"
FILE="$DIR/bn254_g1_compressed.dat"
URL="https://crs.aztec-labs.com/g1_compressed.dat"

mkdir -p "$DIR"
if [ -f "$FILE" ] && [ "$(stat -c %s "$FILE" 2>/dev/null || stat -f %z "$FILE")" -ge "$BYTES" ]; then
  echo "CRS already present: $FILE"; exit 0
fi
echo "Downloading first $POINTS G1 points ($BYTES bytes) from $URL"
curl --fail --proto '=https' --tlsv1.2 -sS -r "0-$((BYTES - 1))" -o "$FILE.tmp" "$URL"
actual=$(stat -c %s "$FILE.tmp" 2>/dev/null || stat -f %z "$FILE.tmp")
[ "$actual" -eq "$BYTES" ] || { echo "Unexpected size: $actual"; rm -f "$FILE.tmp"; exit 1; }
mv "$FILE.tmp" "$FILE"
echo "Saved $FILE"
