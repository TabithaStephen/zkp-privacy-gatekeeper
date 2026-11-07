#!/usr/bin/env bash
# End-to-end proof test for the income-eligibility circuit (Milestone 1).
#
# Runs the REAL pipeline — nargo compile → nargo execute → bb write_vk →
# bb prove → bb verify — and then checks that attacks are rejected.
# Every check prints PASS or FAIL; the script exits non-zero on any FAIL.
#
# Usage (from circuits/income-eligibility):  ./scripts/e2e.sh
# Requires: nargo 1.0.0, bb 6.0.0 on PATH. All values are fictional.
set -euo pipefail
cd "$(dirname "$0")/.."

CIRCUIT=target/income_eligibility.json
OUT=target/e2e
FAILURES=0
pass() { echo "  PASS  $1"; }
fail() { echo "  FAIL  $1"; FAILURES=$((FAILURES + 1)); }

# Encode an integer as one 32-byte big-endian field element (bb's public-input format).
field_hex() { printf '%064x' "$1"; }
# Hex <-> binary helpers (python3 instead of xxd, which is not always installed).
hex_to_file() { python3 -c 'import sys; open(sys.argv[2],"wb").write(bytes.fromhex(sys.argv[1]))' "$1" "$2"; }
file_to_hex() { python3 -c 'import sys; print("".join(open(f,"rb").read().hex() for f in sys.argv[1:]))' "$@"; }

# Write a temporary prover file. nargo -p takes a name relative to the package root.
write_inputs() { # name income threshold
  printf 'income = "%s"\nminimum_income = "%s"\n' "$2" "$3" > "$1.toml"
}

rm -rf "$OUT" && mkdir -p "$OUT"
trap 'rm -f e2e_*.toml' EXIT

echo "== Setup: compile circuit and write verification key"
nargo compile
bb write_vk -b "$CIRCUIT" -o "$OUT/vk" >/dev/null 2>&1
echo "  circuit: $CIRCUIT   vk: $OUT/vk/vk"

# ---------------------------------------------------------------------------
echo "== 1. Income above threshold (950000 >= 800000) -> valid proof"
write_inputs e2e_above 950000 800000
nargo execute -p e2e_above above >/dev/null
start=$(date +%s%N)
bb prove -b "$CIRCUIT" -w target/above.gz -k "$OUT/vk/vk" -o "$OUT/above" >/dev/null 2>&1
prove_ms=$(( ($(date +%s%N) - start) / 1000000 ))
start=$(date +%s%N)
if bb verify -p "$OUT/above/proof" -k "$OUT/vk/vk" -i "$OUT/above/public_inputs" >/dev/null 2>&1; then
  pass "proof verifies"
else
  fail "valid proof did not verify"
fi
verify_ms=$(( ($(date +%s%N) - start) / 1000000 ))

# ---------------------------------------------------------------------------
echo "== 2. Income exactly at threshold (800000 >= 800000) -> valid proof"
write_inputs e2e_equal 800000 800000
nargo execute -p e2e_equal equal >/dev/null
bb prove -b "$CIRCUIT" -w target/equal.gz -k "$OUT/vk/vk" -o "$OUT/equal" >/dev/null 2>&1
if bb verify -p "$OUT/equal/proof" -k "$OUT/vk/vk" -i "$OUT/equal/public_inputs" >/dev/null 2>&1; then
  pass "proof verifies"
else
  fail "valid boundary proof did not verify"
fi

# ---------------------------------------------------------------------------
echo "== 3. Income below threshold (650000 < 800000) -> no witness, so no proof"
write_inputs e2e_below 650000 800000
if nargo execute -p e2e_below below >"$OUT/below.log" 2>&1; then
  fail "witness was generated for an ineligible income"
elif grep -q "income below threshold" "$OUT/below.log"; then
  pass "witness generation refused: 'income below threshold'"
else
  fail "execution failed for an unexpected reason (see $OUT/below.log)"
fi

# ---------------------------------------------------------------------------
echo "== 4. Tampered proof (one byte flipped) -> verification fails"
cp "$OUT/above/proof" "$OUT/tampered_proof"
python3 - "$OUT/tampered_proof" <<'PY'
import sys
p = sys.argv[1]
b = bytearray(open(p, "rb").read())
b[len(b) // 2] ^= 0x01
open(p, "wb").write(b)
PY
if bb verify -p "$OUT/tampered_proof" -k "$OUT/vk/vk" -i "$OUT/above/public_inputs" >/dev/null 2>&1; then
  fail "tampered proof was accepted"
else
  pass "tampered proof rejected"
fi

# ---------------------------------------------------------------------------
echo "== 5. Altered public input (claim the proof was for 1000000) -> verification fails"
# Attack: take a valid proof made for threshold 800000 and present it as
# meeting a stricter threshold. Public inputs are bound into the proof.
hex_to_file "$(field_hex 1000000)" "$OUT/altered_public_inputs"
if bb verify -p "$OUT/above/proof" -k "$OUT/vk/vk" -i "$OUT/altered_public_inputs" >/dev/null 2>&1; then
  fail "proof accepted with an altered threshold"
else
  pass "altered threshold rejected"
fi

# ---------------------------------------------------------------------------
echo "== 6. Privacy: what the verifier receives"
expected_pi=$(field_hex 800000)
actual_pi=$(file_to_hex "$OUT/above/public_inputs")
if [ "$actual_pi" = "$expected_pi" ]; then
  pass "public_inputs contains only the threshold (800000)"
else
  fail "unexpected public_inputs: $actual_pi"
fi
income_hex=$(field_hex 950000)
if file_to_hex "$OUT/above/proof" "$OUT/above/public_inputs" | grep -q "$income_hex"; then
  fail "private income (950000) found encoded in proof or public inputs"
else
  pass "private income (950000) not found as a field element in proof or public inputs"
fi

# ---------------------------------------------------------------------------
echo "== Measurements (this machine, single run — indicative only)"
echo "  proof size:          $(stat -c %s "$OUT/above/proof") bytes"
echo "  public inputs size:  $(stat -c %s "$OUT/above/public_inputs") bytes"
echo "  verification key:    $(stat -c %s "$OUT/vk/vk") bytes"
echo "  bb prove time:       ${prove_ms} ms"
echo "  bb verify time:      ${verify_ms} ms"
bb gates -b "$CIRCUIT" 2>/dev/null | grep -oE '"circuit_size": *[0-9]+' | sed 's/^/  /' || true

echo
if [ "$FAILURES" -eq 0 ]; then
  echo "ALL CHECKS PASSED"
else
  echo "$FAILURES CHECK(S) FAILED"
  exit 1
fi
