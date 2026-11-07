# income-eligibility circuit (Milestone 1)

A first, deliberately limited Noir circuit that proves:

> "I know a private `income` such that `income >= minimum_income`."

```rust
fn main(income: u64, minimum_income: pub u64) {
    assert(income >= minimum_income, "income below threshold");
}
```

## Public vs private

| Input | Visibility | Who knows it | Sent to verifier? |
|---|---|---|---|
| `income` | **private witness** | prover only | **No** |
| `minimum_income` | **public input** (`pub`) | prover and verifier | Yes, as 32 bytes in `public_inputs` |

What the verifier receives: the proof (14,656 bytes), the public inputs (32 bytes: the
threshold) and, separately and once per circuit, the verification key. Not the income.

## ⚠️ Limitation

Nothing ties `income` to a bank. A prover can type any number into the private input
and produce a valid proof. This circuit demonstrates a genuine ZKP workflow only.
Issuer-signed credentials (Milestones 2–3) are what make the claim trustworthy.

## Toolchain (pinned)

| Tool | Version | Source of compatibility |
|---|---|---|
| Noir / `nargo` | 1.0.0 | `noirup -v 1.0.0` |
| Barretenberg / `bb` | 6.0.0 | Noir v1.0.0's own `scripts/install_bb.sh` pins `bbup -v 6.0.0` |

```bash
curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash
noirup -v 1.0.0
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/next/barretenberg/bbup/install | bash
bbup -v 6.0.0
```

## Run it

All commands from `circuits/income-eligibility/`.

```bash
nargo test                 # 6 circuit unit tests (no proofs; checks the logic)
./scripts/e2e.sh           # real proofs + attack checks, prints PASS/FAIL
```

Manual pipeline, step by step:

```bash
cp Prover.example.toml Prover.toml        # fictional inputs; Prover.toml is git-ignored
nargo compile                             # Noir -> ACIR bytecode: target/income_eligibility.json
nargo execute -p Prover witness           # solve the circuit with the private inputs -> target/witness.gz
bb write_vk -b target/income_eligibility.json -o target/vk           # verification key
bb prove  -b target/income_eligibility.json -w target/witness.gz \
          -k target/vk/vk -o target/proof                            # -> proof + public_inputs
bb verify -p target/proof/proof -k target/vk/vk \
          -i target/proof/public_inputs                              # "Proof verified successfully"
```

Note that `bb verify` takes only the proof, the public inputs and the verification key.
It never sees `Prover.toml` or the witness.

If `bb` cannot download its CRS (it uses plain HTTP; some sandboxes only allow HTTPS),
run `./scripts/fetch-crs.sh` first. It fetches the same public file over HTTPS.

## Test results (2026-11-07, Linux x86_64 cloud container)

| # | Case | Expected | Result |
|---|---|---|---|
| 1 | income 950,000 ≥ 800,000 | proof verifies | ✅ PASS |
| 2 | income 800,000 = 800,000 (boundary) | proof verifies | ✅ PASS |
| 3 | income 650,000 < 800,000 | witness generation refused, so no proof | ✅ PASS |
| 4 | one byte of a valid proof flipped | verification fails | ✅ PASS |
| 5 | valid proof presented with threshold 1,000,000 | verification fails | ✅ PASS |
| 6a | `public_inputs` contents | only the threshold | ✅ PASS |
| 6b | income encoded as a field element in proof/public inputs | absent | ✅ PASS |

`nargo test`: 6/6 passed (above, exact boundary, below, one rupee below, zero, max u64).

Single-run measurements (indicative only, not a benchmark): proof 14,656 B · public
inputs 32 B · verification key 3,680 B · `bb prove` ≈ 142 ms · `bb verify` ≈ 18 ms ·
circuit size 2,812 gates (most of that is UltraHonk's fixed overhead, not our one comparison).

Check 6b is a sanity check, not a proof of zero-knowledge. The zero-knowledge
property comes from the proving system's design, not from this test.
