# credential-eligibility circuit (Milestone 3)

Proves, without revealing the income or the credential:

> "I hold a `ZKPG_INCOME_V1` credential, signed with ECDSA P-256 by the issuer whose
> public key is in the public inputs, that is valid at `current_time`, and whose
> income is at least `minimum_income`."

This replaces Milestone 1's limitation (a self-chosen income). The income must now
carry a valid issuer signature.

## Inputs

| Input | Visibility | Checked by |
|---|---|---|
| `issuer_pub_key_x`, `issuer_pub_key_y` (`[u8; 32]` each) | public | circuit: the signature verifies under this key. Verifier: the key is on its trusted list |
| `minimum_income` (u64) | public | circuit: `income >= minimum_income`. Verifier: it equals the requested threshold |
| `current_time` (u64, unix s) | public | circuit: `issued_at <= current_time < expires_at`. Verifier: close to the real time |
| `challenge` (Field) | public | bound into the proof transcript. Verifier: it equals the challenge it issued |
| `signature` (`[u8; 64]`, low-s r‖s) | **private** | circuit: ECDSA P-256 verification |
| `subject_id`, `income`, `issued_at`, `expires_at`, `credential_id` (u64) | **private** | circuit: re-encoded to 48 bytes and hashed with SHA-256, so any change breaks the signature |

The public inputs are 67 field elements (2,144 bytes): 32 + 32 key bytes, then
threshold, time and challenge.

## The verifier's checks matter

The proof only shows the credential was signed by **the key in the public inputs**.
Anyone can create a key, sign a fake credential and produce a proof that `bb verify`
accepts (tested: "self-signed forgery"). **The verifier must also check** that the key
is trusted, and that the threshold, challenge and time are what it asked for.
`checkPublicInputs()` in `packages/credentials/src/public-inputs.ts` does this.

## Run

```bash
cd circuits/credential-eligibility
nargo test                                   # 11 circuit tests (signatures from the real TS issuer)

cd ../../packages/credentials
npm run test:circuit                         # 18 tests with REAL proofs (nargo + bb)
npm run gen:noir-vectors                     # regenerate src/test_vectors.nr (public data only)
```

## Results (2026-11-07, Linux x86_64, single machine)

| Metric | Value |
|---|---|
| Circuit size | 52,416 gates (ECDSA P-256 + SHA-256 dominate; the time and threshold checks add almost nothing) |
| Proof size | 14,656 bytes |
| Public inputs | 2,144 bytes (67 fields) |
| `bb prove` (native) | ≈ 0.8 s |
| `bb verify` (native) | ≈ 11 ms |

## Design decision: issuer key in the clear

Alternative measured: keep the key private and expose `SHA-256(key)` instead.
Result: 58,236 gates (+11%), public inputs ≈ 1.1 KB. Both circuit sizes round up to the
same 2^16 size `bb` pads to, so proving time would be similar. The size saving is small,
and a raw key keeps the verifier's trust check a direct comparison, so the raw key was kept.
