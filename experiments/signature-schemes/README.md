# Signature-scheme experiments (Milestone 2)

This folder answers one question with real code: **can a signature made by a JavaScript
issuer be verified inside a Noir circuit, and are forged or tampered credentials
rejected?** It compares two candidate schemes. The analysis and recommendation are in
[`docs/signature-scheme-evaluation.md`](../../docs/signature-scheme-evaluation.md).

| Folder | Scheme | Issuer side (JS) | Circuit side (Noir) |
|---|---|---|---|
| `ecdsa-p256/` | ECDSA P-256 over SHA-256 | Node.js built-in `crypto` | `std::ecdsa_secp256r1` + `noir-lang/sha256` v0.3.0 |
| `eddsa-babyjubjub/` | EdDSA BabyJubJub-Poseidon | `@zk-kit/eddsa-poseidon` 1.1.0 | `noir-lang/eddsa` (unreleased `master`) + `noir-lang/poseidon` v0.3.0 |

These are **experiments**, not the final credential circuit. Issuer keys are generated
in memory on every run and never written to disk. All credential values are fictional.

## Run

```bash
cd experiments/signature-schemes
npm install
npm test          # = node run.mjs; needs nargo 1.0.0 and bb 6.0.0 on PATH
```

For each scheme the script signs a credential in JavaScript, checks it with the JS
library, then runs the circuit on valid and attack inputs and makes real proofs:

| Case | Expected |
|---|---|
| valid credential | witness solves; `bb` proof verifies |
| `high_s_twin` (ECDSA only) | rejected (see the low-s finding) |
| `tampered_income` (signed ₹9.5L, claims ₹15L) | `invalid issuer signature` |
| `wrong_issuer_key` (attacker signs, issuer key claimed) | `invalid issuer signature` |
| `tampered_signature` | `invalid issuer signature` |
| `below_threshold` (valid ₹6.5L credential vs ₹8L) | `income below threshold` |
