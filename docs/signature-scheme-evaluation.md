# Issuer signature scheme: evaluation

**Status:** experiments complete. **Decision: ECDSA P-256 with low-s normalisation** (approved 2026-11-07).
**Date:** 2026-11-07 · Noir `nargo` 1.0.0 · Barretenberg `bb` 6.0.0 (UltraHonk)
**Code:** [`experiments/signature-schemes/`](../experiments/signature-schemes/)

## 1. Why we need this

Milestone 1's circuit lets the prover type any income. To make the claim trustworthy, a
(simulated) bank **signs** a credential containing the income, and the circuit checks
that signature **inside the proof**. The verifier learns "a credential signed by this
issuer says income ≥ threshold" without seeing the credential or the signature.

The signature check runs inside the circuit, so the scheme must be:
1. a standard, well-studied scheme (no custom cryptography),
2. verifiable in Noir 1.0.0 with maintained libraries,
3. producible by a normal issuer backend (Node.js),
4. affordable to prove, ideally in a browser (Milestone 4).

## 2. Candidates tested

| | **A. ECDSA P-256** (secp256r1) | **B. EdDSA on BabyJubJub with Poseidon** |
|---|---|---|
| What it is | NIST curve; used in TLS, passkeys/WebAuthn, HSMs, cloud KMS | Twisted-Edwards curve built over the BN254 field, used in ZK systems (circom, Semaphore, Iden3) |
| Message hash | SHA-256 over a 40-byte canonical encoding | Poseidon (a "ZK-friendly" hash) over 5 field elements |
| Issuer library | Node.js built-in `crypto` (no dependency) | `@zk-kit/eddsa-poseidon` 1.1.0 |
| Noir verifier | `std::ecdsa_secp256r1::verify_signature` (built into Noir) + `noir-lang/sha256` **v0.3.0 (released, for Noir ≥1.0.0)** | `noir-lang/eddsa` **unreleased `master`** (commit `1ed4e55`) + `noir-lang/poseidon` v0.3.0 |

Not tested: **secp256k1** (similar cost to P-256 but no WebCrypto/HSM advantage) and
**Schnorr on Grumpkin** (cheap, but no mainstream JS issuer tooling).

## 3. Results (measured, not estimated)

Both experiment circuits do the same job: verify the issuer signature over
`(schema_tag, subject_id, income, issued_at, expires_at)`, then check
`income >= minimum_income`. They were run 3 times, each with fresh random issuer keys.
The outcomes were identical every time.

### Correctness: does JS signing agree with Noir verification?

| Case | ECDSA P-256 | EdDSA BJJ |
|---|---|---|
| Valid credential: witness + real `bb` proof verifies | ✅ | ✅ |
| Tampered income (signed ₹9.5L, claimed ₹15L) | ✅ rejected | ✅ rejected |
| Wrong issuer key | ✅ rejected | ✅ rejected |
| Tampered signature | ✅ rejected | ✅ rejected |
| Valid credential, income below threshold | ✅ `income below threshold` | ✅ `income below threshold` |
| High-s twin of a valid signature | ❗ **rejected**, see finding F1 | n/a |

### Cost (single machine, Linux x86_64, native `bb`; median of 3)

| Metric | ECDSA P-256 | EdDSA BJJ | Milestone 1 (no signature) |
|---|---|---|---|
| Circuit size (gates) | **52,416** | **9,420** | 2,812 |
| `bb prove` | ≈ 0.9 s | ≈ 0.27 s | ≈ 0.14 s |
| `bb verify` | ≈ 13 ms | ≈ 12 ms | ≈ 18 ms |
| Proof size | 14,656 B | 14,656 B | 14,656 B |
| Public inputs | 2,080 B (65 fields) | 96 B (3 fields) | 32 B |

Proof size and verification time stay constant: this is a property of UltraHonk.
Proving time grows with circuit size. Browser (WASM) proving will be slower than these
native timings and must be measured in Milestone 4.

> **Outcome (Milestones 4 and 6):** measured in Chromium with 4 threads: about 2.8 s per
> proof once the CRS is cached, and about 9 s for the first proof. Acceptable for this
> use, so the EdDSA fallback was not needed. See [benchmarks](benchmarks/README.md).

## 4. Findings

**F1. Noir's ECDSA verifier requires "low-s" signatures.** For any ECDSA signature
`(r, s)`, `(r, n − s)` is also mathematically valid. Noir/`bb` rejects the high-s form,
and Node's `crypto` returns either form at random. Without normalisation, **about half
of genuine issuer signatures would fail in-circuit.** Fix: the issuer converts `s` to
`min(s, n − s)` after signing. This also closes the signature-malleability gap.

**F2. The released EdDSA library does not compile on Noir 1.0.0.** `noir-lang/eddsa`
v0.1.3 depends on `poseidon` v0.1.1, which fails with 21 type errors. The `master`
branch has been updated, but there is **no release**. Nargo can only pin a tag or a
branch, not a commit, so a reproducible build would require vendoring the library
source into this repo.

**F3. `@zk-kit/eddsa-poseidon` 1.1.0's ES-module build is broken.** It imports
`blakejs` incorrectly. The CommonJS build works.

**F4. ECDSA public inputs are large.** A P-256 public key is passed as 64 separate bytes,
each becoming one public field element (2 KB). This can be reduced by exposing a hash
of the issuer key instead. That is a design option for Milestone 3, not a blocker.

**F5. Canonical encoding matters.** Both designs fix the field order, width and a
schema tag (`ZKPG_IN1`), so the same credential always produces the same bytes or field
elements, and a signature for one credential type cannot be reused for another.

## 5. Trade-offs

| Criterion | ECDSA P-256 | EdDSA BJJ |
|---|---|---|
| Standard / widely reviewed | ✅ NIST, decades of use | ✅ EdDSA is standard; BJJ+Poseidon is a ZK-community standard (EIP-2494) |
| Noir support today | ✅ built into the standard library; SHA-256 lib released | ⚠️ unreleased `master` branch only (F2) |
| Issuer tooling | ✅ Node, WebCrypto, HSMs, cloud KMS: what a real bank would use | ⚠️ ZK-specific JS library; no HSM/KMS support |
| Proving cost | ⚠️ ~5.6× more gates, ~3.5× slower to prove | ✅ small and fast |
| Public input size | ⚠️ 2 KB (fixable, F4) | ✅ 96 B |
| Pitfalls found | low-s normalisation (F1) | dependency (F2), packaging (F3) |
| Interview explainability | ✅ "the same signatures as TLS and passkeys" | ✅ "a ZK-friendly signature designed for circuits" |

## 6. Recommendation

**ECDSA P-256 with low-s normalisation**, with EdDSA-BabyJubJub as a documented
fallback if browser proving turns out too slow in Milestone 4.

Reasoning:
- Every component is **released and built into or maintained for Noir 1.0.0**. The
  EdDSA option rests on an unreleased branch, which is a reproducibility and
  supply-chain concern for a security project.
- It matches how a real issuer would sign: keys can live in an HSM or cloud KMS.
- Its costs are **measured and acceptable** natively (< 1 s to prove). The open risk
  is browser proving time, so Milestone 4 will measure that before committing the UI.

**Decision (2026-11-07): ECDSA P-256 approved.** Implemented in
[`packages/credentials`](../packages/credentials); format in
[`credential-format.md`](credential-format.md).
