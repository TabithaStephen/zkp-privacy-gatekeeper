# Test report

**Status:** Milestone 6 · **Date:** 2026-11-07 · All results below were produced by
actually running the suites on the development machine (Linux x86_64, 4 vCPU). Nothing
here is estimated.

## 1. Summary

| Suite | Command | Kind | Result |
|---|---|---|---|
| Credential circuit | `cd circuits/credential-eligibility && nargo test` | Noir unit (signatures from the real TS issuer) | **11/11** |
| Learning circuit (M1) | `cd circuits/income-eligibility && nargo test` · `./scripts/e2e.sh` | Noir unit · real CLI proofs | **6/6** · **7/7 checks** |
| Credentials package | `npm test -w @zkpg/credentials` | encoding, ECDSA low-s, keys, issue/verify, holder inputs, verifier policy | **70/70** |
| Real proofs via CLI | `npm run test:circuit -w @zkpg/credentials` | nargo + bb: prove, verify, attacks | **18/18** |
| Server security package | `npm test -w @zkpg/server-security` | role tokens, rate limits, headers | **10/10** |
| Issuer API | `npm test -w @zkpg/issuer-demo` | HTTP | **14/14** |
| Verifier API | `npm test -w @zkpg/verifier-api` | HTTP with real noir_js + bb.js proofs: API 7, security suite 24, robustness 8 | **39/39** |
| Web unit | `npm test -w @zkpg/web` | holder inputs and prechecks | **11/11** |
| **Browser end-to-end** | `npm run e2e` | Chromium, all three services, in-browser proving | **24/24 checks** |
| Signature experiments (M2) | `cd experiments/signature-schemes && npm test` | ECDSA vs EdDSA in-circuit | **11/11 cases** |

**179 automated tests** across the Vitest and nargo suites, plus 24 browser checks,
7 CLI e2e checks and 11 experiment cases. Performance: [benchmarks](benchmarks/README.md).

## 2. Blueprint testing table

Every row of the blueprint's minimum testing strategy, with the tests that cover it.

| Test case | Expected | Covered by | Result |
|---|---|---|---|
| Income meets threshold | Valid eligibility proof | `nargo`: `valid_credential_above_threshold`, `valid_at_exact_threshold_and_validity_boundaries`; `test:circuit`: "produces a proof that bb verifies"; verifier API: "returns ELIGIBLE"; E2E step 3 | ✅ |
| Income below threshold | Proof generation fails | `nargo`: `genuine_credential_below_threshold_is_rejected`; `test:circuit`: "a genuine credential below the threshold"; E2E step 5 (UI blocks proving, holder declines → `NOT_ELIGIBLE`) | ✅ |
| Modified proof | Verification fails | `test:circuit`: tampered and truncated proof; verifier API: `PROOF_VERIFICATION_FAILED`; robustness: 25 random proofs with **genuine** public inputs rejected by bb.js, 3 via HTTP | ✅ |
| Wrong issuer public key | Credential authentication fails | `nargo`: `wrong_issuer_key_is_rejected`; `test:circuit`: genuine signature with another key; self-signed forgery → `UNTRUSTED_ISSUER`; forgery relabelled with the trusted key → bb verify fails; credentials: forged `kid` | ✅ |
| Tampered credential | Rejected | `nargo`: tampered income, expiry, signature, signature from another credential; credentials: each of 5 claims and the signature; `test:circuit`: tampered income in the witness | ✅ |
| Expired credential | Rejected | `nargo`: `expired_credential_is_rejected`, `not_yet_valid_credential_is_rejected`; `test:circuit`: expired, early; credentials: at and after `expiresAt`; web: holder precheck | ✅ |
| Reused challenge | Rejected | `test:circuit`: altered challenge fails bb verify; verifier: cross-request `CHALLENGE_MISMATCH`; security suite: same proof twice → 409, **3 concurrent → exactly 1 accepted**, proof vs decline race, **replay after restart → 409** | ✅ |
| Wrong verifier context | Rejected | robustness: proof for lender A submitted to an independent lender B (same threshold) → `CHALLENGE_MISMATCH`; B does not know A's request ids (404) | ✅ |
| Missing or malformed public input | Rejected | verifier: 66 inputs, non-hex, missing proof, non-base64 (400); out-of-range key byte → `MALFORMED_PUBLIC_INPUTS`; credentials: decoder length and range checks; altered threshold/time/key fail bb verify | ✅ |
| Private witness in API request | Must not occur | verifier: payload must be exactly `{proof, publicInputs}` (an `income` field → 400, request stays pending); **E2E: every browser→verifier request inspected: no income, credential, claims or signature** | ✅ |

## 3. Leak checks ("sensitive values must not appear in logs, errors or records")

| Surface | Check | Result |
|---|---|---|
| Proof and public inputs | Income, credential ID, expiry and signature `r`/`s` absent (`test:circuit`); public inputs = key, threshold, time, challenge only | ✅ |
| Verifier database | Byte-level scan of `.sqlite`, `-wal` and `-shm` files for the income (decimal and field encoding) | ✅ none found |
| Audit log | No income; no proof or public-input blobs (fingerprint only) | ✅ |
| Server logs | Issuer and verifier logs scanned in unit, security and E2E tests | ✅ |
| Error messages | Every verifier endpoint probed with income-bearing bad requests; issuer malformed JSON | ✅ never echoed |
| Browser → verifier traffic | All POST bodies captured in E2E | ✅ |
| Role tokens | No `Authorization` header from the browser; built bundle contains no tokens or token names | ✅ |
| Issuer private key | Never in credentials, the public key document or API responses | ✅ |
| Git | `.gitignore` tests; secret-pattern scan before every commit | ✅ |

## 4. Security principles (blueprint §8) → evidence

| Principle | Evidence |
|---|---|
| Data minimisation | Verifier stores public data only; DB byte scan |
| Private witness protection | Strict payload schema; E2E traffic inspection |
| Issuer authenticity | In-circuit ECDSA; trusted-key policy; forgery tests |
| Independent verification | Server re-verifies with bb.js; never trusts a client label (tampered/random proofs) |
| Secret management | Keys and `.env` git-ignored, 0600; tokens only server-side (E2E) |
| Challenge binding | Altered-challenge and cross-verifier tests |
| Safe logging | Log scans in unit, security and E2E tests |
| Consent | E2E: proving disabled until the consent box is ticked; nothing sent before submit |
| Access control | 401 tests for every role route; wrong scheme and query-string tokens rejected |
| Honest claims | Residual risks in [security-model.md §4](security-model.md#4-residual-risks-and-limitations-honest-list) |

## 5. Findings during testing (and fixes)

| Milestone | Finding | Fix |
|---|---|---|
| M1 | A pipeline using `\| tail` hid failing exit codes | Scripts use `set -euo pipefail` |
| M2 | Noir's ECDSA verifier accepts only low-s; Node returns either form | Issuer normalises; verifier rejects high-s |
| M2 | Released `noir-lang/eddsa` does not compile on Noir 1.0.0 | Weighed in the scheme decision |
| M4 | E2E left orphaned servers → HTTP 502 in the next run | Process groups and a busy-port check |
| M6 | Robustness test never reached bb.js: random proofs were stopped earlier by the policy check | Rewritten to pair random proofs with genuine public inputs |
| M6 | Benchmark measured bb.js's Node **wrapper** `bb` (from `node_modules/.bin`) instead of the native binary (+~45 ms per call) | Benchmark resolves the native binary explicitly and records its path |

The `test:circuit` suite also runs under npm, so its `bb` calls go through the same
wrapper. That does not affect correctness (the wrapper runs the native binary), only its
logged timing; authoritative timings come from `npm run bench`.

## 6. Not covered (known gaps)

- No load or soak testing; rate limits are tested functionally, not under real concurrency at scale.
- No browser coverage beyond Chromium (Firefox and Safari WASM threading not tested).
- No formal verification of the circuit; correctness relies on tests plus Noir/bb's audited primitives.
- No test of key rotation in the running services (rotation is unit-tested in `packages/credentials`).
