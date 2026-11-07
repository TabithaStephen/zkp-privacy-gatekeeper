# ZKP Privacy Gatekeeper

**Prove your eligibility. Protect your information.**

A working prototype for **privacy-preserving financial eligibility checks**. An applicant
proves "my bank-attested annual income is at least ₹8,00,000" with a genuine
**zero-knowledge proof** generated **in their own browser**. The lender verifies it
independently and learns that the condition holds, **not the income**.

Built with [Noir](https://noir-lang.org) circuits and the
[Barretenberg](https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg)
UltraHonk proving system, with a React front end and Node.js services.

> Portfolio project. **All data is fictional.** Not a financial product; it does not
> make lending decisions or provide KYC or regulatory compliance.

| Holder reviews the request and consents | Verifier sees an independent result |
|---|---|
| ![Holder wallet: review and consent](docs/screenshots/3-holder-consent.png) | ![Verifier dashboard with audit log](docs/screenshots/6-verifier-results.png) |

---

## In two minutes

**Problem.** To check *"income ≥ ₹8,00,000?"*, lenders usually collect salary slips or
bank statements: far more data than a yes/no decision needs, and every copy is a breach
risk.

**Approach.**

1. A **bank (issuer)** signs a digital credential stating the applicant's income
   (ECDSA P-256).
2. A **lender (verifier)** sends a request: a threshold and a fresh random challenge.
3. The **applicant (holder)** reviews it, consents, and their browser generates a
   zero-knowledge proof that:
   - the credential carries a valid signature from a trusted bank,
   - it has not expired, and
   - its income is at least the threshold.
4. The browser sends **only the proof and its public inputs**. The lender's server
   verifies the proof cryptographically and checks that the public inputs match its own
   request and trusted issuer.

**Result.** The lender gets `ELIGIBLE`, `NOT_ELIGIBLE` or `INVALID`. It never receives
the income, the credential or the signature. This is enforced by the API and checked
by the tests.

## What exactly is proven

> "I hold a `ZKPG_INCOME_V1` credential, signed by the issuer whose public key is in
> the public inputs, that is valid at `current_time`, and whose income is at least
> `minimum_income`."

| Public (sent to the verifier, bound into the proof) | Private (never leaves the holder's device) |
|---|---|
| Issuer public key | Exact annual income |
| Threshold (`minimum_income`) | Credential claims: subject ID, issue/expiry dates, credential ID |
| Request time (`current_time`) | Issuer's signature |
| Verifier's random challenge | |

What the proof does **not** do on its own: decide whether that issuer is trustworthy.
The verifier must check the public key against its trust list. The tests demonstrate
that a self-signed forgery produces a mathematically valid proof that only this policy
check rejects. Details: [architecture](docs/architecture.md).

## Quickstart

Requires **Node.js ≥ 22.12**. Running the app needs **no** Noir toolchain: a compiled
circuit artifact is committed, and `node circuits/credential-eligibility/scripts/export-artifact.mjs --check`
(after `nargo compile`) confirms it matches the circuit source.

```bash
git clone https://github.com/TabithaStephen/zkp-privacy-gatekeeper.git
cd zkp-privacy-gatekeeper
npm install
npm run setup       # writes .env with random demo role tokens (git-ignored, 0600)
```

Then, in three terminals:

```bash
npm run issuer      # issuer API on :4001 (creates a demo signing key, git-ignored)
npm run verifier    # verifier API on :4002 (pins the issuer's published key)
npm run web         # web app on http://localhost:5173
```

### Demo walkthrough

1. **Issuer portal** (Bank): enter a fictional income (e.g. ₹9,50,000) → *Sign and
   issue* → *Deliver to holder wallet*.
2. **Verifier dashboard** (Lender): set a minimum income (e.g. ₹8,00,000) → *Create
   request* → *Open in holder wallet*.
3. **Holder wallet** (You): read what will be shared and what stays on the device →
   tick the consent box → *Generate proof on this device* (about 3–10 s) → *Submit*.
4. Back on the **verifier dashboard**: the request shows **Eligible**, and the audit
   log records the decision with a proof fingerprint, but no income.
5. Try it the other way: request ₹10,00,000. The wallet explains the condition is not
   met and offers *Decline*, which the verifier records as **Not eligible**.

All screenshots: [`docs/screenshots/`](docs/screenshots/).

## Evidence

```bash
npm test            # 144 unit/API tests across all workspaces (real proofs in the verifier tests)
npm run e2e         # Chromium end-to-end: full flow, in-browser proving, privacy checks (24 checks)
npm run bench       # sizes and prove/verify timings (native CLI, Node, Chromium)
```

With Noir `nargo` 1.0.0 and `bb` 6.0.0 installed
([instructions](circuits/income-eligibility/README.md#toolchain-pinned)):

```bash
(cd circuits/credential-eligibility && nargo test)        # 11 circuit tests
npm run test:circuit -w @zkpg/credentials                 # 18 tests with real CLI proofs
```

**179 automated tests** pass. Every case in the blueprint's testing table is mapped to
its tests in the **[test report](docs/test-report.md)**, including:

- tampered and expired credentials;
- wrong issuer keys;
- modified proofs and altered public inputs;
- replay (sequential, concurrent and after a restart);
- the wrong verifier;
- a byte-level scan of the verifier database and logs for leaked income.

**Performance** ([benchmarks](docs/benchmarks/README.md), 4-vCPU machine, indicative):

| | Value |
|---|---|
| Circuit | 52,416 gates (ECDSA P-256 + SHA-256 + range checks) |
| Proof / public inputs | 14,656 B / 2,144 B |
| Prove, Chromium, 4 threads | ≈ 2.8 s (≈ 9 s for the first proof: CRS download and WASM start-up) |
| Prove, native `bb` CLI | ≈ 0.8 s |
| Verify, native `bb` CLI / bb.js | ≈ 20 ms / ≈ 0.4–0.8 s |

## Security highlights

- **Issuer authenticity in-circuit:** ECDSA P-256 over a canonical 48-byte encoding with
  domain separation; low-s signatures only (no malleability).
- **Replay protection:**
  - a random challenge is bound into every proof;
  - each request accepts exactly one decision, using an atomic SQL update, persisted
    across restarts;
  - requests expire after 10 minutes.
- **Strict API:** submissions must be exactly `{proof, publicInputs}`, so an `income`
  field is rejected; body size limits; errors never echo request data.
- **Data minimisation:** the verifier stores only public data, and its audit log keeps a
  proof fingerprint, not the proof.
- **Secrets:**
  - the issuer key and role tokens stay server-side and are git-ignored;
  - role tokens are injected by the server-side proxy and never reach browser code;
  - the services refuse to start with weak tokens.
- **Probing mitigation:** coarse thresholds (₹10,000 steps), rate limits, and a wallet
  warning when a verifier keeps changing its threshold.

The full threat model, with test evidence for each attack, is in the
**[security model](docs/security-model.md)**.

## Repository map

```text
circuits/
  income-eligibility/        M1 learning circuit: income >= threshold (no issuer binding)
  credential-eligibility/    the real circuit: issuer signature + validity + threshold
    artifact/                committed compiled circuit used by the app and the verifier
packages/
  credentials/               credential format, ECDSA low-s signing, holder inputs, verifier policy
  server-security/           role tokens, rate limits, security headers
apps/
  issuer-demo/               Express: simulated bank, signs credentials
  verifier-api/              Express + bb.js + SQLite: requests, verification, audit log
  web/                       React + Vite + Tailwind: holder wallet, issuer portal, verifier dashboard
experiments/signature-schemes/  M2: ECDSA P-256 vs EdDSA BabyJubJub, measured in-circuit
bench/                       reproducible benchmark (npm run bench)
docs/                        design, security, test and benchmark documentation
```

## Documentation

| Document | What it covers |
|---|---|
| [Architecture](docs/architecture.md) | Roles, data flow, processes, access control, request lifecycle |
| [Security model](docs/security-model.md) | Assets, 12 attacks with controls and test evidence, residual risks |
| [Test report](docs/test-report.md) | Blueprint test table → tests → results; leak checks; findings |
| [Benchmarks](docs/benchmarks/README.md) | Sizes and timings, with the environment recorded |
| [Credential format](docs/credential-format.md) | Claims, canonical encoding, signature, public key document |
| [Signature scheme evaluation](docs/signature-scheme-evaluation.md) | Why ECDSA P-256: experiments and trade-offs |
| [Interview guide](docs/interview-guide.md) | The key questions about this project, answered with evidence |
| [Development log](docs/development-log.md) | Milestone-by-milestone record, including mistakes and fixes |

## Tech stack (pinned)

| Layer | Technology |
|---|---|
| Circuits | Noir 1.0.0 (`nargo`), `noir-lang/sha256` v0.3.0 |
| Proving system | Barretenberg UltraHonk: `bb` 6.0.0 CLI, `@aztec-foundation/bb.js` 6.0.0, `@noir-lang/noir_js` 1.0.0 |
| Front end | React 19, TypeScript, Vite 8, Tailwind CSS 4 |
| Services | Node.js 22, Express 5, SQLite (`node:sqlite`) |
| Tests | Vitest 5, Noir tests, Playwright (Chromium) |

## Limitations and future work

This is a prototype. Its known limits are stated plainly
(full list: [security model §4](docs/security-model.md#4-residual-risks-and-limitations-honest-list)):

| Limitation | Possible next step |
|---|---|
| No holder binding: a copied credential file can be used by someone else | Bind credentials to a holder key and prove knowledge of it in-circuit |
| No revocation before expiry | Status list or accumulator keyed by `credentialId`, with a privacy analysis |
| Demo role tokens instead of user login | OIDC or passkey login for issuer and verifier staff |
| Wallet uses plain `localStorage` | Encrypted storage unlocked with WebAuthn |
| Threshold probing is reduced, not eliminated | Holder-side query budgets; verifier accountability |
| Single issuer, single process, in-memory rate limits | Multi-issuer trust registry with key rotation; shared rate-limit store |
| First proof ≈ 9 s in the browser | Preload the CRS and WASM while the user reviews the request |
| Only Chromium tested; no TLS in local development | Cross-browser tests; HTTPS deployment |

## License

[MIT](LICENSE) © 2026 TabithaStephen.

## Acknowledgements

Noir and Barretenberg are developed by the Noir and Aztec teams. This project uses their
public tooling and the public Ignition CRS; it does not modify any cryptographic
primitives.
