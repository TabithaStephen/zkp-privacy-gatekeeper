# ZKP Privacy Gatekeeper

**Prove Your Eligibility. Protect Your Information.**

A portfolio prototype for **privacy-preserving financial eligibility checks** using
genuine Zero-Knowledge Proofs (ZKPs), written in [Noir](https://noir-lang.org) and
proven with [Barretenberg](https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg).

> **Status: Milestone 0 — repository setup.** No circuits, proofs or application code
> exist yet. This README describes the *goal*, not completed features. See
> [`docs/development-log.md`](docs/development-log.md) for what has actually been built and tested.

## The idea

A lender wants to know: *"Is this applicant's annual income at least ₹8,00,000?"*

Today, applicants typically hand over salary slips or bank statements — far more data
than that yes/no decision needs. In this project:

1. A (simulated) **issuer** — e.g. a bank — signs a credential containing the applicant's income.
2. The **holder** generates a ZK proof *on their own device* showing that the
   issuer-signed income meets the lender's threshold.
3. The **verifier** (lender) checks the proof and learns **only** the result —
   not the exact income, not the credential.

The proof, its public inputs and necessary metadata are still transmitted. The goal is
not "zero data shared" but **not exposing the underlying private financial value**.

## Planned architecture

```text
Issuer ──signed credential──▶ Holder ──proof + public inputs──▶ Verifier ──▶ ELIGIBLE / NOT_ELIGIBLE / INVALID
```

| Role | Holds | Sends |
|---|---|---|
| Issuer | Fictional income claim, signing key | Signed credential (to holder only) |
| Holder | Credential, private witness | Proof + public inputs |
| Verifier | Issuer public key, policy, challenge | Result |

## Roadmap

| # | Milestone | Status |
|---|---|---|
| 0 | Environment & repository setup | 🔄 In progress |
| 1 | First real ZKP (income ≥ threshold) | ⏳ Planned |
| 2 | Issuer credential prototype (signing) | ⏳ Planned |
| 3 | Credential-aware ZKP | ⏳ Planned |
| 4 | Holder / issuer / verifier UI | ⏳ Planned |
| 5 | Independent verification API (replay, expiry) | ⏳ Planned |
| 6 | Security & performance tests | ⏳ Planned |
| 7 | Portfolio release | ⏳ Planned |

## Planned stack

React + TypeScript + Vite · Tailwind CSS · Noir / Nargo · Barretenberg (UltraHonk) ·
bb.js · Node.js + Express · Vitest. Exact versions are pinned and recorded in the
development log once installed and verified.

## Scope and honesty

- **Fictional data only.** No real financial documents or personal data.
- Not connected to real banks; not a lending, KYC or compliance product.
- No claims of perfect privacy, absolute security or regulatory compliance.
  Known limitations will be documented as the project develops.

## Security

Issuer signing keys, `.env` files and private witness files (`Prover.toml`) are
excluded from version control by `.gitignore`.
