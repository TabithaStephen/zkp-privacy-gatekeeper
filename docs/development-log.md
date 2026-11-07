# Development Log

An honest, chronological record of what was built, tested and decided.
Nothing is listed as done unless it was actually run.

---

## Milestone 0 — Environment and repository setup

**Date:** 2026-11-07

### Environment (recorded, not assumed)

Development for this milestone ran in a Claude Code cloud container.

| Tool | Version |
|---|---|
| OS / arch | Ubuntu 24.04.5 LTS, x86_64 |
| Node.js | v22.23.4 |
| npm | 10.9.9 |
| pnpm | 10.28.0 |
| Git | 2.43.0 |
| Rust / Cargo | 1.97.0 |
| Noir (`nargo`) | not installed yet (Milestone 1) |
| Barretenberg (`bb`) | not installed yet (Milestone 1) |

### Repository

- Remote: `https://github.com/TabithaStephen/zkp-privacy-gatekeeper`
- State at start: empty (no commits, no branches).
- Workflow: one feature branch per milestone → pull request → review → merge into `main`.
- Bootstrap: because the repository was empty, `main` was created with a single direct
  commit containing only `.gitignore` (approved), so later milestones have a PR base.
  This is the only direct push to `main`.

### Done

- Added `.gitignore` covering dependencies, build output, Noir/bb artifacts,
  private witness files (`Prover.toml`), keys, `.env` files, local databases and logs.
- Added initial `README.md` that states the project's goal and current status honestly.
- Added this development log.

### Decisions

| Decision | Choice | Why |
|---|---|---|
| Noir/bb install method | Official `noirup` / `bbup` installers | Matches official docs and what runs on a developer Mac |
| Branching | Feature branch + PR per milestone | Reviewable, professional history |
| Signature scheme | **Not decided** | Will be chosen in Milestone 2 only after testing real signing + in-circuit verification |

### Open issues

- ~~Push access~~: resolved by installing the Claude GitHub App on the repository.
- Noir and Barretenberg release downloads are blocked in the cloud environment (HTTP 403).
  Network access must be approved before Milestone 1.

### Tests

No code exists yet. Checks run: secret/sensitive-file scan of staged files (see milestone report).

---

## Milestone 1 — First real ZKP

**Date:** 2026-11-07 · **Branch:** `milestone-1/first-zkp`

### Toolchain and compatibility

| Tool | Version | How the version was chosen |
|---|---|---|
| Noir `nargo` | 1.0.0 (git `275d3ab`) | Latest stable release; installed with the official `noirup -v 1.0.0` |
| Barretenberg `bb` | 6.0.0 | Noir v1.0.0's own repository pins it (`scripts/install_bb.sh` → `bbup -v 6.0.0`; integration tests use `@aztec-foundation/bb.js@6.0.0`) |

`bbup`'s automatic Noir→bb lookup table (`bb-versions.json`) stops at `1.0.0-beta.22`,
so `bbup` alone could not pick a version for Noir 1.0.0. The pin above comes from Noir's
own source at the `v1.0.0` tag. For Milestone 4, the browser library must be
`@aztec-foundation/bb.js@6.0.0`; the package moved there from `@aztec/bb.js`.

### Environment issues and how they were resolved

1. **GitHub release downloads blocked (403).** Resolved by approving a dedicated cloud
   environment that allows `github.com` and GitHub's release-asset hosts.
2. **`bb` could not download the CRS.** UltraHonk needs a *structured reference string*:
   public elliptic-curve points from Aztec's Ignition trusted-setup ceremony. `bb`
   downloads it over plain **HTTP**, but the sandbox proxy only carries **HTTPS**.
   Resolved with `scripts/fetch-crs.sh`, which downloads the same official file from the
   same host (`crs.aztec-labs.com`) over HTTPS into `~/.bb-crs/`, where `bb` looks
   first. This is not needed on a normal laptop.

### Done

- Circuit `circuits/income-eligibility/src/main.nr`: `income` (private, `u64`) ≥ `minimum_income` (public).
- 6 Noir unit tests (`nargo test`).
- `scripts/e2e.sh`: real compile → witness → vk → prove → verify, plus attack checks.
- `Prover.example.toml` with fictional values; `Prover.toml` stays git-ignored.

### Decisions

| Decision | Choice | Why |
|---|---|---|
| Integer type | `u64` rupees (blueprint example used `u32`) | `u32` tops out at ≈ ₹429 crore; `u64` gives headroom (e.g. for paise later) at no extra cost |
| Below-threshold behaviour | `assert` fails, so no proof can be made | A below-threshold applicant cannot produce a proof at all. "NOT_ELIGIBLE" will therefore mean "no valid proof submitted", which reveals nothing extra |
| Proving system | UltraHonk (bb default) | Universal setup (Ignition CRS); no per-circuit trusted setup |

### Tests (actual results)

- `nargo test`: **6/6 passed**.
- `scripts/e2e.sh`: **7/7 checks passed**: valid proof (above and boundary); no witness
  below threshold; tampered proof rejected; altered public input rejected
  ("verification failed at reduction step"); `public_inputs` holds only the threshold;
  income not found as a field element in proof or public inputs.
- Measurements (single run): proof 14,656 B, public inputs 32 B, vk 3,680 B,
  prove ≈ 142 ms, verify ≈ 18 ms, 2,812 gates.

### Concepts

- **Witness:** every value that satisfies the circuit, private ones included. Computed by
  `nargo execute`, used only by the prover, never sent to the verifier.
- **Public inputs are bound into the proof.** Changing the threshold after proving
  invalidates the proof (test 5). This is the basis for challenge binding in Milestone 5.
- **Verification key:** derived from the circuit alone, with no private data. Anyone can
  regenerate it from the source and confirm it matches.

### Known limitations

- **No issuer binding.** The prover chooses `income` freely. Milestones 2–3 fix this.
- No challenge/nonce yet, so a proof can be replayed (Milestone 5).
- Timings are from a single run in a cloud container, not a benchmark.

---

## Milestone 2 — Issuer credential prototype

**Date:** 2026-11-07 · **Branch:** `milestone-2/issuer-credential`

### Part A: signature-scheme compatibility experiments (done)

As required, no scheme was chosen before testing real signing against in-circuit
verification. Full write-up: [`signature-scheme-evaluation.md`](signature-scheme-evaluation.md).

- Built two experiment circuits (`experiments/signature-schemes/`): **ECDSA P-256** and
  **EdDSA BabyJubJub-Poseidon**. Each verifies an issuer signature over a fictional
  credential and checks the threshold.
- A Node test runner (`run.mjs`) signs in JS with throwaway in-memory keys, writes the
  circuit inputs, runs `nargo execute`, and proves and verifies valid cases with `bb`.
- **Results:** 11/11 expected outcomes matched, in 3 independent runs with fresh keys.
  Measured cost: ECDSA 52,416 gates and ≈0.9 s to prove; EdDSA 9,420 gates and ≈0.27 s.

### Findings worth remembering

- Noir's ECDSA verifier accepts only **low-s** signatures, while Node's `crypto` returns
  either form. The first run's one failure came from exactly this, in a test
  signature that hadn't been normalised.
- The released `noir-lang/eddsa` (v0.1.3) **does not compile** on Noir 1.0.0. Only its
  unreleased `master` branch works.
- `@zk-kit/eddsa-poseidon` 1.1.0's ESM build is broken; its CommonJS build works.

### Decision

**ECDSA P-256 with low-s normalisation**, approved after the experiments.

### Part B: issuer credential implementation (done)

- **Format spec:** [`credential-format.md`](credential-format.md). The canonical message is
  48 bytes: a schema tag plus 5 u64 claims, big-endian. In JSON, numbers are decimal
  strings, because JS numbers lose precision above 2^53.
- **`packages/credentials`** (TypeScript, strict):
  - encoding with an independent Python test vector,
  - low-s ECDSA signing and verification,
  - key generation and storage (PEM, mode 0600, refuses to overwrite, git-ignored `keys/`),
  - the public key document, with `kid` = RFC 7638 JWK thumbprint,
  - `issueCredential()` / `verifyCredential()` with typed failure reasons.
- **CLIs:** `npm run keygen`, `npm run issue`. The terminal summary omits the income.

### Tests (actual results)

- **Vitest: 56/56 passed** (encoding 16, ECDSA 5, keys 6, credential 29). Covered:
  - valid issue → verify, including after a JSON round trip;
  - tampering with each of the 5 claims, or with the signature, is rejected;
  - the high-s twin is rejected even though plain ECDSA accepts it;
  - an untrusted issuer, and a forged credential claiming the trusted `kid`, are rejected;
  - expired credentials (at and after `expiresAt`) and not-yet-valid credentials are rejected;
  - 10 kinds of malformed input are rejected without throwing;
  - failure details never contain the income;
  - private key material never appears in any output;
  - key rotation and removal work.
- `tsc --noEmit` (strict): clean.
- Manual CLI check: key written with mode 0600; a second `keygen` refuses to overwrite;
  a credential issued from the CLI verifies against the published key; changing its
  income gives `INVALID_SIGNATURE`; Git ignores the key and the credential.
- Regression: Milestone 1 `nargo test` 6/6, `e2e.sh` all passed; signature experiments 11/11.

### Tooling note

npm 10.9.9 crashes ("reading 'edgesOut'") while resolving vitest 5.0.5's optional
peer dependencies; bisecting showed vitest alone triggers it. Fixed with a package-level
`.npmrc` (`legacy-peer-deps=true`) plus an explicitly pinned `vite`. This does not
weaken security: it only stops npm auto-installing peer packages.

### Known limitations

- **Not yet in-circuit.** The circuit still accepts any income; Milestone 3 connects
  the credential to the proof.
- No holder binding and no revocation yet (see `credential-format.md` §6).
- The demo issuer key is a local file. Production would use an HSM or KMS.
