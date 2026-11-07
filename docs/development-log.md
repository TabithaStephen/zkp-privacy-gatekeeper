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
