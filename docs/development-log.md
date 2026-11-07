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
