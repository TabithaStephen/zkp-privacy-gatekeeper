# Architecture

How the parts fit together as of **Milestone 5**. Threats and controls are in
[security-model.md](security-model.md).

## Roles and data flow

```text
 ┌──────────────┐  signed credential   ┌──────────────┐  proof + public inputs  ┌──────────────┐
 │    Issuer    │ ───────────────────▶ │    Holder    │ ──────────────────────▶ │   Verifier   │
 │ (sim. bank)  │   (holder only)      │ (user device)│                         │   (lender)   │
 └──────────────┘                      └──────────────┘ ◀────────────────────── └──────────────┘
  private signing key                   credential + private witness   request:     trusted issuer keys,
  (keys/issuer.pem, 0600)               never leave this device        threshold,   policy, used challenges
                                                                       time, nonce
```

| Step | Who | Code |
|---|---|---|
| 1. Issue and sign credential | Issuer | `packages/credentials`: `issueCredential()` |
| 2. Publish public key (`kid`, JWK, circuit coords) | Issuer | `issuerPublicInfo()` |
| 3. Send request: threshold, current time, random challenge | Verifier | `apps/verifier-api` `POST /api/verifier/requests` |
| 4. Review request, consent, check credential, build inputs | Holder | `apps/web` holder wallet (`zk/inputs.ts`) |
| 5. Generate proof **in the browser** | Holder | `apps/web/src/zk/prover.ts` (noir_js + bb.js WebAssembly) |
| 6. Submit exactly `{proof, publicInputs}` | Holder → Verifier | `POST /api/verifier/requests/:id/proof` |
| 7. Policy check of public inputs | Verifier | `checkPublicInputs()` |
| 8. Cryptographic verification | Verifier | bb.js `UltraHonkBackend.verifyProof` |
| 9. Result: `ELIGIBLE` / `NOT_ELIGIBLE` (declined) / `INVALID` | Verifier | stored per request, shown on the dashboard |

## Processes

| Process | Port | Holds |
|---|---|---|
| `apps/issuer-demo` (Express) | 4001 | issuer **private key** (file, 0600, git-ignored); never sent to clients |
| `apps/verifier-api` (Express + bb.js + SQLite) | 4002 | requests, challenges, decisions and audit log in `data/verifier.sqlite` (public data only), the trusted issuer key |
| `apps/web` (React + Vite) | 5173 | UI. Holder credentials live in the browser's localStorage (demo) |

## Access control (demo)

| Route | Who | How |
|---|---|---|
| `POST /api/issuer/credentials` | issuer | bearer `ISSUER_API_TOKEN` |
| `GET /api/issuer/public-key` | anyone | public |
| `POST/GET /api/verifier/requests`, `GET /api/verifier/audit` | verifier | bearer `VERIFIER_API_TOKEN` |
| `GET /api/verifier/requests/:id`, `POST …/proof`, `POST …/decline` | holder | knowledge of the unguessable request id |

In the demo, the web server's proxy injects the issuer and verifier tokens server-side
for their portal routes (standing in for real login). Browser code never sees a token.

## Request lifecycle

`PENDING` → exactly one of `ELIGIBLE`, `INVALID`, `NOT_ELIGIBLE` (declined) or `EXPIRED`
(no answer within `REQUEST_TTL_SECONDS`, default 600). The transition is a single atomic
SQL update, so concurrent submissions cannot both succeed, and it survives restarts.

The web server sends COOP/COEP headers so the page is cross-origin isolated, which lets
bb.js use multiple threads (SharedArrayBuffer). The circuit artifact
(`circuits/credential-eligibility/artifact/`) is shared by the browser prover and the
verifier, and checked against the source with `export-artifact.mjs --check`.

## What the ZK proof establishes

1. The credential was signed by the issuer key given in the public inputs (ECDSA P-256 over SHA-256 of the canonical 48-byte encoding).
2. The credential is valid at the public `current_time`.
3. The private income is at least the public `minimum_income`.
4. The proof is bound to the public `challenge`.

## What the verifier must check itself

| Check | Why the proof alone is not enough |
|---|---|
| Issuer key is trusted | Anyone can make a key and prove a self-signed credential |
| Threshold equals the requested one | Otherwise a proof for a lower threshold could be reused |
| Challenge equals the one issued, and is unused | Prevents replay (used-challenge tracking: M5) |
| `current_time` is close to now | Otherwise an expired credential could be proven "as of" an old date |
| `bb` verification passes | Proves 1–4 above |

## What the verifier learns and does not learn

| Learns | Does not learn |
|---|---|
| Which trusted issuer signed (via the public key) | Exact income |
| That income ≥ threshold | Subject ID, credential ID, issue or expiry date |
| Request time and challenge (which it chose) | The signature or credential document |

`NOT_ELIGIBLE` cannot be proven: a holder below the threshold cannot produce a
witness at all. The verifier sees only the absence of a valid proof.

## Documents

- [Credential format](credential-format.md) · [Signature scheme evaluation](signature-scheme-evaluation.md) · [Development log](development-log.md)
