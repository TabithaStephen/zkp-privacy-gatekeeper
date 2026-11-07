# Architecture

How the parts fit together as of **Milestone 3**. Later milestones add the UI (M4) and
the verification API (M5). This document is updated as they land.

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
| 3. Send request: threshold, current time, random challenge | Verifier | `ProofRequest` (API in M5) |
| 4. Check credential, build circuit inputs | Holder | `buildCircuitInputs()` |
| 5. Generate proof | Holder | `circuits/credential-eligibility` with nargo + bb (browser bb.js in M4) |
| 6. Cryptographic verification | Verifier | `bb verify` (bb.js in M5) |
| 7. Policy check of public inputs | Verifier | `checkPublicInputs()` |
| 8. Result: `ELIGIBLE` / `NOT_ELIGIBLE` / `INVALID` | Verifier | M5 |

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
