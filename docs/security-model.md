# Security model

Threat model and controls for the prototype as of **Milestone 5**. This is a portfolio
prototype with fictional data, **not** a production system; limitations are listed
explicitly at the end.

## 1. Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Exact income and credential | Holder's browser only | The value the system exists to protect |
| Issuer signing key | Issuer server, `keys/issuer.pem` (0600, git-ignored) | Whoever holds it can mint credentials for any income |
| Role tokens (issuer, verifier) | `.env` (0600, git-ignored), read server-side only | Control who can issue credentials and create or see requests |
| Request decisions and challenges | Verifier SQLite DB | Integrity of eligibility results; replay protection |

## 2. Adversaries and what stops them

| # | Attack | Control | Evidence (test) |
|---|---|---|---|
| A1 | Holder claims an income they don't have | The circuit verifies the issuer's ECDSA signature over the exact claims | `nargo test`: tampered income/expiry/signature; `test:circuit`: tampered income |
| A2 | Holder creates their own "bank" key and self-signs | The verifier accepts only trusted issuer keys | `UNTRUSTED_ISSUER` (circuit + API tests) |
| A3 | Proof reused for another request or verifier (replay) | Challenge bound into the proof; one decision per request (atomic SQL update); decisions persist across restarts | `CHALLENGE_MISMATCH`; security suite: sequential, concurrent (3 at once → 1 accepted), after restart |
| A4 | Old proof presented later | Request expiry (default 10 min) checked before and after verification; `current_time` must equal the request's | Security suite: valid proof after expiry → 410 / `EXPIRED` |
| A5 | Public inputs edited after proving (threshold, time, key) | UltraHonk binds all public inputs; any change fails verification | `test:circuit`: altered challenge/threshold/time/key |
| A6 | Malformed or oversized payloads | Strict schema (exactly `{proof, publicInputs}`), 128 KB body limit, 64 KB proof limit, typed errors; a bad payload does not consume the request | Security suite: income field, 200 KB body → 413, malformed JSON, out-of-range inputs |
| A7 | Verifier narrows down income with many thresholds (binary search) | Thresholds must be multiples of ₹10,000; request-creation rate limit; wallet warns about repeated thresholds from the same verifier; the holder must consent to each request | Security suite: step and rate limits; E2E: probing warning |
| A8 | Unauthorised issuing or request creation | Bearer role tokens (constant-time compare, ≥ 32 chars, server refuses to start without them) | issuer + verifier auth tests (401) |
| A9 | Tokens leaked to the browser | Tokens are injected server-side by the web proxy, only on issuer/verifier routes; client-supplied `Authorization` headers are stripped | E2E: no Authorization header on any browser request; bundle contains no tokens |
| A10 | Private data leaking via storage or logs | Verifier stores only public data; the audit log stores a proof **fingerprint**, not the proof; logs never include incomes; errors never echo request bodies | Security suite: byte-level scan of DB, WAL and SHM files, audit log and logs; E2E: logs and all browser→verifier requests |
| A11 | Signature malleability (high-s twin) | Low-s enforced by the issuer, the JS verifier and the circuit | credentials + experiment tests |
| A12 | Brute force / flooding | Rate limits on issuance (30/min), request creation (30/10 min) and holder submissions (20/min per client) | rate-limit tests (429) |

## 3. What each party learns

| Party | Learns | Does not learn |
|---|---|---|
| Issuer | The income it attests to (it is the source) | Which verifiers the holder talks to |
| Verifier | Trusted issuer key used; income ≥ its threshold; its own challenge and time | Exact income, credential, signature, subject ID, dates |
| Network observer | That a proof was exchanged (use TLS in deployment) | Proof contents reveal nothing beyond the statement |

## 4. Residual risks and limitations (honest list)

- **Threshold probing is reduced, not eliminated.** A verifier with many accounts or
  many requests over time can still learn an income range. Coarse thresholds,
  rate limits and holder consent raise the cost; they do not make it impossible.
- **Rate limits are in-memory and per process.** They reset on restart and do not
  coordinate across instances. Behind the dev proxy all holders share one client IP.
- **Demo authentication.** Role tokens stand in for real user authentication (e.g.
  OIDC). Anyone who can reach the issuer or verifier portal through the proxy acts with
  that role.
- **Issuer key compromise** lets an attacker mint credentials. Mitigations: HSM/KMS,
  key rotation (supported via `kid` trust lists), removing compromised keys from
  verifiers. Credentials already issued under a removed key stop verifying.
- **No holder binding.** A stolen credential file can be used by someone else.
- **No revocation** before expiry (`credentialId` is reserved for a status mechanism).
- **Holder wallet** uses plain `localStorage`; a production wallet would encrypt
  credentials and protect them with device authentication.
- **Request IDs are capabilities**: anyone holding the link can view the request and
  decline it. Requests contain no private data.
- **The `current_time` the verifier chooses is trusted** for expiry; a malicious
  verifier could pick an old time, which only harms itself.
- **No TLS in local development.** A deployment must serve everything over HTTPS.

## 5. Operational rules

- Never commit `.env`, keys (`*.pem`, `keys/`), databases (`*.sqlite`, `data/`),
  credentials (`*.credential.json`) or prover inputs (`Prover.toml`). `.gitignore`
  enforces this; every commit is also scanned before pushing.
- Use fictional data only.
