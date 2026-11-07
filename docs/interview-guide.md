# Interview guide

The questions from the project blueprint, answered for this implementation. Each has a
**short answer** (about 30 seconds, to say out loud), the **detail** behind it, and
**evidence** you can open in the repo. Numbers come from the
[benchmarks](benchmarks/README.md) and [test report](test-report.md).

---

## 1. What problem does the project solve?

**Short answer.** Eligibility checks over-collect data. To decide "income ≥ ₹8 lakh?",
lenders take salary slips and bank statements. This prototype lets an applicant prove
that one fact, backed by a bank's signature, without handing over the income or any
document.

**Detail.** Every stored document is breach and misuse risk for both sides. The goal is
**data minimisation**: the verifier receives a ~14.7 KB proof plus public parameters it
chose itself (threshold, time, challenge) and the issuer's public key. Something is still
transmitted, so this is not "zero data", but the private value is not.

**Evidence:** [README](../README.md#in-two-minutes) · E2E check "income never appears in
any request to the verifier" ([test report §3](test-report.md#3-leak-checks-sensitive-values-must-not-appear-in-logs-errors-or-records)).

## 2. What exactly does the ZKP prove?

**Short answer.** "I hold a credential, signed by the issuer whose public key is in the
public inputs, that is valid at the given time, and whose income is at least the
threshold." It is also bound to the verifier's random challenge.

**Detail.** The Noir circuit (`circuits/credential-eligibility/src/main.nr`):

1. re-encodes the private claims into the canonical 48-byte message and hashes it
   with SHA-256;
2. verifies the issuer's ECDSA P-256 signature over that hash;
3. checks `issued_at ≤ current_time < expires_at`;
4. checks `income ≥ minimum_income`.

It is 52,416 gates and is proven with UltraHonk (Barretenberg).

It does **not** prove that the issuer is trustworthy, that the holder is the credential's
rightful owner, or that the credential hasn't been revoked. Those are the verifier's
policy check, and two documented limitations.

**Evidence:** [circuit README](../circuits/credential-eligibility/README.md) · 11 `nargo`
tests · [architecture](architecture.md#what-the-zk-proof-establishes).

## 3. Why is a trusted issuer necessary?

**Short answer.** Without one, the applicant can simply type a bigger number. A ZK proof
shows a statement about *some* private input is true. It cannot make that input true.

**Detail.** Milestone 1's circuit (`income >= threshold` with a private `income`) was a
genuine ZKP but proved nothing about reality: any prover could choose the input. Binding
the income to a bank's signature, checked *inside* the circuit, moves the trust to a
party that actually knows the income. The verifier then trusts specific issuer keys
(pinned by `kid`), not the applicant.

**Evidence:** [M1 circuit "Limitation"](../circuits/income-eligibility/README.md#limitation) ·
`nargo` test `tampered_income_is_rejected` · the self-signed forgery test (question 5).

## 4. What is private and what is public?

**Short answer.** Public: the issuer's public key, the threshold, the request time and the
challenge. Private: the income, all other credential fields, and the signature.

| Public input | Why it must be public |
|---|---|
| Issuer public key | So the verifier can check it is on its trusted list |
| `minimum_income` | So the verifier knows which threshold was proven |
| `current_time` | So the expiry check uses the verifier's time, not one the holder picked |
| `challenge` | So the proof is tied to this one request (replay protection) |

**Detail.** Public inputs are *bound* into the proof. Changing any of them after proving
makes verification fail (tested for the challenge, the threshold in both directions, the
time, and the issuer key). Leak checks searched the proof bytes for the income, credential
ID, expiry and the signature's `r`/`s` and found none. That is a sanity check; the
zero-knowledge property itself comes from the proving system.

**Evidence:** `test:circuit` "reveals only the expected public inputs" ·
[architecture: what the verifier learns](architecture.md#what-the-verifier-learns-and-does-not-learn).

## 5. How does independent verification work?

**Short answer.** The verifier's server re-checks everything itself. First, a policy check
that the public inputs are *its* threshold, *its* challenge, *its* time and a *trusted*
issuer key. Then cryptographic verification of the proof with bb.js. It never trusts a
label from the browser.

**Detail.** The order in `apps/verifier-api/src/app.ts` is:

1. expiry;
2. already decided?
3. strict payload shape;
4. public-input policy;
5. UltraHonk verification;
6. atomic decision.

The key lesson: **a passing `bb verify` is not enough.** An attacker who creates their own
key, signs "income ₹50 lakh" and proves it gets a proof that verifies, because it really
was signed by the key in its public inputs. Only the trusted-key check rejects it
(`UNTRUSTED_ISSUER`).

**Evidence:** test "a self-signed forgery: valid proof, but the issuer key is not trusted"
(`packages/credentials/test-circuit/proof.test.ts`) · robustness tests: random proofs with
*genuine* public inputs fail at the cryptographic step.

## 6. How are replay attacks prevented?

**Short answer.** In three layers:
- every request carries a fresh 248-bit random challenge that is bound into the proof;
- each request accepts exactly one decision, enforced by an atomic database update that
  survives restarts;
- requests expire after 10 minutes.

**Detail.**

- **Across requests or verifiers:** a proof for request A has A's challenge in its public
  inputs. Submitting it to B fails the policy check (`CHALLENGE_MISMATCH`). Editing the
  challenge breaks the proof.
- **Same request twice:** `UPDATE requests SET status=? WHERE id=? AND status='PENDING'`.
  Only one caller can change a row. Three concurrent identical submissions give exactly
  one `200` and two `409`s.
- **Old proofs:** after `expiresAt`, even a valid proof gets `410 EXPIRED`. Expiry is
  re-checked after verification, because verification takes time.
- **Design choice:** a *malformed* submission (400) does not consume the request, so
  someone with the link can't burn it with junk.

**Evidence:** [security suite](../apps/verifier-api/test/security.test.ts):
replay, concurrency, restart and expiry tests.

## 7. What happens if an issuer key is compromised?

**Short answer.** The attacker can mint credentials for any income, and the proofs would
verify. That is the system's root of trust. Mitigation is about limiting and recovering:
protect the key, rotate it, and remove a compromised key from verifiers' trust lists,
which immediately invalidates everything signed with it.

**Detail.**

- **Prototype:** the key lives only on the issuer server (file mode 0600, git-ignored,
  never sent to clients). In production it belongs in an HSM or cloud KMS. P-256 was
  chosen partly because those support it, unlike BabyJubJub EdDSA.
- **Rotation:** keys are identified by an RFC 7638 `kid`. Verifiers hold a list, so old
  and new keys can overlap. Removing a key makes its credentials fail (unit-tested).
- **Damage limits:** credentials expire within 366 days, and requests within 10 minutes.
- **Not built:** per-credential revocation (`credentialId` is reserved for it), and
  transparency or monitoring of issuance.

**Evidence:** [credential format §4 and §6](credential-format.md) · key rotation test in
`packages/credentials/test/credential.test.ts` ·
[signature scheme evaluation](signature-scheme-evaluation.md).

## 8. What are the limitations of the current prototype?

**Short answer.** No holder binding, no revocation, demo authentication instead of real
login, a plain-localStorage wallet, and threshold probing that is reduced but not
eliminated. It is single-issuer, single-process, Chromium-tested and runs without TLS
locally.

**Detail.**

- **Threshold probing:** a verifier asking ₹8L, then ₹9L, then ₹8.5L can binary-search an
  income. Coarse ₹10,000 steps, rate limits, explicit consent and a wallet warning raise
  the cost; multiple verifier accounts could still get around them.
- **Holder binding:** a stolen credential file works for the thief. The fix is to bind
  credentials to a holder key and prove knowledge of that key in-circuit.
- **Revocation:** adds privacy trade-offs. A status check can reveal which credential is
  being used unless it is designed carefully.

**Evidence:** [security model §4](security-model.md#4-residual-risks-and-limitations-honest-list) ·
[README: limitations and future work](../README.md#limitations-and-future-work) ·
[test report §6](test-report.md#6-not-covered-known-gaps).

---

## Likely follow-up questions

**Why not just a signed JWT saying "eligible"?** Someone has to compute "eligible". If the
bank signs "eligible for lender X at ₹8L", the bank learns every lender and threshold the
applicant uses, and a new credential is needed per request. With a ZKP, one income
credential serves any threshold, the bank isn't involved in each check, and the verifier
checks the math itself.

**What is a witness?** Every value that satisfies the circuit, private ones included.
`noir_js` (or `nargo execute`) computes it on the holder's device; only the prover uses it.
The verifier gets the proof, the public inputs and the verification key.

**Why ECDSA P-256 rather than a "ZK-friendly" signature?** It was measured. EdDSA
BabyJubJub was 5.6× fewer gates (9,420 vs 52,416), but its released Noir library didn't
compile on Noir 1.0.0. P-256 is built into Noir and standard in banking HSMs and
WebCrypto, and ~2.8 s browser proving was acceptable.
([evaluation](signature-scheme-evaluation.md))

**What is "low-s" and why did it matter?** Every ECDSA signature `(r, s)` has a twin
`(r, n−s)` that is also valid. Noir's verifier accepts only the low form, and Node signs
either form at random, so about half of real signatures would have failed. The issuer
normalises to low-s, and the verifier rejects high-s, which also removes malleability.

**Is there a trusted setup?** UltraHonk uses a *universal* structured reference string
from Aztec's Ignition ceremony, not a per-circuit setup. It is public data; the security
assumption is that at least one ceremony participant discarded their secret.

**Can the browser cheat by skipping a check?** The browser can run any code it likes, but
it cannot produce a valid proof for a false statement. The circuit's constraints are in
the verification key the *server* uses. The tests show that bypassing the JS pre-checks
does not help: a tampered witness produces no proof. This is evidence for specific
attacks, not a formal proof of soundness, which rests on UltraHonk and the circuit's constraints.

**What was the hardest bug?** Two good examples, both written up honestly:
- the low-s discovery;
- a benchmark showing native verify at 59 ms instead of 15 ms. The first hypothesis
  (CPU contention) was tested and wrong. The real cause was bb.js's Node wrapper `bb`
  shadowing the native binary on npm's `PATH`.

See the [development log](development-log.md).
