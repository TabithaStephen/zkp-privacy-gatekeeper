# Credential format: `ZKPG_INCOME_V1`

**Status:** implemented in [`packages/credentials`](../packages/credentials) (Milestone 2).
Signature scheme chosen after testing: **ECDSA P-256 over SHA-256, low-s only**
(see [`signature-scheme-evaluation.md`](signature-scheme-evaluation.md)).

All data is fictional. This is a prototype format, not a legal or regulatory credential.

## 1. Claims

| Field | Type | Meaning | Private in the ZK proof? |
|---|---|---|---|
| `subjectId` | u64 | Pseudonymous holder identifier assigned by the issuer | yes |
| `annualIncomeInr` | u64 | Annual income in whole rupees | **yes, the value we protect** |
| `issuedAt` | u64 | Unix time (seconds, UTC) the credential becomes valid | yes |
| `expiresAt` | u64 | Unix time (seconds, UTC) after which it is invalid | yes (circuit checks it against a public date in M3) |
| `credentialId` | u64 | Random identifier, reserved for revocation (later milestone) | yes |

Rules enforced when issuing and when verifying:
- Every value is an integer in `0 … 2^64 − 1`, written as a **decimal string** in JSON
  (JavaScript numbers lose precision above 2^53).
- `expiresAt > issuedAt`.
- Issuer policy: validity period ≤ 366 days.

## 2. Canonical message (what is signed)

The signature covers a fixed-length **48-byte** message. Every field is an unsigned
64-bit **big-endian** integer, in this order:

```text
offset  0  schema_tag      0x5A4B50475F494E31   ("ZKPG_IN1" in ASCII)
offset  8  subjectId
offset 16  annualIncomeInr
offset 24  issuedAt
offset 32  expiresAt
offset 40  credentialId
```

`message_hash = SHA-256(message)` and the issuer signs `message_hash` with ECDSA P-256.

Why this design:
- **Fixed length, fixed order, fixed width.** There is exactly one byte encoding for a
  given set of claims, so the issuer, holder and circuit all hash identical bytes. JSON
  would be ambiguous (key order, whitespace, number formats).
- **Schema tag (domain separation).** A signature made for a different message type or a
  future version cannot be replayed as a `ZKPG_INCOME_V1` credential.
- **Integers only, rupees.** Circuits work on integers; no floating point.

## 3. Signature

- Algorithm: ECDSA, curve P-256 (secp256r1), hash SHA-256.
- Encoding: raw `r || s`, 64 bytes (IEEE P1363), hex in JSON.
- **Low-s required: `s ≤ n/2`.** For any valid `(r, s)`, `(r, n − s)` is also valid
  ECDSA. Noir's in-circuit verifier accepts only the low-s form, so the issuer always
  outputs it and the verifier rejects the high-s form. This also removes signature
  malleability.

## 4. Issuer public key

Published as JSON (see `issuerPublicInfo()`):

```json
{
  "kid": "<RFC 7638 JWK thumbprint, base64url>",
  "alg": "ES256",
  "jwk": { "kty": "EC", "crv": "P-256", "x": "<base64url>", "y": "<base64url>" },
  "circuit": { "x": "<32-byte hex>", "y": "<32-byte hex>" }
}
```

- `kid` (key ID) is the standard JWK thumbprint (RFC 7638): a hash of the public key.
  It changes whenever the key changes, so a holder or verifier can pin exactly which key
  they trust.
- `circuit.x/y` are the same coordinates as raw bytes, the form the Noir circuit takes.
- **Key rotation:** a new key gets a new `kid`. Verifiers keep a list of trusted keys, so
  old credentials remain checkable until they expire, and a compromised key is removed
  from the list (see [Limitations](#6-limitations)).

## 5. Credential document (what the holder stores)

```json
{
  "type": "ZKPG_INCOME_V1",
  "issuer": { "kid": "…" },
  "claims": {
    "subjectId": "1001",
    "annualIncomeInr": "950000",
    "issuedAt": "1767225600",
    "expiresAt": "1798761600",
    "credentialId": "12345678901234567890"
  },
  "signature": { "alg": "ES256", "value": "<128 hex chars: r || s>" }
}
```

The holder keeps this document. It is the input to proof generation (Milestone 3) and
is **never sent to the verifier**.

## 6. Limitations

- **No holder binding yet.** Anyone who obtains a copy of a credential can use it. A
  later design could bind credentials to a holder key.
- **No revocation yet.** `credentialId` is reserved for a status mechanism later.
- **Issuer key compromise.** An attacker with the private key can mint credentials for
  any income. Mitigations: keep the key outside the repo and browser, rotate keys, and
  have verifiers remove compromised `kid`s. A real deployment would use an HSM or KMS.
- **The prototype key is a local file** (git-ignored, permissions 0600). This is
  acceptable for a demo but not for production.
