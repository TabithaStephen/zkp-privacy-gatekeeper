# @zkpg/credentials

The `ZKPG_INCOME_V1` credential: canonical encoding, simulated issuer signing with
**ECDSA P-256 (low-s)**, issuer public-key publishing and credential verification.
Format spec: [`docs/credential-format.md`](../../docs/credential-format.md).

Shared by the issuer now, and by the holder and verifier in later milestones.
All data is fictional.

## Use

```bash
cd packages/credentials
npm install
npm test                 # 56 Vitest tests
npm run typecheck        # TypeScript strict mode

npm run keygen           # demo issuer key -> keys/issuer.pem (0600, git-ignored)
                         # and keys/issuer.public.json (the public key document)
npm run issue -- --subject 1001 --income 950000 --days 365 --out demo.credential.json
```

`keys/` and `*.credential.json` are git-ignored. The issue command's terminal summary
deliberately leaves out the income.

## Modules

| File | Responsibility |
|---|---|
| `src/encoding.ts` | Claim validation, 48-byte canonical message, JSON (decimal-string) parsing |
| `src/ecdsa.ts` | P-256 sign/verify with the low-s rule Noir's circuit verifier requires |
| `src/keys.ts` | Key generation, 0600 PEM storage (no overwrite), public key document, RFC 7638 `kid` |
| `src/credential.ts` | `issueCredential()`, `verifyCredential()` with typed failure reasons |

`verifyCredential()` returns one of: `valid`, `MALFORMED`, `UNSUPPORTED_TYPE`,
`UNKNOWN_ISSUER`, `NON_CANONICAL_SIGNATURE`, `INVALID_SIGNATURE`, `NOT_YET_VALID`,
`EXPIRED`. It never throws on bad input, and its failure details never include claim values.

## Note on `.npmrc`

npm 10.9.x crashes while auto-resolving vitest's optional peer dependencies.
`legacy-peer-deps=true` turns off automatic peer installation, and the one peer
vitest needs (`vite`) is pinned explicitly in `package.json`.
