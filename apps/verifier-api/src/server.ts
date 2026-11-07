import path from 'node:path';
import type { IssuerPublicInfo } from '@zkpg/credentials';
import { assertStrongToken } from '@zkpg/server-security';
import { createVerifierApp } from './app.ts';
import { createBbVerifier } from './proof-verifier.ts';
import { VerifierStore } from './store.ts';

const PORT = Number(process.env.PORT ?? 4002);
const ISSUER_URL = process.env.ISSUER_URL ?? 'http://127.0.0.1:4001';
const DB_PATH = path.resolve(process.env.VERIFIER_DB_PATH ?? 'data/verifier.sqlite');
const verifierToken = assertStrongToken('VERIFIER_API_TOKEN', process.env.VERIFIER_API_TOKEN);

// Trust list for this demo: the key published by the demo issuer, fetched once and pinned.
let trusted: IssuerPublicInfo[] | null = null;
async function trustedIssuers(): Promise<IssuerPublicInfo[]> {
  if (!trusted) {
    const res = await fetch(`${ISSUER_URL}/api/issuer/public-key`);
    if (!res.ok) throw new Error(`could not fetch issuer key (${res.status})`);
    const info = (await res.json()) as IssuerPublicInfo;
    trusted = [{ kid: info.kid, alg: info.alg, jwk: info.jwk, circuit: info.circuit }];
    console.log(`[verifier] trusting issuer kid=${info.kid}`);
  }
  return trusted;
}

const store = new VerifierStore(DB_PATH);
const proofVerifier = await createBbVerifier(Number(process.env.BB_THREADS ?? 1));
const app = createVerifierApp({
  store,
  proofVerifier,
  trustedIssuers,
  verifierToken,
  requestTtlSeconds: BigInt(process.env.REQUEST_TTL_SECONDS ?? 600),
  thresholdStep: BigInt(process.env.THRESHOLD_STEP_INR ?? 10_000),
});
app.listen(PORT, '127.0.0.1', () => console.log(`[verifier] listening on http://127.0.0.1:${PORT} (db ${DB_PATH})`));
