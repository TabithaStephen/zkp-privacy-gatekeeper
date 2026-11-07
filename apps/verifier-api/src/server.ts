import type { IssuerPublicInfo } from '@zkpg/credentials';
import { createVerifierApp } from './app.ts';
import { createBbVerifier } from './proof-verifier.ts';

const PORT = Number(process.env.PORT ?? 4002);
const ISSUER_URL = process.env.ISSUER_URL ?? 'http://127.0.0.1:4001';

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

const proofVerifier = await createBbVerifier(Number(process.env.BB_THREADS ?? 1));
createVerifierApp({ proofVerifier, trustedIssuers }).listen(PORT, '127.0.0.1', () => {
  console.log(`[verifier] listening on http://127.0.0.1:${PORT}`);
});
