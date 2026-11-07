/**
 * Verifier API with a REAL proof: generated in-test with noir_js + bb.js from a
 * credential issued by the real issuer code, then submitted over HTTP.
 */
import fs from 'node:fs';
import type { AddressInfo } from 'node:net';
import { Barretenberg, UltraHonkBackend } from '@aztec-foundation/bb.js';
import { Noir } from '@noir-lang/noir_js';
import { buildCircuitInputs, generateIssuerKeyPair, issueCredential, issuerPublicInfo } from '@zkpg/credentials';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createVerifierApp, type ProofRequestRecord } from '../src/app.ts';
import { ARTIFACT_PATH, createBbVerifier, type ProofVerifier } from '../src/proof-verifier.ts';

const artifact = JSON.parse(fs.readFileSync(ARTIFACT_PATH, 'utf8'));
const issuerKey = generateIssuerKeyPair().privateKey;
const ISSUER = issuerPublicInfo(issuerKey);
const NOW = BigInt(Math.floor(Date.now() / 1000));
const logs: string[] = [];

let base = '';
let server: ReturnType<ReturnType<typeof createVerifierApp>['listen']>;
let verifier: ProofVerifier;
let prover: { api: Barretenberg; backend: UltraHonkBackend };

async function prove(income: bigint, req: ProofRequestRecord, key = issuerKey) {
  const cred = issueCredential(key, { subjectId: 1001n, annualIncomeInr: income, validitySeconds: 30n * 86_400n, issuedAt: NOW - 86_400n });
  const inputs = buildCircuitInputs(cred, issuerPublicInfo(key), {
    minimumIncome: BigInt(req.minimumIncome), currentTime: BigInt(req.currentTime), challenge: BigInt(req.challenge),
  });
  const { witness } = await new Noir(artifact).execute(inputs as never);
  const p = await prover.backend.generateProof(witness);
  return { proof: Buffer.from(p.proof).toString('base64'), publicInputs: p.publicInputs.map((h) => '0x' + h.replace(/^0x/, '').padStart(64, '0')) };
}

const api = (path: string, body?: unknown) =>
  fetch(`${base}${path}`, body === undefined ? {} : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
const newRequest = async (minimumIncome = '800000') => (await (await api('/api/verifier/requests', { verifierName: 'Demo Lender', minimumIncome })).json()) as ProofRequestRecord;

beforeAll(async () => {
  verifier = await createBbVerifier(1);
  const bb = await Barretenberg.new({ threads: 1 });
  prover = { api: bb, backend: new UltraHonkBackend(artifact.bytecode, bb) };
  server = createVerifierApp({ proofVerifier: verifier, trustedIssuers: async () => [ISSUER], now: () => NOW, log: (m) => logs.push(m) }).listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(async () => { server.close(); await verifier.close(); await prover.api.destroy(); });

describe('verifier API', () => {
  it('creates a request with a fresh 32-byte challenge and its own time', async () => {
    const a = await newRequest();
    const b = await newRequest();
    expect(a).toMatchObject({ status: 'PENDING', minimumIncome: '800000', currentTime: NOW.toString() });
    expect(a.challenge).toMatch(/^0x[0-9a-f]{64}$/);
    expect(a.challenge).not.toBe(b.challenge);
  });

  it('returns ELIGIBLE for a valid proof, and accepts only one decision per request', async () => {
    const req = await newRequest();
    const submission = await prove(950_000n, req);
    const res = await api(`/api/verifier/requests/${req.id}/proof`, submission);
    expect(await res.json()).toMatchObject({ status: 'ELIGIBLE' });
    expect((await api(`/api/verifier/requests/${req.id}/proof`, submission)).status).toBe(409);
  });

  it('returns INVALID when a proof made for one request is submitted to another', async () => {
    const reqA = await newRequest();
    const reqB = await newRequest();
    const submission = await prove(950_000n, reqA);
    const res = await (await api(`/api/verifier/requests/${reqB.id}/proof`, submission)).json();
    expect(res).toMatchObject({ status: 'INVALID', reason: 'CHALLENGE_MISMATCH' });
  });

  it('returns INVALID for a self-signed forgery (untrusted issuer)', async () => {
    const req = await newRequest();
    const submission = await prove(5_000_000n, req, generateIssuerKeyPair().privateKey);
    expect(await (await api(`/api/verifier/requests/${req.id}/proof`, submission)).json()).toMatchObject({ status: 'INVALID', reason: 'UNTRUSTED_ISSUER' });
  });

  it('returns INVALID for a tampered proof', async () => {
    const req = await newRequest();
    const s = await prove(950_000n, req);
    const bytes = Buffer.from(s.proof, 'base64');
    bytes[bytes.length >> 1]! ^= 1;
    const res = await (await api(`/api/verifier/requests/${req.id}/proof`, { ...s, proof: bytes.toString('base64') })).json();
    expect(res).toMatchObject({ status: 'INVALID', reason: 'PROOF_VERIFICATION_FAILED' });
  });

  it('records NOT_ELIGIBLE when the holder declines', async () => {
    const req = await newRequest();
    expect(await (await api(`/api/verifier/requests/${req.id}/decline`, {})).json()).toMatchObject({ status: 'NOT_ELIGIBLE', reason: 'NO_PROOF_PROVIDED' });
  });

  it.each([
    ['an income field', (s: object) => ({ ...s, income: '950000' })],
    ['a credential field', (s: object) => ({ ...s, credential: {} })],
    ['a missing proof', (s: { publicInputs: string[] }) => ({ publicInputs: s.publicInputs })],
    ['too few public inputs', (s: { proof: string; publicInputs: string[] }) => ({ proof: s.proof, publicInputs: s.publicInputs.slice(1) })],
    ['non-hex public inputs', (s: { proof: string; publicInputs: string[] }) => ({ proof: s.proof, publicInputs: s.publicInputs.map(() => 'zz') })],
    ['a non-base64 proof', (s: { publicInputs: string[] }) => ({ proof: '!!!', publicInputs: s.publicInputs })],
  ])('rejects a submission with %s (400) and leaves the request pending', async (_label, mutate) => {
    const req = await newRequest();
    const fake = { proof: Buffer.alloc(16).toString('base64'), publicInputs: Array(67).fill('0x' + '0'.repeat(64)) };
    const res = await api(`/api/verifier/requests/${req.id}/proof`, mutate(fake as never));
    expect(res.status).toBe(400);
    expect((await (await api(`/api/verifier/requests/${req.id}`)).json()).status).toBe('PENDING');
  });

  it('validates request creation', async () => {
    expect((await api('/api/verifier/requests', { verifierName: '', minimumIncome: '1' })).status).toBe(400);
    expect((await api('/api/verifier/requests', { verifierName: 'x', minimumIncome: 800000 })).status).toBe(400);
    expect((await api('/api/verifier/requests/does-not-exist')).status).toBe(404);
  });

  it('never logs or stores the income, and stored records hold only public data', async () => {
    const list = await (await api('/api/verifier/requests')).text();
    for (const secret of ['950000', '5000000']) {
      expect(logs.join('\n')).not.toContain(secret);
      expect(list).not.toContain(secret);
    }
  });
});
