/**
 * Verifier API happy paths and core rejections, with REAL proofs (noir_js + bb.js)
 * submitted over HTTP. Security-specific cases live in security.test.ts.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { generateIssuerKeyPair } from '@zkpg/credentials';
import type { ProofVerifier } from '../src/proof-verifier.ts';
import { Prover, sharedVerifier, TestServer, tmpDb } from './harness.ts';

let verifier: ProofVerifier;
let prover: Prover;
let s: TestServer;

beforeAll(async () => {
  verifier = await sharedVerifier();
  prover = await Prover.create();
  s = await new TestServer(tmpDb(), verifier).start();
});
afterAll(async () => { await s.stop(); await verifier.close(); await prover.close(); });

describe('verifier API', () => {
  it('creates a request with a fresh 32-byte challenge, its own time and an expiry', async () => {
    const a = await s.newRequest();
    const b = await s.newRequest();
    expect(a).toMatchObject({ status: 'PENDING', minimumIncome: '800000' });
    expect(BigInt(a.expiresAt) - BigInt(a.currentTime)).toBe(600n);
    expect(a.challenge).toMatch(/^0x[0-9a-f]{64}$/);
    expect(a.challenge).not.toBe(b.challenge);
  });

  it('returns ELIGIBLE for a valid proof', async () => {
    const req = await s.newRequest();
    expect(await (await s.submit(req.id, await prover.prove(950_000n, req))).json()).toMatchObject({ status: 'ELIGIBLE' });
  });

  it('returns INVALID when a proof made for one request is submitted to another', async () => {
    const [a, b] = [await s.newRequest(), await s.newRequest()];
    expect(await (await s.submit(b.id, await prover.prove(950_000n, a))).json()).toMatchObject({ status: 'INVALID', reason: 'CHALLENGE_MISMATCH' });
  });

  it('returns INVALID for a self-signed forgery (untrusted issuer)', async () => {
    const req = await s.newRequest();
    const sub = await prover.prove(5_000_000n, req, generateIssuerKeyPair().privateKey);
    expect(await (await s.submit(req.id, sub)).json()).toMatchObject({ status: 'INVALID', reason: 'UNTRUSTED_ISSUER' });
  });

  it('returns INVALID for a tampered proof', async () => {
    const req = await s.newRequest();
    const sub = await prover.prove(950_000n, req);
    const bytes = Buffer.from(sub.proof, 'base64');
    bytes[bytes.length >> 1]! ^= 1;
    expect(await (await s.submit(req.id, { ...sub, proof: bytes.toString('base64') })).json()).toMatchObject({ status: 'INVALID', reason: 'PROOF_VERIFICATION_FAILED' });
  });

  it('records NOT_ELIGIBLE when the holder declines', async () => {
    const req = await s.newRequest();
    expect(await (await s.call(`/api/verifier/requests/${req.id}/decline`, {})).json()).toMatchObject({ status: 'NOT_ELIGIBLE', reason: 'NO_PROOF_PROVIDED' });
  });

  it('validates request creation', async () => {
    expect((await s.call('/api/verifier/requests', { verifierName: '', minimumIncome: '10000' }, true)).status).toBe(400);
    expect((await s.call('/api/verifier/requests', { verifierName: 'x', minimumIncome: 800000 }, true)).status).toBe(400);
    expect((await s.call('/api/verifier/requests/does-not-exist')).status).toBe(404);
  });
});
