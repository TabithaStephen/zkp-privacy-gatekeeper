/**
 * Milestone 6 additions to the security suite:
 *  - wrong verifier context: two independent verifier instances (different lenders)
 *  - error-message leak sweep: no endpoint echoes an income from a bad request
 *  - robustness: random proofs of the right shape never verify and never crash the server
 * All proofs are REAL (noir_js + bb.js).
 */
import crypto from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { ProofVerifier } from '../src/proof-verifier.ts';
import { Prover, sharedVerifier, TestServer, tmpDb, TOKEN } from './harness.ts';

const INCOME = 987_654n; // distinctive value to search for
let verifier: ProofVerifier;
let prover: Prover;
let lenderA: TestServer;
let lenderB: TestServer;

beforeAll(async () => {
  verifier = await sharedVerifier();
  prover = await Prover.create();
  // These servers test other properties, so lift the rate limits (tested in security.test.ts).
  const limits = { submitLimit: { windowMs: 60_000, max: 10_000 }, createLimit: { windowMs: 60_000, max: 10_000 } };
  lenderA = await new TestServer(tmpDb(), verifier, limits).start();
  lenderB = await new TestServer(tmpDb(), verifier, limits).start();
});
afterAll(async () => {
  await lenderA.stop();
  await lenderB.stop();
  await verifier.close();
  await prover.close();
});

describe('wrong verifier context', () => {
  it("rejects a proof made for lender A when submitted to lender B's request (same threshold)", async () => {
    const reqA = await lenderA.newRequest('800000');
    const reqB = await lenderB.newRequest('800000');
    const proofForA = await prover.prove(INCOME, reqA);
    expect(await (await lenderB.submit(reqB.id, proofForA)).json()).toMatchObject({ status: 'INVALID', reason: 'CHALLENGE_MISMATCH' });
    // …and the same proof still works where it belongs.
    expect(await (await lenderA.submit(reqA.id, proofForA)).json()).toMatchObject({ status: 'ELIGIBLE' });
  });

  it("does not know another verifier's request ids", async () => {
    const reqA = await lenderA.newRequest('800000');
    expect((await lenderB.call(`/api/verifier/requests/${reqA.id}`)).status).toBe(404);
  });
});

describe('error messages never echo private values', () => {
  it('sweeps every endpoint with income-bearing bad requests', async () => {
    const req = await lenderA.newRequest('800000');
    const income = INCOME.toString();
    const attempts: [string, unknown, boolean][] = [
      [`/api/verifier/requests/${req.id}/proof`, { proof: 'AAAA', publicInputs: [], income }, false],
      [`/api/verifier/requests/${req.id}/proof`, `{"income":"${income}"`, false],
      [`/api/verifier/requests/${req.id}/proof`, { proof: income, publicInputs: Array(67).fill(income) }, false],
      [`/api/verifier/requests/${req.id}/decline`, `{"income":"${income}"`, false],
      ['/api/verifier/requests', { verifierName: income, minimumIncome: `${income}x` }, true],
      ['/api/verifier/requests', `{"minimumIncome":"${income}"`, true],
      [`/api/verifier/requests/${income}`, undefined, false],
    ];
    for (const [path, body, auth] of attempts) {
      const res = await lenderA.call(path, body, auth);
      expect(res.status, path).toBeGreaterThanOrEqual(400);
      expect(await res.text(), path).not.toContain(income);
    }
    expect(lenderA.logs.join('\n')).not.toContain(income);
  });
});

describe('robustness', () => {
  it('bb.js rejects 25 random proofs presented with GENUINE public inputs, without throwing', async () => {
    const valid = await prover.prove(INCOME, await lenderA.newRequest('800000'));
    const len = Buffer.from(valid.proof, 'base64').length;
    expect(await verifier.verify(Buffer.from(valid.proof, 'base64'), valid.publicInputs)).toBe(true); // control
    for (let i = 0; i < 25; i++) {
      const lengths = [len, len, 1, len - 32, len * 2]; // right length mostly, plus truncated/oversized
      expect(await verifier.verify(crypto.randomBytes(lengths[i % lengths.length]!), valid.publicInputs)).toBe(false);
    }
  });

  it('over HTTP, random proofs that pass the policy check fail cryptographic verification (never 500)', async () => {
    for (let i = 0; i < 3; i++) {
      const req = await lenderA.newRequest('800000');
      const genuine = await prover.prove(INCOME, req); // genuine public inputs for THIS request
      const forged = { proof: crypto.randomBytes(Buffer.from(genuine.proof, 'base64').length).toString('base64'), publicInputs: genuine.publicInputs };
      const res = await lenderA.submit(req.id, forged);
      expect(res.status).toBe(200);
      expect(await res.json()).toMatchObject({ status: 'INVALID', reason: 'PROOF_VERIFICATION_FAILED' });
    }
  });

  it('never accepts and never crashes on 25 random proofs with random or foreign public inputs', async () => {
    const foreign = await prover.prove(INCOME, await lenderA.newRequest('800000'));
    const len = Buffer.from(foreign.proof, 'base64').length;
    for (let i = 0; i < 25; i++) {
      const req = await lenderA.newRequest('800000');
      const publicInputs = i % 2 === 0 ? foreign.publicInputs : Array.from({ length: 67 }, () => '0x' + crypto.randomBytes(32).toString('hex'));
      const res = await lenderA.submit(req.id, { proof: crypto.randomBytes(len).toString('base64'), publicInputs });
      expect(res.status).toBeLessThan(500);
      expect((await res.json()).status).toBe('INVALID');
    }
  });

  it('keeps serving valid proofs afterwards', async () => {
    const req = await lenderA.newRequest('800000');
    expect(await (await lenderA.submit(req.id, await prover.prove(INCOME, req))).json()).toMatchObject({ status: 'ELIGIBLE' });
  });

  it('rejects a token sent in the wrong scheme or a query string', async () => {
    const res1 = await fetch(`${lenderA.base}/api/verifier/requests`, { headers: { authorization: `Basic ${TOKEN}` } });
    const res2 = await fetch(`${lenderA.base}/api/verifier/requests?token=${TOKEN}`);
    expect([res1.status, res2.status]).toEqual([401, 401]);
  });
});
