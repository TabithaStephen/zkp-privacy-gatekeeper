/**
 * Milestone 5 security suite: access control, replay (sequential, concurrent and
 * across restarts), request expiry, threshold-probing limits, payload hardening and
 * a byte-level scan of the database, audit log and logs for private data.
 * All proofs are REAL (noir_js + bb.js).
 */
import fs from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { ProofVerifier } from '../src/proof-verifier.ts';
import { Prover, sharedVerifier, type Submission, TestServer, tmpDb, TOKEN } from './harness.ts';

const INCOME = 950_000n; // the private value that must never be stored or logged
let verifier: ProofVerifier;
let prover: Prover;
let clock = 1_790_000_000n; // controllable unix time for expiry tests
let ms = 0; // controllable clock for rate limits
const servers: TestServer[] = [];
const dbPaths: string[] = [];

async function server(overrides = {}, dbPath = tmpDb()) {
  dbPaths.push(dbPath);
  const s = await new TestServer(dbPath, verifier, { now: () => clock, clockMs: () => ms, ...overrides }).start();
  servers.push(s);
  return s;
}

beforeAll(async () => {
  verifier = await sharedVerifier();
  prover = await Prover.create();
});
afterAll(async () => {
  for (const s of servers) await s.stop().catch(() => {});
  await verifier.close();
  await prover.close();
});

describe('access control (demo roles)', () => {
  let s: TestServer;
  beforeAll(async () => { s = await server(); });

  it.each([
    ['create without a token', () => fetch(`${s.base}/api/verifier/requests`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"verifierName":"x","minimumIncome":"10000"}' })],
    ['create with a wrong token', () => fetch(`${s.base}/api/verifier/requests`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${TOKEN}x` }, body: '{"verifierName":"x","minimumIncome":"10000"}' })],
    ['list without a token', () => fetch(`${s.base}/api/verifier/requests`)],
    ['audit log without a token', () => fetch(`${s.base}/api/verifier/audit`)],
  ])('rejects %s (401)', async (_l, call) => {
    expect((await call()).status).toBe(401);
  });

  it('records denials in the audit log', async () => {
    const audit = await (await s.call('/api/verifier/audit', undefined, true)).json();
    expect(audit.some((e: { event: string }) => e.event === 'AUTH_DENIED')).toBe(true);
  });

  it('lets a holder read a request by its unguessable id without a token', async () => {
    const req = await s.newRequest();
    expect((await s.call(`/api/verifier/requests/${req.id}`)).status).toBe(200);
  });

  it('sets security headers on API responses', async () => {
    const res = await s.call('/api/verifier/requests/unknown');
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    expect(res.headers.get('x-powered-by')).toBeNull();
  });
});

describe('replay protection', () => {
  let s: TestServer;
  beforeAll(async () => { s = await server(); });

  it('rejects the same valid proof submitted twice (409) and audits it', async () => {
    const req = await s.newRequest();
    const sub = await prover.prove(INCOME, req);
    expect((await s.submit(req.id, sub)).status).toBe(200);
    const again = await s.submit(req.id, sub);
    expect(again.status).toBe(409);
    expect(await again.json()).toMatchObject({ status: 'ELIGIBLE' });
    const audit = await (await s.call('/api/verifier/audit', undefined, true)).json();
    expect(audit.some((e: { event: string; requestId?: string }) => e.event === 'REPLAY_REJECTED' && e.requestId === req.id)).toBe(true);
  });

  it('accepts exactly one of two CONCURRENT valid submissions', async () => {
    const req = await s.newRequest();
    const sub = await prover.prove(INCOME, req);
    const codes = (await Promise.all([s.submit(req.id, sub), s.submit(req.id, sub), s.submit(req.id, sub)])).map((r) => r.status).sort();
    expect(codes).toEqual([200, 409, 409]);
  });

  it('accepts exactly one decision when a proof and a decline race', async () => {
    const req = await s.newRequest();
    const sub = await prover.prove(INCOME, req);
    const [a, b] = await Promise.all([s.submit(req.id, sub), s.call(`/api/verifier/requests/${req.id}/decline`, {})]);
    expect([a.status, b.status].sort()).toEqual([200, 409]);
  });

  it('rejects a proof after the holder declined', async () => {
    const req = await s.newRequest();
    await s.call(`/api/verifier/requests/${req.id}/decline`, {});
    expect((await s.submit(req.id, await prover.prove(INCOME, req))).status).toBe(409);
  });

  it('keeps decisions across a restart, so a replay after restart is still rejected', async () => {
    const dbPath = tmpDb();
    const first = await server({}, dbPath);
    const req = await first.newRequest();
    const sub = await prover.prove(INCOME, req);
    expect((await first.submit(req.id, sub)).status).toBe(200);
    await first.stop();

    const second = await server({}, dbPath);
    expect(await (await second.call(`/api/verifier/requests/${req.id}`)).json()).toMatchObject({ status: 'ELIGIBLE', challenge: req.challenge });
    expect((await second.submit(req.id, sub)).status).toBe(409);
  });
});

describe('request expiry', () => {
  let s: TestServer;
  beforeAll(async () => { s = await server({ requestTtlSeconds: 600n }); });

  it('accepts a proof submitted in the last second before expiry', async () => {
    const req = await s.newRequest();
    const sub = await prover.prove(INCOME, req);
    const saved = clock;
    clock = BigInt(req.expiresAt) - 1n;
    expect(await (await s.submit(req.id, sub)).json()).toMatchObject({ status: 'ELIGIBLE' });
    clock = saved;
  });

  it('rejects a VALID proof once the request has expired (410) and marks it EXPIRED', async () => {
    const req = await s.newRequest();
    const sub = await prover.prove(INCOME, req); // made while the request was live
    const saved = clock;
    clock = BigInt(req.expiresAt);
    const res = await s.submit(req.id, sub);
    expect(res.status).toBe(410);
    expect(await (await s.call(`/api/verifier/requests/${req.id}`)).json()).toMatchObject({ status: 'EXPIRED', reason: 'REQUEST_EXPIRED' });
    expect((await s.call(`/api/verifier/requests/${req.id}/decline`, {})).status).toBe(410);
    clock = saved;
  });

  it('expires stale pending requests when the verifier lists them', async () => {
    const req = await s.newRequest();
    const saved = clock;
    clock += 601n;
    const list = await (await s.call('/api/verifier/requests', undefined, true)).json();
    expect(list.find((r: { id: string }) => r.id === req.id)).toMatchObject({ status: 'EXPIRED' });
    clock = saved;
  });
});

describe('threshold-probing and abuse limits', () => {
  it('only allows thresholds that are multiples of the configured step', async () => {
    const s = await server({ thresholdStep: 10_000n });
    expect((await s.call('/api/verifier/requests', { verifierName: 'x', minimumIncome: '805000' }, true)).status).toBe(400);
    expect((await s.call('/api/verifier/requests', { verifierName: 'x', minimumIncome: '810000' }, true)).status).toBe(201);
  });

  it('rate-limits request creation and audits it', async () => {
    const s = await server({ createLimit: { windowMs: 60_000, max: 3 } });
    ms = 1_000_000;
    const codes = [];
    for (let i = 0; i < 4; i++) codes.push((await s.call('/api/verifier/requests', { verifierName: 'x', minimumIncome: '800000' }, true)).status);
    expect(codes).toEqual([201, 201, 201, 429]);
    const audit = await (await s.call('/api/verifier/audit', undefined, true)).json();
    expect(audit.some((e: { event: string }) => e.event === 'RATE_LIMITED')).toBe(true);
  });

  it('rate-limits holder submissions per client', async () => {
    const s = await server({ submitLimit: { windowMs: 60_000, max: 2 } });
    ms = 2_000_000;
    const req = await s.newRequest();
    const codes = [];
    for (let i = 0; i < 3; i++) codes.push((await s.submit(req.id, { bad: true })).status);
    expect(codes).toEqual([400, 400, 429]);
  });
});

describe('payload hardening', () => {
  let s: TestServer;
  let req: Awaited<ReturnType<TestServer['newRequest']>>;
  let valid: Submission;
  beforeAll(async () => {
    s = await server({ submitLimit: { windowMs: 60_000, max: 1000 } });
    req = await s.newRequest();
    valid = await prover.prove(INCOME, req);
  });

  it('refuses a submission that carries the income, and the request stays PENDING', async () => {
    const res = await s.submit(req.id, { ...valid, income: INCOME.toString() });
    expect(res.status).toBe(400);
    expect((await (await s.call(`/api/verifier/requests/${req.id}`)).json()).status).toBe('PENDING');
  });

  it('refuses an oversized body (413) without crashing', async () => {
    const res = await s.submit(req.id, { proof: 'A'.repeat(200_000), publicInputs: [] });
    expect(res.status).toBe(413);
  });

  it('refuses malformed JSON without echoing it', async () => {
    const res = await s.call(`/api/verifier/requests/${req.id}/proof`, `{"income":"${INCOME}",`);
    expect(res.status).toBe(400);
    expect(await res.text()).not.toContain(INCOME.toString());
  });

  it('marks out-of-range public inputs as INVALID (MALFORMED_PUBLIC_INPUTS)', async () => {
    const r2 = await s.newRequest();
    const bad = { ...valid, publicInputs: valid.publicInputs.map((p, i) => (i === 0 ? '0x' + '0'.repeat(61) + '100' : p)) };
    expect(await (await s.submit(r2.id, bad)).json()).toMatchObject({ status: 'INVALID', reason: 'MALFORMED_PUBLIC_INPUTS' });
  });

  it('still accepts the genuine proof afterwards', async () => {
    expect(await (await s.submit(req.id, valid)).json()).toMatchObject({ status: 'ELIGIBLE' });
  });
});

describe('privacy: nothing private is persisted or logged', () => {
  it('scans every database file, the audit log and the logs for the income and proofs', async () => {
    const s = servers[servers.length - 1]!;
    const audit = JSON.stringify(await (await s.call('/api/verifier/audit?limit=500', undefined, true)).json());
    const incomeDecimal = INCOME.toString();
    const incomeField = INCOME.toString(16).padStart(64, '0');
    const logs = servers.flatMap((x) => x.logs).join('\n');
    expect(logs.length).toBeGreaterThan(0);
    expect(logs).not.toContain(incomeDecimal);
    for (const s2 of servers) await s2.stop().catch(() => {});
    servers.length = 0;

    const files = dbPaths.flatMap((p) => [p, `${p}-wal`, `${p}-shm`]).filter((f) => fs.existsSync(f));
    expect(files.length).toBeGreaterThan(0);
    const blobs = files.map((f) => fs.readFileSync(f));
    for (const b of blobs) {
      expect(b.includes(Buffer.from(incomeDecimal))).toBe(false);
      expect(b.includes(Buffer.from(incomeField, 'hex'))).toBe(false);
    }
    expect(audit).not.toContain(incomeDecimal);
    expect(audit).not.toMatch(/publicInputs|proof"/);
  });
});
