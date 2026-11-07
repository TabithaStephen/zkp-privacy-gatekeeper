import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { generateIssuerKeyPair, verifyCredential } from '@zkpg/credentials';
import { createIssuerApp } from '../src/app.ts';

const key = generateIssuerKeyPair().privateKey;
const TOKEN = 'test-issuer-token-0123456789abcdef0123456789ab';
const logs: string[] = [];
let base = '';
let server: ReturnType<ReturnType<typeof createIssuerApp>['listen']>;

beforeAll(async () => {
  server = createIssuerApp(key, { issuerToken: TOKEN, issueLimit: { windowMs: 60_000, max: 15 }, log: (m) => logs.push(m) }).listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => server.close());

const post = (body: unknown, token: string | null = TOKEN) =>
  fetch(`${base}/api/issuer/credentials`, { method: 'POST', headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify(body) });

describe('issuer API', () => {
  it('publishes the public key and no private material', async () => {
    const res = await fetch(`${base}/api/issuer/public-key`);
    const text = await res.text();
    expect(res.status).toBe(200);
    expect(JSON.parse(text)).toMatchObject({ alg: 'ES256', jwk: { kty: 'EC', crv: 'P-256' } });
    expect(text).not.toMatch(/"d"\s*:/);
    expect(text).not.toContain(key.export({ format: 'jwk' }).d!);
  });

  it('issues a credential that verifies against the published key', async () => {
    const res = await post({ subjectId: '1001', annualIncomeInr: '950000', validityDays: 365 });
    expect(res.status).toBe(201);
    const cred = await res.json();
    const info = await (await fetch(`${base}/api/issuer/public-key`)).json();
    expect(verifyCredential(cred, [info]).valid).toBe(true);
  });

  it.each([
    ['numeric income', { subjectId: '1', annualIncomeInr: 950000, validityDays: 30 }],
    ['negative income', { subjectId: '1', annualIncomeInr: '-5', validityDays: 30 }],
    ['fractional rupees', { subjectId: '1', annualIncomeInr: '100.50', validityDays: 30 }],
    ['zero validity', { subjectId: '1', annualIncomeInr: '1', validityDays: 0 }],
    ['validity over 366 days', { subjectId: '1', annualIncomeInr: '1', validityDays: 400 }],
    ['an unexpected field', { subjectId: '1', annualIncomeInr: '1', validityDays: 30, expiresAt: '9999999999' }],
    ['income above u64', { subjectId: '1', annualIncomeInr: '18446744073709551616', validityDays: 30 }],
  ])('rejects %s', async (_label, body) => {
    expect((await post(body)).status).toBe(400);
  });

  it('rejects malformed JSON without echoing the body', async () => {
    const res = await fetch(`${base}/api/issuer/credentials`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${TOKEN}` }, body: '{"annualIncomeInr":"777777",' });
    expect(res.status).toBe(400);
    expect(await res.text()).not.toContain('777777');
  });

  it('requires the issuer role token to issue (public key stays public)', async () => {
    const body = { subjectId: '1', annualIncomeInr: '1', validityDays: 1 };
    expect((await post(body, null)).status).toBe(401);
    expect((await post(body, TOKEN + 'x')).status).toBe(401);
    expect((await fetch(`${base}/api/issuer/public-key`)).status).toBe(200);
  });

  it('sets security headers', async () => {
    const res = await fetch(`${base}/api/issuer/public-key`);
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    expect(res.headers.get('x-powered-by')).toBeNull();
  });

  it('never logs income values', async () => {
    await post({ subjectId: '1001', annualIncomeInr: '1234567', validityDays: 30 });
    expect(logs.join('\n')).not.toContain('1234567');
    expect(logs.join('\n')).not.toContain('777777');
  });

  it('rate-limits issuance', async () => {
    const codes = [];
    for (let i = 0; i < 16; i++) codes.push((await post({ subjectId: '1', annualIncomeInr: '1', validityDays: 1 })).status);
    expect(codes).toContain(429);
  });
});
