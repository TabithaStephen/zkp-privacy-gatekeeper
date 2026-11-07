import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { generateIssuerKeyPair, verifyCredential } from '@zkpg/credentials';
import { createIssuerApp } from '../src/app.ts';

const key = generateIssuerKeyPair().privateKey;
const logs: string[] = [];
let base = '';
let server: ReturnType<ReturnType<typeof createIssuerApp>['listen']>;

beforeAll(async () => {
  server = createIssuerApp(key, (m) => logs.push(m)).listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => server.close());

const post = (body: unknown) =>
  fetch(`${base}/api/issuer/credentials`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

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
    const res = await fetch(`${base}/api/issuer/credentials`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"annualIncomeInr":"777777",' });
    expect(res.status).toBe(400);
    expect(await res.text()).not.toContain('777777');
  });

  it('never logs income values', async () => {
    await post({ subjectId: '1001', annualIncomeInr: '1234567', validityDays: 30 });
    expect(logs.join('\n')).not.toContain('1234567');
    expect(logs.join('\n')).not.toContain('777777');
  });
});
