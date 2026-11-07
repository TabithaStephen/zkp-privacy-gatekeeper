import type { AddressInfo } from 'node:net';
import express from 'express';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { assertStrongToken, rateLimit, requireRoleToken, securityHeaders, tokensEqual } from '../src/index.ts';

const TOKEN = 'a'.repeat(40);
let clock = 0;
let base = '';
let server: ReturnType<ReturnType<typeof express>['listen']>;
const denied: string[] = [];

beforeAll(async () => {
  const app = express();
  app.use(securityHeaders);
  app.get('/secure', requireRoleToken('verifier', TOKEN, () => denied.push('x')), (_q, r) => { r.json({ ok: true }); });
  app.get('/limited', rateLimit({ windowMs: 1000, max: 3, now: () => clock }), (_q, r) => { r.json({ ok: true }); });
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => server.close());

describe('requireRoleToken', () => {
  it.each([
    ['no header', undefined, 401],
    ['wrong token', `Bearer ${'b'.repeat(40)}`, 401],
    ['token without Bearer', TOKEN, 401],
    ['a prefix of the token', `Bearer ${TOKEN.slice(0, 39)}`, 401],
    ['the correct token', `Bearer ${TOKEN}`, 200],
  ])('%s → %i', async (_l, auth, status) => {
    const res = await fetch(`${base}/secure`, auth ? { headers: { authorization: auth } } : {});
    expect(res.status).toBe(status);
  });
  it('reports denials (for the audit log)', () => expect(denied.length).toBeGreaterThan(0));
});

describe('rateLimit', () => {
  it('allows max requests per window, then 429 with Retry-After, then resets', async () => {
    clock = 10_000;
    const codes = [];
    for (let i = 0; i < 4; i++) codes.push((await fetch(`${base}/limited`)).status);
    expect(codes).toEqual([200, 200, 200, 429]);
    expect((await fetch(`${base}/limited`)).headers.get('retry-after')).toBe('1');
    clock = 11_000;
    expect((await fetch(`${base}/limited`)).status).toBe(200);
  });
});

describe('helpers', () => {
  it('sets security headers', async () => {
    const res = await fetch(`${base}/limited`);
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    expect(res.headers.get('x-frame-options')).toBe('DENY');
  });
  it('rejects weak or missing tokens at start-up', () => {
    expect(() => assertStrongToken('T', undefined)).toThrow(/at least 32/);
    expect(() => assertStrongToken('T', 'short')).toThrow();
    expect(assertStrongToken('T', TOKEN)).toBe(TOKEN);
  });
  it('compares tokens of different lengths safely', () => {
    expect(tokensEqual('abc', 'abcd')).toBe(false);
    expect(tokensEqual(TOKEN, TOKEN)).toBe(true);
  });
});
