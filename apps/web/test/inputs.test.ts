import { describe, expect, it } from 'vitest';
import { BN254_R, normalizePublicInputs, precheck, toBase64, toCircuitInputs } from '../src/zk/inputs.ts';
import type { Credential, IssuerInfo, ProofRequest } from '../src/zk/types.ts';

const issuer: IssuerInfo = {
  name: 'Test Issuer', kid: 'kid-1', alg: 'ES256',
  jwk: { kty: 'EC', crv: 'P-256', x: '', y: '' },
  circuit: { x: '0a'.repeat(32), y: 'ff'.repeat(32) },
};
const cred: Credential = {
  type: 'ZKPG_INCOME_V1',
  issuer: { kid: 'kid-1' },
  claims: { subjectId: '1001', annualIncomeInr: '950000', issuedAt: '1000', expiresAt: '2000', credentialId: '42' },
  signature: { alg: 'ES256', value: '01'.repeat(64) },
};
const req: ProofRequest = {
  id: 'r1', verifierName: 'Demo Lender', minimumIncome: '800000', currentTime: '1500',
  challenge: '0x' + 'ab'.repeat(31).padStart(64, '0'), createdAt: '', status: 'PENDING',
};

describe('holder precheck', () => {
  it('accepts a matching, valid, sufficient credential', () => {
    expect(precheck(cred, issuer, req)).toEqual({ ok: true });
  });
  it.each([
    ['wrong issuer', { ...cred, issuer: { kid: 'other' } }, req, 'WRONG_ISSUER'],
    ['not yet valid', cred, { ...req, currentTime: '999' }, 'NOT_YET_VALID'],
    ['expired (at expiresAt)', cred, { ...req, currentTime: '2000' }, 'EXPIRED'],
    ['below threshold', cred, { ...req, minimumIncome: '950001' }, 'BELOW_THRESHOLD'],
    ['malformed income', { ...cred, claims: { ...cred.claims, annualIncomeInr: '9.5e5' } }, req, 'MALFORMED'],
    ['malformed signature', { ...cred, signature: { alg: 'ES256' as const, value: 'zz' } }, req, 'MALFORMED'],
  ])('rejects %s', (_l, c, r, reason) => {
    expect(precheck(c as Credential, issuer, r)).toMatchObject({ ok: false, reason });
  });
});

describe('toCircuitInputs', () => {
  it('maps to the circuit ABI names with byte arrays for key and signature', () => {
    const i = toCircuitInputs(cred, issuer, req);
    expect(Object.keys(i).sort()).toEqual(['challenge', 'credential_id', 'current_time', 'expires_at', 'income', 'issued_at', 'issuer_pub_key_x', 'issuer_pub_key_y', 'minimum_income', 'signature', 'subject_id']);
    expect(i.issuer_pub_key_x).toEqual(Array(32).fill('10'));
    expect(i.issuer_pub_key_y).toEqual(Array(32).fill('255'));
    expect(i.signature).toHaveLength(64);
    expect(i.challenge).toBe(BigInt(req.challenge).toString());
  });
  it('refuses a challenge outside the field', () => {
    expect(() => toCircuitInputs(cred, issuer, { ...req, challenge: '0x' + BN254_R.toString(16) })).toThrow();
  });
});

describe('encoding helpers', () => {
  it('normalises public inputs to 0x + 64 lowercase hex', () => {
    expect(normalizePublicInputs(['0xABC', '5'])).toEqual(['0x' + '0'.repeat(61) + 'abc', '0x' + '0'.repeat(63) + '5']);
  });
  it('base64-encodes large byte arrays', () => {
    const bytes = new Uint8Array(70_000).map((_, i) => i % 256);
    expect(toBase64(bytes)).toBe(Buffer.from(bytes).toString('base64'));
  });
});
