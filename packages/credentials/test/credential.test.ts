import { describe, expect, it } from 'vitest';
import { type Credential, issueCredential, MAX_VALIDITY_SECONDS, verifyCredential } from '../src/credential.ts';
import { highSTwin } from '../src/ecdsa.ts';
import { CredentialFormatError } from '../src/encoding.ts';
import { generateIssuerKeyPair, issuerPublicInfo } from '../src/keys.ts';

const DAY = 86_400n;
const T0 = 1_767_225_600n; // 2026-01-01T00:00:00Z
const issuer = generateIssuerKeyPair().privateKey;
const attacker = generateIssuerKeyPair().privateKey;
const TRUSTED = [issuerPublicInfo(issuer)];

const issue = (income = 950_000n) =>
  issueCredential(issuer, { subjectId: 1001n, annualIncomeInr: income, validitySeconds: 365n * DAY, issuedAt: T0 });
const at = (seconds: bigint) => ({ now: seconds });
const clone = (c: Credential): Credential => JSON.parse(JSON.stringify(c));

describe('issueCredential', () => {
  it('issues a credential that verifies against the trusted issuer', () => {
    const result = verifyCredential(issue(), TRUSTED, at(T0 + DAY));
    expect(result.valid).toBe(true);
    if (result.valid) expect(result.claims.annualIncomeInr).toBe(950_000n);
  });

  it('survives a JSON round trip (what the holder actually stores)', () => {
    expect(verifyCredential(JSON.parse(JSON.stringify(issue())), TRUSTED, at(T0 + DAY)).valid).toBe(true);
  });

  it('gives each credential a fresh random credentialId', () => {
    const ids = new Set(Array.from({ length: 20 }, () => issue().claims.credentialId));
    expect(ids.size).toBe(20);
  });

  it('enforces the validity-period policy', () => {
    const req = { subjectId: 1n, annualIncomeInr: 1n, issuedAt: T0 };
    expect(() => issueCredential(issuer, { ...req, validitySeconds: 0n })).toThrow(CredentialFormatError);
    expect(() => issueCredential(issuer, { ...req, validitySeconds: MAX_VALIDITY_SECONDS + 1n })).toThrow(CredentialFormatError);
  });

  it('never includes private key material in the credential or the public key document', () => {
    const text = JSON.stringify(issue()) + JSON.stringify(TRUSTED);
    const d = issuer.export({ format: 'jwk' }).d!;
    expect(text).not.toContain(d);
    expect(text).not.toMatch(/"d"\s*:/);
    expect(text).not.toContain('PRIVATE KEY');
  });
});

describe('verifyCredential rejects', () => {
  it('a tampered income (signed 9.5L, claims 15L)', () => {
    const c = clone(issue());
    c.claims.annualIncomeInr = '1500000';
    expect(verifyCredential(c, TRUSTED, at(T0 + DAY))).toMatchObject({ valid: false, reason: 'INVALID_SIGNATURE' });
  });

  it.each(['subjectId', 'issuedAt', 'expiresAt', 'credentialId'] as const)('a tampered %s', (field) => {
    const c = clone(issue());
    c.claims[field] = (BigInt(c.claims[field]) + 1n).toString();
    expect(verifyCredential(c, TRUSTED, at(T0 + DAY))).toMatchObject({ valid: false, reason: 'INVALID_SIGNATURE' });
  });

  it('a tampered signature', () => {
    const c = clone(issue());
    const sig = Buffer.from(c.signature.value, 'hex');
    sig[5]! ^= 0x01;
    c.signature.value = sig.toString('hex');
    expect(verifyCredential(c, TRUSTED, at(T0 + DAY))).toMatchObject({ valid: false });
  });

  it('the high-s twin of a genuine signature', () => {
    const c = clone(issue());
    c.signature.value = highSTwin(Buffer.from(c.signature.value, 'hex')).toString('hex');
    expect(verifyCredential(c, TRUSTED, at(T0 + DAY))).toMatchObject({ valid: false, reason: 'NON_CANONICAL_SIGNATURE' });
  });

  it('a credential from an untrusted issuer', () => {
    const forged = issueCredential(attacker, { subjectId: 1001n, annualIncomeInr: 5_000_000n, validitySeconds: DAY, issuedAt: T0 });
    expect(verifyCredential(forged, TRUSTED, at(T0 + 1n))).toMatchObject({ valid: false, reason: 'UNKNOWN_ISSUER' });
  });

  it('a forgery that claims the trusted issuer kid but is signed by another key', () => {
    const forged = issueCredential(attacker, { subjectId: 1001n, annualIncomeInr: 5_000_000n, validitySeconds: DAY, issuedAt: T0 });
    forged.issuer.kid = TRUSTED[0]!.kid;
    expect(verifyCredential(forged, TRUSTED, at(T0 + 1n))).toMatchObject({ valid: false, reason: 'INVALID_SIGNATURE' });
  });

  it('an expired credential (at and after expiresAt)', () => {
    const c = issue();
    const exp = BigInt(c.claims.expiresAt);
    expect(verifyCredential(c, TRUSTED, at(exp - 1n)).valid).toBe(true);
    expect(verifyCredential(c, TRUSTED, at(exp))).toMatchObject({ valid: false, reason: 'EXPIRED' });
    expect(verifyCredential(c, TRUSTED, at(exp + 365n * DAY))).toMatchObject({ valid: false, reason: 'EXPIRED' });
  });

  it('a credential that is not yet valid', () => {
    expect(verifyCredential(issue(), TRUSTED, at(T0 - 1n))).toMatchObject({ valid: false, reason: 'NOT_YET_VALID' });
  });

  it('with no trusted issuers at all', () => {
    expect(verifyCredential(issue(), [], at(T0 + 1n))).toMatchObject({ valid: false, reason: 'UNKNOWN_ISSUER' });
  });

  it.each([
    ['null', null],
    ['a string', 'credential'],
    ['an empty object', {}],
    ['a wrong type', { ...issue(), type: 'OTHER_V1' }],
    ['a missing kid', { ...issue(), issuer: {} }],
    ['a wrong algorithm', { ...issue(), signature: { alg: 'RS256', value: issue().signature.value } }],
    ['a short signature', { ...issue(), signature: { alg: 'ES256', value: 'abcd' } }],
    ['uppercase signature hex', { ...issue(), signature: { alg: 'ES256', value: issue().signature.value.toUpperCase() } }],
    ['an extra claim', { ...issue(), claims: { ...issue().claims, verified: 'true' } }],
    ['a numeric claim', { ...issue(), claims: { ...issue().claims, annualIncomeInr: 950000 } }],
  ])('malformed input without throwing: %s', (_label, doc) => {
    const r = verifyCredential(doc, TRUSTED, at(T0 + 1n));
    expect(r.valid).toBe(false);
  });

  it('without leaking the income value in failure details', () => {
    const c = clone(issue(987_654n));
    c.claims.annualIncomeInr = '987654.0';
    const r = verifyCredential(c, TRUSTED, at(T0 + 1n));
    expect(JSON.stringify(r)).not.toContain('987654');
  });
});

describe('key rotation', () => {
  it('accepts credentials from any key on the trust list and rejects removed keys', () => {
    const newKey = generateIssuerKeyPair().privateKey;
    const oldCred = issue();
    const newCred = issueCredential(newKey, { subjectId: 7n, annualIncomeInr: 1n, validitySeconds: DAY, issuedAt: T0 });
    const both = [...TRUSTED, issuerPublicInfo(newKey)];
    expect(verifyCredential(oldCred, both, at(T0 + 1n)).valid).toBe(true);
    expect(verifyCredential(newCred, both, at(T0 + 1n)).valid).toBe(true);
    // "compromised" old key removed from the trust list
    expect(verifyCredential(oldCred, [issuerPublicInfo(newKey)], at(T0 + 1n))).toMatchObject({ valid: false, reason: 'UNKNOWN_ISSUER' });
  });
});
