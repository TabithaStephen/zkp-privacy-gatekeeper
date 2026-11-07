import { describe, expect, it } from 'vitest';
import { type Claims, CredentialFormatError, encodeMessage, parseClaims, serializeClaims, U64_MAX } from '../src/encoding.ts';

const CLAIMS: Claims = {
  subjectId: 1001n,
  annualIncomeInr: 950_000n,
  issuedAt: 1_767_225_600n, // 2026-01-01T00:00:00Z
  expiresAt: 1_798_761_600n, // 2027-01-01T00:00:00Z
  credentialId: 42n,
};

describe('canonical encoding', () => {
  it('matches an independently computed test vector (Python struct.pack(">Q"))', () => {
    expect(encodeMessage(CLAIMS).toString('hex')).toBe(
      '5a4b50475f494e31' + // schema tag "ZKPG_IN1"
        '00000000000003e9' + // subjectId 1001
        '00000000000e7ef0' + // annualIncomeInr 950000
        '000000006955b900' + // issuedAt
        '000000006b36ec80' + // expiresAt
        '000000000000002a', // credentialId 42
    );
  });

  it('is exactly 48 bytes and deterministic', () => {
    const a = encodeMessage(CLAIMS);
    expect(a).toHaveLength(48);
    expect(encodeMessage({ ...CLAIMS })).toEqual(a);
  });

  it('changes when any single field changes', () => {
    const base = encodeMessage(CLAIMS).toString('hex');
    for (const field of Object.keys(CLAIMS) as (keyof Claims)[]) {
      const changed = { ...CLAIMS, [field]: CLAIMS[field] + 1n };
      if (field === 'issuedAt') changed.expiresAt += 1n; // keep expiresAt > issuedAt
      expect(encodeMessage(changed).toString('hex'), field).not.toBe(base);
    }
  });

  it('accepts the u64 boundaries', () => {
    expect(() => encodeMessage({ ...CLAIMS, annualIncomeInr: 0n })).not.toThrow();
    expect(() => encodeMessage({ ...CLAIMS, annualIncomeInr: U64_MAX })).not.toThrow();
  });

  it.each([
    ['negative income', { annualIncomeInr: -1n }],
    ['income above u64', { annualIncomeInr: U64_MAX + 1n }],
    ['expiry equal to issue time', { expiresAt: CLAIMS.issuedAt }],
    ['expiry before issue time', { expiresAt: CLAIMS.issuedAt - 1n }],
  ])('rejects %s', (_label, patch) => {
    expect(() => encodeMessage({ ...CLAIMS, ...patch })).toThrow(CredentialFormatError);
  });
});

describe('JSON claim serialisation', () => {
  it('round-trips through decimal strings without precision loss', () => {
    const big = { ...CLAIMS, credentialId: U64_MAX };
    expect(parseClaims(JSON.parse(JSON.stringify(serializeClaims(big))))).toEqual(big);
  });

  it.each([
    ['a JSON number', { annualIncomeInr: 950000 }],
    ['a leading zero', { annualIncomeInr: '0950000' }],
    ['a decimal point', { annualIncomeInr: '950000.5' }],
    ['a negative sign', { annualIncomeInr: '-1' }],
    ['scientific notation', { annualIncomeInr: '9.5e5' }],
    ['whitespace', { annualIncomeInr: ' 950000' }],
  ])('rejects %s', (_label, patch) => {
    expect(() => parseClaims({ ...serializeClaims(CLAIMS), ...patch })).toThrow(CredentialFormatError);
  });

  it('rejects missing and unexpected fields', () => {
    const { credentialId: _omit, ...missing } = serializeClaims(CLAIMS);
    expect(() => parseClaims(missing)).toThrow(/credentialId/);
    expect(() => parseClaims({ ...serializeClaims(CLAIMS), isAdmin: 'true' })).toThrow(/unexpected/);
  });
});
