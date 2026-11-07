import { describe, expect, it } from 'vitest';
import { BN254_R, buildCircuitInputs, ProofRequestError, toProverToml } from '../src/circuit-inputs.ts';
import { issueCredential } from '../src/credential.ts';
import { generateIssuerKeyPair, issuerPublicInfo } from '../src/keys.ts';
import { checkPublicInputs, decodePublicInputs, PUBLIC_INPUT_COUNT, PublicInputError } from '../src/public-inputs.ts';

const T0 = 1_767_225_600n;
const key = generateIssuerKeyPair().privateKey;
const ISSUER = issuerPublicInfo(key);
const cred = issueCredential(key, { subjectId: 1001n, annualIncomeInr: 950_000n, validitySeconds: 365n * 86_400n, issuedAt: T0 });
const REQ = { minimumIncome: 800_000n, currentTime: T0 + 86_400n, challenge: 123_456_789n };

describe('buildCircuitInputs (holder side)', () => {
  it('maps a credential and request onto the circuit inputs', () => {
    const inputs = buildCircuitInputs(cred, ISSUER, REQ);
    expect(inputs.issuer_pub_key_x).toHaveLength(32);
    expect(inputs.signature).toHaveLength(64);
    expect(inputs.income).toBe('950000');
    expect(inputs.minimum_income).toBe('800000');
    expect(inputs.challenge).toBe('123456789');
    expect(toProverToml(inputs)).toContain('income = "950000"');
  });

  it.each([
    ['an expired credential', { ...REQ, currentTime: BigInt(cred.claims.expiresAt) }, /EXPIRED/],
    ['a not-yet-valid credential', { ...REQ, currentTime: T0 - 1n }, /NOT_YET_VALID/],
    ['a challenge outside the field', { ...REQ, challenge: BN254_R }, /field element/],
    ['a negative threshold', { ...REQ, minimumIncome: -1n }, /u64/],
  ])('refuses %s', (_label, req, msg) => {
    expect(() => buildCircuitInputs(cred, ISSUER, req)).toThrow(msg);
  });

  it('refuses a tampered credential before any proving is attempted', () => {
    const tampered = { ...cred, claims: { ...cred.claims, annualIncomeInr: '1500000' } };
    expect(() => buildCircuitInputs(tampered, ISSUER, REQ)).toThrow(ProofRequestError);
  });

  it('refuses a credential from a different issuer than the one supplied', () => {
    expect(() => buildCircuitInputs(cred, issuerPublicInfo(generateIssuerKeyPair().publicKey), REQ)).toThrow(/UNKNOWN_ISSUER/);
  });
});

/** Encodes values the way bb writes public_inputs: 32-byte big-endian fields. */
function encodeFields(values: bigint[]): Buffer {
  return Buffer.concat(values.map((v) => Buffer.from(v.toString(16).padStart(64, '0'), 'hex')));
}
const keyFields = (hex: string) => (hex.match(/../g) ?? []).map((b) => BigInt(parseInt(b, 16)));
const publicInputBuffer = (x = ISSUER.circuit.x, min = REQ.minimumIncome, time = REQ.currentTime, ch = REQ.challenge) =>
  encodeFields([...keyFields(x), ...keyFields(ISSUER.circuit.y), min, time, ch]);

describe('decodePublicInputs / checkPublicInputs (verifier side)', () => {
  const expected = { trustedIssuers: [ISSUER], minimumIncome: REQ.minimumIncome, challenge: REQ.challenge, now: REQ.currentTime, maxClockSkewSeconds: 300n };

  it('decodes 67 fields in circuit declaration order', () => {
    expect(PUBLIC_INPUT_COUNT).toBe(67);
    const pi = decodePublicInputs(publicInputBuffer());
    expect(pi).toEqual({ issuerX: ISSUER.circuit.x, issuerY: ISSUER.circuit.y, minimumIncome: 800_000n, currentTime: REQ.currentTime, challenge: REQ.challenge });
    expect(checkPublicInputs(pi, expected)).toEqual({ ok: true, issuerKid: ISSUER.kid });
  });

  it('rejects wrong length and out-of-range key bytes', () => {
    expect(() => decodePublicInputs(Buffer.alloc(66 * 32))).toThrow(PublicInputError);
    const bad = publicInputBuffer();
    bad[31] = 0x00; bad[30] = 0x01; // first key field = 256
    expect(() => decodePublicInputs(bad)).toThrow(/out of range/);
  });

  it.each([
    ['an untrusted issuer', publicInputBuffer(issuerPublicInfo(generateIssuerKeyPair().publicKey).circuit.x), 'UNTRUSTED_ISSUER'],
    ['a different threshold', publicInputBuffer(undefined, 100n), 'THRESHOLD_MISMATCH'],
    ['a different challenge', publicInputBuffer(undefined, undefined, undefined, 1n), 'CHALLENGE_MISMATCH'],
    ['a stale time', publicInputBuffer(undefined, undefined, REQ.currentTime - 301n), 'STALE_TIME'],
    ['a future time', publicInputBuffer(undefined, undefined, REQ.currentTime + 301n), 'STALE_TIME'],
  ])('flags %s', (_label, buf, reason) => {
    expect(checkPublicInputs(decodePublicInputs(buf), expected)).toEqual({ ok: false, reason });
  });
});
