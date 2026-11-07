/**
 * ZKPG_INCOME_V1 claims and their canonical 48-byte encoding.
 * Spec: docs/credential-format.md. The Noir circuit (Milestone 3) must hash
 * exactly these bytes, so any change here is a breaking format change.
 */

export const CREDENTIAL_TYPE = 'ZKPG_INCOME_V1' as const;
/** "ZKPG_IN1" in ASCII; domain-separates this message type from any other. */
export const SCHEMA_TAG = 0x5a4b50475f494e31n;
export const MESSAGE_LENGTH = 48;
export const U64_MAX = (1n << 64n) - 1n;

export interface Claims {
  subjectId: bigint;
  annualIncomeInr: bigint;
  issuedAt: bigint; // unix seconds, UTC
  expiresAt: bigint; // unix seconds, UTC
  credentialId: bigint;
}

/** Order matters: this is the byte order of the signed message. */
export const CLAIM_FIELDS = ['subjectId', 'annualIncomeInr', 'issuedAt', 'expiresAt', 'credentialId'] as const;

export class CredentialFormatError extends Error {
  override name = 'CredentialFormatError';
}

/** Throws CredentialFormatError if claims are out of range or inconsistent. */
export function validateClaims(claims: Claims): void {
  for (const field of CLAIM_FIELDS) {
    const v = claims[field];
    if (typeof v !== 'bigint') throw new CredentialFormatError(`${field} must be a bigint`);
    if (v < 0n || v > U64_MAX) throw new CredentialFormatError(`${field} must be within 0..2^64-1`);
  }
  if (claims.expiresAt <= claims.issuedAt) {
    throw new CredentialFormatError('expiresAt must be after issuedAt');
  }
}

/** Canonical message: schema_tag || 5 claims, each u64 big-endian (48 bytes). */
export function encodeMessage(claims: Claims): Buffer {
  validateClaims(claims);
  const out = Buffer.alloc(MESSAGE_LENGTH);
  out.writeBigUInt64BE(SCHEMA_TAG, 0);
  CLAIM_FIELDS.forEach((field, i) => out.writeBigUInt64BE(claims[field], 8 * (i + 1)));
  return out;
}

/** JSON form uses decimal strings: JS numbers lose precision above 2^53. */
export type SerializedClaims = Record<(typeof CLAIM_FIELDS)[number], string>;

export function serializeClaims(claims: Claims): SerializedClaims {
  return Object.fromEntries(CLAIM_FIELDS.map((f) => [f, claims[f].toString(10)])) as SerializedClaims;
}

const DECIMAL = /^(0|[1-9][0-9]*)$/;

export function parseClaims(raw: unknown): Claims {
  if (typeof raw !== 'object' || raw === null) throw new CredentialFormatError('claims must be an object');
  const obj = raw as Record<string, unknown>;
  const extra = Object.keys(obj).filter((k) => !(CLAIM_FIELDS as readonly string[]).includes(k));
  if (extra.length) throw new CredentialFormatError(`unexpected claim field(s): ${extra.join(', ')}`);
  const claims = {} as Claims;
  for (const field of CLAIM_FIELDS) {
    const v = obj[field];
    if (typeof v !== 'string' || !DECIMAL.test(v)) {
      throw new CredentialFormatError(`${field} must be a canonical decimal string`);
    }
    claims[field] = BigInt(v);
  }
  validateClaims(claims);
  return claims;
}
