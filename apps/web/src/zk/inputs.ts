/**
 * HOLDER side (browser): map a stored credential + verifier request to circuit inputs.
 * Mirrors packages/credentials buildCircuitInputs(), without Node crypto. The
 * signature is not re-checked here: the circuit itself rejects an invalid
 * signature ("invalid issuer signature"), so it remains the authority.
 */
import type { Credential, IssuerInfo, ProofRequest } from './types.ts';

export const BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const U64_MAX = (1n << 64n) - 1n;

export type PrecheckResult =
  | { ok: true }
  | { ok: false; reason: 'WRONG_ISSUER' | 'NOT_YET_VALID' | 'EXPIRED' | 'BELOW_THRESHOLD' | 'MALFORMED'; message: string };

export function precheck(cred: Credential, issuer: IssuerInfo, req: ProofRequest): PrecheckResult {
  const c = cred.claims;
  const nums = [c.subjectId, c.annualIncomeInr, c.issuedAt, c.expiresAt, c.credentialId, req.minimumIncome, req.currentTime];
  if (cred.type !== 'ZKPG_INCOME_V1' || !nums.every((n) => DECIMAL.test(n) && BigInt(n) <= U64_MAX) || !/^[0-9a-f]{128}$/.test(cred.signature.value)) {
    return { ok: false, reason: 'MALFORMED', message: 'This credential is not in the expected format.' };
  }
  if (cred.issuer.kid !== issuer.kid) return { ok: false, reason: 'WRONG_ISSUER', message: 'This credential was not issued by the trusted issuer.' };
  const now = BigInt(req.currentTime);
  if (now < BigInt(c.issuedAt)) return { ok: false, reason: 'NOT_YET_VALID', message: 'This credential is not valid yet.' };
  if (now >= BigInt(c.expiresAt)) return { ok: false, reason: 'EXPIRED', message: 'This credential has expired.' };
  if (BigInt(c.annualIncomeInr) < BigInt(req.minimumIncome)) {
    return { ok: false, reason: 'BELOW_THRESHOLD', message: 'Your credential does not meet this condition, so no valid proof can be created.' };
  }
  return { ok: true };
}

const hexBytes = (hex: string): string[] => (hex.match(/../g) ?? []).map((b) => String(parseInt(b, 16)));

export type CircuitInputs = Record<string, string | string[]>;

export function toCircuitInputs(cred: Credential, issuer: IssuerInfo, req: ProofRequest): CircuitInputs {
  const challenge = BigInt(req.challenge);
  if (challenge < 0n || challenge >= BN254_R) throw new Error('challenge is not a field element');
  return {
    issuer_pub_key_x: hexBytes(issuer.circuit.x),
    issuer_pub_key_y: hexBytes(issuer.circuit.y),
    minimum_income: req.minimumIncome,
    current_time: req.currentTime,
    challenge: challenge.toString(),
    signature: hexBytes(cred.signature.value),
    subject_id: cred.claims.subjectId,
    income: cred.claims.annualIncomeInr,
    issued_at: cred.claims.issuedAt,
    expires_at: cred.claims.expiresAt,
    credential_id: cred.claims.credentialId,
  };
}

/** bb.js returns public inputs as hex strings; normalise to 0x + 64 lowercase hex chars. */
export function normalizePublicInputs(publicInputs: string[]): string[] {
  return publicInputs.map((h) => '0x' + h.replace(/^0x/i, '').toLowerCase().padStart(64, '0'));
}

export function toBase64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
