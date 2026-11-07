/**
 * VERIFIER side: decode and check the public inputs of a credential_eligibility proof.
 *
 * The proof only shows "a credential signed by THE KEY IN THE PUBLIC INPUTS is valid
 * at current_time and meets minimum_income". The verifier must therefore check that
 * every public input is what IT expects: a trusted issuer key, its own threshold,
 * its own challenge and a current time close to now. bb's cryptographic check
 * (bb verify / bb.js) is separate and must also pass.
 */
import { type IssuerPublicInfo } from './keys.ts';

const FIELD_BYTES = 32;
/** Declaration order in circuits/credential-eligibility/src/main.nr. */
export const PUBLIC_INPUT_COUNT = 32 + 32 + 1 + 1 + 1;

export interface PublicInputs {
  issuerX: string; // 32-byte hex
  issuerY: string;
  minimumIncome: bigint;
  currentTime: bigint;
  challenge: bigint;
}

export class PublicInputError extends Error {
  override name = 'PublicInputError';
}

/** Parses bb's public_inputs file: concatenated 32-byte big-endian field elements. */
export function decodePublicInputs(buf: Uint8Array): PublicInputs {
  if (buf.length !== PUBLIC_INPUT_COUNT * FIELD_BYTES) {
    throw new PublicInputError(`expected ${PUBLIC_INPUT_COUNT} public inputs, got ${buf.length / FIELD_BYTES}`);
  }
  const fields = Array.from({ length: PUBLIC_INPUT_COUNT }, (_, i) =>
    BigInt('0x' + Buffer.from(buf.subarray(i * FIELD_BYTES, (i + 1) * FIELD_BYTES)).toString('hex')),
  );
  const keyBytes = (start: number) =>
    fields.slice(start, start + 32).map((f) => {
      if (f > 255n) throw new PublicInputError('issuer key byte out of range');
      return f.toString(16).padStart(2, '0');
    }).join('');
  return {
    issuerX: keyBytes(0),
    issuerY: keyBytes(32),
    minimumIncome: fields[64]!,
    currentTime: fields[65]!,
    challenge: fields[66]!,
  };
}

export interface ExpectedRequest {
  trustedIssuers: readonly IssuerPublicInfo[];
  minimumIncome: bigint;
  challenge: bigint;
  now: bigint;
  /** Allowed |current_time - now| in seconds. */
  maxClockSkewSeconds: bigint;
}

export type PublicInputCheck =
  | { ok: true; issuerKid: string }
  | { ok: false; reason: 'UNTRUSTED_ISSUER' | 'THRESHOLD_MISMATCH' | 'CHALLENGE_MISMATCH' | 'STALE_TIME' };

export function checkPublicInputs(pi: PublicInputs, expected: ExpectedRequest): PublicInputCheck {
  const issuer = expected.trustedIssuers.find((i) => i.circuit.x === pi.issuerX && i.circuit.y === pi.issuerY);
  if (!issuer) return { ok: false, reason: 'UNTRUSTED_ISSUER' };
  if (pi.minimumIncome !== expected.minimumIncome) return { ok: false, reason: 'THRESHOLD_MISMATCH' };
  if (pi.challenge !== expected.challenge) return { ok: false, reason: 'CHALLENGE_MISMATCH' };
  const skew = pi.currentTime > expected.now ? pi.currentTime - expected.now : expected.now - pi.currentTime;
  if (skew > expected.maxClockSkewSeconds) return { ok: false, reason: 'STALE_TIME' };
  return { ok: true, issuerKid: issuer.kid };
}
