/**
 * Issue and verify ZKPG_INCOME_V1 credentials (spec: docs/credential-format.md).
 *
 * verifyCredential() is what a HOLDER (or a test) uses to check a credential
 * before building a proof. The relying-party verifier never sees the credential:
 * in Milestone 3 the same checks move inside the ZK circuit.
 */
import crypto, { type KeyObject } from 'node:crypto';
import {
  CREDENTIAL_TYPE,
  CredentialFormatError,
  type Claims,
  encodeMessage,
  parseClaims,
  type SerializedClaims,
  serializeClaims,
} from './encoding.ts';
import { signLowS, isLowS, verifyLowS, SIGNATURE_LENGTH } from './ecdsa.ts';
import { type IssuerPublicInfo, issuerPublicInfo, publicKeyFromInfo } from './keys.ts';

export const MAX_VALIDITY_SECONDS = 366n * 24n * 60n * 60n;

export interface Credential {
  type: typeof CREDENTIAL_TYPE;
  issuer: { kid: string };
  claims: SerializedClaims;
  signature: { alg: 'ES256'; value: string };
}

export interface IssueRequest {
  subjectId: bigint;
  annualIncomeInr: bigint;
  validitySeconds: bigint;
  /** Defaults to the current time. */
  issuedAt?: bigint;
}

const nowSeconds = (): bigint => BigInt(Math.floor(Date.now() / 1000));
const randomU64 = (): bigint => crypto.randomBytes(8).readBigUInt64BE();

export function issueCredential(privateKey: KeyObject, req: IssueRequest): Credential {
  if (req.validitySeconds <= 0n || req.validitySeconds > MAX_VALIDITY_SECONDS) {
    throw new CredentialFormatError('validity must be between 1 second and 366 days');
  }
  const issuedAt = req.issuedAt ?? nowSeconds();
  const claims: Claims = {
    subjectId: req.subjectId,
    annualIncomeInr: req.annualIncomeInr,
    issuedAt,
    expiresAt: issuedAt + req.validitySeconds,
    credentialId: randomU64(),
  };
  const signature = signLowS(privateKey, encodeMessage(claims));
  return {
    type: CREDENTIAL_TYPE,
    issuer: { kid: issuerPublicInfo(privateKey).kid },
    claims: serializeClaims(claims),
    signature: { alg: 'ES256', value: signature.toString('hex') },
  };
}

export type VerifyFailure =
  | 'MALFORMED'
  | 'UNSUPPORTED_TYPE'
  | 'UNKNOWN_ISSUER'
  | 'NON_CANONICAL_SIGNATURE'
  | 'INVALID_SIGNATURE'
  | 'NOT_YET_VALID'
  | 'EXPIRED';

export type VerifyResult =
  | { valid: true; claims: Claims; issuer: IssuerPublicInfo }
  | { valid: false; reason: VerifyFailure; detail?: string };

const HEX_SIG = new RegExp(`^[0-9a-f]{${SIGNATURE_LENGTH * 2}}$`);
const fail = (reason: VerifyFailure, detail?: string): VerifyResult =>
  detail === undefined ? { valid: false, reason } : { valid: false, reason, detail };

/**
 * Checks structure, trusted issuer, signature (low-s) and validity window.
 * Never throws for bad input; error details never include claim values.
 */
export function verifyCredential(
  doc: unknown,
  trustedIssuers: readonly IssuerPublicInfo[],
  opts: { now?: bigint } = {},
): VerifyResult {
  if (typeof doc !== 'object' || doc === null) return fail('MALFORMED', 'credential must be an object');
  const c = doc as Partial<Record<keyof Credential, unknown>>;
  if (c.type !== CREDENTIAL_TYPE) return fail('UNSUPPORTED_TYPE');

  const kid = (c.issuer as { kid?: unknown } | undefined)?.kid;
  if (typeof kid !== 'string') return fail('MALFORMED', 'issuer.kid missing');

  const sig = c.signature as { alg?: unknown; value?: unknown } | undefined;
  if (sig?.alg !== 'ES256' || typeof sig.value !== 'string' || !HEX_SIG.test(sig.value)) {
    return fail('MALFORMED', 'signature must be ES256 with 64-byte lowercase hex r||s');
  }

  let claims: Claims;
  try {
    claims = parseClaims(c.claims);
  } catch (e) {
    return fail('MALFORMED', e instanceof CredentialFormatError ? e.message : 'invalid claims');
  }

  // Look the issuer up by kid, and only accept keys the caller explicitly trusts.
  const issuer = trustedIssuers.find((i) => i.kid === kid);
  if (!issuer) return fail('UNKNOWN_ISSUER');

  const signature = Buffer.from(sig.value, 'hex');
  if (!isLowS(signature)) return fail('NON_CANONICAL_SIGNATURE', 'high-s signatures are rejected');
  if (!verifyLowS(publicKeyFromInfo(issuer), encodeMessage(claims), signature)) {
    return fail('INVALID_SIGNATURE');
  }

  const now = opts.now ?? nowSeconds();
  if (now < claims.issuedAt) return fail('NOT_YET_VALID');
  if (now >= claims.expiresAt) return fail('EXPIRED');
  return { valid: true, claims, issuer };
}
