/**
 * HOLDER side: turn a stored credential plus a verifier's request into inputs for
 * circuits/credential-eligibility. Runs on the holder's device; the result contains
 * the PRIVATE witness and must never be sent to the verifier.
 */
import { type Credential, verifyCredential } from './credential.ts';
import { type IssuerPublicInfo } from './keys.ts';
import { U64_MAX } from './encoding.ts';

/** BN254 scalar field modulus: every circuit Field value must be below it. */
export const BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** What a verifier asks for (all values become PUBLIC inputs). */
export interface ProofRequest {
  minimumIncome: bigint;
  currentTime: bigint; // unix seconds
  challenge: bigint; // random nonce, < BN254_R
}

/** Noir input names → values, in the form nargo / noir_js accept. */
export interface CircuitInputs {
  issuer_pub_key_x: string[];
  issuer_pub_key_y: string[];
  minimum_income: string;
  current_time: string;
  challenge: string;
  signature: string[];
  subject_id: string;
  income: string;
  issued_at: string;
  expires_at: string;
  credential_id: string;
}

export class ProofRequestError extends Error {
  override name = 'ProofRequestError';
}

const byteArray = (hex: string): string[] => (hex.match(/../g) ?? []).map((b) => String(parseInt(b, 16)));

export function validateRequest(req: ProofRequest): void {
  if (req.minimumIncome < 0n || req.minimumIncome > U64_MAX) throw new ProofRequestError('minimumIncome out of u64 range');
  if (req.currentTime < 0n || req.currentTime > U64_MAX) throw new ProofRequestError('currentTime out of u64 range');
  if (req.challenge < 0n || req.challenge >= BN254_R) throw new ProofRequestError('challenge must be a BN254 field element');
}

/**
 * Checks the credential first (same rules the circuit enforces), so the holder gets
 * a clear reason instead of a failed witness. Does NOT check the threshold: whether
 * to attempt a proof below the threshold is the caller's decision (it will fail).
 */
export function buildCircuitInputs(credential: unknown, issuer: IssuerPublicInfo, req: ProofRequest): CircuitInputs {
  validateRequest(req);
  const check = verifyCredential(credential, [issuer], { now: req.currentTime });
  if (!check.valid) throw new ProofRequestError(`credential unusable: ${check.reason}`);
  const c = credential as Credential;
  return {
    issuer_pub_key_x: byteArray(issuer.circuit.x),
    issuer_pub_key_y: byteArray(issuer.circuit.y),
    minimum_income: req.minimumIncome.toString(),
    current_time: req.currentTime.toString(),
    challenge: req.challenge.toString(),
    signature: byteArray(c.signature.value),
    subject_id: c.claims.subjectId,
    income: c.claims.annualIncomeInr,
    issued_at: c.claims.issuedAt,
    expires_at: c.claims.expiresAt,
    credential_id: c.claims.credentialId,
  };
}

/** Prover.toml text for the nargo CLI. Treat the output as secret (it holds the witness). */
export function toProverToml(inputs: CircuitInputs): string {
  const value = (v: string | string[]) => (Array.isArray(v) ? `[${v.map((x) => `"${x}"`).join(', ')}]` : `"${v}"`);
  return Object.entries(inputs).map(([k, v]) => `${k} = ${value(v)}`).join('\n') + '\n';
}
