/**
 * ECDSA P-256 over SHA-256 with the LOW-S rule.
 *
 * For any valid signature (r, s), (r, n - s) is also valid. Noir's in-circuit
 * secp256r1 verifier accepts only s <= n/2 (measured in Milestone 2), and Node
 * returns either form at random, so we always normalise when signing and
 * reject high-s when verifying.
 */
import crypto, { type KeyObject } from 'node:crypto';

/** Order of the P-256 group. */
export const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const HALF_N = P256_N >> 1n;
export const SIGNATURE_LENGTH = 64;

const sOf = (sig: Uint8Array): bigint => BigInt('0x' + Buffer.from(sig.subarray(32, 64)).toString('hex'));

function withS(sig: Uint8Array, s: bigint): Buffer {
  const out = Buffer.from(sig);
  Buffer.from(s.toString(16).padStart(64, '0'), 'hex').copy(out, 32);
  return out;
}

export function isLowS(sig: Uint8Array): boolean {
  return sig.length === SIGNATURE_LENGTH && sOf(sig) <= HALF_N;
}

/** Signs SHA-256(message); returns raw r||s (64 bytes) in low-s form. */
export function signLowS(privateKey: KeyObject, message: Uint8Array): Buffer {
  const sig = crypto.sign('sha256', message, { key: privateKey, dsaEncoding: 'ieee-p1363' });
  const s = sOf(sig);
  return s > HALF_N ? withS(sig, P256_N - s) : sig;
}

/** Verifies a raw r||s signature; high-s is rejected to match the circuit. */
export function verifyLowS(publicKey: KeyObject, message: Uint8Array, sig: Uint8Array): boolean {
  if (!isLowS(sig)) return false;
  return crypto.verify('sha256', message, { key: publicKey, dsaEncoding: 'ieee-p1363' }, sig);
}

/** Test helper: the mathematically valid high-s twin of a signature. */
export function highSTwin(sig: Uint8Array): Buffer {
  return withS(sig, P256_N - sOf(sig));
}
