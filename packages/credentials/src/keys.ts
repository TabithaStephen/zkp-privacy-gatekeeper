/**
 * Issuer key handling (ECDSA P-256).
 *
 * The PRIVATE key is only ever held as a Node KeyObject or written to a local
 * PEM file with permissions 0600 in a git-ignored location. It is never placed
 * in a credential, a public-key document, a log line or browser code.
 */
import crypto, { type KeyObject } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export interface IssuerPublicInfo {
  kid: string;
  alg: 'ES256';
  jwk: { kty: 'EC'; crv: 'P-256'; x: string; y: string };
  /** Same coordinates as 32-byte big-endian hex: the form the Noir circuit takes. */
  circuit: { x: string; y: string };
}

export function generateIssuerKeyPair(): { privateKey: KeyObject; publicKey: KeyObject } {
  return crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
}

function assertP256(key: KeyObject): void {
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
    throw new Error('issuer key must be an EC P-256 key');
  }
}

/** Writes the private key as PKCS#8 PEM, mode 0600. Refuses to overwrite. */
export function savePrivateKey(privateKey: KeyObject, filePath: string): void {
  assertP256(privateKey);
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  fs.writeFileSync(filePath, pem, { mode: 0o600, flag: 'wx' }); // 'wx' fails if the file exists
}

export function loadPrivateKey(filePath: string): KeyObject {
  const key = crypto.createPrivateKey(fs.readFileSync(filePath));
  assertP256(key);
  return key;
}

/** RFC 7638 JWK thumbprint: SHA-256 over the required members in lexicographic order. */
function jwkThumbprint(jwk: { crv: string; kty: string; x: string; y: string }): string {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return crypto.createHash('sha256').update(canonical).digest('base64url');
}

/** Public-key document to publish. Accepts a private or public KeyObject. */
export function issuerPublicInfo(key: KeyObject): IssuerPublicInfo {
  const publicKey = key.type === 'private' ? crypto.createPublicKey(key) : key;
  assertP256(publicKey);
  const { x, y } = publicKey.export({ format: 'jwk' });
  if (!x || !y) throw new Error('could not export public key coordinates');
  const jwk = { kty: 'EC' as const, crv: 'P-256' as const, x, y };
  return {
    kid: jwkThumbprint(jwk),
    alg: 'ES256',
    jwk,
    circuit: {
      x: Buffer.from(x, 'base64url').toString('hex'),
      y: Buffer.from(y, 'base64url').toString('hex'),
    },
  };
}

/** Rebuilds a public KeyObject from a published document (e.g. a verifier's trust list). */
export function publicKeyFromInfo(info: IssuerPublicInfo): KeyObject {
  const key = crypto.createPublicKey({ key: { ...info.jwk }, format: 'jwk' });
  if (issuerPublicInfo(key).kid !== info.kid) throw new Error('kid does not match the public key');
  return key;
}
