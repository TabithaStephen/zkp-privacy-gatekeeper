import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { generateIssuerKeyPair, issuerPublicInfo, loadPrivateKey, publicKeyFromInfo, savePrivateKey } from '../src/keys.ts';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'zkpg-keys-'));
afterAll(() => fs.rmSync(tmp, { recursive: true, force: true }));

describe('issuer keys', () => {
  it('saves the private key with 0600 permissions and loads it back', () => {
    const { privateKey } = generateIssuerKeyPair();
    const file = path.join(tmp, 'a', 'issuer.pem');
    savePrivateKey(privateKey, file);
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
    expect(issuerPublicInfo(loadPrivateKey(file)).kid).toBe(issuerPublicInfo(privateKey).kid);
  });

  it('refuses to overwrite an existing key file', () => {
    const file = path.join(tmp, 'b.pem');
    savePrivateKey(generateIssuerKeyPair().privateKey, file);
    expect(() => savePrivateKey(generateIssuerKeyPair().privateKey, file)).toThrow(/EEXIST/);
  });

  it('rejects non-P-256 keys', () => {
    const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
    expect(() => issuerPublicInfo(privateKey)).toThrow(/P-256/);
    const file = path.join(tmp, 'k1.pem');
    fs.writeFileSync(file, privateKey.export({ type: 'pkcs8', format: 'pem' }));
    expect(() => loadPrivateKey(file)).toThrow(/P-256/);
  });

  it('computes kid as the RFC 7638 JWK thumbprint', () => {
    // Recompute independently: SHA-256 of {"crv","kty","x","y"} in lexicographic order, no whitespace.
    const info = issuerPublicInfo(generateIssuerKeyPair().publicKey);
    const { crv, kty, x, y } = info.jwk;
    const expected = crypto.createHash('sha256').update(`{"crv":"${crv}","kty":"${kty}","x":"${x}","y":"${y}"}`).digest('base64url');
    expect(info.kid).toBe(expected);
  });

  it('exposes circuit coordinates as 32-byte hex equal to the JWK coordinates', () => {
    const info = issuerPublicInfo(generateIssuerKeyPair().publicKey);
    expect(info.circuit.x).toMatch(/^[0-9a-f]{64}$/);
    expect(Buffer.from(info.circuit.x, 'hex').toString('base64url')).toBe(info.jwk.x);
    expect(Buffer.from(info.circuit.y, 'hex').toString('base64url')).toBe(info.jwk.y);
  });

  it('rebuilds a public key from the published document and detects a kid/key mismatch', () => {
    const a = issuerPublicInfo(generateIssuerKeyPair().publicKey);
    const b = issuerPublicInfo(generateIssuerKeyPair().publicKey);
    expect(issuerPublicInfo(publicKeyFromInfo(a)).kid).toBe(a.kid);
    expect(() => publicKeyFromInfo({ ...a, jwk: b.jwk })).toThrow(/kid/);
  });
});
