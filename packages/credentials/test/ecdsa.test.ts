import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { highSTwin, isLowS, P256_N, signLowS, verifyLowS } from '../src/ecdsa.ts';
import { generateIssuerKeyPair } from '../src/keys.ts';

const { privateKey, publicKey } = generateIssuerKeyPair();
const msg = Buffer.from('fictional message');

describe('ECDSA P-256 low-s', () => {
  it('always produces low-s signatures (100 signatures)', () => {
    for (let i = 0; i < 100; i++) expect(isLowS(signLowS(privateKey, msg))).toBe(true);
  });

  it('produces signatures that standard Node verification accepts', () => {
    const sig = signLowS(privateKey, msg);
    expect(crypto.verify('sha256', msg, { key: publicKey, dsaEncoding: 'ieee-p1363' }, sig)).toBe(true);
    expect(verifyLowS(publicKey, msg, sig)).toBe(true);
  });

  it('rejects the high-s twin even though plain ECDSA accepts it (malleability closed)', () => {
    const twin = highSTwin(signLowS(privateKey, msg));
    expect(crypto.verify('sha256', msg, { key: publicKey, dsaEncoding: 'ieee-p1363' }, twin)).toBe(true);
    expect(verifyLowS(publicKey, msg, twin)).toBe(false);
  });

  it('rejects wrong length, a different message and a different key', () => {
    const sig = signLowS(privateKey, msg);
    expect(verifyLowS(publicKey, msg, sig.subarray(0, 63))).toBe(false);
    expect(verifyLowS(publicKey, Buffer.from('other message'), sig)).toBe(false);
    expect(verifyLowS(generateIssuerKeyPair().publicKey, msg, sig)).toBe(false);
  });

  it('uses the correct P-256 group order', () => {
    // n from SEC 2 / FIPS 186-4
    expect(P256_N.toString(16)).toBe('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
  });
});
