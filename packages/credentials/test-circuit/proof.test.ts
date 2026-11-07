/**
 * End-to-end with REAL proofs (nargo 1.0.0 + bb 6.0.0 UltraHonk):
 * issuer signs → holder builds inputs → circuit → bb prove → bb verify → verifier policy.
 */
import fs from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildCircuitInputs, type CircuitInputs } from '../src/circuit-inputs.ts';
import { issueCredential } from '../src/credential.ts';
import { generateIssuerKeyPair, issuerPublicInfo } from '../src/keys.ts';
import { checkPublicInputs, decodePublicInputs } from '../src/public-inputs.ts';
import { Prover, setField } from './prover.ts';

const DAY = 86_400n;
const T0 = 1_767_225_600n;
const NOW = T0 + 30n * DAY;

const issuerKey = generateIssuerKeyPair().privateKey;
const ISSUER = issuerPublicInfo(issuerKey);
const attackerKey = generateIssuerKeyPair().privateKey;
const ATTACKER = issuerPublicInfo(attackerKey);

const issue = (key = issuerKey, income = 950_000n) =>
  issueCredential(key, { subjectId: 1001n, annualIncomeInr: income, validitySeconds: 365n * DAY, issuedAt: T0 });
const REQUEST = { minimumIncome: 800_000n, currentTime: NOW, challenge: 0xc0ffee_1234_5678n };
const POLICY = { trustedIssuers: [ISSUER], minimumIncome: REQUEST.minimumIncome, challenge: REQUEST.challenge, now: NOW, maxClockSkewSeconds: 300n };

// Field indices in public_inputs (circuit declaration order).
const PI = { X0: 0, MIN_INCOME: 64, CURRENT_TIME: 65, CHALLENGE: 66 };

const prover = new Prover();
let valid: { proof: string; publicInputs: string; ms: number };
let validInputs: CircuitInputs;

beforeAll(() => {
  prover.setup();
  validInputs = buildCircuitInputs(issue(), ISSUER, REQUEST);
  const r = prover.execute('valid', validInputs);
  if (!r.ok) throw new Error(`valid witness failed: ${r.error}`);
  valid = prover.prove('valid');
});
afterAll(() => prover.cleanup());

describe('valid credential', () => {
  it('produces a proof that bb verifies', () => {
    expect(prover.verify(valid.proof, valid.publicInputs)).toBe(true);
  });

  it('passes the verifier public-input policy', () => {
    const pi = decodePublicInputs(fs.readFileSync(valid.publicInputs));
    expect(checkPublicInputs(pi, POLICY)).toEqual({ ok: true, issuerKid: ISSUER.kid });
  });

  it('reveals only the expected public inputs: no income, signature or claims', () => {
    const pi = decodePublicInputs(fs.readFileSync(valid.publicInputs));
    expect(pi).toEqual({ issuerX: ISSUER.circuit.x, issuerY: ISSUER.circuit.y, minimumIncome: 800_000n, currentTime: NOW, challenge: REQUEST.challenge });

    const sent = Buffer.concat([fs.readFileSync(valid.proof), fs.readFileSync(valid.publicInputs)]).toString('hex');
    const asField = (v: string) => BigInt(v).toString(16).padStart(64, '0');
    const sigHex = Buffer.from(validInputs.signature.map(Number)).toString('hex');
    expect(sent).not.toContain(asField(validInputs.income));
    expect(sent).not.toContain(asField(validInputs.credential_id));
    expect(sent).not.toContain(asField(validInputs.expires_at));
    expect(sent).not.toContain(sigHex.slice(0, 64)); // r
    expect(sent).not.toContain(sigHex.slice(64)); // s
  });
});

describe('the circuit refuses to produce a witness for', () => {
  it('a genuine credential below the threshold', () => {
    expect(prover.execute('below', buildCircuitInputs(issue(issuerKey, 650_000n), ISSUER, REQUEST))).toEqual({ ok: false, error: 'income below threshold' });
  });

  it('a tampered income (holder skips the JS pre-check and edits the witness)', () => {
    expect(prover.execute('tampered', { ...validInputs, income: '1500000' })).toEqual({ ok: false, error: 'invalid issuer signature' });
  });

  it('a genuine signature presented with a different issuer key', () => {
    const k = ATTACKER.circuit;
    const inputs = { ...validInputs, issuer_pub_key_x: [...Buffer.from(k.x, 'hex')].map(String), issuer_pub_key_y: [...Buffer.from(k.y, 'hex')].map(String) };
    expect(prover.execute('wrongkey', inputs)).toEqual({ ok: false, error: 'invalid issuer signature' });
  });

  it('an expired credential (request time after expiry)', () => {
    expect(prover.execute('expired', { ...validInputs, current_time: (T0 + 400n * DAY).toString() })).toEqual({ ok: false, error: 'credential expired' });
  });

  it('a credential used before its issue time', () => {
    expect(prover.execute('early', { ...validInputs, current_time: (T0 - 1n).toString() })).toEqual({ ok: false, error: 'credential not yet valid' });
  });
});

describe('the verifier rejects', () => {
  it('a self-signed forgery: valid proof, but the issuer key is not trusted', () => {
    const forged = buildCircuitInputs(issue(attackerKey, 5_000_000n), ATTACKER, REQUEST);
    expect(prover.execute('forged', forged)).toEqual({ ok: true });
    const p = prover.prove('forged');
    expect(prover.verify(p.proof, p.publicInputs)).toBe(true); // mathematically valid…
    const pi = decodePublicInputs(fs.readFileSync(p.publicInputs));
    expect(checkPublicInputs(pi, POLICY)).toEqual({ ok: false, reason: 'UNTRUSTED_ISSUER' }); // …but not trusted
  });

  it('a self-signed forgery relabelled with the trusted issuer key', () => {
    const p = prover.prove('forged');
    const trustedKey = Buffer.from(ISSUER.circuit.x, 'hex');
    const relabelled = prover.variant(p.publicInputs, 'relabelled_pi', (b) => {
      for (let i = 0; i < 32; i++) setField(b, PI.X0 + i, BigInt(trustedKey[i]!));
    });
    expect(prover.verify(p.proof, relabelled)).toBe(false);
  });

  it.each([
    ['challenge (replay into another request)', PI.CHALLENGE, 0xbad_c0ffeen],
    ['threshold raised to ₹10L', PI.MIN_INCOME, 1_000_000n],
    ['threshold lowered to ₹0', PI.MIN_INCOME, 0n],
    ['current_time moved back into validity', PI.CURRENT_TIME, T0 + 1n],
  ])('a valid proof with an altered %s', (_label, index, value) => {
    const altered = prover.variant(valid.publicInputs, `pi_${index}_${value}`, (b) => setField(b, index, value));
    expect(prover.verify(valid.proof, altered)).toBe(false);
  });

  it('a replayed proof: cryptographically valid, but the challenge belongs to an old request', () => {
    const pi = decodePublicInputs(fs.readFileSync(valid.publicInputs));
    expect(checkPublicInputs(pi, { ...POLICY, challenge: 0x9999n })).toEqual({ ok: false, reason: 'CHALLENGE_MISMATCH' });
  });

  it('a tampered proof', () => {
    const tampered = prover.variant(valid.proof, 'tampered_proof', (b) => { b[b.length >> 1]! ^= 1; });
    expect(prover.verify(tampered, valid.publicInputs)).toBe(false);
  });

  it('a truncated proof', () => {
    const truncated = prover.variant(valid.proof, 'truncated_proof', () => {});
    fs.truncateSync(truncated, 1000);
    expect(prover.verify(truncated, valid.publicInputs)).toBe(false);
  });
});

describe('measurements (indicative, single machine)', () => {
  it('records proof size and timings', () => {
    const t = performance.now();
    expect(prover.verify(valid.proof, valid.publicInputs)).toBe(true);
    const verifyMs = performance.now() - t;
    const m = {
      proofBytes: fs.statSync(valid.proof).size,
      publicInputBytes: fs.statSync(valid.publicInputs).size,
      proveMs: Math.round(valid.ms),
      verifyMsIncludingProcessStart: Math.round(verifyMs),
    };
    console.log('[metrics]', JSON.stringify(m));
    expect(m.publicInputBytes).toBe(67 * 32);
  });
});
