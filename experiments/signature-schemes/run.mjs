// Milestone 2 experiment: does a signature produced by a JavaScript issuer verify
// inside a Noir circuit, and are forged/tampered credentials rejected?
//
// For each candidate scheme this script:
//   1. generates a throwaway issuer key IN MEMORY (never written to disk),
//   2. signs a fictional income credential and checks it with the JS library,
//   3. writes Noir prover inputs (case_*.toml, git-ignored) for valid and attack cases,
//   4. runs `nargo execute` and compares the outcome with the expected result,
//   5. for valid cases, generates and verifies a real UltraHonk proof with `bb`
//      and records gate count, proof size and timings.
//
// Usage: npm test   (requires nargo 1.0.0 and bb 6.0.0 on PATH)
import { createRequire } from 'node:module';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const require = createRequire(import.meta.url);
// The package's ESM build fails to import `blakejs`; its CommonJS build works.
const eddsa = require('@zk-kit/eddsa-poseidon');
const { poseidon5 } = require('poseidon-lite/poseidon5');

const ROOT = path.dirname(new URL(import.meta.url).pathname);
const PROVE_RUNS = 3;

// ── Fictional credential (shared by both schemes) ───────────────────────────
const SCHEMA_TAG = 0x5a4b50475f494e31n; // "ZKPG_IN1": domain separation
const CREDENTIAL = {
  subject_id: 1001n, // fictional holder
  income: 950000n, // ₹9,50,000
  issued_at: 1767225600n, // 2026-01-01T00:00:00Z
  expires_at: 1798761600n, // 2027-01-01T00:00:00Z
};
const THRESHOLD = 800000n;

// ── Helpers ─────────────────────────────────────────────────────────────────
const u64be = (v) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(v);
  return b;
};
const bytesToToml = (buf) => `[${[...buf].map((x) => `"${x}"`).join(', ')}]`;
const hex = (v) => `"0x${v.toString(16)}"`;

function toml(obj) {
  return Object.entries(obj)
    .map(([k, v]) => `${k} = ${v}`)
    .join('\n') + '\n';
}

function credentialFields(c) {
  return {
    subject_id: `"${c.subject_id}"`,
    income: `"${c.income}"`,
    issued_at: `"${c.issued_at}"`,
    expires_at: `"${c.expires_at}"`,
  };
}

function run(cmd, args, cwd) {
  return execFileSync(cmd, args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

function median(xs) {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)];
}

// ── ECDSA P-256 (Node.js built-in crypto) ───────────────────────────────────
const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

function ecdsaEncode(c) {
  return Buffer.concat([SCHEMA_TAG, c.subject_id, c.income, c.issued_at, c.expires_at].map(u64be));
}

function ecdsaKeypair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  return {
    privateKey,
    publicKey,
    x: Buffer.from(jwk.x, 'base64url'),
    y: Buffer.from(jwk.y, 'base64url'),
  };
}

function withS(sig, sValue) {
  const out = Buffer.from(sig);
  Buffer.from(sValue.toString(16).padStart(64, '0'), 'hex').copy(out, 32);
  return out;
}

// FINDING: Noir/bb's secp256r1 verifier only accepts LOW-S signatures (s <= n/2).
// Node's crypto returns either form at random, so the issuer must normalise.
function ecdsaSign(privateKey, credential) {
  // IEEE P1363 = raw r||s (64 bytes), the format Noir's verify_signature expects.
  const sig = crypto.sign('sha256', ecdsaEncode(credential), { key: privateKey, dsaEncoding: 'ieee-p1363' });
  const s = BigInt('0x' + sig.subarray(32).toString('hex'));
  return s > P256_N / 2n ? withS(sig, P256_N - s) : sig;
}

function ecdsaCases() {
  const issuer = ecdsaKeypair();
  const attacker = ecdsaKeypair();
  const sig = ecdsaSign(issuer.privateKey, CREDENTIAL);

  // Sanity check with the JS library itself before involving the circuit.
  const jsOk = crypto.verify('sha256', ecdsaEncode(CREDENTIAL), { key: issuer.publicKey, dsaEncoding: 'ieee-p1363' }, sig);
  if (!jsOk) throw new Error('ECDSA: JS self-verification failed');

  // ECDSA signatures are malleable: (r, s) and (r, n - s) are both mathematically
  // valid. `sig` is already low-s; build its high-s twin to test the circuit's rule.
  const lowS = BigInt('0x' + sig.subarray(32).toString('hex'));
  const sigLow = sig;
  const sigHigh = withS(sig, P256_N - lowS);
  if (!crypto.verify('sha256', ecdsaEncode(CREDENTIAL), { key: issuer.publicKey, dsaEncoding: 'ieee-p1363' }, sigHigh)) {
    throw new Error('ECDSA: high-s twin should be valid for Node crypto');
  }

  const belowCred = { ...CREDENTIAL, income: 650000n };
  const sigBelow = ecdsaSign(issuer.privateKey, belowCred);
  const flipped = Buffer.from(sigLow);
  flipped[10] ^= 0x01;

  const base = (pub, signature, cred) => ({
    issuer_pub_key_x: bytesToToml(pub.x),
    issuer_pub_key_y: bytesToToml(pub.y),
    minimum_income: `"${THRESHOLD}"`,
    signature: bytesToToml(signature),
    ...credentialFields(cred),
  });

  return [
    { name: 'valid_low_s', inputs: base(issuer, sigLow, CREDENTIAL), expect: 'ok' },
    { name: 'high_s_twin', inputs: base(issuer, sigHigh, CREDENTIAL), expect: 'invalid issuer signature' },
    { name: 'tampered_income', inputs: base(issuer, sigLow, { ...CREDENTIAL, income: 1500000n }), expect: 'invalid issuer signature' },
    { name: 'wrong_issuer_key', inputs: base(attacker, sigLow, CREDENTIAL), expect: 'invalid issuer signature' },
    { name: 'tampered_signature', inputs: base(issuer, flipped, CREDENTIAL), expect: 'invalid issuer signature' },
    { name: 'below_threshold', inputs: base(issuer, sigBelow, belowCred), expect: 'income below threshold' },
  ];
}

// ── EdDSA over BabyJubJub with Poseidon (@zk-kit/eddsa-poseidon) ─────────────
function eddsaMessage(c) {
  return poseidon5([SCHEMA_TAG, c.subject_id, c.income, c.issued_at, c.expires_at]);
}

function eddsaKeypair() {
  const privateKey = crypto.randomBytes(32);
  const [x, y] = eddsa.derivePublicKey(privateKey);
  return { privateKey, x, y };
}

function eddsaCases() {
  const issuer = eddsaKeypair();
  const attacker = eddsaKeypair();
  const msg = eddsaMessage(CREDENTIAL);
  const sig = eddsa.signMessage(issuer.privateKey, msg);

  if (!eddsa.verifySignature(msg, sig, [issuer.x, issuer.y])) throw new Error('EdDSA: JS self-verification failed');

  const belowCred = { ...CREDENTIAL, income: 650000n };
  const sigBelow = eddsa.signMessage(issuer.privateKey, eddsaMessage(belowCred));

  const base = (pub, s, cred) => ({
    issuer_pub_key_x: hex(pub.x),
    issuer_pub_key_y: hex(pub.y),
    minimum_income: `"${THRESHOLD}"`,
    signature_s: hex(s.S),
    signature_r8_x: hex(s.R8[0]),
    signature_r8_y: hex(s.R8[1]),
    ...credentialFields(cred),
  });

  return [
    { name: 'valid', inputs: base(issuer, sig, CREDENTIAL), expect: 'ok' },
    { name: 'tampered_income', inputs: base(issuer, sig, { ...CREDENTIAL, income: 1500000n }), expect: 'invalid issuer signature' },
    { name: 'wrong_issuer_key', inputs: base(attacker, sig, CREDENTIAL), expect: 'invalid issuer signature' },
    { name: 'tampered_signature', inputs: base(issuer, { ...sig, S: sig.S + 1n }, CREDENTIAL), expect: 'invalid issuer signature' },
    { name: 'below_threshold', inputs: base(issuer, sigBelow, belowCred), expect: 'income below threshold' },
  ];
}

// ── Runner ──────────────────────────────────────────────────────────────────
function measure(dir, pkg, caseName) {
  const circuit = `target/${pkg}.json`;
  const out = `target/bench/${caseName}`;
  fs.rmSync(path.join(dir, out), { recursive: true, force: true });
  run('bb', ['write_vk', '-b', circuit, '-o', `${out}/vk`], dir);

  const proveMs = [];
  for (let i = 0; i < PROVE_RUNS; i++) {
    const t = performance.now();
    run('bb', ['prove', '-b', circuit, '-w', `target/${caseName}.gz`, '-k', `${out}/vk/vk`, '-o', `${out}/proof`], dir);
    proveMs.push(performance.now() - t);
  }
  const verifyMs = [];
  for (let i = 0; i < PROVE_RUNS; i++) {
    const t = performance.now();
    run('bb', ['verify', '-p', `${out}/proof/proof`, '-k', `${out}/vk/vk`, '-i', `${out}/proof/public_inputs`], dir);
    verifyMs.push(performance.now() - t);
  }
  const gates = run('bb', ['gates', '-b', circuit], dir).match(/"circuit_size":\s*(\d+)/)?.[1];
  return {
    gates: Number(gates),
    proveMs: Math.round(median(proveMs)),
    verifyMs: Math.round(median(verifyMs)),
    proofBytes: fs.statSync(path.join(dir, out, 'proof/proof')).size,
    publicInputBytes: fs.statSync(path.join(dir, out, 'proof/public_inputs')).size,
  };
}

function runScheme(label, dirName, pkg, cases) {
  const dir = path.join(ROOT, dirName);
  console.log(`\n== ${label}`);
  run('nargo', ['compile'], dir);
  let failures = 0;
  let metrics = null;
  for (const c of cases) {
    fs.writeFileSync(path.join(dir, `case_${c.name}.toml`), toml(c.inputs));
    let outcome;
    try {
      run('nargo', ['execute', '-p', `case_${c.name}`, c.name], dir);
      outcome = 'ok';
    } catch (e) {
      const msg = String(e.stderr || e.stdout || e.message);
      outcome = msg.match(/(invalid issuer signature|income below threshold)/)?.[1] ?? `error: ${msg.split('\n').find((l) => l.trim()) ?? 'unknown'}`;
    }
    const status = outcome === c.expect ? 'PASS' : 'FAIL';
    if (status === 'FAIL') failures++;
    console.log(`  ${status.padEnd(4)}  ${c.name.padEnd(20)} expected: ${c.expect.padEnd(26)} got: ${outcome}`);

    if (outcome === 'ok' && c.expect === 'ok') {
      metrics = measure(dir, pkg, c.name);
      console.log(`        real proof generated and verified by bb ✓`);
    }
  }
  if (metrics) {
    console.log(`  metrics: ${metrics.gates} gates | prove ${metrics.proveMs} ms | verify ${metrics.verifyMs} ms (median of ${PROVE_RUNS}) | proof ${metrics.proofBytes} B | public inputs ${metrics.publicInputBytes} B`);
  }
  return failures;
}

let failures = 0;
failures += runScheme('ECDSA P-256 (Node crypto) → Noir std::ecdsa_secp256r1 + sha256 v0.3.0', 'ecdsa-p256', 'ecdsa_p256_experiment', ecdsaCases());
failures += runScheme('EdDSA BabyJubJub-Poseidon (@zk-kit) → noir-lang/eddsa@master + poseidon v0.3.0', 'eddsa-babyjubjub', 'eddsa_babyjubjub_experiment', eddsaCases());

console.log(failures === 0 ? '\nALL EXPECTED OUTCOMES MATCHED' : `\n${failures} UNEXPECTED OUTCOME(S)`);
process.exit(failures === 0 ? 0 : 1);
