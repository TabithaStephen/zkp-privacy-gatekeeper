/**
 * Reproducible benchmark for the credential-eligibility circuit.
 *
 *   npm run bench                 (builds the web app, then runs everything)
 *   npm run bench -- --runs 7     (more runs per configuration)
 *
 * Measures, on THIS machine:
 *   - sizes: gates, compiled artifact, verification key, proof, public inputs
 *   - witness generation (noir_js)
 *   - native bb CLI prove / verify   (skipped if `bb` is not on PATH)
 *   - Node bb.js (WASM) prove / verify with 1 and 4 threads
 *   - Chromium bb.js prove / verify: run 1 "cold" (CRS download + WASM start-up), then warm runs
 * and writes docs/benchmarks/results.json and docs/benchmarks/README.md.
 * All inputs are fictional; the throwaway issuer key lives only in memory.
 */
import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { Barretenberg, UltraHonkBackend } from '@aztec-foundation/bb.js';
import { Noir } from '@noir-lang/noir_js';
import { buildCircuitInputs, generateIssuerKeyPair, issueCredential, issuerPublicInfo } from '@zkpg/credentials';

const ROOT = path.resolve(import.meta.dirname, '..');
const ARTIFACT = path.join(ROOT, 'circuits/credential-eligibility/artifact/credential_eligibility.json');
const OUT_DIR = path.join(ROOT, 'docs/benchmarks');
const { values } = parseArgs({ options: { runs: { type: 'string', default: '5' } } });
const RUNS = Math.max(3, Number(values.runs));

const artifact = JSON.parse(fs.readFileSync(ARTIFACT, 'utf8'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'zkpg-bench-'));

// ── Stats ──────────────────────────────────────────────────────────────────
interface Stats { n: number; median: number; min: number; max: number }
function stats(xs: number[]): Stats {
  const s = [...xs].sort((a, b) => a - b);
  const mid = s.length >> 1;
  const median = s.length % 2 ? s[mid]! : (s[mid - 1]! + s[mid]!) / 2;
  return { n: s.length, median: Math.round(median), min: Math.round(s[0]!), max: Math.round(s[s.length - 1]!) };
}
const fmt = (st: Stats) => `${st.median} ms (min ${st.min}, max ${st.max}, n=${st.n})`;

// ── Inputs: a real credential signed by the real issuer code ────────────────
const key = generateIssuerKeyPair().privateKey;
const now = BigInt(Math.floor(Date.now() / 1000));
const credential = issueCredential(key, { subjectId: 1001n, annualIncomeInr: 950_000n, validitySeconds: 30n * 86_400n, issuedAt: now - 86_400n });
const inputs = buildCircuitInputs(credential, issuerPublicInfo(key), { minimumIncome: 800_000n, currentTime: now, challenge: 0x1234_5678_9abcn });

const results: Record<string, unknown> = {};

// ── Environment ─────────────────────────────────────────────────────────────
// Resolve the NATIVE bb binary explicitly. Under npm/npx, node_modules/.bin comes first on
// PATH and contains bb.js's Node wrapper called `bb`, which adds ~45 ms of Node start-up
// to every call (found while investigating an inflated verify time).
function nativeBb(): string {
  const candidates = [process.env.BB_BINARY, path.join(os.homedir(), '.bb/bb'),
    ...(process.env.PATH ?? '').split(':').filter((d) => !d.includes('node_modules')).map((d) => path.join(d, 'bb'))];
  return candidates.find((c): c is string => !!c && fs.existsSync(c) && !fs.readFileSync(c).subarray(0, 2).equals(Buffer.from('#!'))) ?? '';
}
const bbPath = nativeBb();
// Some packages do not export package.json, so read it from node_modules directly.
const pkg = (name: string) => JSON.parse(fs.readFileSync(path.join(ROOT, 'node_modules', name, 'package.json'), 'utf8')).version as string;
results.environment = {
  date: new Date().toISOString(),
  os: `${os.type()} ${os.release()} (${os.arch()})`,
  cpu: os.cpus()[0]?.model ?? 'unknown',
  logicalCores: os.cpus().length,
  memoryGiB: Math.round(os.totalmem() / 2 ** 30),
  node: process.version,
  noirVersion: artifact.noir_version,
  noirJs: pkg('@noir-lang/noir_js'),
  bbJs: pkg('@aztec-foundation/bb.js'),
  bbCli: bbPath ? `${execFileSync(bbPath, ['--version'], { encoding: 'utf8' }).trim()} (${bbPath})` : 'not installed',
  runsPerConfig: RUNS,
};
console.log('Environment:', results.environment);

// ── Witness (noir_js) ───────────────────────────────────────────────────────
const witnessTimes: number[] = [];
let witness!: Uint8Array;
for (let i = 0; i < RUNS; i++) {
  const t = performance.now();
  ({ witness } = await new Noir(artifact).execute(inputs as never));
  witnessTimes.push(performance.now() - t);
}
results.witnessNoirJs = stats(witnessTimes);
console.log('Witness (noir_js):', fmt(results.witnessNoirJs as Stats));

// ── Native bb CLI (same witness, written in nargo's witness.gz format) ──────
// Uses the native binary resolved by nativeBb() (see above). Timings include spawning
// the process from Node (~5 ms).
if (bbPath) {
  const bytecodeFile = path.join(tmp, 'circuit.json');
  fs.writeFileSync(bytecodeFile, JSON.stringify(artifact));
  fs.writeFileSync(path.join(tmp, 'witness.gz'), witness);
  execFileSync(bbPath, ['write_vk', '-b', bytecodeFile, '-o', path.join(tmp, 'vk')], { stdio: 'pipe' });
  const gates = execFileSync(bbPath, ['gates', '-b', bytecodeFile], { encoding: 'utf8' }).match(/"circuit_size":\s*(\d+)/)?.[1];
  results.gates = Number(gates);
  const prove: number[] = [];
  const verify: number[] = [];
  for (let i = 0; i < RUNS; i++) {
    let t = performance.now();
    execFileSync(bbPath, ['prove', '-b', bytecodeFile, '-w', path.join(tmp, 'witness.gz'), '-k', path.join(tmp, 'vk/vk'), '-o', path.join(tmp, 'proof')], { stdio: 'pipe' });
    prove.push(performance.now() - t);
    t = performance.now();
    execFileSync(bbPath, ['verify', '-p', path.join(tmp, 'proof/proof'), '-k', path.join(tmp, 'vk/vk'), '-i', path.join(tmp, 'proof/public_inputs')], { stdio: 'pipe' });
    verify.push(performance.now() - t);
  }
  results.nativeBbCli = { prove: stats(prove), verify: stats(verify), note: 'includes process start-up' };
  console.log(`Native bb CLI: prove ${fmt(stats(prove))}; verify ${fmt(stats(verify))}`);
}

let proofBytes = 0;
let publicInputCount = 0;
let vkBytes = 0;
// ── Node bb.js ──────────────────────────────────────────────────────────────
for (const threads of [1, 4]) {
  const prove: number[] = [];
  const verify: number[] = [];
  for (let i = 0; i < RUNS; i++) {
    const api = await Barretenberg.new({ threads });
    const backend = new UltraHonkBackend(artifact.bytecode, api);
    let t = performance.now();
    const proof = await backend.generateProof(witness);
    prove.push(performance.now() - t);
    t = performance.now();
    if (!(await backend.verifyProof(proof))) throw new Error('bb.js proof did not verify');
    verify.push(performance.now() - t);
    proofBytes = proof.proof.length;
    publicInputCount = proof.publicInputs.length;
    if (!vkBytes) vkBytes = (await backend.getVerificationKey()).length;
    await api.destroy();
  }
  results[`nodeBbJs_${threads}t`] = { prove: stats(prove), verify: stats(verify) };
  console.log(`Node bb.js ${threads} thread(s): prove ${fmt(stats(prove))}; verify ${fmt(stats(verify))}`);
}

// ── Browser (Chromium via Playwright) ───────────────────────────────────────
try {
  const { chromium } = createRequire(import.meta.url)('playwright');
  const web = spawn('npx', ['vite', 'preview', '--port', '4174', '--strictPort'], { cwd: path.join(ROOT, 'apps/web'), stdio: 'ignore', detached: true });
  try {
    for (let i = 0; i < 100; i++) {
      try { if ((await fetch('http://127.0.0.1:4174/bench.html')).ok) break; } catch { /* starting */ }
      await new Promise((r) => setTimeout(r, 200));
    }
    const proxy = process.env.HTTPS_PROXY ? { server: process.env.HTTPS_PROXY, bypass: '127.0.0.1,localhost' } : undefined;
    const browser = await chromium.launch(proxy ? { proxy } : {});
    const page = await (await browser.newContext()).newPage(); // fresh profile: run 1 is genuinely cold
    await page.goto('http://127.0.0.1:4174/bench.html');
    await page.waitForFunction(() => 'zkpgBench' in window);
    type BenchResult = { threads: number; isolated: boolean; proofBytes: number; runs: { witnessMs: number; proveMs: number; verifyMs: number; verified: boolean }[] };
    const r: BenchResult = await page.evaluate(
      ({ i, n }: { i: Record<string, unknown>; n: number }) => (window as unknown as { zkpgBench: (a: unknown, b: number) => Promise<BenchResult> }).zkpgBench(i, n),
      { i: inputs as unknown as Record<string, unknown>, n: RUNS },
    );
    await browser.close();
    if (!r.runs.every((x) => x.verified)) throw new Error('browser proof did not verify');
    const warm = r.runs.slice(1);
    results.browserChromium = {
      threads: r.threads,
      crossOriginIsolated: r.isolated,
      cold: { witnessMs: Math.round(r.runs[0]!.witnessMs), proveMs: Math.round(r.runs[0]!.proveMs), verifyMs: Math.round(r.runs[0]!.verifyMs) },
      warm: { witness: stats(warm.map((x) => x.witnessMs)), prove: stats(warm.map((x) => x.proveMs)), verify: stats(warm.map((x) => x.verifyMs)) },
    };
    console.log(`Browser (${r.threads} threads): cold prove ${Math.round(r.runs[0]!.proveMs)} ms; warm prove ${fmt(stats(warm.map((x) => x.proveMs)))}`);
  } finally {
    try { process.kill(-web.pid!, 'SIGTERM'); } catch { /* exited */ }
  }
} catch (e) {
  results.browserChromium = { skipped: String((e as Error).message).split('\n')[0] };
  console.log('Browser benchmark skipped:', (results.browserChromium as { skipped: string }).skipped);
}

results.sizes = {
  proofBytes,
  publicInputs: publicInputCount,
  publicInputBytes: publicInputCount * 32,
  verificationKeyBytes: vkBytes,
  compiledArtifactBytes: fs.statSync(ARTIFACT).size,
};
fs.rmSync(tmp, { recursive: true, force: true });

// ── Write results ───────────────────────────────────────────────────────────
fs.mkdirSync(OUT_DIR, { recursive: true });
fs.writeFileSync(path.join(OUT_DIR, 'results.json'), JSON.stringify(results, null, 2) + '\n');

const env = results.environment as Record<string, string | number>;
const s = results.sizes as Record<string, number>;
const row = (label: string, r?: { prove: Stats; verify: Stats }) => (r ? `| ${label} | ${fmt(r.prove)} | ${fmt(r.verify)} |` : `| ${label} | not run | not run |`);
const b = results.browserChromium as { threads?: number; cold?: { proveMs: number; verifyMs: number }; warm?: { prove: Stats; verify: Stats }; skipped?: string };
const md = `# Benchmarks: credential-eligibility circuit

Generated by \`npm run bench\` (\`bench/run.ts\`) on ${String(env.date).slice(0, 10)}. **Single machine,
indicative only.** Re-run on your own hardware; do not compare across machines.

## Environment

| | |
|---|---|
| OS | ${env.os} |
| CPU | ${env.cpu} (${env.logicalCores} logical cores), ${env.memoryGiB} GiB RAM |
| Node.js | ${env.node} |
| Noir | ${env.noirVersion} (noir_js ${env.noirJs}) |
| Barretenberg | bb.js ${env.bbJs}; CLI ${env.bbCli} |
| Runs per configuration | ${env.runsPerConfig} (median, min, max) |

## Sizes

| Metric | Value |
|---|---|
| Circuit size | ${results.gates ? `${(results.gates as number).toLocaleString('en-US')} gates` : 'n/a (bb CLI not installed)'} |
| Proof | ${s.proofBytes!.toLocaleString('en-US')} bytes |
| Public inputs | ${s.publicInputs} fields = ${s.publicInputBytes!.toLocaleString('en-US')} bytes |
| Verification key | ${s.verificationKeyBytes!.toLocaleString('en-US')} bytes |
| Compiled circuit artifact (committed) | ${s.compiledArtifactBytes!.toLocaleString('en-US')} bytes |

## Timings

Witness generation (noir_js): ${fmt(results.witnessNoirJs as Stats)}

| Configuration | Prove | Verify |
|---|---|---|
${row('Native bb CLI (incl. process start-up)', results.nativeBbCli as { prove: Stats; verify: Stats } | undefined)}
${row('Node bb.js WASM, 1 thread', results.nodeBbJs_1t as { prove: Stats; verify: Stats })}
${row('Node bb.js WASM, 4 threads', results.nodeBbJs_4t as { prove: Stats; verify: Stats })}
${b.warm ? `| Chromium bb.js, ${b.threads} threads, **cold** (run 1: CRS download + WASM start-up) | ${b.cold!.proveMs} ms | ${b.cold!.verifyMs} ms |\n| Chromium bb.js, ${b.threads} threads, warm (runs 2–${RUNS}) | ${fmt(b.warm.prove)} | ${fmt(b.warm.verify)} |` : `| Chromium | skipped: ${b.skipped} | |`}

Each bb.js run creates a fresh Barretenberg instance, as the app does, so start-up cost is
included. Raw numbers: [\`results.json\`](results.json).
`;
fs.writeFileSync(path.join(OUT_DIR, 'README.md'), md);
console.log(`\nWrote ${path.relative(ROOT, OUT_DIR)}/results.json and README.md`);
process.exit(0);
