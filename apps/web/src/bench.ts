/**
 * Browser benchmark entry (bench.html). Exposes window.zkpgBench, which proves and
 * verifies the credential circuit `runs` times with the given inputs and reports
 * per-run timings. Run 1 includes CRS download and WebAssembly start-up ("cold").
 */
import artifact from '../../../circuits/credential-eligibility/artifact/credential_eligibility.json';

interface RunTiming { witnessMs: number; proveMs: number; verifyMs: number; verified: boolean }

declare global {
  interface Window { zkpgBench: (inputs: Record<string, unknown>, runs: number) => Promise<{ threads: number; isolated: boolean; runs: RunTiming[]; proofBytes: number }> }
}

window.zkpgBench = async (inputs, runs) => {
  const [{ Noir }, { Barretenberg, UltraHonkBackend }] = await Promise.all([import('@noir-lang/noir_js'), import('@aztec-foundation/bb.js')]);
  const threads = globalThis.crossOriginIsolated ? Math.min(navigator.hardwareConcurrency || 4, 8) : 1;
  const out: RunTiming[] = [];
  let proofBytes = 0;
  for (let i = 0; i < runs; i++) {
    const t0 = performance.now();
    const { witness } = await new Noir(artifact as never).execute(inputs as never);
    const t1 = performance.now();
    const api = await Barretenberg.new({ threads }); // a fresh instance per run, as the app does
    const backend = new UltraHonkBackend(artifact.bytecode, api);
    const proof = await backend.generateProof(witness);
    const t2 = performance.now();
    const verified = await backend.verifyProof(proof);
    const t3 = performance.now();
    await api.destroy();
    proofBytes = proof.proof.length;
    out.push({ witnessMs: t1 - t0, proveMs: t2 - t1, verifyMs: t3 - t2, verified });
  }
  return { threads, isolated: globalThis.crossOriginIsolated, runs: out, proofBytes };
};
