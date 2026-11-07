/**
 * In-browser proof generation: noir_js computes the witness, bb.js (WebAssembly)
 * generates the UltraHonk proof. Everything here runs on the holder's device; only
 * the returned ProofSubmission is ever sent anywhere.
 */
import artifact from '../../../../circuits/credential-eligibility/artifact/credential_eligibility.json';
import { type CircuitInputs, normalizePublicInputs, toBase64 } from './inputs.ts';
import type { ProofSubmission } from './types.ts';

export type Stage = 'loading' | 'witness' | 'proving' | 'done';

export interface ProofResult {
  submission: ProofSubmission;
  proofBytes: number;
  threads: number;
  timings: { witnessMs: number; proveMs: number; totalMs: number };
}

/** Maps the circuit's assertion messages to user-facing explanations. */
export function explainCircuitError(err: unknown): string {
  const msg = String((err as Error)?.message ?? err);
  if (msg.includes('invalid issuer signature')) return 'The credential signature is not valid for this issuer (it may have been altered).';
  if (msg.includes('income below threshold')) return 'Your credential does not meet the requested condition.';
  if (msg.includes('credential expired')) return 'The credential has expired.';
  if (msg.includes('credential not yet valid')) return 'The credential is not valid yet.';
  return `Proof generation failed: ${msg}`;
}

export async function generateProof(inputs: CircuitInputs, onStage: (s: Stage) => void): Promise<ProofResult> {
  onStage('loading');
  const [{ Noir }, { Barretenberg, UltraHonkBackend }] = await Promise.all([
    import('@noir-lang/noir_js'),
    import('@aztec-foundation/bb.js'),
  ]);

  const t0 = performance.now();
  onStage('witness');
  const { witness } = await new Noir(artifact as never).execute(inputs as never);
  const t1 = performance.now();

  onStage('proving');
  // Multi-threading needs SharedArrayBuffer, which requires cross-origin isolation.
  const threads = globalThis.crossOriginIsolated ? Math.min(navigator.hardwareConcurrency || 4, 8) : 1;
  const api = await Barretenberg.new({ threads });
  try {
    const backend = new UltraHonkBackend(artifact.bytecode, api);
    const proof = await backend.generateProof(witness);
    const t2 = performance.now();
    onStage('done');
    return {
      submission: { proof: toBase64(proof.proof), publicInputs: normalizePublicInputs(proof.publicInputs) },
      proofBytes: proof.proof.length,
      threads,
      timings: { witnessMs: Math.round(t1 - t0), proveMs: Math.round(t2 - t1), totalMs: Math.round(t2 - t0) },
    };
  } finally {
    await api.destroy();
  }
}
