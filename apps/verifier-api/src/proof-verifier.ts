/**
 * Cryptographic verification of credential_eligibility proofs with bb.js (UltraHonk).
 * Uses ONLY the proof, the public inputs and the verification key derived from the
 * committed circuit artifact. It never sees a witness or credential.
 */
import fs from 'node:fs';
import path from 'node:path';
import { Barretenberg, UltraHonkBackend } from '@aztec-foundation/bb.js';

export const ARTIFACT_PATH = path.resolve(import.meta.dirname, '../../../circuits/credential-eligibility/artifact/credential_eligibility.json');

export interface ProofVerifier {
  verify(proof: Uint8Array, publicInputs: string[]): Promise<boolean>;
  close(): Promise<void>;
}

export async function createBbVerifier(threads = 1): Promise<ProofVerifier> {
  const artifact = JSON.parse(fs.readFileSync(ARTIFACT_PATH, 'utf8')) as { bytecode: string };
  const api = await Barretenberg.new({ threads });
  const backend = new UltraHonkBackend(artifact.bytecode, api);
  return {
    async verify(proof, publicInputs) {
      try {
        return await backend.verifyProof({ proof, publicInputs });
      } catch {
        return false; // malformed proofs make bb.js throw; treat as invalid
      }
    },
    close: () => api.destroy(),
  };
}
