/**
 * Thin wrapper around the nargo and bb CLIs for integration tests.
 * Witness/prover files are written to a temp dir OUTSIDE the repository, because
 * they contain the private witness.
 */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { type CircuitInputs, toProverToml } from '../src/circuit-inputs.ts';

export const CIRCUIT_DIR = path.resolve(import.meta.dirname, '../../../circuits/credential-eligibility');
const BYTECODE = path.join(CIRCUIT_DIR, 'target/credential_eligibility.json');

export class Prover {
  readonly tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'zkpg-proofs-'));
  readonly vk = path.join(this.tmp, 'vk/vk');

  setup(): void {
    execFileSync('nargo', ['compile'], { cwd: CIRCUIT_DIR, stdio: 'pipe' });
    execFileSync('bb', ['write_vk', '-b', BYTECODE, '-o', path.join(this.tmp, 'vk')], { stdio: 'pipe' });
  }

  cleanup(): void {
    fs.rmSync(this.tmp, { recursive: true, force: true });
    for (const f of fs.readdirSync(path.join(CIRCUIT_DIR, 'target'))) {
      if (f.startsWith('it_') && f.endsWith('.gz')) fs.rmSync(path.join(CIRCUIT_DIR, 'target', f));
    }
  }

  /** Solves the witness. Returns the circuit's assertion message on failure. */
  execute(name: string, inputs: CircuitInputs): { ok: true } | { ok: false; error: string } {
    const toml = path.join(this.tmp, `${name}.toml`);
    fs.writeFileSync(toml, toProverToml(inputs), { mode: 0o600 });
    try {
      execFileSync('nargo', ['execute', '-p', toml.replace(/\.toml$/, ''), `it_${name}`], { cwd: CIRCUIT_DIR, stdio: 'pipe' });
      return { ok: true };
    } catch (e) {
      const out = String((e as { stderr?: Buffer }).stderr ?? '');
      const msg = out.match(/(invalid issuer signature|credential expired|credential not yet valid|income below threshold)/);
      return { ok: false, error: msg?.[1] ?? out.split('\n')[0] ?? 'unknown' };
    }
  }

  /** Generates a real UltraHonk proof; returns file paths and the prove time. */
  prove(name: string): { proof: string; publicInputs: string; ms: number } {
    const out = path.join(this.tmp, `proof_${name}`);
    const t = performance.now();
    execFileSync('bb', ['prove', '-b', BYTECODE, '-w', path.join(CIRCUIT_DIR, `target/it_${name}.gz`), '-k', this.vk, '-o', out], { stdio: 'pipe' });
    return { proof: path.join(out, 'proof'), publicInputs: path.join(out, 'public_inputs'), ms: performance.now() - t };
  }

  /** Cryptographic verification with bb: uses ONLY proof, public inputs and vk. */
  verify(proof: string, publicInputs: string): boolean {
    try {
      execFileSync('bb', ['verify', '-p', proof, '-k', this.vk, '-i', publicInputs], { stdio: 'pipe' });
      return true;
    } catch {
      return false;
    }
  }

  /** Copies a file into the temp dir with a modification applied. */
  variant(src: string, name: string, edit: (b: Buffer) => void): string {
    const b = fs.readFileSync(src);
    edit(b);
    const dst = path.join(this.tmp, name);
    fs.writeFileSync(dst, b);
    return dst;
  }
}

/** Overwrites public input number `index` (32-byte big-endian field) in place. */
export function setField(buf: Buffer, index: number, value: bigint): void {
  Buffer.from(value.toString(16).padStart(64, '0'), 'hex').copy(buf, index * 32);
}
