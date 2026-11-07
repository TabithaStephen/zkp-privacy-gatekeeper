/**
 * Test harness: a real verifier app (SQLite store, bb.js verification) plus a real
 * prover (noir_js + bb.js) that turns credentials from the real issuer code into proofs.
 */
import fs from 'node:fs';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import type { KeyObject } from 'node:crypto';
import { Barretenberg, UltraHonkBackend } from '@aztec-foundation/bb.js';
import { Noir } from '@noir-lang/noir_js';
import { buildCircuitInputs, generateIssuerKeyPair, issueCredential, issuerPublicInfo } from '@zkpg/credentials';
import { createVerifierApp, type ProofRequestRecord, type VerifierConfig } from '../src/app.ts';
import { ARTIFACT_PATH, createBbVerifier, type ProofVerifier } from '../src/proof-verifier.ts';
import { VerifierStore } from '../src/store.ts';

export const TOKEN = 'test-verifier-token-0123456789abcdef0123456789';
export const artifact = JSON.parse(fs.readFileSync(ARTIFACT_PATH, 'utf8'));
export const issuerKey = generateIssuerKeyPair().privateKey;
export const ISSUER = issuerPublicInfo(issuerKey);

export interface Submission { proof: string; publicInputs: string[] }

export class Prover {
  private constructor(private api: Barretenberg, private backend: UltraHonkBackend) {}
  static async create() {
    const api = await Barretenberg.new({ threads: 1 });
    return new Prover(api, new UltraHonkBackend(artifact.bytecode, api));
  }
  async prove(income: bigint, req: ProofRequestRecord, key: KeyObject = issuerKey): Promise<Submission> {
    const issuedAt = BigInt(req.currentTime) - 86_400n;
    const cred = issueCredential(key, { subjectId: 1001n, annualIncomeInr: income, validitySeconds: 30n * 86_400n, issuedAt });
    const inputs = buildCircuitInputs(cred, issuerPublicInfo(key), {
      minimumIncome: BigInt(req.minimumIncome), currentTime: BigInt(req.currentTime), challenge: BigInt(req.challenge),
    });
    const { witness } = await new Noir(artifact).execute(inputs as never);
    const p = await this.backend.generateProof(witness);
    return { proof: Buffer.from(p.proof).toString('base64'), publicInputs: p.publicInputs.map((h) => '0x' + h.replace(/^0x/, '').padStart(64, '0')) };
  }
  close() { return this.api.destroy(); }
}

export class TestServer {
  base = '';
  logs: string[] = [];
  store!: VerifierStore;
  private server!: ReturnType<ReturnType<typeof createVerifierApp>['listen']>;
  constructor(readonly dbPath: string, private verifier: ProofVerifier, private overrides: Partial<VerifierConfig> = {}) {}

  async start() {
    this.store = new VerifierStore(this.dbPath);
    this.server = createVerifierApp({
      store: this.store,
      proofVerifier: this.verifier,
      trustedIssuers: async () => [ISSUER],
      verifierToken: TOKEN,
      log: (m) => this.logs.push(m),
      ...this.overrides,
    }).listen(0);
    await new Promise((r) => this.server.once('listening', r));
    this.base = `http://127.0.0.1:${(this.server.address() as AddressInfo).port}`;
    return this;
  }
  async stop() {
    await new Promise((r) => this.server.close(r));
    this.store.close();
  }

  call(p: string, body?: unknown, auth = false) {
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (auth) headers.authorization = `Bearer ${TOKEN}`;
    return fetch(`${this.base}${p}`, body === undefined ? { headers } : { method: 'POST', headers, body: typeof body === 'string' ? body : JSON.stringify(body) });
  }
  async newRequest(minimumIncome = '800000'): Promise<ProofRequestRecord> {
    const res = await this.call('/api/verifier/requests', { verifierName: 'Demo Lender', minimumIncome }, true);
    if (res.status !== 201) throw new Error(`create failed: ${res.status}`);
    return (await res.json()) as ProofRequestRecord;
  }
  submit(id: string, s: unknown) {
    return this.call(`/api/verifier/requests/${id}/proof`, s);
  }
}

export async function sharedVerifier() {
  return createBbVerifier(1);
}

export const tmpDb = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'zkpg-verifier-')), 'verifier.sqlite');
