/**
 * Independent verifier (a fictional lender).
 *
 *  POST /api/verifier/requests                 create a proof request (threshold + fresh challenge)
 *  GET  /api/verifier/requests                 list requests and results (no private data exists here)
 *  GET  /api/verifier/requests/:id             one request (the holder reviews this before consenting)
 *  POST /api/verifier/requests/:id/proof       submit {proof, publicInputs}; nothing else is accepted
 *  POST /api/verifier/requests/:id/decline     holder declines or cannot prove → NOT_ELIGIBLE
 *
 * Milestone 5 adds request expiry, audit logs, access control and the security test suite.
 */
import crypto from 'node:crypto';
import express, { type NextFunction, type Request, type Response } from 'express';
import { BN254_R, checkPublicInputs, decodePublicInputs, type IssuerPublicInfo, PUBLIC_INPUT_COUNT, PublicInputError, U64_MAX } from '@zkpg/credentials';
import type { ProofVerifier } from './proof-verifier.ts';

export type Status = 'PENDING' | 'ELIGIBLE' | 'NOT_ELIGIBLE' | 'INVALID';

export interface ProofRequestRecord {
  id: string;
  verifierName: string;
  minimumIncome: string; // decimal string, whole rupees
  currentTime: string; // unix seconds, chosen by the verifier
  challenge: string; // 0x-hex field element
  createdAt: string;
  status: Status;
  reason?: string;
  decidedAt?: string;
}

const DECIMAL = /^(0|[1-9][0-9]*)$/;
const FIELD_HEX = /^0x[0-9a-f]{64}$/;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
const MAX_PROOF_BYTES = 64 * 1024;

/** Random 248-bit challenge: always below the BN254 field modulus. */
export function newChallenge(): bigint {
  const c = BigInt('0x' + crypto.randomBytes(31).toString('hex'));
  if (c >= BN254_R) throw new Error('unreachable');
  return c;
}

export interface VerifierDeps {
  proofVerifier: ProofVerifier;
  trustedIssuers: () => Promise<IssuerPublicInfo[]>;
  now?: () => bigint;
  log?: (msg: string) => void;
}

export function createVerifierApp(deps: VerifierDeps) {
  const now = deps.now ?? (() => BigInt(Math.floor(Date.now() / 1000)));
  const log = deps.log ?? console.log;
  const requests = new Map<string, ProofRequestRecord>();

  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '128kb' }));

  const decide = (r: ProofRequestRecord, status: Exclude<Status, 'PENDING'>, reason?: string) => {
    r.status = status;
    r.decidedAt = new Date().toISOString();
    if (reason) r.reason = reason;
    log(`[verifier] request=${r.id} result=${status}${reason ? ` reason=${reason}` : ''}`);
  };

  app.post('/api/verifier/requests', (req: Request, res: Response) => {
    const { verifierName, minimumIncome } = (req.body ?? {}) as Record<string, unknown>;
    if (typeof verifierName !== 'string' || verifierName.trim().length === 0 || verifierName.length > 80) {
      return res.status(400).json({ error: 'verifierName must be 1-80 characters' });
    }
    if (typeof minimumIncome !== 'string' || !DECIMAL.test(minimumIncome) || BigInt(minimumIncome) > U64_MAX) {
      return res.status(400).json({ error: 'minimumIncome must be a decimal string (whole rupees)' });
    }
    const record: ProofRequestRecord = {
      id: crypto.randomUUID(),
      verifierName: verifierName.trim(),
      minimumIncome,
      currentTime: now().toString(),
      challenge: '0x' + newChallenge().toString(16).padStart(64, '0'),
      createdAt: new Date().toISOString(),
      status: 'PENDING',
    };
    requests.set(record.id, record);
    log(`[verifier] created request=${record.id} threshold=${minimumIncome}`);
    return res.status(201).json(record);
  });

  app.get('/api/verifier/requests', (_req, res) => {
    res.json([...requests.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt)));
  });

  app.get('/api/verifier/requests/:id', (req, res) => {
    const r = requests.get(req.params.id);
    return r ? res.json(r) : res.status(404).json({ error: 'unknown request' });
  });

  app.post('/api/verifier/requests/:id/decline', (req, res) => {
    const r = requests.get(req.params.id);
    if (!r) return res.status(404).json({ error: 'unknown request' });
    if (r.status !== 'PENDING') return res.status(409).json({ error: 'request already decided', status: r.status });
    decide(r, 'NOT_ELIGIBLE', 'NO_PROOF_PROVIDED');
    return res.json(r);
  });

  app.post('/api/verifier/requests/:id/proof', async (req, res) => {
    const r = requests.get(req.params.id);
    if (!r) return res.status(404).json({ error: 'unknown request' });
    if (r.status !== 'PENDING') return res.status(409).json({ error: 'request already decided', status: r.status });

    // Strict payload: exactly {proof, publicInputs}. Anything else, e.g. an income
    // or credential field, is refused so private data cannot be submitted even by mistake.
    const body = req.body as Record<string, unknown> | undefined;
    const keys = body && typeof body === 'object' ? Object.keys(body).sort() : [];
    if (keys.join(',') !== 'proof,publicInputs') {
      return res.status(400).json({ error: 'body must contain exactly: proof, publicInputs' });
    }
    const { proof, publicInputs } = body as { proof: unknown; publicInputs: unknown };
    if (typeof proof !== 'string' || !BASE64.test(proof) || proof.length > (MAX_PROOF_BYTES * 4) / 3) {
      return res.status(400).json({ error: 'proof must be base64' });
    }
    if (!Array.isArray(publicInputs) || publicInputs.length !== PUBLIC_INPUT_COUNT || !publicInputs.every((p) => typeof p === 'string' && FIELD_HEX.test(p))) {
      return res.status(400).json({ error: `publicInputs must be ${PUBLIC_INPUT_COUNT} 0x-prefixed 32-byte hex strings` });
    }

    // 1. Policy: are these the public inputs THIS request asked for, from a trusted issuer?
    let decoded;
    try {
      decoded = decodePublicInputs(Buffer.concat(publicInputs.map((h: string) => Buffer.from(h.slice(2), 'hex'))));
    } catch (e) {
      if (e instanceof PublicInputError) { decide(r, 'INVALID', 'MALFORMED_PUBLIC_INPUTS'); return res.json(r); }
      throw e;
    }
    const policy = checkPublicInputs(decoded, {
      trustedIssuers: await deps.trustedIssuers(),
      minimumIncome: BigInt(r.minimumIncome),
      challenge: BigInt(r.challenge),
      now: BigInt(r.currentTime),
      maxClockSkewSeconds: 0n, // current_time must be exactly the one this request chose
    });
    if (!policy.ok) { decide(r, 'INVALID', policy.reason); return res.json(r); }

    // 2. Cryptography: does the proof verify for exactly these public inputs?
    const ok = await deps.proofVerifier.verify(Buffer.from(proof, 'base64'), publicInputs);
    if (!ok) { decide(r, 'INVALID', 'PROOF_VERIFICATION_FAILED'); return res.json(r); }

    decide(r, 'ELIGIBLE');
    return res.json(r);
  });

  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    const status = (err as { status?: number }).status ?? 500;
    log(`[verifier] error status=${status} type=${(err as Error)?.name ?? 'unknown'}`);
    res.status(status).json({ error: status === 500 ? 'internal error' : 'bad request' });
  });

  return app;
}
