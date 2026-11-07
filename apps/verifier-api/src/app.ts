/**
 * Independent verifier (a fictional lender), Milestone 5 hardening.
 *
 *  Verifier role (bearer token):
 *    POST /api/verifier/requests              create a request: threshold + fresh challenge + expiry
 *    GET  /api/verifier/requests              list requests and results
 *    GET  /api/verifier/audit                 privacy-conscious audit log
 *  Holder (capability: the unguessable request id):
 *    GET  /api/verifier/requests/:id          review a request before consenting
 *    POST /api/verifier/requests/:id/proof    submit exactly {proof, publicInputs}
 *    POST /api/verifier/requests/:id/decline  decline → NOT_ELIGIBLE
 *
 * Order of checks for a submission: expiry → already decided (replay) → payload
 * shape → public-input policy → cryptographic verification → atomic decision.
 */
import crypto from 'node:crypto';
import express, { type NextFunction, type Request, type Response } from 'express';
import { BN254_R, checkPublicInputs, decodePublicInputs, type IssuerPublicInfo, PUBLIC_INPUT_COUNT, PublicInputError, U64_MAX } from '@zkpg/credentials';
import { rateLimit, requireRoleToken, securityHeaders } from '@zkpg/server-security';
import type { ProofVerifier } from './proof-verifier.ts';
import type { ProofRequestRecord, VerifierStore } from './store.ts';

export type { ProofRequestRecord, Status } from './store.ts';

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

export interface VerifierConfig {
  store: VerifierStore;
  proofVerifier: ProofVerifier;
  trustedIssuers: () => Promise<IssuerPublicInfo[]>;
  verifierToken: string;
  /** How long a holder has to answer a request. */
  requestTtlSeconds?: bigint;
  /** Thresholds must be multiples of this (limits how precisely repeated queries can narrow an income). */
  thresholdStep?: bigint;
  /** Max requests a verifier may create per window. */
  createLimit?: { windowMs: number; max: number };
  /** Max submissions (proof/decline) per client IP per window. */
  submitLimit?: { windowMs: number; max: number };
  now?: () => bigint;
  clockMs?: () => number;
  log?: (msg: string) => void;
}

export function createVerifierApp(cfg: VerifierConfig) {
  const { store } = cfg;
  const now = cfg.now ?? (() => BigInt(Math.floor(Date.now() / 1000)));
  const log = cfg.log ?? console.log;
  const ttl = cfg.requestTtlSeconds ?? 600n;
  const step = cfg.thresholdStep ?? 10_000n;

  const app = express();
  app.disable('x-powered-by');
  app.use(securityHeaders);
  app.use(express.json({ limit: '128kb' }));

  const verifierOnly = requireRoleToken('verifier', cfg.verifierToken, (req) => {
    store.audit({ event: 'AUTH_DENIED', reason: `${req.method} ${req.path}` });
    log(`[verifier] auth denied ${req.method} ${req.path}`);
  });
  const limited = (opts: { windowMs: number; max: number }, scope: string) =>
    rateLimit({ ...opts, ...(cfg.clockMs ? { now: cfg.clockMs } : {}), onLimited: (req) => store.audit({ event: 'RATE_LIMITED', reason: `${scope} ${req.ip ?? ''}`.trim() }) });
  const createLimiter = limited(cfg.createLimit ?? { windowMs: 10 * 60_000, max: 30 }, 'create');
  const submitLimiter = limited(cfg.submitLimit ?? { windowMs: 60_000, max: 20 }, 'submit');

  /** Loads a request, first expiring it if its deadline has passed. */
  const load = (id: string): ProofRequestRecord | undefined => {
    const r = store.get(id);
    if (r?.status === 'PENDING' && BigInt(r.expiresAt) <= now()) {
      if (store.decide(r.id, 'EXPIRED', 'REQUEST_EXPIRED')) {
        store.audit({ event: 'EXPIRED', requestId: r.id, outcome: 'EXPIRED', reason: 'REQUEST_EXPIRED' });
        log(`[verifier] request=${r.id} result=EXPIRED`);
      }
      return store.get(id);
    }
    return r;
  };

  const finish = (res: Response, r: ProofRequestRecord, status: 'ELIGIBLE' | 'NOT_ELIGIBLE' | 'INVALID', reason?: string, extra: { issuerKid?: string; proofDigest?: string } = {}) => {
    if (!store.decide(r.id, status, reason)) {
      // Lost a race with a concurrent submission: the request was decided in between.
      store.audit({ event: 'REPLAY_REJECTED', requestId: r.id, reason: 'CONCURRENT_SUBMISSION', ...extra });
      return res.status(409).json({ error: 'request already decided', status: store.get(r.id)?.status });
    }
    store.audit({ event: status === 'NOT_ELIGIBLE' ? 'DECLINED' : 'DECISION', requestId: r.id, outcome: status, ...(reason ? { reason } : {}), ...extra });
    log(`[verifier] request=${r.id} result=${status}${reason ? ` reason=${reason}` : ''}`);
    return res.json(store.get(r.id));
  };

  /** Shared guard for holder actions: unknown → 404, expired → 410, decided → 409. */
  const pendingOr = (req: Request, res: Response): ProofRequestRecord | undefined => {
    const r = load(String(req.params.id));
    if (!r) { res.status(404).json({ error: 'unknown request' }); return undefined; }
    if (r.status === 'EXPIRED') { res.status(410).json({ error: 'request expired', status: r.status }); return undefined; }
    if (r.status !== 'PENDING') {
      store.audit({ event: 'REPLAY_REJECTED', requestId: r.id, reason: 'ALREADY_DECIDED' });
      res.status(409).json({ error: 'request already decided', status: r.status });
      return undefined;
    }
    return r;
  };

  // ── Verifier role ─────────────────────────────────────────────────────────
  app.post('/api/verifier/requests', verifierOnly, createLimiter, (req, res) => {
    const { verifierName, minimumIncome } = (req.body ?? {}) as Record<string, unknown>;
    if (typeof verifierName !== 'string' || verifierName.trim().length === 0 || verifierName.length > 80) {
      return res.status(400).json({ error: 'verifierName must be 1-80 characters' });
    }
    if (typeof minimumIncome !== 'string' || !DECIMAL.test(minimumIncome) || BigInt(minimumIncome) > U64_MAX) {
      return res.status(400).json({ error: 'minimumIncome must be a decimal string (whole rupees)' });
    }
    if (BigInt(minimumIncome) % step !== 0n) {
      return res.status(400).json({ error: `minimumIncome must be a multiple of ₹${step} (limits threshold probing)` });
    }
    const t = now();
    const record = store.createRequest({
      id: crypto.randomUUID(),
      verifierName: verifierName.trim(),
      minimumIncome,
      currentTime: t.toString(),
      challenge: '0x' + newChallenge().toString(16).padStart(64, '0'),
      createdAt: new Date().toISOString(),
      expiresAt: (t + ttl).toString(),
    });
    store.audit({ event: 'REQUEST_CREATED', requestId: record.id, reason: `threshold=${minimumIncome}` });
    log(`[verifier] created request=${record.id} threshold=${minimumIncome}`);
    return res.status(201).json(record);
  });

  app.get('/api/verifier/requests', verifierOnly, (_req, res) => {
    store.expirePending(now()).forEach((id) => store.audit({ event: 'EXPIRED', requestId: id, outcome: 'EXPIRED', reason: 'REQUEST_EXPIRED' }));
    res.json(store.list());
  });

  app.get('/api/verifier/audit', verifierOnly, (req, res) => {
    const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 500);
    res.json(store.auditLog(limit));
  });

  // ── Holder actions (capability: request id) ───────────────────────────────
  app.get('/api/verifier/requests/:id', (req, res) => {
    const r = load(req.params.id);
    return r ? res.json(r) : res.status(404).json({ error: 'unknown request' });
  });

  app.post('/api/verifier/requests/:id/decline', submitLimiter, (req, res) => {
    const r = pendingOr(req, res);
    if (!r) return;
    return finish(res, r, 'NOT_ELIGIBLE', 'NO_PROOF_PROVIDED');
  });

  app.post('/api/verifier/requests/:id/proof', submitLimiter, async (req, res) => {
    const r = pendingOr(req, res);
    if (!r) return;

    // Strict payload: exactly {proof, publicInputs}. Anything else, e.g. an income
    // or credential field, is refused, and the request stays pending.
    const reject = (error: string) => {
      store.audit({ event: 'PAYLOAD_REJECTED', requestId: r.id, reason: error.split(' ')[0] ?? 'invalid' });
      return res.status(400).json({ error });
    };
    const body = req.body as Record<string, unknown> | undefined;
    const keys = body && typeof body === 'object' ? Object.keys(body).sort() : [];
    if (keys.join(',') !== 'proof,publicInputs') return reject('body must contain exactly: proof, publicInputs');
    const { proof, publicInputs } = body as { proof: unknown; publicInputs: unknown };
    if (typeof proof !== 'string' || !BASE64.test(proof) || proof.length > (MAX_PROOF_BYTES * 4) / 3) return reject('proof must be base64');
    if (!Array.isArray(publicInputs) || publicInputs.length !== PUBLIC_INPUT_COUNT || !publicInputs.every((p) => typeof p === 'string' && FIELD_HEX.test(p))) {
      return reject(`publicInputs must be ${PUBLIC_INPUT_COUNT} 0x-prefixed 32-byte hex strings`);
    }

    const proofBytes = Buffer.from(proof, 'base64');
    const proofDigest = crypto.createHash('sha256').update(proofBytes).digest('hex').slice(0, 32);
    store.audit({ event: 'PROOF_RECEIVED', requestId: r.id, proofDigest });

    // 1. Policy: are these the public inputs THIS request asked for, from a trusted issuer?
    let decoded;
    try {
      decoded = decodePublicInputs(Buffer.concat(publicInputs.map((h: string) => Buffer.from(h.slice(2), 'hex'))));
    } catch (e) {
      if (e instanceof PublicInputError) return finish(res, r, 'INVALID', 'MALFORMED_PUBLIC_INPUTS', { proofDigest });
      throw e;
    }
    const trusted = await cfg.trustedIssuers();
    const policy = checkPublicInputs(decoded, {
      trustedIssuers: trusted,
      minimumIncome: BigInt(r.minimumIncome),
      challenge: BigInt(r.challenge),
      now: BigInt(r.currentTime),
      maxClockSkewSeconds: 0n, // current_time must be exactly the one this request chose
    });
    if (!policy.ok) return finish(res, r, 'INVALID', policy.reason, { proofDigest });

    // 2. Cryptography: does the proof verify for exactly these public inputs?
    const ok = await cfg.proofVerifier.verify(proofBytes, publicInputs);
    if (!ok) return finish(res, r, 'INVALID', 'PROOF_VERIFICATION_FAILED', { proofDigest, issuerKid: policy.issuerKid });

    // 3. A deadline may have passed while verifying: re-check before accepting.
    if (BigInt(r.expiresAt) <= now()) {
      load(r.id);
      return res.status(410).json({ error: 'request expired', status: 'EXPIRED' });
    }
    return finish(res, r, 'ELIGIBLE', undefined, { proofDigest, issuerKid: policy.issuerKid });
  });

  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    const status = (err as { status?: number }).status ?? 500;
    log(`[verifier] error status=${status} type=${(err as Error)?.name ?? 'unknown'}`);
    res.status(status).json({ error: status === 500 ? 'internal error' : status === 413 ? 'payload too large' : 'bad request' });
  });

  return app;
}
