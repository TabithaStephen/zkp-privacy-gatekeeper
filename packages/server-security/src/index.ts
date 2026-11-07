/**
 * Shared HTTP hardening for the issuer and verifier services.
 *
 *  - requireRoleToken: demo access control. A role (issuer / verifier) is proven by a
 *    bearer token from the environment. Compared in constant time.
 *  - rateLimit: fixed-window, in-memory limiter (per process). Slows threshold probing
 *    and brute-force attempts; a multi-instance deployment would need a shared store.
 *  - securityHeaders: no caching of API responses, no MIME sniffing, no framing.
 */
import crypto from 'node:crypto';
import type { NextFunction, Request, RequestHandler, Response } from 'express';

export const MIN_TOKEN_LENGTH = 32;

/** Throws at start-up if a role token is missing or weak. */
export function assertStrongToken(name: string, value: string | undefined): string {
  if (!value || value.length < MIN_TOKEN_LENGTH) {
    throw new Error(`${name} must be set to a random string of at least ${MIN_TOKEN_LENGTH} characters (run: npm run setup)`);
  }
  return value;
}

const digest = (s: string) => crypto.createHash('sha256').update(s).digest();

/** Constant-time comparison (hashing first makes the lengths equal). */
export function tokensEqual(a: string, b: string): boolean {
  return crypto.timingSafeEqual(digest(a), digest(b));
}

export function requireRoleToken(role: string, expected: string, onDenied?: (req: Request) => void): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    const header = req.get('authorization') ?? '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : '';
    if (token && tokensEqual(token, expected)) return next();
    onDenied?.(req);
    res.status(401).json({ error: `${role} role required` });
  };
}

export interface RateLimitOptions {
  windowMs: number;
  max: number;
  key?: (req: Request) => string;
  now?: () => number;
  onLimited?: (req: Request) => void;
}

export function rateLimit(opts: RateLimitOptions): RequestHandler {
  const hits = new Map<string, { start: number; count: number }>();
  const now = opts.now ?? Date.now;
  const keyOf = opts.key ?? ((req: Request) => req.ip ?? 'unknown');
  return (req, res, next) => {
    const t = now();
    const k = keyOf(req);
    let w = hits.get(k);
    if (!w || t - w.start >= opts.windowMs) {
      w = { start: t, count: 0 };
      hits.set(k, w);
    }
    w.count++;
    if (hits.size > 10_000) for (const [key, v] of hits) if (t - v.start >= opts.windowMs) hits.delete(key);
    if (w.count > opts.max) {
      opts.onLimited?.(req);
      res.setHeader('Retry-After', String(Math.ceil((w.start + opts.windowMs - t) / 1000)));
      return res.status(429).json({ error: 'too many requests' });
    }
    next();
  };
}

export const securityHeaders: RequestHandler = (_req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
  next();
};
