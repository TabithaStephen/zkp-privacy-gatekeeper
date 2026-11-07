/**
 * Simulated issuer (a fictional bank). Signs ZKPG_INCOME_V1 credentials.
 *
 * Security notes:
 *  - The signing key is loaded server-side only; it is never sent to clients.
 *  - Logs never contain income values or full credentials (safe-logging rule).
 *  - Access control for this demo role is added in Milestone 5.
 */
import express, { type Request, type Response } from 'express';
import type { KeyObject } from 'node:crypto';
import { CredentialFormatError, issueCredential, issuerPublicInfo, MAX_VALIDITY_SECONDS } from '@zkpg/credentials';

const DECIMAL = /^(0|[1-9][0-9]*)$/;
const ALLOWED_FIELDS = new Set(['subjectId', 'annualIncomeInr', 'validityDays']);

export function createIssuerApp(privateKey: KeyObject, log: (msg: string) => void = console.log) {
  const app = express();
  const publicInfo = issuerPublicInfo(privateKey);
  app.disable('x-powered-by');
  app.use(express.json({ limit: '4kb' }));

  app.get('/api/issuer/public-key', (_req: Request, res: Response) => {
    res.json({ name: 'Fictional Bank of Example (demo issuer)', ...publicInfo });
  });

  app.post('/api/issuer/credentials', (req: Request, res: Response) => {
    const body = req.body as Record<string, unknown> | undefined;
    if (!body || typeof body !== 'object') return res.status(400).json({ error: 'JSON body required' });
    const extra = Object.keys(body).filter((k) => !ALLOWED_FIELDS.has(k));
    if (extra.length) return res.status(400).json({ error: `unexpected field(s): ${extra.join(', ')}` });

    const { subjectId, annualIncomeInr, validityDays } = body;
    if (typeof subjectId !== 'string' || !DECIMAL.test(subjectId)) return res.status(400).json({ error: 'subjectId must be a decimal string' });
    if (typeof annualIncomeInr !== 'string' || !DECIMAL.test(annualIncomeInr)) return res.status(400).json({ error: 'annualIncomeInr must be a decimal string (whole rupees)' });
    if (typeof validityDays !== 'number' || !Number.isInteger(validityDays) || validityDays < 1) {
      return res.status(400).json({ error: 'validityDays must be a positive integer' });
    }
    const validitySeconds = BigInt(validityDays) * 86_400n;
    if (validitySeconds > MAX_VALIDITY_SECONDS) return res.status(400).json({ error: 'validityDays must be at most 366' });

    try {
      const credential = issueCredential(privateKey, { subjectId: BigInt(subjectId), annualIncomeInr: BigInt(annualIncomeInr), validitySeconds });
      log(`[issuer] issued ${credential.type} kid=${credential.issuer.kid} expires=${credential.claims.expiresAt}`);
      return res.status(201).json(credential);
    } catch (e) {
      if (e instanceof CredentialFormatError) return res.status(400).json({ error: e.message });
      throw e;
    }
  });

  // Generic error handler: never echo request bodies (they contain income).
  app.use((err: unknown, _req: Request, res: Response, _next: express.NextFunction) => {
    const status = (err as { status?: number }).status ?? 500;
    log(`[issuer] error status=${status} type=${(err as Error)?.name ?? 'unknown'}`);
    res.status(status).json({ error: status === 500 ? 'internal error' : 'bad request' });
  });

  return app;
}
