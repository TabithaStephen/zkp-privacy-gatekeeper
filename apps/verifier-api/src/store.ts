/**
 * Persistent verifier state in SQLite (node:sqlite, built into Node 22).
 *
 * Stores ONLY public data: request parameters, challenges, decisions and an audit
 * trail. It never stores incomes, credentials, proofs or public-input blobs; the
 * audit log keeps a SHA-256 fingerprint of each proof instead.
 *
 * Replay protection: a request is decided by ONE atomic statement
 *   UPDATE ... SET status = ? WHERE id = ? AND status = 'PENDING'
 * so two concurrent submissions cannot both succeed, and decisions survive restarts.
 */
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

export type Status = 'PENDING' | 'ELIGIBLE' | 'NOT_ELIGIBLE' | 'INVALID' | 'EXPIRED';

export interface ProofRequestRecord {
  id: string;
  verifierName: string;
  minimumIncome: string;
  currentTime: string;
  challenge: string;
  createdAt: string;
  expiresAt: string; // unix seconds
  status: Status;
  reason?: string;
  decidedAt?: string;
}

export type AuditEvent =
  | 'REQUEST_CREATED'
  | 'PROOF_RECEIVED'
  | 'DECISION'
  | 'DECLINED'
  | 'EXPIRED'
  | 'REPLAY_REJECTED'
  | 'PAYLOAD_REJECTED'
  | 'AUTH_DENIED'
  | 'RATE_LIMITED';

export interface AuditEntry {
  id: number;
  at: string;
  event: AuditEvent;
  requestId?: string;
  outcome?: string;
  reason?: string;
  issuerKid?: string;
  proofDigest?: string; // first 16 bytes of SHA-256(proof), hex
}

interface Row {
  [k: string]: string | number | null;
}

const toRecord = (r: Row): ProofRequestRecord => ({
  id: String(r.id),
  verifierName: String(r.verifier_name),
  minimumIncome: String(r.minimum_income),
  currentTime: String(r.current_time),
  challenge: String(r.challenge),
  createdAt: String(r.created_at),
  expiresAt: String(r.expires_at),
  status: r.status as Status,
  ...(r.reason ? { reason: String(r.reason) } : {}),
  ...(r.decided_at ? { decidedAt: String(r.decided_at) } : {}),
});

export class VerifierStore {
  private db: DatabaseSync;

  constructor(file: string) {
    if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(file);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS requests (
        id             TEXT PRIMARY KEY,
        verifier_name  TEXT NOT NULL,
        minimum_income TEXT NOT NULL,
        current_time   TEXT NOT NULL,
        challenge      TEXT NOT NULL UNIQUE,
        created_at     TEXT NOT NULL,
        expires_at     TEXT NOT NULL,
        status         TEXT NOT NULL DEFAULT 'PENDING',
        reason         TEXT,
        decided_at     TEXT
      );
      CREATE TABLE IF NOT EXISTS audit_log (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        at           TEXT NOT NULL,
        event        TEXT NOT NULL,
        request_id   TEXT,
        outcome      TEXT,
        reason       TEXT,
        issuer_kid   TEXT,
        proof_digest TEXT
      );
    `);
  }

  createRequest(r: Omit<ProofRequestRecord, 'status'>): ProofRequestRecord {
    this.db
      .prepare('INSERT INTO requests (id, verifier_name, minimum_income, current_time, challenge, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(r.id, r.verifierName, r.minimumIncome, r.currentTime, r.challenge, r.createdAt, r.expiresAt);
    return { ...r, status: 'PENDING' };
  }

  get(id: string): ProofRequestRecord | undefined {
    const row = this.db.prepare('SELECT * FROM requests WHERE id = ?').get(id) as Row | undefined;
    return row ? toRecord(row) : undefined;
  }

  list(limit = 200): ProofRequestRecord[] {
    return (this.db.prepare('SELECT * FROM requests ORDER BY created_at DESC LIMIT ?').all(limit) as Row[]).map(toRecord);
  }

  /** Atomic PENDING → decided transition. Returns false if already decided. */
  decide(id: string, status: Exclude<Status, 'PENDING'>, reason?: string): boolean {
    const res = this.db
      .prepare("UPDATE requests SET status = ?, reason = ?, decided_at = ? WHERE id = ? AND status = 'PENDING'")
      .run(status, reason ?? null, new Date().toISOString(), id);
    return res.changes === 1;
  }

  /** Marks every pending request whose expiry has passed as EXPIRED. Returns their ids. */
  expirePending(nowSeconds: bigint): string[] {
    const rows = this.db.prepare("SELECT id, expires_at FROM requests WHERE status = 'PENDING'").all() as Row[];
    const due = rows.filter((r) => BigInt(String(r.expires_at)) <= nowSeconds).map((r) => String(r.id));
    for (const id of due) this.decide(id, 'EXPIRED', 'REQUEST_EXPIRED');
    return due;
  }

  audit(e: Omit<AuditEntry, 'id' | 'at'>): void {
    this.db
      .prepare('INSERT INTO audit_log (at, event, request_id, outcome, reason, issuer_kid, proof_digest) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(new Date().toISOString(), e.event, e.requestId ?? null, e.outcome ?? null, e.reason ?? null, e.issuerKid ?? null, e.proofDigest ?? null);
  }

  auditLog(limit = 100): AuditEntry[] {
    return (this.db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT ?').all(limit) as Row[]).map((r) => ({
      id: Number(r.id),
      at: String(r.at),
      event: r.event as AuditEvent,
      ...(r.request_id ? { requestId: String(r.request_id) } : {}),
      ...(r.outcome ? { outcome: String(r.outcome) } : {}),
      ...(r.reason ? { reason: String(r.reason) } : {}),
      ...(r.issuer_kid ? { issuerKid: String(r.issuer_kid) } : {}),
      ...(r.proof_digest ? { proofDigest: String(r.proof_digest) } : {}),
    }));
  }

  close(): void {
    this.db.close();
  }
}
