/**
 * Holder wallet storage (demo): credentials and a privacy-conscious history in
 * localStorage on THIS browser only. A production wallet would use encrypted storage.
 * History entries never contain the income.
 */
import type { Credential, RequestStatus } from './zk/types.ts';

const CRED_KEY = 'zkpg.wallet.credentials.v1';
const HIST_KEY = 'zkpg.wallet.history.v1';

export interface HistoryEntry {
  requestId: string;
  verifierName: string;
  minimumIncome: string;
  result: RequestStatus;
  reason?: string;
  at: string;
}

function read<T>(key: string): T[] {
  try {
    const v = JSON.parse(localStorage.getItem(key) ?? '[]');
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
}
function write<T>(key: string, v: T[]) {
  try {
    localStorage.setItem(key, JSON.stringify(v));
  } catch {
    /* storage unavailable: keep in memory only */
  }
}

export const wallet = {
  credentials: () => read<Credential>(CRED_KEY),
  addCredential(c: Credential) {
    const all = read<Credential>(CRED_KEY).filter((x) => x.claims.credentialId !== c.claims.credentialId);
    write(CRED_KEY, [c, ...all]);
  },
  removeCredential(credentialId: string) {
    write(CRED_KEY, read<Credential>(CRED_KEY).filter((x) => x.claims.credentialId !== credentialId));
  },
  history: () => read<HistoryEntry>(HIST_KEY),
  addHistory(e: HistoryEntry) {
    write(HIST_KEY, [e, ...read<HistoryEntry>(HIST_KEY)].slice(0, 50));
  },
};
