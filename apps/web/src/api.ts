import type { Credential, IssuerInfo, ProofRequest, ProofSubmission } from './zk/types.ts';

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { ...init, headers: { 'content-type': 'application/json', ...(init?.headers ?? {}) } });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error((body as { error?: string }).error ?? `HTTP ${res.status}`);
  return body as T;
}
const post = <T>(path: string, body: unknown) => call<T>(path, { method: 'POST', body: JSON.stringify(body) });

export const issuerApi = {
  publicKey: () => call<IssuerInfo>('/api/issuer/public-key'),
  issue: (b: { subjectId: string; annualIncomeInr: string; validityDays: number }) => post<Credential>('/api/issuer/credentials', b),
};

export const verifierApi = {
  create: (b: { verifierName: string; minimumIncome: string }) => post<ProofRequest>('/api/verifier/requests', b),
  list: () => call<ProofRequest[]>('/api/verifier/requests'),
  get: (id: string) => call<ProofRequest>(`/api/verifier/requests/${encodeURIComponent(id)}`),
  submit: (id: string, s: ProofSubmission) => post<ProofRequest>(`/api/verifier/requests/${encodeURIComponent(id)}/proof`, s),
  decline: (id: string) => post<ProofRequest>(`/api/verifier/requests/${encodeURIComponent(id)}/decline`, {}),
};
