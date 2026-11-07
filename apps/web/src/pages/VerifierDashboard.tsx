import { type FormEvent, useCallback, useEffect, useState } from 'react';
import { verifierApi } from '../api.ts';
import { Button, Card, Empty, Field, inputClass, Mono, Notice, StatusBadge } from '../components/ui.tsx';
import { formatInr, formatIso, short } from '../format.ts';
import type { ProofRequest } from '../zk/types.ts';

const REASONS: Record<string, string> = {
  NO_PROOF_PROVIDED: 'Holder declined or could not prove',
  UNTRUSTED_ISSUER: 'Credential issuer is not trusted',
  THRESHOLD_MISMATCH: 'Proof is for a different threshold',
  CHALLENGE_MISMATCH: 'Proof belongs to another request',
  STALE_TIME: 'Proof uses a different request time',
  PROOF_VERIFICATION_FAILED: 'Cryptographic verification failed',
  MALFORMED_PUBLIC_INPUTS: 'Malformed public inputs',
};

export function VerifierDashboard() {
  const [form, setForm] = useState({ verifierName: 'Demo Lender', minimumIncome: '800000' });
  const [requests, setRequests] = useState<ProofRequest[]>([]);
  const [latest, setLatest] = useState<ProofRequest | null>(null);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);

  const refresh = useCallback(() => {
    verifierApi.list().then((r) => { setRequests(r); setError(''); }).catch((e) => setError(`Verifier service unavailable: ${e.message}`));
  }, []);
  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 2500);
    return () => clearInterval(t);
  }, [refresh]);

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    try {
      const r = await verifierApi.create(form);
      setLatest(r); setCopied(false); refresh();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  const holderLink = latest ? `${window.location.origin}${window.location.pathname}#/holder?request=${latest.id}` : '';

  return (
    <div className="space-y-6">
      <div className="grid gap-6 lg:grid-cols-[1fr_1.1fr]">
        <Card title="Create a verification request" subtitle="Ask an applicant to prove an income condition. A fresh random challenge is generated each time.">
          <form onSubmit={onCreate} className="space-y-4">
            <Field label="Verifier name" hint="Shown to the applicant before they consent.">
              <input className={inputClass} required maxLength={80} value={form.verifierName} onChange={(e) => setForm({ ...form, verifierName: e.target.value })} />
            </Field>
            <Field label="Minimum annual income (₹)">
              <input className={inputClass} inputMode="numeric" pattern="[0-9]+" required value={form.minimumIncome} onChange={(e) => setForm({ ...form, minimumIncome: e.target.value })} />
            </Field>
            <Button type="submit">Create request</Button>
          </form>
          {error && <div className="mt-4"><Notice tone="bad">{error}</Notice></div>}
        </Card>

        <Card title="Share with the applicant" subtitle="The applicant opens this request in their wallet, reviews it and decides whether to prove.">
          {latest ? (
            <div className="space-y-4">
              <p className="text-sm">Condition: <strong>annual income ≥ {formatInr(latest.minimumIncome)}</strong></p>
              <div>
                <p className="mb-1.5 text-xs uppercase tracking-wider text-muted">Request ID</p>
                <p className="break-all rounded-lg border border-navy-700 bg-navy-850 p-3"><Mono>{latest.id}</Mono></p>
              </div>
              <div className="flex flex-wrap gap-3">
                <Button variant="secondary" onClick={() => { void navigator.clipboard?.writeText(holderLink).then(() => setCopied(true)); }}>{copied ? 'Link copied' : 'Copy wallet link'}</Button>
                <a href={`#/holder?request=${latest.id}`} className="inline-flex items-center rounded-lg px-4 py-2 text-sm text-accent hover:underline">Open in holder wallet →</a>
              </div>
              <p className="text-xs text-muted">Challenge <Mono>{short(latest.challenge, 8)}</Mono>. The proof must be bound to this value, so it cannot be reused for another request.</p>
            </div>
          ) : (
            <p className="text-sm text-muted">Create a request to get a shareable link.</p>
          )}
        </Card>
      </div>

      <Card title="Verification requests" subtitle="Results come from independent proof verification on the server. Exact incomes are never received or stored.">
        {requests.length === 0 ? (
          <Empty>No requests yet.</Empty>
        ) : (
          <div className="-mx-5 overflow-x-auto">
            <table className="w-full min-w-[640px] text-left text-sm">
              <thead className="text-xs uppercase tracking-wider text-muted">
                <tr className="border-b border-navy-700">
                  <th className="px-5 py-2 font-medium">Created</th>
                  <th className="px-5 py-2 font-medium">Verifier</th>
                  <th className="px-5 py-2 font-medium">Condition</th>
                  <th className="px-5 py-2 font-medium">Result</th>
                  <th className="px-5 py-2 font-medium">Detail</th>
                </tr>
              </thead>
              <tbody>
                {requests.map((r) => (
                  <tr key={r.id} data-request-id={r.id} className="border-b border-navy-800 last:border-0">
                    <td className="px-5 py-3 text-muted">{formatIso(r.createdAt)}</td>
                    <td className="px-5 py-3">{r.verifierName}</td>
                    <td className="px-5 py-3">income ≥ {formatInr(r.minimumIncome)}</td>
                    <td className="px-5 py-3"><StatusBadge status={r.status} /></td>
                    <td className="px-5 py-3 text-muted">
                      {r.status === 'ELIGIBLE' && 'Proof verified · income not disclosed'}
                      {r.reason && (REASONS[r.reason] ?? r.reason)}
                      {r.status === 'PENDING' && <>Awaiting applicant · <Mono>{short(r.id, 4)}</Mono></>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
