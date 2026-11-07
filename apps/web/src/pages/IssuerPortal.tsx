import { type FormEvent, useEffect, useState } from 'react';
import { issuerApi } from '../api.ts';
import { Button, Card, Field, inputClass, KeyValue, Mono, Notice } from '../components/ui.tsx';
import { formatInr, formatUnix, short } from '../format.ts';
import { wallet } from '../wallet.ts';
import type { Credential, IssuerInfo } from '../zk/types.ts';

export function IssuerPortal() {
  const [info, setInfo] = useState<IssuerInfo | null>(null);
  const [error, setError] = useState('');
  const [form, setForm] = useState({ subjectId: '1001', annualIncomeInr: '950000', validityDays: '365' });
  const [issued, setIssued] = useState<Credential | null>(null);
  const [delivered, setDelivered] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    issuerApi.publicKey().then(setInfo).catch((e) => setError(`Issuer service unavailable: ${e.message}`));
  }, []);

  async function onIssue(e: FormEvent) {
    e.preventDefault();
    setBusy(true); setError(''); setDelivered(false);
    try {
      setIssued(await issuerApi.issue({ subjectId: form.subjectId, annualIncomeInr: form.annualIncomeInr, validityDays: Number(form.validityDays) }));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid gap-6 lg:grid-cols-[1fr_1.1fr]">
      <div className="space-y-6">
        <Card title="Issuer identity" subtitle="Public information any verifier can use to check credentials.">
          {info ? (
            <KeyValue items={[
              ['Issuer', info.name],
              ['Signature', 'ECDSA P-256 (ES256), low-s'],
              ['Key ID (kid)', <Mono key="kid">{short(info.kid, 10)}</Mono>],
              ['Public key x', <Mono key="x">{short(info.circuit.x, 8)}</Mono>],
            ]} />
          ) : (
            <p className="text-sm text-muted">{error || 'Loading…'}</p>
          )}
          <p className="mt-4 text-xs text-muted">The signing (private) key stays on the issuer server. It is never sent to this browser.</p>
        </Card>

        <Card title="Issue an income credential" subtitle="Simulates a bank attesting to a fictional applicant's annual income.">
          <form onSubmit={onIssue} className="space-y-4">
            <Field label="Subject ID" hint="Fictional, pseudonymous holder identifier.">
              <input className={inputClass} inputMode="numeric" pattern="[0-9]+" required value={form.subjectId} onChange={(e) => setForm({ ...form, subjectId: e.target.value })} />
            </Field>
            <Field label="Annual income (₹, whole rupees)" hint="Fictional value. It is signed into the credential.">
              <input className={inputClass} inputMode="numeric" pattern="[0-9]+" required value={form.annualIncomeInr} onChange={(e) => setForm({ ...form, annualIncomeInr: e.target.value })} />
            </Field>
            <Field label="Validity (days)" hint="1–366 days.">
              <input className={inputClass} type="number" min={1} max={366} required value={form.validityDays} onChange={(e) => setForm({ ...form, validityDays: e.target.value })} />
            </Field>
            <Button type="submit" disabled={busy || !info}>{busy ? 'Signing…' : 'Sign and issue credential'}</Button>
          </form>
          {error && info && <div className="mt-4"><Notice tone="bad">{error}</Notice></div>}
        </Card>
      </div>

      <Card title="Issued credential" subtitle="Delivered to the holder only. Verifiers never receive it.">
        {issued ? (
          <div className="space-y-4">
            <KeyValue items={[
              ['Type', issued.type],
              ['Subject ID', issued.claims.subjectId],
              ['Annual income', formatInr(issued.claims.annualIncomeInr)],
              ['Valid from', formatUnix(issued.claims.issuedAt)],
              ['Expires', formatUnix(issued.claims.expiresAt)],
              ['Credential ID', <Mono key="id">{short(issued.claims.credentialId, 6)}</Mono>],
            ]} />
            <div>
              <p className="mb-1.5 text-xs uppercase tracking-wider text-muted">Signature (r‖s)</p>
              <p className="break-all rounded-lg border border-navy-700 bg-navy-850 p-3"><Mono>{issued.signature.value}</Mono></p>
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <Button onClick={() => { wallet.addCredential(issued); setDelivered(true); }} disabled={delivered}>
                {delivered ? 'Delivered' : 'Deliver to holder wallet'}
              </Button>
              {delivered && <a className="text-sm text-accent hover:underline" href="#/holder">Open holder wallet →</a>}
            </div>
            <p className="text-xs text-muted">Demo shortcut: delivery stores the credential in this browser's holder wallet.</p>
          </div>
        ) : (
          <p className="text-sm text-muted">No credential issued yet.</p>
        )}
      </Card>
    </div>
  );
}
