import { type FormEvent, useEffect, useMemo, useState } from 'react';
import { issuerApi, verifierApi } from '../api.ts';
import { Button, Card, Empty, Field, inputClass, KeyValue, Mono, Notice, StatusBadge } from '../components/ui.tsx';
import { formatInr, formatIso, formatUnix, short } from '../format.ts';
import { type HistoryEntry, wallet } from '../wallet.ts';
import { precheck, toCircuitInputs } from '../zk/inputs.ts';
import { explainCircuitError, generateProof, type ProofResult, type Stage } from '../zk/prover.ts';
import type { Credential, IssuerInfo, ProofRequest } from '../zk/types.ts';

const STAGE_TEXT: Record<Stage, string> = {
  loading: 'Loading the proving engine (WebAssembly)…',
  witness: 'Checking your credential against the circuit…',
  proving: 'Generating the zero-knowledge proof on this device…',
  done: 'Proof ready.',
};

export function HolderWallet({ initialRequestId }: { initialRequestId: string }) {
  const [credentials, setCredentials] = useState<Credential[]>(wallet.credentials);
  const [history, setHistory] = useState<HistoryEntry[]>(wallet.history);
  const [issuer, setIssuer] = useState<IssuerInfo | null>(null);

  const [requestId, setRequestId] = useState(initialRequestId);
  const [request, setRequest] = useState<ProofRequest | null>(null);
  const [loadError, setLoadError] = useState('');
  const [selectedId, setSelectedId] = useState('');
  const [consent, setConsent] = useState(false);
  const [stage, setStage] = useState<Stage | null>(null);
  const [proof, setProof] = useState<ProofResult | null>(null);
  const [proofError, setProofError] = useState('');
  const [result, setResult] = useState<ProofRequest | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => { issuerApi.publicKey().then(setIssuer).catch(() => setIssuer(null)); }, []);
  useEffect(() => { if (initialRequestId) void loadRequest(initialRequestId); }, [initialRequestId]);

  const selected = credentials.find((c) => c.claims.credentialId === selectedId) ?? credentials[0];
  const check = useMemo(() => (selected && issuer && request ? precheck(selected, issuer, request) : null), [selected, issuer, request]);

  function resetFlow() {
    setConsent(false); setStage(null); setProof(null); setProofError(''); setResult(null);
  }

  async function loadRequest(id: string) {
    resetFlow(); setRequest(null); setLoadError('');
    try {
      setRequest(await verifierApi.get(id.trim()));
    } catch (e) {
      setLoadError(`Could not load request: ${(e as Error).message}`);
    }
  }

  function record(r: ProofRequest) {
    const entry: HistoryEntry = { requestId: r.id, verifierName: r.verifierName, minimumIncome: r.minimumIncome, result: r.status, at: new Date().toISOString(), ...(r.reason ? { reason: r.reason } : {}) };
    wallet.addHistory(entry);
    setHistory(wallet.history());
  }

  async function onGenerate() {
    if (!selected || !issuer || !request) return;
    setProofError(''); setProof(null);
    try {
      setProof(await generateProof(toCircuitInputs(selected, issuer, request), setStage));
    } catch (e) {
      setStage(null);
      setProofError(explainCircuitError(e));
    }
  }

  async function onSubmit() {
    if (!proof || !request) return;
    setSubmitting(true);
    try {
      const r = await verifierApi.submit(request.id, proof.submission);
      setResult(r); record(r);
    } catch (e) {
      setProofError((e as Error).message);
    } finally {
      setSubmitting(false);
    }
  }

  async function onDecline() {
    if (!request) return;
    try {
      const r = await verifierApi.decline(request.id);
      setResult(r); record(r);
    } catch (e) {
      setProofError((e as Error).message);
    }
  }

  const decided = request && request.status !== 'PENDING';
  const expired = !!request && (request.status === 'EXPIRED' || BigInt(request.expiresAt) * 1000n <= BigInt(Date.now()));
  const otherThresholds = request ? wallet.recentThresholds(request.verifierName).filter((t) => t !== request.minimumIncome) : [];

  return (
    <div className="space-y-6">
      <div className="grid gap-6 lg:grid-cols-[1fr_1.35fr]">
        {/* ── Credentials ─────────────────────────────────────────── */}
        <Card title="My credentials" subtitle="Stored only in this browser. Your exact income is visible to you, not to verifiers.">
          {credentials.length === 0 ? (
            <Empty>No credentials yet. Ask the <a href="#/issuer" className="text-accent hover:underline">issuer</a> for one.</Empty>
          ) : (
            <ul className="space-y-3">
              {credentials.map((c) => {
                const expired = BigInt(c.claims.expiresAt) * 1000n < BigInt(Date.now());
                return (
                  <li key={c.claims.credentialId} className="rounded-lg border border-navy-700 bg-navy-850 p-4">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <p className="text-sm font-medium">Income credential <span className="text-muted">· {c.type}</span></p>
                        <p className="mt-0.5 text-xs text-muted">Issuer <Mono>{short(c.issuer.kid, 6)}</Mono>{issuer?.kid === c.issuer.kid ? ` · ${issuer.name}` : ' · unknown issuer'}</p>
                      </div>
                      <span className={`rounded-full border px-2 py-0.5 text-xs ${expired ? 'border-bad/40 text-bad' : 'border-ok/40 text-ok'}`}>{expired ? 'Expired' : 'Valid'}</span>
                    </div>
                    <div className="mt-3 grid grid-cols-2 gap-3 text-sm">
                      <div><p className="text-xs text-muted">Annual income (private)</p><p>{formatInr(c.claims.annualIncomeInr)}</p></div>
                      <div><p className="text-xs text-muted">Expires</p><p>{formatUnix(c.claims.expiresAt)}</p></div>
                    </div>
                    <button className="mt-3 text-xs text-muted hover:text-bad" onClick={() => { wallet.removeCredential(c.claims.credentialId); setCredentials(wallet.credentials()); }}>Remove</button>
                  </li>
                );
              })}
            </ul>
          )}
        </Card>

        {/* ── Verification request ────────────────────────────────── */}
        <Card title="Verification request" subtitle="Review exactly what a verifier asks for before anything is generated or shared.">
          <form className="flex gap-2" onSubmit={(e: FormEvent) => { e.preventDefault(); void loadRequest(requestId); }}>
            <input aria-label="Request ID" className={inputClass} placeholder="Paste a request ID from the verifier" value={requestId} onChange={(e) => setRequestId(e.target.value)} />
            <Button type="submit" variant="secondary" disabled={!requestId.trim()}>Load</Button>
          </form>
          {loadError && <div className="mt-4"><Notice tone="bad">{loadError}</Notice></div>}

          {request && (
            <div className="mt-5 space-y-5">
              <div className="rounded-lg border border-accent/30 bg-accent/5 p-4">
                <p className="text-xs uppercase tracking-wider text-muted">{request.verifierName} asks you to prove</p>
                <p className="mt-1 text-lg font-semibold">Annual income ≥ {formatInr(request.minimumIncome)}</p>
                <p className="mt-1 text-xs text-muted">Requested {formatIso(request.createdAt)} · respond by {formatUnix(request.expiresAt)} · challenge <Mono>{short(request.challenge, 6)}</Mono></p>
              </div>

              <div className="grid gap-3 sm:grid-cols-2">
                <div className="rounded-lg border border-navy-700 p-3">
                  <p className="text-xs font-medium uppercase tracking-wider text-ok">Shared with the verifier</p>
                  <ul className="mt-2 space-y-1 text-sm text-ink/90">
                    <li>• A zero-knowledge proof (~14.7 KB)</li>
                    <li>• The issuer's public key</li>
                    <li>• The threshold, request time and challenge</li>
                    <li>• That the condition is met</li>
                  </ul>
                </div>
                <div className="rounded-lg border border-navy-700 p-3">
                  <p className="text-xs font-medium uppercase tracking-wider text-accent">Stays on this device</p>
                  <ul className="mt-2 space-y-1 text-sm text-ink/90">
                    <li>• Your exact income</li>
                    <li>• The credential and its signature</li>
                    <li>• Subject ID, issue and expiry dates</li>
                  </ul>
                </div>
              </div>

              {otherThresholds.length > 0 && !result && (
                <Notice tone="warn">
                  {request.verifierName} has already asked you about {otherThresholds.length === 1 ? 'a different threshold' : `${otherThresholds.length} different thresholds`} in the last 24 hours
                  ({otherThresholds.map((t) => formatInr(t)).join(', ')}). Answering many thresholds can let a verifier narrow down your income.
                </Notice>
              )}

              {expired && !result ? (
                <Notice tone="warn">This request has expired. Ask the verifier for a new one.</Notice>
              ) : decided && !result ? (
                <Notice tone="warn">This request has already been answered ({request.status}).</Notice>
              ) : credentials.length === 0 ? (
                <Notice tone="warn">You need a credential to respond.</Notice>
              ) : (
                <>
                  {credentials.length > 1 && (
                    <Field label="Credential to use">
                      <select className={inputClass} value={selected?.claims.credentialId} onChange={(e) => { setSelectedId(e.target.value); resetFlow(); }}>
                        {credentials.map((c) => <option key={c.claims.credentialId} value={c.claims.credentialId}>Income credential · expires {formatUnix(c.claims.expiresAt)}</option>)}
                      </select>
                    </Field>
                  )}

                  {check && !check.ok && (
                    <Notice tone="warn">
                      {check.message} {check.reason === 'BELOW_THRESHOLD' && 'You can decline: the verifier will see "not eligible", but not your income.'}
                    </Notice>
                  )}

                  {!result && (
                    <>
                      <label className="flex items-start gap-3 text-sm">
                        <input type="checkbox" className="mt-0.5 h-4 w-4 accent-[var(--color-accent)]" checked={consent} disabled={!!proof || !check?.ok} onChange={(e) => setConsent(e.target.checked)} />
                        <span>I consent to generating a proof that my annual income is at least {formatInr(request.minimumIncome)} and sharing it with <strong>{request.verifierName}</strong>.</span>
                      </label>

                      <div className="flex flex-wrap gap-3">
                        {!proof && (
                          <Button onClick={onGenerate} disabled={!consent || !check?.ok || (stage !== null && stage !== 'done')}>
                            {stage && stage !== 'done' ? 'Generating…' : 'Generate proof on this device'}
                          </Button>
                        )}
                        {proof && <Button onClick={onSubmit} disabled={submitting}>{submitting ? 'Submitting…' : 'Submit proof to verifier'}</Button>}
                        <Button variant="ghost" onClick={onDecline} disabled={submitting}>Decline request</Button>
                      </div>
                    </>
                  )}

                  {stage && stage !== 'done' && (
                    <div className="flex items-center gap-3 text-sm text-muted" role="status">
                      <span className="h-4 w-4 animate-spin rounded-full border-2 border-accent border-t-transparent" aria-hidden />
                      {STAGE_TEXT[stage]}
                    </div>
                  )}
                  {proofError && <Notice tone="bad">{proofError}</Notice>}

                  {proof && !result && (
                    <div className="rounded-lg border border-navy-700 bg-navy-850 p-4">
                      <p className="text-sm font-medium">Proof generated locally in {(proof.timings.totalMs / 1000).toFixed(1)} s <span className="text-muted">({proof.threads} thread{proof.threads > 1 ? 's' : ''})</span></p>
                      <p className="mt-2 text-xs text-muted">Exactly this will be sent ({proof.proofBytes.toLocaleString()} B proof + {proof.submission.publicInputs.length} public inputs):</p>
                      <pre className="mt-2 max-h-40 overflow-auto rounded border border-navy-700 bg-navy-950 p-3 font-mono text-[11.5px] text-ink/80">
{JSON.stringify({ proof: `${proof.submission.proof.slice(0, 48)}… (${proof.submission.proof.length} chars)`, publicInputs: [...proof.submission.publicInputs.slice(64), `… ${proof.submission.publicInputs.length - 3} issuer-key fields`] }, null, 2)}
                      </pre>
                    </div>
                  )}

                  {result && (
                    <div className="flex items-center gap-3" data-testid="holder-result">
                      <StatusBadge status={result.status} />
                      <span className="text-sm text-muted">
                        {result.status === 'ELIGIBLE' && `${result.verifierName} verified your proof. Your income was not shared.`}
                        {result.status === 'NOT_ELIGIBLE' && 'You declined. No proof or income was shared.'}
                        {result.status === 'INVALID' && `The verifier rejected the proof (${result.reason}).`}
                      </span>
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </Card>
      </div>

      {/* ── History ─────────────────────────────────────────────── */}
      <Card title="Verification history" subtitle="Kept on this device. Records which conditions you proved, never your income.">
        {history.length === 0 ? (
          <Empty>No verification attempts yet.</Empty>
        ) : (
          <div className="-mx-5 overflow-x-auto">
            <table className="w-full min-w-[560px] text-left text-sm">
              <thead className="text-xs uppercase tracking-wider text-muted">
                <tr className="border-b border-navy-700">
                  <th className="px-5 py-2 font-medium">When</th>
                  <th className="px-5 py-2 font-medium">Verifier</th>
                  <th className="px-5 py-2 font-medium">Condition</th>
                  <th className="px-5 py-2 font-medium">Result</th>
                </tr>
              </thead>
              <tbody>
                {history.map((h) => (
                  <tr key={h.requestId + h.at} className="border-b border-navy-800 last:border-0">
                    <td className="px-5 py-3 text-muted">{formatIso(h.at)}</td>
                    <td className="px-5 py-3">{h.verifierName}</td>
                    <td className="px-5 py-3">income ≥ {formatInr(h.minimumIncome)}</td>
                    <td className="px-5 py-3"><StatusBadge status={h.result} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {issuer === null && <p className="mt-3 text-xs text-warn">Issuer service unavailable: credentials cannot be checked right now.</p>}
      </Card>

      <KeyValueFootnote />
    </div>
  );
}

function KeyValueFootnote() {
  return (
    <Card title="How this works">
      <KeyValue items={[
        ['Proof system', 'UltraHonk (Barretenberg) via bb.js WebAssembly'],
        ['Circuit', 'Noir: ECDSA P-256 issuer signature + validity window + threshold'],
        ['Where the proof is made', 'In this browser tab. Private inputs never leave it'],
        ['What the verifier checks', 'The proof, trusted issuer key, its own threshold, challenge and time'],
      ]} />
    </Card>
  );
}
