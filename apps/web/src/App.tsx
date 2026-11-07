import { useEffect, useState } from 'react';
import { HolderWallet } from './pages/HolderWallet.tsx';
import { IssuerPortal } from './pages/IssuerPortal.tsx';
import { VerifierDashboard } from './pages/VerifierDashboard.tsx';

type Route = 'holder' | 'issuer' | 'verifier';
const ROUTES: { id: Route; label: string; role: string }[] = [
  { id: 'holder', label: 'Holder wallet', role: 'You' },
  { id: 'issuer', label: 'Issuer portal', role: 'Bank' },
  { id: 'verifier', label: 'Verifier dashboard', role: 'Lender' },
];

function parseHash(): { route: Route; params: URLSearchParams } {
  const [path, query] = window.location.hash.replace(/^#\/?/, '').split('?');
  const route = (ROUTES.find((r) => r.id === path)?.id ?? 'holder') as Route;
  return { route, params: new URLSearchParams(query ?? '') };
}

export function App() {
  const [{ route, params }, setLoc] = useState(parseHash);
  useEffect(() => {
    const onHash = () => setLoc(parseHash());
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  return (
    <div className="mx-auto flex min-h-screen max-w-6xl flex-col px-4 sm:px-6">
      <header className="flex flex-col gap-4 py-6 sm:flex-row sm:items-center sm:justify-between">
        <a href="#/holder" className="flex items-center gap-3">
          <span className="grid h-9 w-9 place-items-center rounded-lg border border-accent/40 bg-accent/10 text-accent" aria-hidden>
            <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 3l7 3v5c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V6l7-3z" /><path d="M9 12l2 2 4-4" /></svg>
          </span>
          <span>
            <span className="block text-[15px] font-semibold tracking-tight">ZKP Privacy Gatekeeper</span>
            <span className="block text-xs text-muted">Prove your eligibility. Protect your information.</span>
          </span>
        </a>
        <nav aria-label="Role" className="flex gap-1 overflow-x-auto rounded-xl border border-navy-700 bg-navy-900 p-1">
          {ROUTES.map((r) => (
            <a
              key={r.id}
              href={`#/${r.id}`}
              aria-current={route === r.id ? 'page' : undefined}
              className={`whitespace-nowrap rounded-lg px-3 py-1.5 text-sm transition-colors ${route === r.id ? 'bg-navy-700 text-ink' : 'text-muted hover:text-ink'}`}
            >
              {r.label} <span className="ml-1 text-xs text-muted">· {r.role}</span>
            </a>
          ))}
        </nav>
      </header>

      <main className="flex-1 pb-10">
        {route === 'holder' && <HolderWallet initialRequestId={params.get('request') ?? ''} />}
        {route === 'issuer' && <IssuerPortal />}
        {route === 'verifier' && <VerifierDashboard />}
      </main>

      <footer className="border-t border-navy-800 py-5 text-xs text-muted">
        Portfolio prototype. <strong className="font-medium text-ink/80">All data is fictional.</strong> Not a financial product; does not make
        lending decisions or provide regulatory compliance.
      </footer>
    </div>
  );
}
