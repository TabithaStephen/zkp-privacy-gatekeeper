import type { ReactNode } from 'react';
import type { RequestStatus } from '../zk/types.ts';

export function Card({ title, subtitle, actions, children, className = '' }: { title?: ReactNode; subtitle?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`rounded-xl border border-navy-700 bg-navy-900/80 shadow-[0_1px_0_0_rgb(255_255_255/0.03)_inset] ${className}`}>
      {(title || actions) && (
        <header className="flex flex-wrap items-start justify-between gap-3 border-b border-navy-700 px-5 py-4">
          <div>
            {title && <h2 className="text-[15px] font-semibold tracking-tight text-ink">{title}</h2>}
            {subtitle && <p className="mt-0.5 text-sm text-muted">{subtitle}</p>}
          </div>
          {actions}
        </header>
      )}
      <div className="px-5 py-4">{children}</div>
    </section>
  );
}

export function Button({ children, variant = 'primary', ...props }: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'secondary' | 'danger' | 'ghost' }) {
  const styles = {
    primary: 'bg-accent text-navy-950 hover:bg-accent-strong disabled:bg-navy-700 disabled:text-muted',
    secondary: 'border border-navy-600 bg-navy-800 text-ink hover:border-accent/60 disabled:opacity-50',
    danger: 'border border-bad/40 bg-bad/10 text-bad hover:bg-bad/20 disabled:opacity-50',
    ghost: 'text-muted hover:text-ink disabled:opacity-50',
  }[variant];
  return (
    <button {...props} className={`inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition-colors disabled:cursor-not-allowed ${styles} ${props.className ?? ''}`}>
      {children}
    </button>
  );
}

export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-xs font-medium uppercase tracking-wider text-muted">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-muted">{hint}</span>}
    </label>
  );
}

export const inputClass =
  'w-full rounded-lg border border-navy-600 bg-navy-850 px-3 py-2 text-sm text-ink placeholder:text-muted/60 focus:border-accent focus:outline-none';

const statusStyle: Record<RequestStatus, string> = {
  PENDING: 'border-navy-600 bg-navy-800 text-muted',
  ELIGIBLE: 'border-ok/40 bg-ok/10 text-ok',
  NOT_ELIGIBLE: 'border-warn/40 bg-warn/10 text-warn',
  INVALID: 'border-bad/40 bg-bad/10 text-bad',
};
const statusLabel: Record<RequestStatus, string> = { PENDING: 'Pending', ELIGIBLE: 'Eligible', NOT_ELIGIBLE: 'Not eligible', INVALID: 'Invalid' };

export function StatusBadge({ status }: { status: RequestStatus }) {
  return (
    <span data-status={status} className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium ${statusStyle[status]}`}>
      <span className="h-1.5 w-1.5 rounded-full bg-current" aria-hidden />
      {statusLabel[status]}
    </span>
  );
}

export function KeyValue({ items }: { items: [string, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-3 sm:grid-cols-2">
      {items.map(([k, v]) => (
        <div key={k} className="min-w-0">
          <dt className="text-xs uppercase tracking-wider text-muted">{k}</dt>
          <dd className="mt-0.5 truncate text-sm text-ink">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Notice({ tone = 'info', children }: { tone?: 'info' | 'ok' | 'warn' | 'bad'; children: ReactNode }) {
  const s = { info: 'border-accent/30 bg-accent/5 text-ink', ok: 'border-ok/40 bg-ok/10 text-ok', warn: 'border-warn/40 bg-warn/10 text-warn', bad: 'border-bad/40 bg-bad/10 text-bad' }[tone];
  return <div role={tone === 'bad' ? 'alert' : 'status'} className={`rounded-lg border px-4 py-3 text-sm ${s}`}>{children}</div>;
}

export function Mono({ children }: { children: ReactNode }) {
  return <code className="font-mono text-[12.5px] text-ink/90">{children}</code>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="rounded-lg border border-dashed border-navy-600 px-4 py-6 text-center text-sm text-muted">{children}</p>;
}
