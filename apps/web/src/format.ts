const inr = new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR', maximumFractionDigits: 0 });

/** ₹8,00,000 style (Indian digit grouping); works for values beyond 2^53. */
export const formatInr = (decimal: string): string => inr.format(BigInt(decimal));

export const formatUnix = (seconds: string): string =>
  new Date(Number(seconds) * 1000).toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' });

export const formatIso = (iso: string): string => new Date(iso).toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' });

export const short = (s: string, n = 6): string => (s.length <= n * 2 + 1 ? s : `${s.slice(0, n)}…${s.slice(-n)}`);
