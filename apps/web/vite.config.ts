import path from 'node:path';
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { loadEnv, type ProxyOptions } from 'vite';
import { defineConfig } from 'vitest/config';

// Cross-origin isolation lets bb.js use SharedArrayBuffer for multi-threaded proving.
const isolation = {
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'require-corp',
};

export default defineConfig(({ mode }) => {
  // Role tokens come from the repo-root .env (or the environment). They are used ONLY
  // here, server-side in the proxy, and are never exposed to browser code (Vite only
  // exposes VITE_-prefixed variables to the client).
  const env = { ...loadEnv(mode, path.resolve(import.meta.dirname, '../..'), ''), ...process.env };

  // Demo stand-in for real authentication: the proxy acts as the logged-in issuer /
  // verifier for their portals. Holder routes (GET a request by id, submit proof,
  // decline) are deliberately NOT given the verifier token.
  const withToken = (target: string, token: string | undefined, needsAuth: (method: string, url: string) => boolean): ProxyOptions => ({
    target,
    configure: (proxy) => {
      proxy.on('proxyReq', (proxyReq, req) => {
        proxyReq.removeHeader('authorization'); // never forward a client-supplied token
        if (token && needsAuth(req.method ?? 'GET', (req.url ?? '').split('?')[0]!)) proxyReq.setHeader('authorization', `Bearer ${token}`);
      });
    },
  });
  const proxy = {
    '/api/issuer': withToken('http://127.0.0.1:4001', env.ISSUER_API_TOKEN, (m, u) => m === 'POST' && u === '/api/issuer/credentials'),
    '/api/verifier': withToken('http://127.0.0.1:4002', env.VERIFIER_API_TOKEN, (m, u) => u === '/api/verifier/requests' || u === '/api/verifier/audit'),
  };

  return {
    plugins: [react(), tailwindcss()],
    server: { port: 5173, strictPort: true, headers: isolation, proxy },
    preview: { port: 4173, strictPort: true, headers: isolation, proxy },
    // bb.js and the Noir packages ship WebAssembly; let Vite serve them as-is.
    optimizeDeps: { exclude: ['@aztec-foundation/bb.js', '@noir-lang/noir_js', '@noir-lang/acvm_js', '@noir-lang/noirc_abi'] },
    // bb.js (~5.4 MB WebAssembly glue) is loaded with a dynamic import only when the holder
    // generates a proof, so its size does not affect initial page load.
    build: {
      target: 'es2022',
      chunkSizeWarningLimit: 6000,
      // bench.html is a measurement page used by bench/run.ts; it is not linked from the app.
      rollupOptions: { input: { main: path.resolve(import.meta.dirname, 'index.html'), bench: path.resolve(import.meta.dirname, 'bench.html') } },
    },
    worker: { format: 'es' },
    test: { include: ['test/**/*.test.ts'] },
  };
});
