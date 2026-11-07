import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

// Cross-origin isolation lets bb.js use SharedArrayBuffer for multi-threaded proving.
const isolation = {
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'require-corp',
};
// The issuer and verifier run as separate services; the dev server proxies to them.
const proxy = {
  '/api/issuer': 'http://127.0.0.1:4001',
  '/api/verifier': 'http://127.0.0.1:4002',
};

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: { port: 5173, strictPort: true, headers: isolation, proxy },
  preview: { port: 4173, strictPort: true, headers: isolation, proxy },
  // bb.js and the Noir packages ship WebAssembly; let Vite serve them as-is.
  optimizeDeps: { exclude: ['@aztec-foundation/bb.js', '@noir-lang/noir_js', '@noir-lang/acvm_js', '@noir-lang/noirc_abi'] },
  // bb.js (~5.4 MB WebAssembly glue) is loaded with a dynamic import only when the holder
  // generates a proof, so its size does not affect initial page load.
  build: { target: 'es2022', chunkSizeWarningLimit: 6000 },
  worker: { format: 'es' },
  test: { include: ['test/**/*.test.ts'] },
});
