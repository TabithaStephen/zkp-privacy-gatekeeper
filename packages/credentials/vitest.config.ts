import { defineConfig } from 'vitest/config';

// Fast unit tests only. Real-proof tests: `npm run test:circuit` (needs nargo + bb).
export default defineConfig({ test: { include: ['test/**/*.test.ts'] } });
