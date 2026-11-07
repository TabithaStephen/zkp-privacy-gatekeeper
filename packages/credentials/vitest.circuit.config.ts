import { defineConfig } from 'vitest/config';

// Integration tests that generate and verify REAL proofs with nargo 1.0.0 + bb 6.0.0.
export default defineConfig({
  test: {
    include: ['test-circuit/**/*.test.ts'],
    testTimeout: 120_000,
    hookTimeout: 300_000,
    fileParallelism: false,
  },
});
