import { defineConfig } from 'vitest/config';

// Tests generate a real proof with noir_js + bb.js (a few seconds).
export default defineConfig({ test: { testTimeout: 60_000, hookTimeout: 180_000 } });
