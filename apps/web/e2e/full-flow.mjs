#!/usr/bin/env node
/**
 * End-to-end test in a real browser (Chromium via Playwright):
 * issuer → holder wallet (consent, IN-BROWSER proof) → verifier, plus a decline flow.
 * Starts all three services, records every request the browser sends to the
 * verifier, and asserts the income never appears in any of them.
 *
 *   npm run build -w @zkpg/web && node apps/web/e2e/full-flow.mjs [--screenshots]
 */
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');

const ROOT = path.resolve(import.meta.dirname, '../../..');
const SHOTS = path.join(ROOT, 'docs/screenshots');
const takeShots = process.argv.includes('--screenshots');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'zkpg-e2e-'));
const procs = [];
let failures = 0;
const check = (ok, label) => { console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}`); if (!ok) failures++; };

// Each service runs in its own process group so the whole tree (npx → tsx → node)
// can be stopped; otherwise orphaned servers keep the ports busy.
function start(name, cmd, args, cwd, env = {}) {
  const p = spawn(cmd, args, { cwd, env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'], detached: true });
  const log = [];
  p.stdout.on('data', (d) => log.push(String(d)));
  p.stderr.on('data', (d) => log.push(String(d)));
  procs.push({ name, p, log });
  return log;
}
async function waitFor(url, ms = 60_000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    try { if ((await fetch(url)).ok) return; } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error(`timeout waiting for ${url}`);
}

async function assertPortFree(port) {
  try {
    await fetch(`http://127.0.0.1:${port}/`);
    throw new Error(`port ${port} is already in use; stop the running service first`);
  } catch (e) {
    if (String(e.message).includes('already in use')) throw e;
  }
}
for (const port of [4001, 4002, 4173]) await assertPortFree(port);

// Fresh random role tokens for this run (never written to disk).
const TOKENS = { ISSUER_API_TOKEN: crypto.randomBytes(32).toString('hex'), VERIFIER_API_TOKEN: crypto.randomBytes(32).toString('hex') };
const issuerLog = start('issuer', 'npx', ['tsx', 'src/server.ts'], path.join(ROOT, 'apps/issuer-demo'), { ...TOKENS, ISSUER_PRIVATE_KEY_PATH: path.join(tmp, 'issuer.pem'), PORT: '4001' });
const verifierLog = start('verifier', 'npx', ['tsx', 'src/server.ts'], path.join(ROOT, 'apps/verifier-api'), { ...TOKENS, VERIFIER_DB_PATH: path.join(tmp, 'verifier.sqlite'), PORT: '4002' });
start('web', 'npx', ['vite', 'preview'], path.join(ROOT, 'apps/web'), TOKENS);

let browser;
let page;
try {
  await waitFor('http://127.0.0.1:4001/api/issuer/public-key');
  await waitFor('http://127.0.0.1:4002/api/verifier/requests/unknown').catch(() => {});
  await new Promise((r) => setTimeout(r, 1500));
  await waitFor('http://127.0.0.1:4173/');

  const proxy = process.env.HTTPS_PROXY ? { server: process.env.HTTPS_PROXY, bypass: '127.0.0.1,localhost' } : undefined;
  browser = await chromium.launch(proxy ? { proxy } : {});
  page = await browser.newPage({ viewport: { width: 1360, height: 900 }, deviceScaleFactor: takeShots ? 2 : 1 });
  const sent = [];
  const browserHeaders = [];
  page.on('request', (r) => {
    browserHeaders.push(JSON.stringify(r.headers()));
    if (r.url().includes('/api/verifier/') && r.method() === 'POST') sent.push({ url: r.url(), body: r.postData() ?? '' });
  });
  page.on('pageerror', (e) => console.log('  [pageerror]', e.message));
  const shot = async (name) => { if (takeShots) { fs.mkdirSync(SHOTS, { recursive: true }); await page.screenshot({ path: path.join(SHOTS, `${name}.png`), fullPage: true }); } };
  const BASE = 'http://127.0.0.1:4173/';

  console.log('== 1. Issuer issues and delivers a ₹9,50,000 credential');
  await page.goto(`${BASE}#/issuer`);
  await page.getByText('ECDSA P-256 (ES256), low-s').waitFor();
  await page.getByLabel('Annual income (₹, whole rupees)').fill('950000');
  await page.getByRole('button', { name: 'Sign and issue credential' }).click();
  await page.getByRole('button', { name: 'Deliver to holder wallet' }).click();
  await page.getByRole('button', { name: 'Delivered' }).waitFor();
  await shot('1-issuer-portal');
  check(true, 'credential issued and delivered');

  console.log('== 2. Verifier creates a request: income ≥ ₹8,00,000');
  await page.goto(`${BASE}#/verifier`);
  await page.getByRole('button', { name: 'Create request' }).click();
  const requestId = (await page.locator('text=Request ID').locator('xpath=following-sibling::p').innerText()).trim();
  check(/^[0-9a-f-]{36}$/.test(requestId), `request created (${requestId.slice(0, 8)}…)`);
  await shot('2-verifier-request');

  console.log('== 3. Holder reviews, consents, proves IN THE BROWSER, submits');
  await page.goto(`${BASE}#/holder?request=${requestId}`);
  await page.getByText('Annual income ≥ ₹8,00,000').waitFor();
  const isolated = await page.evaluate(() => globalThis.crossOriginIsolated);
  check(isolated === true, 'page is cross-origin isolated (multi-threaded proving available)');
  const generate = page.getByRole('button', { name: 'Generate proof on this device' });
  check(await generate.isDisabled(), 'proof generation is disabled until consent is given');
  await page.getByRole('checkbox').check();
  await shot('3-holder-consent');
  const t0 = Date.now();
  await generate.click();
  await page.getByRole('button', { name: 'Submit proof to verifier' }).waitFor({ timeout: 180_000 });
  const browserProveMs = Date.now() - t0;
  const reported = await page.getByText(/Proof generated locally in/).innerText();
  check(true, `in-browser proof generated: ${reported} (wall clock incl. engine load ${(browserProveMs / 1000).toFixed(1)} s)`);
  check(!sent.some((x) => x.url.includes(`/requests/${requestId}/`)), 'nothing was sent for this request before the holder clicked submit');
  await shot('4-holder-proof-ready');
  await page.getByRole('button', { name: 'Submit proof to verifier' }).click();
  await page.locator('[data-testid="holder-result"] [data-status="ELIGIBLE"]').waitFor();
  check(true, 'holder sees ELIGIBLE');
  await shot('5-holder-eligible');

  await page.goto(`${BASE}#/verifier`);
  await page.locator(`tr[data-request-id="${requestId}"] [data-status="ELIGIBLE"]`).waitFor();
  check(true, 'verifier dashboard shows ELIGIBLE for the request');
  await shot('6-verifier-results');

  console.log('== 4. Second proof (warm: CRS cached in IndexedDB, engine already downloaded)');
  await page.getByRole('button', { name: 'Create request' }).click();
  const reqWarm = (await page.locator('text=Request ID').locator('xpath=following-sibling::p').innerText()).trim();
  await page.goto(`${BASE}#/holder?request=${reqWarm}`);
  await page.getByText('Annual income ≥ ₹8,00,000').waitFor();
  await page.getByRole('checkbox').check();
  await page.getByRole('button', { name: 'Generate proof on this device' }).click();
  await page.getByRole('button', { name: 'Submit proof to verifier' }).waitFor({ timeout: 180_000 });
  check(true, `warm in-browser proof: ${await page.getByText(/Proof generated locally in/).innerText()}`);
  await page.getByRole('button', { name: 'Submit proof to verifier' }).click();
  await page.locator('[data-testid="holder-result"] [data-status="ELIGIBLE"]').waitFor();
  await page.goto(`${BASE}#/verifier`);

  console.log('== 5. Request above the credential income: holder declines');
  await page.getByLabel('Minimum annual income (₹)').fill('1000000');
  await page.getByRole('button', { name: 'Create request' }).click();
  const req2 = (await page.locator('text=Request ID').locator('xpath=following-sibling::p').innerText()).trim();
  await page.goto(`${BASE}#/holder?request=${req2}`);
  await page.getByText('Your credential does not meet this condition').waitFor();
  check(await page.getByText(/has already asked you about a different threshold/).isVisible(), 'wallet warns that the verifier is asking a different threshold (probing signal)');
  check(await page.getByRole('checkbox').isDisabled(), 'consent and proving are unavailable when the condition is not met');
  await page.getByRole('button', { name: 'Decline request' }).click();
  await page.locator('[data-testid="holder-result"] [data-status="NOT_ELIGIBLE"]').waitFor();
  check(true, 'decline recorded as NOT_ELIGIBLE');

  console.log('== 6. Verifier audit log and role tokens');
  await page.goto(`${BASE}#/verifier`);
  await page.locator('[data-audit-event="DECISION"]').first().waitFor();
  check(await page.locator('[data-audit-event="DECLINED"]').count() > 0, 'audit log shows decisions and the decline');
  const auditText = await page.locator('text=Audit log').locator('xpath=ancestor::section').innerText();
  check(!auditText.includes('950000') && !auditText.includes('9,50,000'), 'audit log shows no income');
  const tokenSeen = browserHeaders.some((h) => h.includes(TOKENS.VERIFIER_API_TOKEN) || h.includes(TOKENS.ISSUER_API_TOKEN) || /authorization/i.test(h));
  check(!tokenSeen, 'browser never sends or holds a role token (no Authorization header on any request)');
  const bundle = fs.readdirSync(path.join(ROOT, 'apps/web/dist/assets')).filter((f) => f.endsWith('.js')).map((f) => fs.readFileSync(path.join(ROOT, 'apps/web/dist/assets', f), 'utf8')).join('');
  check(!bundle.includes(TOKENS.VERIFIER_API_TOKEN) && !bundle.includes('VERIFIER_API_TOKEN') && !bundle.includes('ISSUER_API_TOKEN'), 'built JS bundle contains no role tokens or token variable names');
  const direct = await fetch('http://127.0.0.1:4002/api/verifier/requests');
  check(direct.status === 401, 'verifier API refuses to list requests without the verifier token (401)');

  console.log('== 7. Privacy: everything the browser sent to the verifier');
  const proofPosts = sent.filter((s) => s.url.endsWith('/proof'));
  check(proofPosts.length === 2, `exactly two proof submissions (${sent.length} POSTs total)`);
  const keys = proofPosts.map((p) => Object.keys(JSON.parse(p.body)).sort().join(','));
  check(keys.every((k) => k === 'proof,publicInputs'), `every submission has exactly {proof,publicInputs}`);
  const allSent = sent.map((s) => s.body).join('\n');
  check(!allSent.includes('950000'), 'income (950000) never appears in any request to the verifier');
  check(!/"signature"|"claims"|"credential"/.test(allSent), 'no credential, claims or signature sent to the verifier');
  const serverLogs = issuerLog.join('') + verifierLog.join('');
  check(!serverLogs.includes('950000'), 'income never appears in issuer or verifier logs');
} catch (e) {
  console.error('  ERROR', e.message.split('\n')[0]);
  if (page) {
    const alerts = await page.locator('[role=alert]').allInnerTexts().catch(() => []);
    if (alerts.length) console.error('  visible errors:', alerts.join(' | '));
    const f = path.join(tmp, '..', `zkpg-e2e-failure-${Date.now()}.png`);
    await page.screenshot({ path: f, fullPage: true }).catch(() => {});
    console.error(`  failure screenshot: ${f}`);
  }
  failures++;
} finally {
  await browser?.close();
  for (const { p } of procs) { try { process.kill(-p.pid, 'SIGTERM'); } catch { /* already exited */ } }
  fs.rmSync(tmp, { recursive: true, force: true });
}

console.log(failures === 0 ? '\nE2E: ALL CHECKS PASSED' : `\nE2E: ${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
