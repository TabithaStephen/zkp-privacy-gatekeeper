#!/usr/bin/env node
// Exports a slim, committed copy of the compiled circuit for the web app and verifier
// service, so they run without the Noir toolchain. Only the fields needed to prove and
// verify are kept (debug symbols and source map are dropped).
//
//   nargo compile && node scripts/export-artifact.mjs           # write artifact
//   nargo compile && node scripts/export-artifact.mjs --check   # fail if stale
import fs from 'node:fs';
import path from 'node:path';

const dir = path.resolve(import.meta.dirname, '..');
const compiled = JSON.parse(fs.readFileSync(path.join(dir, 'target/credential_eligibility.json'), 'utf8'));
const slim = {
  noir_version: compiled.noir_version,
  hash: compiled.hash,
  abi: compiled.abi,
  bytecode: compiled.bytecode,
};
const out = path.join(dir, 'artifact/credential_eligibility.json');
const text = JSON.stringify(slim, null, 2) + '\n';

if (process.argv.includes('--check')) {
  const current = fs.existsSync(out) ? fs.readFileSync(out, 'utf8') : '';
  if (current !== text) {
    console.error('artifact/credential_eligibility.json is STALE: run `nargo compile && node scripts/export-artifact.mjs`');
    process.exit(1);
  }
  console.log('artifact is up to date with the circuit source');
} else {
  fs.writeFileSync(out, text);
  console.log(`wrote ${out} (${text.length} bytes)`);
}
