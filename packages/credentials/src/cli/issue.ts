/**
 * Issue a FICTIONAL income credential.
 *   npm run issue -- --subject 1001 --income 950000 [--days 365] [--key keys/issuer.pem] [--out demo.credential.json]
 * The summary printed to the terminal deliberately omits the income value
 * (safe-logging rule); the credential itself goes to --out or stdout.
 */
import fs from 'node:fs';
import { parseArgs } from 'node:util';
import { issueCredential } from '../credential.ts';
import { loadPrivateKey } from '../keys.ts';

const { values } = parseArgs({
  options: {
    subject: { type: 'string' },
    income: { type: 'string' },
    days: { type: 'string', default: '365' },
    key: { type: 'string', default: process.env.ISSUER_PRIVATE_KEY_PATH ?? 'keys/issuer.pem' },
    out: { type: 'string' },
  },
});

const DECIMAL = /^(0|[1-9][0-9]*)$/;
for (const [name, v] of [['--subject', values.subject], ['--income', values.income], ['--days', values.days]] as const) {
  if (!v || !DECIMAL.test(v)) {
    console.error(`${name} must be a non-negative integer`);
    process.exit(1);
  }
}

const credential = issueCredential(loadPrivateKey(values.key), {
  subjectId: BigInt(values.subject!),
  annualIncomeInr: BigInt(values.income!),
  validitySeconds: BigInt(values.days!) * 86_400n,
});
const json = JSON.stringify(credential, null, 2) + '\n';
if (values.out) {
  fs.writeFileSync(values.out, json, { mode: 0o600 });
  console.error(`Credential written to ${values.out}`);
} else {
  process.stdout.write(json);
}
console.error(`Issued ${credential.type} for subject ${credential.claims.subjectId}, issuer kid ${credential.issuer.kid}, expires ${new Date(Number(credential.claims.expiresAt) * 1000).toISOString()}`);
