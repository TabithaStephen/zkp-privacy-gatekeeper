/**
 * Generate a DEMO issuer key pair.
 *   npm run keygen [-- --out keys/issuer.pem]
 * Writes the private key (0600, git-ignored path) and prints the PUBLIC key
 * document. Refuses to overwrite an existing key.
 */
import fs from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { generateIssuerKeyPair, issuerPublicInfo, savePrivateKey } from '../keys.ts';

const { values } = parseArgs({ options: { out: { type: 'string', default: 'keys/issuer.pem' } } });
const out = path.resolve(values.out);

if (fs.existsSync(out)) {
  console.error(`Refusing to overwrite existing key: ${out}`);
  process.exit(1);
}
const { privateKey } = generateIssuerKeyPair();
savePrivateKey(privateKey, out);
const info = issuerPublicInfo(privateKey);
const pubPath = out.replace(/\.pem$/, '') + '.public.json';
fs.writeFileSync(pubPath, JSON.stringify(info, null, 2) + '\n');

console.error(`Private key written to ${out} (mode 0600). Never commit or share it.`);
console.error(`Public key document written to ${pubPath}`);
console.log(JSON.stringify(info, null, 2));
