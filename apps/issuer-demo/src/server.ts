import fs from 'node:fs';
import path from 'node:path';
import { generateIssuerKeyPair, issuerPublicInfo, loadPrivateKey, savePrivateKey } from '@zkpg/credentials';
import { assertStrongToken } from '@zkpg/server-security';
import { createIssuerApp } from './app.ts';

const PORT = Number(process.env.PORT ?? 4001);
const issuerToken = assertStrongToken('ISSUER_API_TOKEN', process.env.ISSUER_API_TOKEN);
const KEY_PATH = path.resolve(process.env.ISSUER_PRIVATE_KEY_PATH ?? 'keys/issuer.pem');

if (!fs.existsSync(KEY_PATH)) {
  if (process.env.NODE_ENV === 'production') {
    console.error(`[issuer] no key at ${KEY_PATH}; refusing to auto-generate in production`);
    process.exit(1);
  }
  savePrivateKey(generateIssuerKeyPair().privateKey, KEY_PATH);
  console.log(`[issuer] generated DEMO signing key at ${KEY_PATH} (mode 0600, git-ignored)`);
}
const key = loadPrivateKey(KEY_PATH);
createIssuerApp(key, { issuerToken }).listen(PORT, '127.0.0.1', () => {
  console.log(`[issuer] listening on http://127.0.0.1:${PORT}  kid=${issuerPublicInfo(key).kid}`);
});
