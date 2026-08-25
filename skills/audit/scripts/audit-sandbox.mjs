#!/usr/bin/env node
import { createHash, randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { realpathSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const profile = '(version 1) (deny network*) (allow network-inbound (local ip "localhost:*")) (allow network-outbound (remote ip "localhost:*")) (allow default)';
const root = resolve(dirname(realpathSync(fileURLToPath(import.meta.url))), '../../..');
if (process.platform !== 'darwin') {
  console.error('audit-sandbox requires a host network-denial adapter on this platform');
  process.exit(2);
}
const receipt = {
  schemaVersion: 1,
  kind: 'audit-network-sandbox-receipt',
  enforcedBy: 'sandbox-exec',
  networkDenied: true,
  profileDigest: `sha256:${createHash('sha256').update(profile).digest('hex')}`,
  nonce: randomBytes(16).toString('hex'),
};
const result = spawnSync('/usr/bin/sandbox-exec', [
  '-p', profile, process.execPath, resolve(root, 'tools/audit/audit-run.mjs'), ...process.argv.slice(2),
], {
  stdio: 'inherit',
  shell: false,
  env: {
    ...process.env,
    AUDIT_NETWORK_GUARD: 'active',
    AUDIT_NETWORK_SANDBOX_RECEIPT: JSON.stringify(receipt),
  },
});
process.exit(result.status ?? 1);
