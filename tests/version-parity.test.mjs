import assert from 'node:assert/strict';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { versionParityReport } from '../scripts/check-version-parity.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));

test('every shipped product surface consumes one release version', () => {
  assert.deepEqual(versionParityReport(root).issues, []);
});

test('development identity cannot pass stable release validation', () => {
  const report = versionParityReport(root, { stable: true });
  assert.equal(report.status, 'fail');
  assert.ok(report.issues.some(({ path, reason }) => path === 'release/version.json' && reason.includes('stable release')));
});
