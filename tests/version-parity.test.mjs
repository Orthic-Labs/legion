import assert from 'node:assert/strict';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { isDevelopmentVersion, versionParityReport } from '../scripts/check-version-parity.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));

test('every shipped product surface consumes one release version', () => {
  assert.deepEqual(versionParityReport(root).issues, []);
});

test('stable identity passes stable validation while development identity is rejected', () => {
  const report = versionParityReport(root, { stable: true });
  assert.equal(report.status, 'pass');
  assert.deepEqual(report.issues, []);
  assert.equal(isDevelopmentVersion('0.1.0-dev.1'), true);
  assert.equal(isDevelopmentVersion('0.1.0'), false);
});
