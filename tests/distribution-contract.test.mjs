import assert from 'node:assert/strict';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { validateDistributionContract } from '../scripts/check-distribution-contract.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));

test('distribution contract keeps Node private and direct bootstrap blocked coherently', () => {
  assert.deepEqual(validateDistributionContract(root), { ok: true, issues: [] });
});
