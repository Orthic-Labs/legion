import assert from 'node:assert/strict';
import test from 'node:test';

import { validateAtomicCanons } from '../scripts/check-atomic-canons.mjs';

test('subsystem atomic canons are normalized, unique, and pending index is current', () => {
  const result = validateAtomicCanons();
  assert.equal(result.canons, 8);
  assert.ok(result.atoms >= 90);
  assert.ok(result.closed > 0);
});

