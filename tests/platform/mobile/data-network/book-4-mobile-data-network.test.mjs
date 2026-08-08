import test from 'node:test';
import assert from 'node:assert/strict';
import { planMobileDataNetwork } from '../../../../providers/runtime/mobile/network/index.mjs';

test('B4-029 covers actor-scoped network, sync, storage, migration, pressure, and cache', () => {
  const receipt = planMobileDataNetwork({ actorId: 'user-1', supportedSchemaVersions: ['1'] });
  for (const family of ['network', 'sync', 'storage', 'migration', 'pressure', 'cache']) assert.ok(receipt.scenarios.some((item) => item.family === family));
  assert.ok(receipt.scenarios.some((item) => item.id === 'sync:offline-replay' && item.actorId === 'user-1'));
  assert.ok(receipt.scenarios.some((item) => item.id === 'storage:credentials' && item.requiresPlatformEvidence));
  assert.ok(receipt.scenarios.some((item) => item.id === 'migration:1-to-current' && item.invariants.includes('preserve-user-data')));
  assert.deepEqual(receipt.denominator, { total: receipt.scenarios.length, accounted: receipt.scenarios.length });
});
