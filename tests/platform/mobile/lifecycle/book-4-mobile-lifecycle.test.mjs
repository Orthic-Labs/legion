import test from 'node:test';
import assert from 'node:assert/strict';
import { planMobileLifecycle } from '../../../../providers/runtime/mobile/lifecycle/index.mjs';

test('B4-027 types blocked execution and covers critical lifecycle outcomes', () => {
  const blocked = planMobileLifecycle({ deviceCapability: { status: 'unavailable' } });
  for (const id of ['process-death', 'cold-deep-link', 'cold-notification']) assert.ok(blocked.scenarios.some((item) => item.id === id && item.status === 'blocked'));
  const ready = planMobileLifecycle({ deviceCapability: { status: 'available' } });
  for (const id of ['fresh-install', 'app-upgrade', 'system-interruption', 'corrupt-partial-state']) assert.ok(ready.scenarios.some((item) => item.id === id && item.status === 'unproven'));
  assert.deepEqual(ready.coverageGaps, ['device-execution-not-run']);
});
