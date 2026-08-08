import test from 'node:test';
import assert from 'node:assert/strict';
import { assessServiceRuntime } from '../../../providers/runtime/service/core/index.mjs';
import { createServiceFixtureAdapter } from '../../../providers/runtime/service/faults/index.mjs';

test('B4-035 types local service and worker runtime evidence plus production-only gaps', async () => {
  const receipt = await assessServiceRuntime({ target: { id: 'svc', artifactDigest: 'sha256:svc', environment: 'isolated-local' }, adapter: { execute: async (scenario) => ({ status: scenario.id === 'worker-restart' ? 'fail' : 'pass', terminal: true }) }, productionControls: ['regional-failover'] });
  assert.equal(receipt.status, 'fail');
  assert.ok(receipt.receipts.some((item) => item.id === 'worker-restart' && item.status === 'fail'));
  assert.ok(receipt.coverageGaps.includes('production-external-evidence-missing:regional-failover'));
  assert.equal(receipt.claims.source, 'unaffected');
});

test('B4-035 fixture adapter binds every runtime scenario and cleanup', async () => {
  const seen = [];
  const adapter = createServiceFixtureAdapter('clean', { onExecute: ({ id, binding }) => seen.push([id, binding.artifactDigest]) });
  const receipt = await assessServiceRuntime({ target: { id: 'svc', artifactDigest: 'sha256:svc', environment: 'isolated', deployment: 'candidate', region: 'local', datastore: 'db', queue: 'jobs' }, adapter });
  assert.equal(receipt.status, 'pass');
  assert.equal(seen.length, receipt.receipts.length);
  assert.ok(receipt.receipts.every((item) => item.cleanup?.status === 'pass'));
  assert.ok(receipt.receipts.find((item) => item.id === 'worker-restart').evidence.restartable);
});

test('B4-035 defect, partial, stale, and unsupported fixtures stay typed', async () => {
  const expected = { defect: 'fail', partial: 'partial', 'stale-environment': 'unproven', 'unsupported-runtime': 'blocked' };
  for (const [fixture, status] of Object.entries(expected)) {
    const result = await createServiceFixtureAdapter(fixture).execute({ id: 'fault-recovery', binding: {} });
    assert.equal(result.status, status, fixture);
    assert.equal(result.terminal, true);
  }
});
