import assert from 'node:assert/strict';
import test from 'node:test';

import {
  adversarialMigrationDistributedBindingIds,
  assessDistributedFailureModes,
  executeAdversarialMigrationDistributedCase,
  selectMigrationTarget,
  validateAdversarialMigrationDistributedObservation,
} from '../lib/adversarial-migration-distributed.mjs';

const coexistence = Object.freeze({
  owner: 'owner', reconciliation: 'versioned', telemetry: 'monitor',
  expiry: '2026-09-01T00:00:00.000Z', rollback: 'compensate', trigger: 'lag',
  reconciled: true, telemetryActive: true,
});

test('migration selection lets transition facts eliminate static hard-cut preference', () => {
  const selected = selectMigrationTarget({
    transitionRisk: { activeLegacyConsumers: true },
    candidates: [
      { id: 'static-hard-cut', mode: 'HARD_CUT', baseScore: 100 },
      { id: 'safe-coexistence', mode: 'BOUNDED_COEXISTENCE', baseScore: 1, coexistence, observations: { reconciled: true, telemetryActive: true } },
    ],
  });
  assert.equal(selected.selected.id, 'safe-coexistence');
  assert.equal(selected.readiness.ready, true);
  assert.ok(selected.comparison.eliminated.some((entry) => entry.candidate.id === 'static-hard-cut'));
});

test('distributed assessment independently rejects duplicate & ordering regression', () => {
  const observed = assessDistributedFailureModes({
    scope: { issuerId: 'issuer', sessionId: 'session', runId: 'run', workspaceId: 'workspace' },
    now: '2026-08-15T00:00:00.000Z',
    events: [{ nonce: 'one', sequence: 4 }, { nonce: 'one', sequence: 5 }, { nonce: 'two', sequence: 3 }],
    coexistence,
  });
  assert.equal(observed.duplicate.replayDenied, true);
  assert.equal(observed.ordering.regressionDenied, true);
  assert.equal(observed.consistency.ready, true);
});

test('S11 evaluators have independent structured outputs & never depend on row expectations', () => {
  assert.deepEqual(adversarialMigrationDistributedBindingIds(), ['AE-ADVERSARIAL-004', 'AE-ADVERSARIAL-005']);
  for (const id of adversarialMigrationDistributedBindingIds()) {
    const result = executeAdversarialMigrationDistributedCase({ id, family: 'adversarial', expect: { outcome: 'tampered' } });
    assert.equal(result.status, 'PASS');
    assert.equal(validateAdversarialMigrationDistributedObservation(id, result.observed), true);
  }
  assert.equal(executeAdversarialMigrationDistributedCase({ id: 'AE-ADVERSARIAL-006' }), null);
});
