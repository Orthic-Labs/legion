import test from 'node:test';
import assert from 'node:assert/strict';
import { recoverControlState } from '../src/lib/cli/commands/governance/delivery/control-recovery.mjs';
import { assessMigrationCutover, ABSENCE_SURFACES } from '../src/lib/cli/commands/governance/delivery/migration-cutover.mjs';
import { assessControlRetirement } from '../src/lib/cli/commands/governance/delivery/control-lifecycle.mjs';

test('authenticated recovery preserves state, verifies replacement, then resumes', () => {
  const broken = { revision: 1, corrupt: true };
  const result = recoverControlState({ controlId: 'control-1', state: broken, authorization: { controlId: 'control-1', operation: 'RECOVER_CONTROL_STATE' }, authenticate: () => true, repair: () => ({ revision: 2 }), verify: (state) => state.revision === 2 });
  assert.equal(result.code, 'ARC_RECOVERY_RESUMED');
  assert.equal(result.preservedState, broken);
  assert.equal(result.verification, 'PASS');
});

test('failed recovery verification quarantines original & replacement', () => {
  const result = recoverControlState({ controlId: 'control-1', state: { corrupt: true }, authorization: { controlId: 'control-1', operation: 'RECOVER_CONTROL_STATE' }, authenticate: () => true, repair: () => ({ revision: 2 }), verify: () => false });
  assert.equal(result.code, 'ARC_RECOVERY_VERIFY_FAILED');
  assert.deepEqual(result.quarantine.recoveredState, { revision: 2 });
});

test('hard cut fails when typed absence scan finds old path', () => {
  const absence_checks = Object.fromEntries(ABSENCE_SURFACES.map((key) => [key, []]));
  const absence = Object.fromEntries(ABSENCE_SURFACES.map((key) => [key, []]));
  absence.imports = [{ path: 'old.mjs' }];
  const result = assessMigrationCutover({ plan: { mode: 'HARD_CUT', hard_cut: { absence_checks } }, observations: { absence } });
  assert.equal(result.code, 'ARC_MIGRATION_ABSENCE_PROOF_FAILED');
  assert.equal(result.ready, false);
});

test('coexistence requires bounded contract fields & verified observations', () => {
  const result = assessMigrationCutover({ plan: { mode: 'BOUNDED_COEXISTENCE', bounded_coexistence: { owner: 'a' } }, observations: { coexistence: {} } });
  assert.equal(result.code, 'ARC_MIGRATION_READINESS_FAILED');
  assert.ok(result.failures.some((failure) => failure.field === 'expiry'));
});

test('retirement denial retains an explicit non-terminal lifecycle status', () => {
  const result = assessControlRetirement({ record: { control_id: 'control-1', status: 'RETIRED' }, consumerScan: { complete: false, liveConsumers: ['runtime'] }, obligationDisposition: { complete: false, open: ['safety'] }, migrationEvidence: { completed: false }, evalProof: { status: 'FAIL', fresh: false } });
  assert.equal(result.code, 'ARC_RETIREMENT_DENIED');
  assert.equal(result.status, 'ACTIVE');
});

test('retirement requires consumer scan, obligation disposition, migration & fresh eval proof', () => {
  const result = assessControlRetirement({ record: { control_id: 'control-1', status: 'RETIRED' }, consumerScan: { complete: true, liveConsumers: [] }, obligationDisposition: { complete: true, open: [] }, migrationEvidence: { completed: true }, evalProof: { status: 'PASS', fresh: true } });
  assert.equal(result.code, 'ARC_RETIREMENT_ALLOWED');
  assert.equal(result.status, 'RETIRED');
});
