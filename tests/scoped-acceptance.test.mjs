import assert from 'node:assert/strict';
import test from 'node:test';
import {
  compileScopedAcceptance,
  diffScopedAcceptance,
  fingerprintAcceptanceItem,
} from '../packages/arcane/lib/scoped-acceptance.mjs';

const item = (id, outcome = id) => ({
  acceptance_id: id,
  outcome,
  owner: 'owner',
  dependencies: [],
  observable_surface: `${id} output`,
  verification_method: `${id} test`,
  result: 'OPEN',
  evidence: null,
});
const acceptanceStageFixtures = () => [
  { stage_id: 'S01', owner: 'one', dependencies: [], required_items: [item('S01-01')] },
  { stage_id: 'S02', owner: 'two', dependencies: ['S01'], required_items: [item('S02-01')] },
  { stage_id: 'S03', owner: 'three', dependencies: ['S01'], required_items: [item('S03-01')] },
  { stage_id: 'S04', owner: 'four', dependencies: ['S02', 'S03'], required_items: [item('S04-01')] },
];
const serial = { schedule_version: 1, waves: [['S02'], ['S03'], ['S04']] };
const parallel = { schedule_version: 2, waves: [['S02', 'S03'], ['S04']] };

test('result and evidence changes never alter acceptance contract identity', () => {
  const original = item('S01-01');
  const completed = { ...original, result: 'PASS', evidence: 'fresh exact-state receipt' };
  assert.equal(fingerprintAcceptanceItem(original), fingerprintAcceptanceItem(completed));
});

test('schedule-only reshuffle invalidates no acceptance stage', () => {
  const result = diffScopedAcceptance(
    { stages: acceptanceStageFixtures(), schedule: serial },
    { stages: acceptanceStageFixtures(), schedule: parallel },
  );
  assert.equal(result.scheduleChanged, true);
  assert.equal(result.acceptanceChanged, false);
  assert.deepEqual(result.invalidatedStageIds, []);
  assert.deepEqual(result.preservedStageIds, ['S01', 'S02', 'S03', 'S04']);
  assert.notEqual(result.before.scheduleFingerprint, result.after.scheduleFingerprint);
  assert.equal(result.before.acceptanceManifestFingerprint, result.after.acceptanceManifestFingerprint);
});

test('semantic change invalidates only changed stage and descendants', () => {
  const before = acceptanceStageFixtures();
  const after = acceptanceStageFixtures();
  after[1].required_items[0].outcome = 'changed S02 outcome';
  const result = diffScopedAcceptance(
    { stages: before, schedule: parallel },
    { stages: after, schedule: parallel },
  );
  assert.deepEqual(result.directlyChangedStageIds, ['S02']);
  assert.deepEqual(result.invalidatedStageIds, ['S02', 'S04']);
  assert.deepEqual(result.preservedStageIds, ['S01', 'S03']);
});

test('compiled identities separate acceptance manifest from execution schedule', () => {
  const compiled = compileScopedAcceptance(acceptanceStageFixtures(), parallel);
  assert.match(compiled.acceptanceManifestFingerprint, /^sha256:[0-9a-f]{64}$/);
  assert.match(compiled.scheduleFingerprint, /^sha256:[0-9a-f]{64}$/);
  assert.equal(Object.keys(compiled.stageFingerprints).length, 4);
});
