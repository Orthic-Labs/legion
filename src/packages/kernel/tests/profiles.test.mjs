import assert from 'node:assert/strict';
import test from 'node:test';

import { DEFAULT_PROFILE_POLICY, downgradeModelProfile, loadModelProfile } from '../lib/profiles.mjs';

test('profile policy requires complete coherent packet limits', () => {
  assert.throws(
    () => loadModelProfile('strict', { strict: { maxPacketTasks: 1, maxConcurrency: 1 } }),
    (error) => error.code === 'INVALID_ARGUMENT' && error.category === 'policy',
  );
  assert.throws(
    () => loadModelProfile('standard', {
      standard: {
        ...DEFAULT_PROFILE_POLICY.standard,
        maxMutationConcurrency: 3,
        maxConcurrency: 2,
      },
    }),
    /mutation concurrency cannot exceed total concurrency/,
  );
});

test('model authority cannot request a profile change regardless of casing', () => {
  const profile = loadModelProfile('advanced');
  assert.throws(
    () => downgradeModelProfile(profile, 'self-selected', { requestedBy: 'MODEL' }),
    (error) => error.code === 'AUTHORITY_DENIED' && error.category === 'authority',
  );
});

test('policy downgrade is monotonic and preserves supplied policy limits', () => {
  const policy = {
    strict: { ...DEFAULT_PROFILE_POLICY.strict, maxPacketTasks: 2 },
    standard: { ...DEFAULT_PROFILE_POLICY.standard, maxPacketTasks: 5 },
    advanced: { ...DEFAULT_PROFILE_POLICY.advanced, maxPacketTasks: 9 },
  };
  const downgraded = downgradeModelProfile(loadModelProfile('advanced', policy), 'scenario regression', { policy });
  assert.equal(downgraded.name, 'standard');
  assert.equal(downgraded.limits.maxPacketTasks, 5);
  assert.equal(downgraded.downgrade.from, 'advanced');
});
