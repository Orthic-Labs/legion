import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { compileAdvisoryProfile, DEFAULT_MANIFEST_ROOT, requireCanonicalAdvisoryProfile } from '../src/lib/verification/arcane/advisory-profile.mjs';
import { CapabilityStore } from '../src/lib/guard/compat/effects/capability-store.mjs';

test('canonical compiler accepts every current bundle/profile deterministically', () => {
  for (const bundleId of ['ads', 'brand-identity', 'designer', 'marketing', 'research', 'seo', 'social', 'writing']) {
    for (const profileId of ['audit', 'authoring']) {
      const first = compileAdvisoryProfile({ bundleId, profileId });
      const second = compileAdvisoryProfile({ bundleId, profileId });
      assert.deepEqual(first, second);
      assert.equal(Object.isFrozen(first), true);
      assert.equal(first.bundleId, bundleId);
      assert.equal(first.profileId, profileId);
      assert.equal(first.manifestDigest.startsWith('sha256:'), true);
      assert.equal(first.profileDigest.startsWith('sha256:'), true);
    }
  }
});

test('compiler rejects traversal, missing profile, invalid manifest & substituted authority fields', () => {
  assert.throws(() => compileAdvisoryProfile({ bundleId: '../research', profileId: 'audit' }), /invalid advisory/);
  assert.throws(() => compileAdvisoryProfile({ bundleId: 'research', profileId: 'missing' }), /profile is invalid/);
  const canonical = compileAdvisoryProfile({ bundleId: 'research', profileId: 'audit' });
  for (const changed of [
    { ...canonical, mutationAllowed: true },
    { ...canonical, publishAllowed: true },
    { ...canonical, manifestDigest: `sha256:${'0'.repeat(64)}` },
    { ...canonical, profileDigest: `sha256:${'0'.repeat(64)}` },
  ]) assert.throws(() => requireCanonicalAdvisoryProfile(changed), /differs from canonical/);

  const root = mkdtempSync(join(tmpdir(), 'arcane-profile-'));
  const manifest = JSON.parse(readFileSync(join(DEFAULT_MANIFEST_ROOT, 'research.json'), 'utf8'));
  manifest.id = 'other';
  writeFileSync(join(root, 'research.json'), JSON.stringify(manifest));
  assert.throws(() => compileAdvisoryProfile({ bundleId: 'research', profileId: 'audit', manifestRoot: root }), /manifest is invalid|id differs/);
});

test('durable capability stores exact profile & denies missing, wrong, or extra binding', () => {
  const root = mkdtempSync(join(tmpdir(), 'arcane-profile-cap-'));
  const now = Date.parse('2026-08-12T00:00:00.000Z');
  const store = new CapabilityStore({ root, clock: () => now });
  const profile = compileAdvisoryProfile({ bundleId: 'research', profileId: 'authoring' });
  const capabilityId = 'cap_0123456789ABCDEFGHJKMNPQRS';
  store.issue({ capabilityId, runId: 'run_0123456789ABCDEFGHJKMNPQRS', taskId: 'T-1', workspace: '/repo', contractId: 'EC-602', contractVersion: 1, contractDigest: `sha256:${'a'.repeat(64)}`, sourceRevision: 'abcdef0', authority: 'alchemist', turnId: 'turn-1', operation: 'write', effectClass: 'FILE_WRITE', targets: ['x.txt'], policyId: 'POL-1', policyVersion: 1, policyDigest: `sha256:${'b'.repeat(64)}`, advisoryProfile: profile, approvalEvidence: null, issuedAt: '2026-08-12T00:00:00.000Z', expiresAt: '2026-08-12T00:15:00.000Z', maxUses: 1, delegable: false });
  assert.deepEqual(store.get(capabilityId).advisoryProfile, profile);
  const ctx = { effectClass: 'FILE_WRITE', target: 'x.txt', now: '2026-08-12T00:00:01.000Z' };
  assert.equal(store.check(capabilityId, ctx).code, 'ARC_BINDING_MISMATCH');
  assert.equal(store.check(capabilityId, { ...ctx, advisoryProfile: compileAdvisoryProfile({ bundleId: 'research', profileId: 'audit' }) }).code, 'ARC_BINDING_MISMATCH');
  assert.equal(store.check(capabilityId, { ...ctx, advisoryProfile: profile }).allowed, true);

  const legacy = new CapabilityStore();
  legacy.issue({ capabilityId: 'cap_legacy', effectClass: 'FILE_WRITE', targets: ['x.txt'] });
  assert.equal(legacy.check('cap_legacy', { effectClass: 'FILE_WRITE', target: 'x.txt' }).allowed, true);
  assert.equal(legacy.check('cap_legacy', { effectClass: 'FILE_WRITE', target: 'x.txt', advisoryProfile: profile }).code, 'ARC_BINDING_MISMATCH');
});
