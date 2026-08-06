import assert from 'node:assert/strict';
import test from 'node:test';
import { patchEffectGraph, blocksAutoApply } from '../../lib/remediation/effect-graph.mjs';
import { verifyPatch } from '../../lib/remediation/verify-patch.mjs';
import { applyReceipt, requireApplyCapability, rollbackReceipt, treeFingerprint } from '../../lib/remediation/apply.mjs';
import { baselineRecord, classifyFinding, findingFingerprint } from '../../lib/policy/baseline.mjs';
import { acceptedRisk, evaluateRisk, isExpired } from '../../lib/policy/accepted-risk.mjs';

test('patch effect graph maps finding to patch to affected surfaces', () => {
  const graph = patchEffectGraph({
    patchDigest: 'sha256:p', findingIds: ['f1'], changedFiles: ['a.ts'],
    changedSymbols: ['updateProject'], publicSurfaceChanges: ['public-api:updateProject'],
    affectedProviders: ['language.javascript'], requiredTests: ['test/update.test.ts'],
    runtimeSurfaces: [], securityPaths: ['authorization.object-write'], residualRisks: ['behavior change'],
  });
  assert.equal(graph.kind, 'nemesis-patch-effect-graph');
  assert.equal(graph.patchDigest, 'sha256:p');
});

test('unplanned public-surface changes block auto-apply', () => {
  const blocked = patchEffectGraph({ patchDigest: 'sha256:p', findingIds: [], changedFiles: [], changedSymbols: [], publicSurfaceChanges: ['api change'], affectedProviders: [], requiredTests: [], runtimeSurfaces: [], securityPaths: [], residualRisks: [] });
  assert.equal(blocksAutoApply(blocked), true);
  const clean = patchEffectGraph({ patchDigest: 'sha256:p', findingIds: [], changedFiles: ['a.ts'], changedSymbols: [], publicSurfaceChanges: [], affectedProviders: [], requiredTests: [], runtimeSurfaces: [], securityPaths: [], residualRisks: [] });
  assert.equal(blocksAutoApply(clean), false);
});

test('neutral verification reruns affected providers and baseline gates', () => {
  const proposal = { id: 'p1', patch: { digest: 'sha256:p' } };
  const ok = verifyPatch({ proposal, affectedProviderResults: [{ complete: true, status: 'pass' }], baselineGates: [{ passed: true }] });
  assert.equal(ok.valid, true);
  assert.equal(ok.verifiedBy, 'neutral-verification');
  const failing = verifyPatch({ proposal, affectedProviderResults: [{ complete: false, status: 'error' }], baselineGates: [] });
  assert.equal(failing.valid, false);
  assert.ok(failing.coverageGaps.some((gap) => gap.kind === 'affected-provider-failed'));
});

test('apply requires explicit host mutation capability', () => {
  assert.throws(() => requireApplyCapability({ capabilities: { mutation: false } }), /mutation capability/);
  assert.doesNotThrow(() => requireApplyCapability({ capabilities: { mutation: true } }));
});

test('apply verifies the target tree fingerprint before apply', () => {
  const before = treeFingerprint(['a.ts']);
  const after = treeFingerprint(['a.ts', 'b.ts']);
  assert.notEqual(before, after);
  const receipt = applyReceipt({ proposalId: 'p1', patchDigest: 'sha256:p', worktreePath: '/w', beforeFingerprint: before, afterFingerprint: after, applied: true });
  assert.equal(receipt.applied, true);
  assert.equal(receipt.rolledBack, false);
});

test('rollback restores the pre-apply fingerprint', () => {
  const before = treeFingerprint(['a.ts']);
  const after = treeFingerprint(['a.ts', 'b.ts']);
  const apply = applyReceipt({ proposalId: 'p1', patchDigest: 'sha256:p', worktreePath: '/w', beforeFingerprint: before, afterFingerprint: after, applied: true });
  const rollback = rollbackReceipt({ apply, reversePatchDigest: 'sha256:rev', restoredFingerprint: before, worktreePath: '/w' });
  assert.equal(rollback.restored, true);
});

test('baseline classifies new, resolved, unchanged, reopened findings', () => {
  const fp = 'sha256:f';
  assert.equal(classifyFinding({ fingerprint: fp, inBaseline: false, inCurrent: true }), 'new');
  assert.equal(classifyFinding({ fingerprint: fp, inBaseline: true, inCurrent: false }), 'resolved');
  assert.equal(classifyFinding({ fingerprint: fp, inBaseline: true, inCurrent: true }), 'unchanged');
  assert.equal(classifyFinding({ fingerprint: fp, inBaseline: false, inCurrent: false }), 'reopened');
});

test('finding fingerprint is semantic, not line-bound', () => {
  const a = findingFingerprint({ ruleId: 'r', file: 'a.ts', line: 3 });
  const b = findingFingerprint({ ruleId: 'r', file: 'a.ts', line: 99 });
  assert.equal(a, b, 'line movement must not change the fingerprint');
  const c = findingFingerprint({ ruleId: 'r', file: 'b.ts', line: 3 });
  assert.notEqual(a, c);
});

test('accepted risk expires and reopens automatically', () => {
  const risk = acceptedRisk({ subjectKind: 'finding', subjectId: 'f1', acceptedBy: 'human', reason: 'low exposure', acceptedAt: '2026-01-01', expiresAt: '2026-06-01', bindingDigest: 'sha256:b' });
  assert.equal(isExpired(risk, '2026-07-01'), true);
  assert.equal(isExpired(risk, '2026-05-01'), false);
  const state = evaluateRisk({ records: [risk], subjectKind: 'finding', subjectId: 'f1', currentBindingDigest: 'sha256:b', now: '2026-07-01' });
  assert.equal(state.active, false);
  assert.equal(state.expired.length, 1);
});

test('identity-changed subjects reopen automatically', () => {
  const risk = acceptedRisk({ subjectKind: 'finding', subjectId: 'f1', acceptedBy: 'human', reason: 'x', acceptedAt: '2026-01-01', expiresAt: null, bindingDigest: 'sha256:old' });
  const state = evaluateRisk({ records: [risk], subjectKind: 'finding', subjectId: 'f1', currentBindingDigest: 'sha256:new', now: '2026-01-02' });
  assert.equal(state.active, false);
  assert.equal(state.bindingMismatch.length, 1);
});

test('accepted risk changes workflow status, never severity', () => {
  const risk = acceptedRisk({ subjectKind: 'finding', subjectId: 'f1', acceptedBy: 'human', reason: 'x', acceptedAt: '2026-01-01', expiresAt: '2030-01-01', bindingDigest: 'sha256:b' });
  const state = evaluateRisk({ records: [risk], subjectKind: 'finding', subjectId: 'f1', currentBindingDigest: 'sha256:b', now: '2026-01-02' });
  assert.equal(state.active, true);
  assert.equal(state.truthUnchanged, true);
});
