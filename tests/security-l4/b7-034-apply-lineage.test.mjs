// B7-034 — controlled application, rollback, baseline, lineage, accepted risk.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  applyProposal,
  applyReceipt,
  buildApplyReceiptSchema,
  requireApplyCapability,
  rollbackReceipt,
  treeFingerprint,
} from '../../lib/remediation/apply.mjs';
import { rollbackApply } from '../../lib/remediation/rollback.mjs';
import { LINEAGE_STATES, classifyLineage, lineageLedger } from '../../lib/policy/lineage.mjs';
import { acceptedRisk, buildAcceptedRiskSchema, evaluateRisk, isExpired } from '../../lib/policy/accepted-risk.mjs';
import { baselineRecord, classifyFinding, findingFingerprint } from '../../lib/policy/baseline.mjs';

const binding = {
  planDigest: 'sha256:plan',
  repositoryRevision: 'abc123',
  dirtyPatchDigest: null,
  cortexGenerationId: 'gen',
  cortexManifestDigest: 'sha256:manifest',
  registryDigest: 'sha256:registry',
};

const before = treeFingerprint(['a.ts']);
const after = treeFingerprint(['a.ts', 'b.ts']);

const proposal = {
  id: 'sha256:proposal',
  findingIds: ['sha256:finding'],
  producer: { id: 'code.agent', contextId: 'ctx-producer' },
  patch: { path: 'patches/code.patch', digest: 'sha256:patch' },
  targetPaths: ['a.ts'],
  binding,
};

const verification = {
  kind: 'nemesis-remediation-verification',
  proposalId: 'sha256:proposal',
  verifiedBy: 'neutral-verification',
  verifier: { id: 'verify.neutral', contextId: 'ctx-verifier' },
  valid: true,
  coverageGaps: [],
  binding,
};

function mutator(overrides = {}) {
  const calls = [];
  return {
    calls,
    apply: async (spec) => {
      calls.push(spec);
      if (overrides.fail) return { ok: false, error: overrides.error ?? 'apply failed', fingerprint: overrides.leftAt ?? before };
      return { ok: true, fingerprint: after, reversePatchDigest: 'sha256:reverse' };
    },
    restore: async () => (overrides.restoreFail ? { ok: false, fingerprint: after } : { ok: true, fingerprint: before }),
  };
}

function host(mutation = true) {
  return { capabilities: { mutation } };
}

async function apply(overrides = {}) {
  return applyProposal({
    proposal,
    verification,
    host: overrides.host ?? host(),
    mutator: overrides.mutator ?? mutator(),
    targetFingerprint: overrides.targetFingerprint ?? before,
    observedFingerprint: overrides.observedFingerprint ?? before,
    binding,
  });
}

test('application requires explicit capability and never happens without it', async () => {
  assert.throws(() => requireApplyCapability({ capabilities: { mutation: false } }), /mutation capability/);
  const blocked = mutator();
  await assert.rejects(() => apply({ host: host(false), mutator: blocked }), /mutation capability/);
  assert.equal(blocked.calls.length, 0, 'no mutation may be attempted without capability');
});

test('application cannot proceed on stale target identity', async () => {
  const stale = mutator();
  await assert.rejects(
    () => apply({ mutator: stale, observedFingerprint: after }),
    /target repository fingerprint/,
  );
  assert.equal(stale.calls.length, 0);
});

test('an unverified or invalidly-verified proposal is never applied', async () => {
  const blocked = mutator();
  await assert.rejects(
    () => applyProposal({ proposal, verification: { ...verification, valid: false }, host: host(), mutator: blocked, targetFingerprint: before, observedFingerprint: before, binding }),
    /valid neutral verification/,
  );
  await assert.rejects(
    () => applyProposal({ proposal, verification: null, host: host(), mutator: blocked, targetFingerprint: before, observedFingerprint: before, binding }),
    /valid neutral verification/,
  );
  // A verifier that is the producer invalidates the whole application.
  await assert.rejects(
    () => applyProposal({ proposal, verification: { ...verification, verifier: { id: 'code.agent', contextId: 'ctx-x' } }, host: host(), mutator: blocked, targetFingerprint: before, observedFingerprint: before, binding }),
    /producer may not verify its own proposal/,
  );
  assert.equal(blocked.calls.length, 0);
});

test('the engine delegates the mutation and never writes to a repository itself', async () => {
  const applier = mutator();
  const receipt = await apply({ mutator: applier });
  assert.equal(receipt.applied, true);
  assert.equal(receipt.afterFingerprint, after);
  assert.equal(receipt.appliedBy, 'host-mutator');
  assert.equal(applier.calls.length, 1);
  assert.equal(applier.calls[0].patchDigest, 'sha256:patch');
  for (const source of ['../../lib/remediation/apply.mjs', '../../lib/remediation/rollback.mjs']) {
    const text = readFileSync(new URL(source, import.meta.url), 'utf8');
    assert.ok(!/writeFileSync|rmSync|node:fs/.test(text), `${source} must not mutate a repository directly`);
  }
});

test('a failed application stops in a recoverable state and is never reported applied', async () => {
  const receipt = await apply({ mutator: mutator({ fail: true, error: 'conflict' }) });
  assert.equal(receipt.applied, false);
  assert.equal(receipt.error, 'conflict');
  assert.equal(receipt.recoverable, true);
  assert.equal(receipt.observedFingerprint, before);
  assert.ok(receipt.recovery.command);
});

test('rollback restores the pre-apply fingerprint and a failed rollback is never suppressed', async () => {
  const applier = mutator();
  const receipt = await apply({ mutator: applier });
  const rolled = await rollbackApply({ applyReceipt: receipt, mutator: applier, expectedFingerprint: before });
  assert.equal(rolled.restored, true);
  assert.equal(rolled.restoredFingerprint, before);
  const failed = await rollbackApply({ applyReceipt: receipt, mutator: mutator({ restoreFail: true }), expectedFingerprint: before });
  assert.equal(failed.restored, false);
  assert.ok(failed.recovery.command, 'a failed rollback must carry exact recovery data');
  assert.equal(rollbackReceipt({ apply: receipt, reversePatchDigest: 'sha256:rev', restoredFingerprint: before, worktreePath: '/w' }).restored, true);
});

test('lineage classifies every state from stable identity', () => {
  assert.deepEqual([...LINEAGE_STATES].sort(), ['accepted', 'expired', 'new', 'reopened', 'resolved', 'superseded', 'unchanged']);
  const fingerprint = 'sha256:f1';
  assert.equal(classifyLineage({ fingerprint, inBaseline: false, inCurrent: true }), 'new');
  assert.equal(classifyLineage({ fingerprint, inBaseline: true, inCurrent: true }), 'unchanged');
  assert.equal(classifyLineage({ fingerprint, inBaseline: true, inCurrent: false }), 'resolved');
  assert.equal(classifyLineage({ fingerprint, inBaseline: true, inCurrent: true, previouslyResolved: true }), 'reopened');
  assert.equal(classifyLineage({ fingerprint, inBaseline: true, inCurrent: true, acceptedRisk: { active: true } }), 'accepted');
  assert.equal(classifyLineage({ fingerprint, inBaseline: true, inCurrent: true, acceptedRisk: { active: false, expired: true } }), 'expired');
  assert.equal(classifyLineage({ fingerprint, inBaseline: true, inCurrent: false, supersededBy: 'sha256:f2' }), 'superseded');
});

test('the lineage ledger is keyed on stable fingerprints, not line numbers', () => {
  const baselineFinding = { id: 'b1', ruleId: 'r', file: 'a.ts', line: 3, rootCauseDigest: 'sha256:root' };
  const currentFinding = { id: 'c1', ruleId: 'r', file: 'a.ts', line: 99, rootCauseDigest: 'sha256:root' };
  assert.equal(findingFingerprint(baselineFinding), findingFingerprint(currentFinding));
  const ledger = lineageLedger({
    baseline: baselineRecord({ id: 'base', revision: 'r0', findings: [{ ...baselineFinding, fingerprint: findingFingerprint(baselineFinding) }], createdAt: '2026-01-01' }),
    current: [currentFinding],
    acceptedRiskRecords: [],
    now: '2026-08-08',
    binding,
  });
  assert.equal(ledger.kind, 'nemesis-finding-lineage');
  assert.equal(ledger.entries.length, 1);
  assert.equal(ledger.entries[0].state, 'unchanged');
  assert.equal(ledger.entries[0].fingerprint, findingFingerprint(currentFinding));
  assert.deepEqual(ledger.binding, binding);
});

test('accepted risk changes workflow state only — never truth, never severity', () => {
  const finding = { id: 'c1', ruleId: 'r', file: 'a.ts', line: 1, rootCauseDigest: 'sha256:root', severity: 'high', evidenceStrength: 'verified' };
  const fingerprint = findingFingerprint(finding);
  const risk = acceptedRisk({ subjectKind: 'finding', subjectId: fingerprint, acceptedBy: 'human', reason: 'compensating control', acceptedAt: '2026-01-01', expiresAt: '2026-06-01', bindingDigest: 'sha256:b' });
  const ledger = lineageLedger({
    baseline: baselineRecord({ id: 'base', revision: 'r0', findings: [{ ...finding, fingerprint }], createdAt: '2026-01-01' }),
    current: [finding],
    acceptedRiskRecords: [risk],
    currentBindingDigest: 'sha256:b',
    now: '2026-03-01',
    binding,
  });
  assert.equal(ledger.entries[0].state, 'accepted');
  assert.equal(ledger.entries[0].severity, 'high', 'accepted risk must not change severity');
  assert.equal(ledger.entries[0].evidenceStrength, 'verified', 'accepted risk must not change evidence');
  assert.equal(ledger.entries[0].truthUnchanged, true);

  // Expiry reopens.
  assert.equal(isExpired(risk, '2026-07-01'), true);
  const expiredLedger = lineageLedger({
    baseline: baselineRecord({ id: 'base', revision: 'r0', findings: [{ ...finding, fingerprint }], createdAt: '2026-01-01' }),
    current: [finding],
    acceptedRiskRecords: [risk],
    currentBindingDigest: 'sha256:b',
    now: '2026-07-01',
    binding,
  });
  assert.equal(expiredLedger.entries[0].state, 'expired');

  // Identity change reopens.
  const mismatched = lineageLedger({
    baseline: baselineRecord({ id: 'base', revision: 'r0', findings: [{ ...finding, fingerprint }], createdAt: '2026-01-01' }),
    current: [finding],
    acceptedRiskRecords: [risk],
    currentBindingDigest: 'sha256:different',
    now: '2026-03-01',
    binding,
  });
  assert.equal(mismatched.entries[0].state, 'unchanged');
  assert.equal(evaluateRisk({ records: [risk], subjectKind: 'finding', subjectId: fingerprint, currentBindingDigest: 'sha256:different', now: '2026-03-01' }).active, false);
});

test('a higher-impact path reopens an accepted risk', () => {
  const finding = { id: 'c1', ruleId: 'r', file: 'a.ts', rootCauseDigest: 'sha256:root', severity: 'critical' };
  const fingerprint = findingFingerprint(finding);
  const risk = acceptedRisk({ subjectKind: 'finding', subjectId: fingerprint, acceptedBy: 'human', reason: 'low exposure', acceptedAt: '2026-01-01', expiresAt: null, bindingDigest: 'sha256:b' });
  const ledger = lineageLedger({
    baseline: baselineRecord({ id: 'base', revision: 'r0', findings: [{ ...finding, fingerprint, severity: 'low' }], createdAt: '2026-01-01' }),
    current: [finding],
    acceptedRiskRecords: [risk],
    currentBindingDigest: 'sha256:b',
    now: '2026-03-01',
    binding,
  });
  assert.equal(ledger.entries[0].state, 'reopened');
  assert.match(ledger.entries[0].reopenReason, /higher-impact/);
});

test('the committed apply-receipt and accepted-risk schemas match their generators', () => {
  const applySchema = JSON.parse(readFileSync(new URL('../../schemas/remediation/apply-receipt-v1.schema.json', import.meta.url), 'utf8'));
  assert.deepEqual(applySchema, buildApplyReceiptSchema());
  assert.ok(applySchema.required.includes('beforeFingerprint'));
  assert.ok(applySchema.required.includes('verificationDigest'));
  const riskSchema = JSON.parse(readFileSync(new URL('../../schemas/remediation/accepted-risk-v1.schema.json', import.meta.url), 'utf8'));
  assert.deepEqual(riskSchema, buildAcceptedRiskSchema());
  assert.equal(riskSchema.properties.truthUnchanged.const, true);
  assert.ok(!('severity' in riskSchema.properties), 'accepted risk must not carry severity');
});

test('the pre-existing apply helpers still behave', () => {
  const receipt = applyReceipt({ proposalId: 'p1', patchDigest: 'sha256:p', worktreePath: '/w', beforeFingerprint: before, afterFingerprint: after, applied: true });
  assert.equal(receipt.applied, true);
  assert.equal(receipt.rolledBack, false);
  assert.equal(classifyFinding({ fingerprint: 'sha256:f', inBaseline: true, inCurrent: true }), 'unchanged');
});
