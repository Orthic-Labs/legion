import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { AMENDED_BUDGET_BOUND_FIELDS, BudgetGovernanceStore, BUDGET_AMENDMENT_BOUND_FIELDS, BUDGET_BOUND_FIELDS, BUDGET_SCOPE_EXPANSION_BOUND_FIELDS } from '../lib/budget-governance-store.mjs';
import { digestValue } from '../lib/canonical.mjs';
import { generateTestKeyRing } from '../lib/keys.mjs';
import { signRecord } from '../lib/receipt-auth.mjs';
const budget = (id, version, lineage = 'L-1') => ({ schemaVersion: 1, kind: 'arcane-budget-governance', contractId: id, version, contractDigest: digestValue({ id, version }), objectiveLineageId: lineage, objectiveDigest: digestValue('objective'), legionBlastMapCapMs: 10, sagePlanningCapMs: 10, maxContractVersions: 2, resumeEvidence: null, amendmentEvidence: null, userScopeExpansionEvidence: null });
test('budget seals authenticate, cap lineage, & terminally stop cap, retry, progress, invalid waits', () => {
  const ring = generateTestKeyRing(); let time = 0; const root = mkdtempSync(path.join(os.tmpdir(), 'budget-')); const store = new BudgetGovernanceStore({ root, keyRing: ring, monotonicNow: () => time });
  const signed = budget('EC-1', 1); signed.authentication = signRecord(signed, { keyRing: ring, keyId: 'k1', boundFields: BUDGET_BOUND_FIELDS, macDomain: 'arcane-budget-governance-v1' }); assert.equal(store.seal(signed).contractId, 'EC-1');
  const run = store.begin({ contractId: 'EC-1', version: 1, taskId: 'T-1', runId: 'deadline', activeTimeCapMs: 10, progressDeadlineMs: 5 }); time = 6; assert.equal(store.observe(run).code, 'PROGRESS_DEADLINE');
  const retry = store.begin({ contractId: 'EC-1', version: 1, taskId: 'T-1', runId: 'retry', activeTimeCapMs: 10, progressDeadlineMs: 10 }); const attempt = { method: 'test', inputState: 'same', error: 'same' }; assert.equal(store.observe(retry, { retry: attempt }).kind, 'BUDGET_OK'); assert.equal(store.observe(retry, { retry: attempt }).kind, 'BUDGET_OK'); assert.equal(store.observe(retry, { retry: attempt }).kind, 'BUDGET_OK'); assert.equal(store.observe(retry, { retry: attempt }).code, 'IDENTICAL_RETRY');
  const wait = store.begin({ contractId: 'EC-1', version: 1, taskId: 'T-1', runId: 'wait', activeTimeCapMs: 10, progressDeadlineMs: 10 }); assert.equal(store.observe(wait, { externalWait: { durationMs: 1 } }).code, 'INVALID_WAIT');
  assert.equal(store.inspect({ contractId: 'EC-1', version: 1, taskId: 'T-1', runId: 'wait' }).events.length, 1);
  const beforeMissing = readdirSync(path.join(root, 'runs')).length;
  assert.throws(() => store.inspect({ contractId: 'EC-1', version: 1, taskId: 'T-1', runId: 'missing' }), /unavailable/);
  assert.equal(readdirSync(path.join(root, 'runs')).length, beforeMissing, 'read-only inspect creates nothing');
  const waitSnapshot = readdirSync(path.join(root, 'runs')).map((name) => path.join(root, 'runs', name)).find((file) => JSON.parse(readFileSync(file, 'utf8')).runId === 'wait');
  assert.equal(existsSync(waitSnapshot), true);
  const tampered = JSON.parse(readFileSync(waitSnapshot, 'utf8')); tampered.excludedWaitMs += 1; writeFileSync(waitSnapshot, JSON.stringify(tampered));
  assert.throws(() => store.inspect({ contractId: 'EC-1', version: 1, taskId: 'T-1', runId: 'wait' }), /authentication failed/);
});

test('role caps & authenticated amendments bind budget changes', () => {
  const ring = generateTestKeyRing(); const root = mkdtempSync(path.join(os.tmpdir(), 'budget-amend-')); const store = new BudgetGovernanceStore({ root, keyRing: ring });
  const first = budget('EC-2', 1); first.authentication = signRecord(first, { keyRing: ring, keyId: 'k1', boundFields: BUDGET_BOUND_FIELDS, macDomain: 'arcane-budget-governance-v1' }); store.seal(first);
  assert.throws(() => store.begin({ contractId: 'EC-2', version: 1, taskId: 'T', authorityRole: 'legion', activeTimeCapMs: 11, progressDeadlineMs: 1 }), /role run ceiling/);
  const second = budget('EC-2', 2); second.contractDigest = digestValue({ id: 'EC-2', version: 2 }); second.legionBlastMapCapMs = 11; second.amendmentEvidence = { schemaVersion: 1, kind: 'arcane-budget-amendment', priorContractDigest: first.contractDigest, newContractDigest: second.contractDigest, priorLegionBlastMapCapMs: 10, newLegionBlastMapCapMs: 11, priorSagePlanningCapMs: 10, newSagePlanningCapMs: 10, scopeExpanded: true, sageAuthority: 'sage', observedAt: new Date().toISOString() }; second.amendmentEvidence.authentication = signRecord(second.amendmentEvidence, { keyRing: ring, keyId: 'k1', boundFields: BUDGET_AMENDMENT_BOUND_FIELDS, macDomain: 'arcane-budget-amendment-v1' });
  second.authentication = signRecord(second, { keyRing: ring, keyId: 'k1', boundFields: AMENDED_BUDGET_BOUND_FIELDS, macDomain: 'arcane-budget-governance-v1' }); assert.throws(() => store.seal(second), /scope expansion/);
  second.userScopeExpansionEvidence = { schemaVersion: 1, kind: 'arcane-budget-scope-expansion-evidence', priorContractDigest: first.contractDigest, newContractDigest: second.contractDigest, userTurnDigest: digestValue('user scope'), sessionId: 's', observedAt: new Date().toISOString() }; second.userScopeExpansionEvidence.authentication = signRecord(second.userScopeExpansionEvidence, { keyRing: ring, keyId: 'k1', boundFields: BUDGET_SCOPE_EXPANSION_BOUND_FIELDS, macDomain: 'arcane-budget-scope-expansion-v1' }); second.authentication = signRecord(second, { keyRing: ring, keyId: 'k1', boundFields: AMENDED_BUDGET_BOUND_FIELDS, macDomain: 'arcane-budget-governance-v1' }); assert.equal(store.seal(second).version, 2);
});
