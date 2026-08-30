import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { AMENDED_BUDGET_BOUND_FIELDS, BudgetGovernanceStore, BUDGET_AMENDMENT_BOUND_FIELDS, BUDGET_BOUND_FIELDS, BUDGET_SCOPE_EXPANSION_BOUND_FIELDS } from '../src/lib/cli/commands/governance/execution/budget-governance-store.mjs';
import { digestValue } from '../src/lib/contracts/arcane/canonical.mjs';
import { generateTestKeyRing } from '../src/lib/guard/compat/host/keys.mjs';
import { signRecord } from '../src/lib/guard/compat/audit/receipt-auth.mjs';
import { AuthorityInvocationProofIssuer } from '../src/lib/contracts/arcane/authority-invocation-proof.mjs';
import { HostEventLedger } from '../src/lib/host/arcane/host-event-ledger.mjs';
const budget = (id, version, lineage = 'L-1') => ({ schemaVersion: 1, kind: 'arcane-budget-governance', contractId: id, version, contractDigest: digestValue({ id, version }), objectiveLineageId: lineage, objectiveDigest: digestValue('objective'), legionBlastMapCapMs: 10, sagePlanningCapMs: 10, maxContractVersions: 2, resumeEvidence: null, amendmentEvidence: null, userScopeExpansionEvidence: null });
test('budget seals authenticate, cap lineage, & terminally stop cap, retry, progress, invalid waits', () => {
  const ring = generateTestKeyRing(); let time = 0; const root = mkdtempSync(path.join(os.tmpdir(), 'budget-')); const store = new BudgetGovernanceStore({ root, keyRing: ring, monotonicNow: () => time });
  const signed = budget('EC-1', 1); signed.authentication = signRecord(signed, { keyRing: ring, keyId: 'k1', boundFields: BUDGET_BOUND_FIELDS, macDomain: 'arcane-budget-governance-v1' }); assert.equal(store.seal(signed).contractId, 'EC-1');
  const run = store.begin({ contractId: 'EC-1', version: 1, taskId: 'T-1', runId: 'deadline', activeTimeCapMs: 10, progressDeadlineMs: 5 }); time = 6; assert.equal(store.observe(run).code, 'PROGRESS_DEADLINE');
  const retry = store.begin({ contractId: 'EC-1', version: 1, taskId: 'T-1', runId: 'retry', activeTimeCapMs: 10, progressDeadlineMs: 10 }); const attempt = { method: 'test', inputState: 'same', error: 'same' }; assert.equal(store.observe(retry, { retry: attempt }).kind, 'BUDGET_OK'); const retryStop = store.observe(retry, { retry: attempt }); assert.equal(retryStop.code, 'IDENTICAL_RETRY'); assert.equal(retryStop.attempts, 2);
  const wait = store.begin({ contractId: 'EC-1', version: 1, taskId: 'T-1', runId: 'wait', activeTimeCapMs: 10, progressDeadlineMs: 10 }); assert.equal(store.observe(wait, { externalWait: { durationMs: 1 } }).code, 'INVALID_WAIT');
  assert.equal(store.inspect({ contractId: 'EC-1', version: 1, taskId: 'T-1', runId: 'wait' }).events.length, 1);
  const beforeMissing = readdirSync(path.join(root, 'runs')).length;
  assert.throws(() => store.inspect({ contractId: 'EC-1', version: 1, taskId: 'T-1', runId: 'missing' }), /unavailable/);
  assert.equal(readdirSync(path.join(root, 'runs')).length, beforeMissing, 'read-only inspect creates nothing');
  const waitSnapshot = readdirSync(path.join(root, 'runs')).map((name) => path.join(root, 'runs', name)).find((file) => JSON.parse(readFileSync(file, 'utf8')).runId === 'wait');
  assert.equal(existsSync(waitSnapshot), true);
  const tampered = JSON.parse(readFileSync(waitSnapshot, 'utf8')); tampered.excludedWaitMs += 1; writeFileSync(waitSnapshot, JSON.stringify(tampered));
  assert.throws(() => store.inspect({ contractId: 'EC-1', version: 1, taskId: 'T-1', runId: 'wait' }), /authentication failed/);
  const budgetFile = readdirSync(root).map((name) => path.join(root, name)).find((file) => file.endsWith('.json')); const changedBudget = JSON.parse(readFileSync(budgetFile, 'utf8')); changedBudget.legionBlastMapCapMs = 99; writeFileSync(budgetFile, JSON.stringify(changedBudget)); assert.throws(() => store.require('EC-1', 1), /authentication/);
});

test('role caps & authenticated amendments bind budget changes', () => {
  const ring = generateTestKeyRing(); const root = mkdtempSync(path.join(os.tmpdir(), 'budget-amend-')); const ledger = new HostEventLedger({ root: path.join(root, 'host-events'), keyRing: ring, keyId: 'k1', clock: () => '2026-08-12T00:00:00.000Z' });
  const first = budget('EC-2', 1); first.authentication = signRecord(first, { keyRing: ring, keyId: 'k1', boundFields: BUDGET_BOUND_FIELDS, macDomain: 'arcane-budget-governance-v1' });
  const binding = { runId: 'run-budget', taskId: 'T-1', contractId: 'EC-2', contractVersion: 1, contractDigest: first.contractDigest }; const sageEvent = ledger.append({ eventId: 'sage-amend', adapter: 'codex', eventType: 'SubagentStart', sessionId: 'sage-session', binding, observedAuthority: 'sage', payload: { task: 'amend budget' } }); const issuer = new AuthorityInvocationProofIssuer({ root: path.join(root, 'proofs'), keyRing: ring, keyId: 'k1', ledgerStore: ledger, clock: () => '2026-08-12T00:00:00.000Z' }); const proof = issuer.issue({ ledger: sageEvent, binding: { ...binding, sessionId: 'sage-session' }, purpose: 'budget-amendment', role: 'sage' }).proof; const userEvent = ledger.append({ eventId: 'user-expand', adapter: 'codex', eventType: 'UserPromptSubmit', sessionId: 'user-session', binding, observedAuthority: null, payload: { prompt: 'expand scope' } }); const store = new BudgetGovernanceStore({ root, keyRing: ring, proofIssuer: issuer, hostEventLedger: ledger });
  store.seal(first);
  assert.throws(() => store.begin({ contractId: 'EC-2', version: 1, taskId: 'T', authorityRole: 'legion', activeTimeCapMs: 11, progressDeadlineMs: 1 }), /role run ceiling/);
  const second = budget('EC-2', 2); second.contractDigest = digestValue({ id: 'EC-2', version: 2 }); second.legionBlastMapCapMs = 11; second.amendmentEvidence = { schemaVersion: 1, kind: 'arcane-budget-amendment', priorContractDigest: first.contractDigest, newContractDigest: second.contractDigest, priorLegionBlastMapCapMs: 10, newLegionBlastMapCapMs: 11, priorSagePlanningCapMs: 10, newSagePlanningCapMs: 10, scopeExpanded: true, invocationProofDigest: digestValue(proof), observedAt: new Date().toISOString() }; second.amendmentEvidence.authentication = signRecord(second.amendmentEvidence, { keyRing: ring, keyId: 'k1', boundFields: BUDGET_AMENDMENT_BOUND_FIELDS, macDomain: 'arcane-budget-amendment-v1' });
  second.authentication = signRecord(second, { keyRing: ring, keyId: 'k1', boundFields: AMENDED_BUDGET_BOUND_FIELDS, macDomain: 'arcane-budget-governance-v1' }); assert.throws(() => store.seal(second), /scope expansion/);
  second.userScopeExpansionEvidence = { schemaVersion: 1, kind: 'arcane-budget-scope-expansion-evidence', priorContractDigest: first.contractDigest, newContractDigest: second.contractDigest, userTurnDigest: userEvent.payloadDigest, hostEventDigest: digestValue(userEvent), sessionId: userEvent.sessionId, observedAt: new Date().toISOString() }; second.userScopeExpansionEvidence.authentication = signRecord(second.userScopeExpansionEvidence, { keyRing: ring, keyId: 'k1', boundFields: BUDGET_SCOPE_EXPANSION_BOUND_FIELDS, macDomain: 'arcane-budget-scope-expansion-v1' }); second.authentication = signRecord(second, { keyRing: ring, keyId: 'k1', boundFields: AMENDED_BUDGET_BOUND_FIELDS, macDomain: 'arcane-budget-governance-v1' }); assert.equal(store.seal(second).version, 2);
});
