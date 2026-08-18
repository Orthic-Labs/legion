// S11 delivery/continuity bindings compose production guards.  They deliberately
// leave a corpus row pending where no production ingress and consumer exist.
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createArchitectureState, applyArchitectureEvent, validateArchitectureState } from '../architecture-state.mjs';
import { digestValue } from '../canonical.mjs';
import { openDelivery, finalizeClose } from '../delivery-guard.mjs';
import { validateGate, executeValidatedGate } from '../gate-validity.mjs';
import { BudgetGovernanceStore, BUDGET_BOUND_FIELDS } from '../budget-governance-store.mjs';
import { generateTestKeyRing } from '../keys.mjs';
import { signRecord } from '../receipt-auth.mjs';

const NOW = '2026-08-14T00:00:00.000Z';
const owner = Object.freeze({ sessionId: 's11-delivery', runId: 's11-delivery-run', taskId: 'AE' });
const acceptance = (id) => ({ schema: 'acceptance-ledger.v1', ledger_version: 1, intent_epoch: 1, acceptance_fingerprint: digestValue(id), frozen_at: NOW, items: [] });
const state = (id) => createArchitectureState({ objective_lineage_id: `s11:${id}`, budget_ref: `s11:${id}`, acceptance_ledger: acceptance(id) });
const attempts = (run) => { try { run(); return null; } catch (error) { return error; } };

function temporaryRepository() {
  const root = mkdtempSync(join(tmpdir(), 'arcane-s11-delivery-'));
  writeFileSync(join(root, 'README.md'), 's11\n');
  for (const args of [['init', '-q'], ['config', 'user.email', 's11@example.test'], ['config', 'user.name', 's11'], ['add', 'README.md'], ['commit', '-qm', 'seed']]) execFileSync('git', args, { cwd: root });
  return root;
}

function ownershipBinding() {
  const root = temporaryRepository();
  try {
    const delivery = openDelivery({ repositories: [root], readOnly: false, owner });
    const denied = attempts(() => openDelivery({ repositories: [root], readOnly: false, owner: { ...owner, runId: 'competing-run' } }));
    if (denied?.code !== 'ARC_INTEGRATION_OWNER_CONFLICT') throw new Error('competing integration writer was not denied');
    finalizeClose(delivery, { owner });
    return { ingress: 'delivery-guard.openDelivery', consumer: 'delivery lease', code: denied.code };
  } finally { rmSync(root, { recursive: true, force: true }); }
}

function frozenRealizationBinding() {
  let observed = applyArchitectureEvent(state('AE-HANDOFF-005'), { event_type: 'DECISION_FROZEN', payload: { id: 'D-1', decision_status: 'frozen', realization_status: 'pending' } });
  observed = applyArchitectureEvent(observed, { event_type: 'EFFECT_RECORDED', payload: { id: 'R-1', decision_id: 'D-1', realization_status: 'diverged', correction_route: 'alchemist' } });
  if (!validateArchitectureState(observed).valid || observed.decision.items[0].decision_status !== 'frozen' || observed.execution.effects[0].realization_status !== 'diverged') throw new Error('frozen decision divergence was not preserved');
  return { ingress: 'architecture-state.applyArchitectureEvent', consumer: 'architecture state', state_fingerprint: observed.state_fingerprint };
}

function budgetBinding(caseId, { lineage = false } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'arcane-s11-budget-'));
  try {
    let now = 0;
    const keyRing = generateTestKeyRing(['k1']);
    const store = new BudgetGovernanceStore({ root, keyRing, monotonicNow: () => now });
    const budget = { schemaVersion: 1, kind: 'arcane-budget-governance', contractId: 'EC-711', version: 1, contractDigest: digestValue(caseId), objectiveLineageId: `lineage:${caseId}`, objectiveDigest: digestValue(`objective:${caseId}`), legionBlastMapCapMs: 1, sagePlanningCapMs: 1, maxContractVersions: 2, resumeEvidence: null };
    budget.authentication = signRecord(budget, { keyRing, keyId: keyRing.activeKeyId(), boundFields: BUDGET_BOUND_FIELDS, macDomain: 'arcane-budget-governance-v1' });
    store.seal(budget);
    const run = store.begin({ contractId: 'EC-711', version: 1, taskId: caseId, authorityRole: 'legion', activeTimeCapMs: 1, progressDeadlineMs: 100, runId: `run:${caseId}` });
    now = 2;
    const terminal = store.observe(run);
    if (terminal.kind !== 'BUDGET_STOP' || terminal.code !== 'ACTIVE_CAP') throw new Error('finite inherited budget did not stop execution');
    if (lineage) {
      const reloaded = store.begin({ contractId: 'EC-711', version: 1, taskId: caseId, authorityRole: 'legion', activeTimeCapMs: 1, progressDeadlineMs: 100, runId: `run:${caseId}` });
      if (store.observe(reloaded).kind !== 'BUDGET_STOP') throw new Error('terminal lineage budget was reset');
    }
    return { ingress: 'budget-governance-store.begin/observe', consumer: 'authenticated budget event ledger', terminal: terminal.code };
  } finally { rmSync(root, { recursive: true, force: true }); }
}

function machineryDefectBinding() {
  const contract = { id: 's11-invalid-gate', inspectedScope: 'src/**', discoveryBreadth: 'bounded', blockingFilter: 'known', threshold: 1, gates: true, authority: 'oracle', failureSemantics: 'deny' };
  const validity = validateGate({ contract, fixtures: { knownGood: { id: 'good', expected: 'PASS' }, knownBad: { id: 'bad', expected: 'FAIL' }, empty: null, malformed: { id: 'malformed', expected: 'FAIL' } }, execute: (fixture) => ({ status: fixture.expected }) });
  const result = executeValidatedGate({ contract, validity, inspected: ['src/allowed.mjs'] });
  if (result.code !== 'ARC_GATE_INVALID' || result.detail?.machineryDefect !== 'OUT_OF_SCOPE_MACHINERY_DEFECT') throw new Error('gate machinery defect was not classified');
  return { ingress: 'gate-validity.validateGate', consumer: 'validated delivery gate', machinery_defect: result.detail.machineryDefect };
}

const BINDINGS = Object.freeze({
  'AE-HANDOFF-005': frozenRealizationBinding,
  'AE-INTEGRATION-OWNERSHIP-001': ownershipBinding,
  'AE-CONCURRENCY-ATTENTION-005': ownershipBinding,
  'AE-CONTROL-PLANE-BUDGETS-001': () => budgetBinding('AE-CONTROL-PLANE-BUDGETS-001'),
  'AE-LINEAGE-BUDGETS-001': () => budgetBinding('AE-LINEAGE-BUDGETS-001', { lineage: true }),
  'AE-MACHINERY-DEFECTS-001': machineryDefectBinding,
});

export function deliveryContinuityBindings() { return Object.freeze(Object.keys(BINDINGS).sort()); }

export function executeDeliveryContinuityCase(row) {
  const binding = BINDINGS[row?.id];
  if (!binding) return null;
  try {
    const observed = binding();
    return Object.freeze({ id: row.id, family: row.family, status: 'PASS', reason: 'production ingress and structured consumer observed', observed: Object.freeze(observed) });
  } catch (error) {
    return Object.freeze({ id: row.id, family: row.family, status: 'FAIL', reason: `production delivery-continuity binding failed: ${error.message}` });
  }
}
