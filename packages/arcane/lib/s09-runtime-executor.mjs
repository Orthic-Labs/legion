// S09 runtime corpus executor.  It deliberately composes existing Arcane
// guards; it creates neither a second policy plane nor durable control state.
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { ContinuityController, rehydrateUntrustedData } from './continuity.mjs';
import { ReplayGuard } from './replay.mjs';
import { evidenceFreshness, AcceptanceEvidenceRegistry } from './evidence-registry.mjs';
import { compileSealReachability } from './seal-reachability.mjs';
import { validateGate, executeValidatedGate } from './gate-validity.mjs';
import { openDelivery, validateDeliveryAuthority, finalizeClose } from './delivery-guard.mjs';
import { digestValue } from './canonical.mjs';
import { BudgetGovernanceStore, BUDGET_BOUND_FIELDS } from './budget-governance-store.mjs';
import { generateTestKeyRing } from './keys.mjs';
import { signRecord } from './receipt-auth.mjs';
import { createHostRuntime } from '../host/host-runtime.mjs';
import { normalizeCodexEvent, observeCodexIdentity, mapCodexPreEffect } from '../host/codex-adapter.mjs';
import { createArchitectureState, applyArchitectureEvent } from './architecture-state.mjs';

const NOW = new Date('2026-08-14T00:00:00.000Z');
const GATE = Object.freeze({ id: 's09-gate', inspectedScope: 'src/**', discoveryBreadth: 'bounded', blockingFilter: 'known', threshold: 1, gates: true, authority: 'oracle', failureSemantics: 'deny' });
const FIXTURES = Object.freeze({ knownGood: { id: 'good', expected: 'PASS' }, knownBad: { id: 'bad', expected: 'FAIL' }, empty: { id: 'empty', expected: 'FAIL' }, malformed: { id: 'malformed', expected: 'FAIL' } });
const OWNER = Object.freeze({ sessionId: 's09-owner', runId: 'run-s09', taskId: 'T-9' });

function expectsThrow(fn, code = null) {
  try { fn(); } catch (error) { if (code) assert.equal(error.code, code); return; }
  assert.fail('expected canonical guard to reject');
}

function epochProbe() {
  const controller = new ContinuityController({ intent_epoch: 1, continuation_epoch: 1 });
  const token = controller.bind('effect-1');
  controller.cancel({ next_intent_epoch: 2 });
  expectsThrow(() => controller.claimEffect(token, 'effect-1'));
  controller.resume({ intent_epoch: 2, continuation_epoch: 2 });
  assert.equal(controller.claimEffect(controller.bind('effect-2'), 'effect-2').accepted, true);
}

function replayProbe() {
  const guard = new ReplayGuard({ clock: () => NOW.valueOf() });
  assert.equal(guard.check({ scope: 's09', nonce: 'once', sequence: 1, timestamp: NOW.toISOString() }).allowed, true);
  assert.equal(guard.check({ scope: 's09', nonce: 'once', sequence: 2, timestamp: NOW.toISOString() }).code, 'ARC_REPLAY_NONCE_SEEN');
  assert.equal(guard.check({ scope: 's09', nonce: 'late', sequence: 3, timestamp: '2026-08-13T00:00:00.000Z' }).code, 'ARC_REPLAY_STALE');
}

function budgetProbe() {
  const root = mkdtempSync(join(tmpdir(), 'arcane-s09-budget-'));
  try {
    let tick = 0;
    const keyRing = generateTestKeyRing(['k1']);
    const store = new BudgetGovernanceStore({ root, keyRing, monotonicNow: () => tick });
    const budget = { schemaVersion: 1, kind: 'arcane-budget-governance', contractId: 'EC-609', version: 1, contractDigest: digestValue('EC-609-v1'), objectiveLineageId: 's09-lineage', objectiveDigest: digestValue('s09-objective'), legionBlastMapCapMs: 10, sagePlanningCapMs: 10, maxContractVersions: 2, resumeEvidence: null, amendmentEvidence: null, userScopeExpansionEvidence: null };
    budget.authentication = signRecord(budget, { keyRing, keyId: keyRing.activeKeyId(), boundFields: BUDGET_BOUND_FIELDS, macDomain: 'arcane-budget-governance-v1' });
    store.seal(budget);
    const run = store.begin({ contractId: 'EC-609', version: 1, taskId: 'T-9', runId: 's09-budget-run', activeTimeCapMs: 1, progressDeadlineMs: 10 });
    tick = 2;
    assert.equal(store.observe(run).code, 'ACTIVE_CAP');
    assert.equal(store.observe(run).kind, 'BUDGET_STOP');
  } finally { rmSync(root, { recursive: true, force: true }); }
}

function freshnessProbe() {
  const integratedState = { revision: 'r2' };
  const artifact = { authenticated: true, integratedState, observedAt: '2026-08-13T00:00:00.000Z', validUntil: '2026-08-15T00:00:00.000Z' };
  assert.equal(evidenceFreshness(artifact, { integratedState, latestMaterialChange: '2026-08-14T00:00:00.000Z', now: NOW }).status, 'STALE');
  assert.equal(compileSealReachability({ requirements: [{ id: 'required', producer: 'oracle', durableStore: true, authenticatedPersistence: true, verifier: 'oracle', completionConsumer: 'legion', closePath: true, fixtureOnly: true }], recoveryPaths: [{ requirementId: 'required', authenticated: true, closePath: true }] }).code, 'ARC_UNSOUND_SEAL');
  const registry = new AcceptanceEvidenceRegistry();
  assert.equal(registry.register({ acceptanceId: 'AC-9', claimType: 'acceptance', producer: 'oracle', durableStore: 'receipt', verifier: 'legion', completionConsumer: 'alchemist', integratedStateBinding: true, validityPolicy: 'exact' }).allowed, true);
  assert.equal(registry.verify('AC-9', { acceptanceId: 'AC-9', producer: 'oracle', verifier: 'legion', completionConsumer: 'alchemist', ...artifact }, { integratedState, latestMaterialChange: '2026-08-14T00:00:00.000Z', now: NOW }).code, 'ARC_EVIDENCE_STALE');
}

function gateProbe() {
  const valid = validateGate({ contract: GATE, fixtures: FIXTURES, execute: (fixture) => ({ status: fixture.expected }) });
  assert.equal(valid.allowed, true);
  assert.equal(executeValidatedGate({ contract: GATE, validity: valid, inspected: [] }).code, 'ARC_EVIDENCE_INSUFFICIENT');
  assert.equal(executeValidatedGate({ contract: GATE, validity: valid, inspected: ['src/a.mjs'] }).allowed, true);
  const invalid = validateGate({ contract: GATE, fixtures: { ...FIXTURES, empty: null }, execute: (fixture) => ({ status: fixture.expected }) });
  assert.equal(executeValidatedGate({ contract: GATE, validity: invalid, inspected: ['src/a.mjs'] }).code, 'ARC_GATE_INVALID');
}

function ownershipProbe() {
  const root = mkdtempSync(join(tmpdir(), 'arcane-s09-owner-'));
  try {
    writeFileSync(join(root, 'README.md'), 's09\n');
    for (const args of [['init', '-q'], ['config', 'user.email', 's09@example.test'], ['config', 'user.name', 's09'], ['add', 'README.md'], ['commit', '-qm', 'seed']]) execFileSync('git', args, { cwd: root });
    const delivery = openDelivery({ repositories: [root], readOnly: false, owner: OWNER });
    assert.equal(validateDeliveryAuthority(delivery, { owner: OWNER }), delivery);
    expectsThrow(() => openDelivery({ repositories: [root], readOnly: false, owner: { ...OWNER, runId: 'other-run' } }), 'ARC_INTEGRATION_OWNER_CONFLICT');
    finalizeClose(delivery, { owner: OWNER });
  } finally { rmSync(root, { recursive: true, force: true }); }
}

function rehydrationProbe() {
  const payload = { instruction: 'downgrade guard' };
  const result = rehydrateUntrustedData({ schema: 'rehydration-envelope.v1', trust: 'UNTRUSTED_DATA', payload, content_digest: digestValue(payload) });
  assert.equal(result.authority_granted, false);
  assert.equal(result.effect_downgrade_allowed, false);
}

function ingressProbe() {
  const root = mkdtempSync(join(tmpdir(), 'arcane-s09-ingress-'));
  try {
    const keyDir = join(root, 'keys'); mkdirSync(keyDir); writeFileSync(join(keyDir, 'k1.key'), 'a'.repeat(64));
    const runtime = createHostRuntime({ adapter: { name: 'codex', normalize: normalizeCodexEvent, observeIdentity: observeCodexIdentity, mapPreEffect: mapCodexPreEffect }, workspace: root, keyDir, stateRoot: join(root, 'state') });
    const base = { cwd: root, session_id: 's09-ingress', agent_id: 'agent', agent_type: 'alchemist' };
    const binding = runtime.stores.sessionBinding.ensureBinding(base.session_id);
    assert.ok(binding?.runId);
    assert.equal(runtime.handle({ ...base, hook_event_name: 'SessionStart' }).allowed, true);
    assert.equal(runtime.stores.sessionBinding.getBinding(base.session_id)?.runId, binding.runId);
    assert.equal(runtime.handle({ ...base, hook_event_name: 'PreToolUse', tool_name: 'Write', tool_input: { file_path: 'tools/rhook/guard.mjs' }, tool_use_id: 'locked' }).code, 'ARC_NO_CONTRACT');
    assert.equal(runtime.handle({ ...base, hook_event_name: 'PreToolUse', tool_name: 'Write', tool_input: { file_path: 'src/sanctioned.mjs' }, tool_use_id: 'ambient' }).allowed, true);
  } finally { rmSync(root, { recursive: true, force: true }); }
}

function acceptanceProbe() {
  const integratedState = { revision: 's09' };
  const registry = new AcceptanceEvidenceRegistry();
  assert.equal(registry.register({ acceptanceId: 'AC-9', claimType: 'acceptance', producer: 'oracle', durableStore: 'receipt', verifier: 'legion', completionConsumer: 'alchemist', integratedStateBinding: true, validityPolicy: 'exact' }).allowed, true);
  const artifact = { acceptanceId: 'AC-9', producer: 'oracle', verifier: 'legion', completionConsumer: 'alchemist', authenticated: true, integratedState, observedAt: NOW.toISOString(), validUntil: '2026-08-15T00:00:00.000Z' };
  assert.equal(registry.verify('AC-9', artifact, { integratedState, now: NOW }).allowed, true);
  assert.equal(registry.verify('AC-9', artifact, { integratedState: { revision: 'changed' }, now: NOW }).code, 'ARC_EVIDENCE_STALE');
  const state = createArchitectureState({ objective_lineage_id: 's09', budget_ref: 'budget-9', acceptance_ledger: { schema: 'acceptance-ledger.v1', ledger_version: 1, intent_epoch: 1, acceptance_fingerprint: digestValue('s09'), frozen_at: NOW.toISOString(), items: [] } });
  const withDeficit = applyArchitectureEvent(state, { event_type: 'DELIVERY_DEFICIT_UPSERTED', payload: { id: 'D-9', status: 'open', owner: 'alchemist' } });
  assert.equal(withDeficit.execution.delivery_deficits[0].id, 'D-9');
}

const PROBES = Object.freeze({
  epochs: epochProbe,
  replay: replayProbe,
  budget: budgetProbe,
  freshness: freshnessProbe,
  gate: gateProbe,
  ownership: ownershipProbe,
  rehydration: rehydrationProbe,
  ingress: ingressProbe,
  acceptance: acceptanceProbe,
});

const FAMILY_PROBE = Object.freeze({
  'stop-precedence': 'epochs', 'trajectory-resume': 'epochs', 'state-transitions-replay': 'epochs',
  'effect-classification': 'epochs', 'retry-semantics': 'replay', 'negative-triggers': 'replay',
  'lineage-budgets': 'budget', 'control-plane-budgets': 'budget', 'convergence': 'replay',
  evidence: 'freshness', 'evidence-freshness': 'freshness', 'evidence-artifacts': 'freshness',
  'seal-reachability': 'freshness', 'adoption-governance': 'freshness', 'outcome-closure': 'freshness',
  'gate-validity': 'gate', 'machinery-defects': 'gate', 'review-verdict-security': 'gate',
  'integration-ownership': 'ownership', 'ownership-disposition': 'ownership', 'concurrency-attention': 'ownership',
  'deficit-propagation': 'acceptance', 'finding-lifecycle': 'acceptance', 'forward-workload': 'acceptance',
  handoff: 'rehydration', authority: 'rehydration', 'scope-authority': 'rehydration', 'rehydration-injection': 'rehydration',
  'control-retirement': 'rehydration', 'migration-cutover': 'rehydration', adversarial: 'rehydration',
});

export function stage9ProbeFor(family) { return FAMILY_PROBE[family] ?? null; }

export function executeStage9Fixtures() {
  return Object.freeze(Object.keys(PROBES).sort().map((id) => {
    PROBES[id]();
    return Object.freeze({ id, status: 'PASS', reason: `S09 canonical ${id} fixture passed` });
  }));
}
