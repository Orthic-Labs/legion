import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { canonicalJson } from '../packages/arcane/lib/canonical.mjs';
import { ReceiptStore } from '../packages/arcane/lib/receipt-store.mjs';
import { generateTestKeyRing } from '../packages/arcane/lib/keys.mjs';
import { validateSchema } from '../lib/qualification/schema-validator.mjs';
import { classifyEffect, routeArchitecture } from '../packages/arcane/lib/architecture-router.mjs';
import { applyArchitectureEvent, createArchitectureState, stateFingerprint, validateArchitectureState } from '../packages/arcane/lib/architecture-state.mjs';
import { ArchitectureEventStore } from '../packages/arcane/lib/architecture-event-store.mjs';
import { architectureDecisionFingerprint, architectureEvidenceFingerprint, architectureFindingFingerprint, architectureRetryFingerprint } from '../packages/arcane/lib/architecture-fingerprints.mjs';

const router = JSON.parse(await readFile(new URL('./fixtures/stage3/router.json', import.meta.url)));
const events = JSON.parse(await readFile(new URL('./fixtures/stage3/events.json', import.meta.url)));
const digest = (char) => `sha256:${char.repeat(64)}`;
const clone = (value) => structuredClone(value);
const fullState = () => createArchitectureState({
  objective_lineage_id: events.objective_lineage_id,
  acceptance_ledger: { schema: 'acceptance-ledger.v1', ledger_version: 1, intent_epoch: 1, acceptance_fingerprint: digest('a'), frozen_at: '2026-08-13T00:00:00Z', items: [{ id: 'AC-1', disposition: 'REQUIRED', source: 'EC-605', requirement: 'Stage 3 replay', observable_acceptance_surface: 'exact replay result', verification_method: 'node --test', owner: 'arcane-state', dependencies: [], result: 'OPEN', evidence: [] }] },
  budget_ref: 'budget-s03',
});
const proposal = (event = events.architecture) => ({
  objective_lineage_id: events.objective_lineage_id, execution_id: events.execution_id, intent_epoch: 1,
  repository_id: 'repo-s03', actor_role: 'alchemist', phase: 'execute', acceptance_ids: [], decision_ids: [], finding_ids: [],
  input_fingerprint: digest('1'), output_refs: [], checkpoint_ref: null, cost_delta: {}, retry_class: 'none', terminal_reason: null, privacy_class: 'metadata', ...event,
});
const harness = () => {
  const root = mkdtempSync(join(tmpdir(), 'legion-s03-'));
  const keyRing = generateTestKeyRing(['s03']);
  const receiptStore = new ReceiptStore({ root });
  return { root, keyRing, receiptStore, store: new ArchitectureEventStore({ receiptStore, keyRing, keyId: 's03', clock: () => '2026-08-13T00:00:00.000Z' }) };
};

test('S03-01 deterministic route/self-upgrade & effect precedence/ambiguity', () => {
  const baseline = routeArchitecture(router.insignificant);
  assert.deepEqual(routeArchitecture(clone(router.insignificant)), baseline);
  assert.equal(baseline.depth, 'D0');
  const optimized = routeArchitecture(router.significant);
  assert.equal(optimized.objective, 'optimize');
  assert.throws(() => routeArchitecture({ ...router.significant, objective: 'best_shape', prior_route: optimized }), /self-upgrade/i);
  assert.equal(classifyEffect({ declared_type: 'one_way', category: 'FILE_WRITE' }).matched_rule, 'declared_type');
  assert.equal(classifyEffect({ declared_type: 'unknown', category: 'FILE_DELETE' }).matched_rule, 'capability_category');
  assert.deepEqual(classifyEffect({ declared_type: 'unknown' }), { declared_type: 'unknown', matched_rule: 'safe_default', basis: 'ambiguous', door: 'authority_sensitive' });
});

test('S03-02 state v4 requires full projection domains, counters, fingerprints & stable upserts', () => {
  const state = fullState();
  assert.equal(validateArchitectureState(state).valid, true);
  for (const key of ['schema','task','mandate','intent','acceptance_ledger','context','architecture','uncertainty','decision','evidence','assurance','description','convergence','execution','integration','evidence_reachability','gate_validity','machinery_defects','state_fingerprint']) assert.ok(Object.hasOwn(state, key), key);
  assert.equal(state.task.budget_ref, 'budget-s03'); assert.equal(state.intent.intent_epoch, 1); assert.equal(state.intent.continuation_epoch, 1);
  for (const [owner, key] of [[state.decision,'fingerprints'],[state.evidence,'lifecycle'],[state.evidence,'artifact_envelopes'],[state.assurance,'findings'],[state.execution.retry,'fingerprints'],[state.execution,'delivery_deficits'],[state.execution,'downstream_acknowledgements'],[state.integration,'ownership_dispositions'],[state.integration,'migration_cutover']]) assert.ok(Object.hasOwn(owner, key), key);
  let patched = applyArchitectureEvent(state, { event_type: 'DECISION_RECORDED', payload: { id: 'D-2' } });
  patched = applyArchitectureEvent(patched, { event_type: 'DECISION_RECORDED', payload: { id: 'D-1' } });
  patched = applyArchitectureEvent(patched, { event_type: 'DECISION_RECORDED', payload: { id: 'D-1', fingerprint: digest('9') } });
  assert.deepEqual(patched.decision.items.map((item) => item.id), ['D-1', 'D-2']);
  patched = applyArchitectureEvent(patched, { event_type: 'FINGERPRINTS_RECORDED', payload: { decision: [architectureDecisionFingerprint({ id: 'D-1' })], evidence: [architectureEvidenceFingerprint({ id: 'E-1' })], finding: [architectureFindingFingerprint({ id: 'F-1' })], retry: [architectureRetryFingerprint({ id: 'R-1' })] } });
  assert.equal(patched.decision.fingerprints.length, 1); assert.equal(patched.evidence.fingerprints.length, 1); assert.equal(patched.assurance.fingerprints.length, 1); assert.equal(patched.execution.retry.fingerprints.length, 1);
  patched = applyArchitectureEvent(patched, { event_type: 'BUDGET_SNAPSHOT_RECORDED', payload: { id: 'budget-observation-1', budget_ref: 'arcane-budget-run:run-s03', budget_digest: digest('b'), observed_counters: { active_time_ms: 10, excluded_wait_ms: 0, retry_count: 1, event_count: 2 } } });
  assert.deepEqual(patched.execution.budget_snapshots[0].observed_counters, { active_time_ms: 10, excluded_wait_ms: 0, retry_count: 1, event_count: 2 });
  assert.throws(() => applyArchitectureEvent(patched, { event_type: 'BUDGET_SNAPSHOT_RECORDED', payload: { id: 'budget-duplicate', budget_ref: 'budget-s03', budget_digest: digest('b'), observed_counters: { active_time_ms: 0, excluded_wait_ms: 0, retry_count: 0, event_count: 0 }, legionBlastMapCapMs: 999999999 } }));
  assert.equal(validateArchitectureState(patched).valid, true);
});

test('S03-03 five closed schemas reject unknown fields & event payload mismatches', () => {
  const h = harness();
  try {
    const initial = fullState();
    h.store.replay({ objective_lineage_id: events.objective_lineage_id, initial_state: initial });
    const accepted = h.store.accept(proposal(), { expected_state_fingerprint: initial.state_fingerprint });
    const replay = h.store.replay({ objective_lineage_id: events.objective_lineage_id, initial_state: initial });
    const schema = (name) => JSON.parse(readFileSync(new URL(`../doctrine/architecture/schemas/${name}.schema.json`, import.meta.url)));
    for (const [name, value] of [['architecture-router-input', router.significant], ['architecture-route', routeArchitecture(router.significant)], ['architecture-state', initial], ['execution-trajectory-event', accepted.event], ['architecture-replay-result', replay]]) {
      assert.deepEqual(validateSchema(schema(name), value), [], name);
      const bad = clone(value); bad.extra = true; assert.ok(validateSchema(schema(name), bad).length, `${name} closed`);
    }
    const withBudget = applyArchitectureEvent(initial, { event_type: 'BUDGET_SNAPSHOT_RECORDED', payload: { id: 'budget-observation-schema', budget_ref: 'arcane-budget-run:run-s03', budget_digest: digest('b'), observed_counters: { active_time_ms: 1, excluded_wait_ms: 0, retry_count: 0, event_count: 1 } } });
    assert.deepEqual(validateSchema(schema('architecture-state'), withBudget), []);
    const authorityDuplicate = clone(withBudget); authorityDuplicate.execution.budget_snapshots[0].maxContractVersions = 99;
    assert.ok(validateSchema(schema('architecture-state'), authorityDuplicate).length, 'budget authority duplication rejected by state schema');
    assert.equal(h.store.accept(proposal(events.invalid_payload), { expected_state_fingerprint: accepted.state_fingerprint }).accepted, false);
  } finally { rmSync(h.root, { recursive: true, force: true }); }
});

test('S03-04 authenticated acceptance has exact lineage/sequence/predecessor & rejected proposals mutate nothing', () => {
  const h = harness();
  try {
    const initial = fullState();
    h.store.replay({ objective_lineage_id: events.objective_lineage_id, initial_state: initial });
    const first = h.store.accept(proposal(), { expected_state_fingerprint: initial.state_fingerprint });
    assert.equal(first.accepted, true);
    const history = h.store.events({ objective_lineage_id: events.objective_lineage_id });
    assert.equal(history.length, 1); assert.equal(history[0].sequence, 1); assert.equal(history[0].predecessor_digest, null); assert.ok(history[0].authentication);
    const before = canonicalJson(history);
    assert.equal(h.store.accept({ ...proposal(), event_id: 'caller-owned' }, { expected_state_fingerprint: first.state_fingerprint }).accepted, false);
    assert.equal(h.store.accept(proposal(), { expected_state_fingerprint: initial.state_fingerprint }).accepted, false);
    assert.equal(h.store.accept(proposal({ event_type: 'BUDGET_SNAPSHOT_RECORDED', payload: { id: 'budget-duplicate', objectiveLineageId: events.objective_lineage_id, legionBlastMapCapMs: 999999999, sagePlanningCapMs: 999999999, maxContractVersions: 99 } }), { expected_state_fingerprint: first.state_fingerprint }).accepted, false);
    assert.equal(h.store.accept(proposal({ event_type: 'EFFECT_DENIED', payload: { id: 'effect-denied', authority: 'root' } }), { expected_state_fingerprint: first.state_fingerprint }).accepted, false);
    assert.equal(h.store.accept(proposal({ event_type: 'RECOVERY_RECORDED', payload: { id: 'recovery-s04', authority: 'root' } }), { expected_state_fingerprint: first.state_fingerprint }).accepted, false);
    assert.equal(canonicalJson(h.store.events({ objective_lineage_id: events.objective_lineage_id })), before);
  } finally { rmSync(h.root, { recursive: true, force: true }); }
});

test('S03-05 exact replay twice/reopen & no duplicate authority store', () => {
  const h = harness();
  try {
    const initial = fullState(); h.store.replay({ objective_lineage_id: events.objective_lineage_id, initial_state: initial }); const accepted = h.store.accept(proposal(), { expected_state_fingerprint: initial.state_fingerprint });
    const one = h.store.replay({ objective_lineage_id: events.objective_lineage_id, initial_state: initial });
    const two = h.store.replay({ objective_lineage_id: events.objective_lineage_id, initial_state: initial });
    assert.equal(canonicalJson(one), canonicalJson(two));
    assert.equal(one.last_sequence, 1); assert.equal(one.state.execution.trajectory.last_sequence, 1); assert.equal(one.state_fingerprint, accepted.state_fingerprint);
    assert.deepEqual(Object.keys(one).sort(), ['authority_minted', 'event_count', 'last_event_digest', 'last_sequence', 'schema', 'state', 'state_fingerprint']);
    const reopened = new ArchitectureEventStore({ receiptStore: h.receiptStore, keyRing: h.keyRing, keyId: 's03', clock: () => '2026-08-13T00:00:00.000Z' });
    assert.equal(canonicalJson(reopened.replay({ objective_lineage_id: events.objective_lineage_id, initial_state: initial })), canonicalJson(one));
    assert.equal(Object.hasOwn(accepted.state, 'receipt_store'), false); assert.equal(Object.hasOwn(accepted.state, 'budget_store'), false);
  } finally { rmSync(h.root, { recursive: true, force: true }); }
});

test('S03-06 tamper, reorder, substitution & fingerprint negatives fail closed', () => {
  const h = harness();
  try {
    const initial = fullState(); h.store.replay({ objective_lineage_id: events.objective_lineage_id, initial_state: initial }); const first = h.store.accept(proposal(), { expected_state_fingerprint: initial.state_fingerprint });
    assert.equal(first.accepted, true);
    const second = h.store.accept(proposal(events.episode), { expected_state_fingerprint: first.state_fingerprint }); assert.equal(second.accepted, true);
    const file = join(h.root, 'receipts.jsonl'); const original = readFileSync(file, 'utf8'); const lines = original.trim().split('\n');
    const tampered = JSON.parse(lines[0]); tampered.record.resulting_state_fingerprint = digest('0'); writeFileSync(file, `${JSON.stringify(tampered)}\n${lines[1]}\n`);
    assert.throws(() => h.store.replay({ objective_lineage_id: events.objective_lineage_id, initial_state: initial }));
    writeFileSync(file, `${[...lines].reverse().join('\n')}\n`); assert.throws(() => h.store.replay({ objective_lineage_id: events.objective_lineage_id, initial_state: initial }));
    writeFileSync(file, original); const substituted = JSON.parse(lines[1]); substituted.record.objective_lineage_id = 'OL-substituted'; writeFileSync(file, `${lines[0]}\n${JSON.stringify(substituted)}\n`);
    assert.throws(() => h.store.replay({ objective_lineage_id: events.objective_lineage_id, initial_state: initial }));
  } finally { rmSync(h.root, { recursive: true, force: true }); }
});

test('S03-07 legal/illegal transitions & invalidation remain separate axes', () => {
  const state = fullState();
  assert.equal(applyArchitectureEvent(state, { event_type: 'ARCHITECTURE_TRANSITIONED', payload: events.architecture.payload }).task.architecture_status, 'TAILORED');
  assert.equal(applyArchitectureEvent(state, { event_type: 'EXECUTION_EPISODE_TRANSITIONED', payload: events.episode.payload }).execution.episode_state, 'QUEUED');
  assert.throws(() => applyArchitectureEvent(state, events.invalid_payload));
  assert.throws(() => applyArchitectureEvent(state, { event_type: 'INVALIDATION_RECORDED', payload: { scope: 'ROOT' } }));
});

test('architecture state accepts scoped acceptance v2 while preserving v1 replay compatibility', () => {
  const legacy = fullState();
  assert.equal(validateArchitectureState(legacy).valid, true);
  const scoped = structuredClone(legacy);
  scoped.acceptance_ledger = {
    schema: 'acceptance-ledger.v2',
    ledger_version: 2,
    intent_epoch: 1,
    acceptance_manifest_fingerprint: digest('b'),
    schedule_fingerprint: digest('c'),
    schedule: { schedule_version: 1, waves: [['AC-1']] },
    frozen_at: '2026-08-13T00:00:00Z',
    items: [{ ...legacy.acceptance_ledger.items[0], item_fingerprint: digest('d') }],
  };
  scoped.state_fingerprint = stateFingerprint(scoped);
  assert.equal(validateArchitectureState(scoped).valid, true);
  assert.deepEqual(validateSchema(JSON.parse(readFileSync(join(import.meta.dirname, '..', 'doctrine', 'architecture', 'schemas', 'architecture-state.schema.json'), 'utf8')), scoped), []);
});
