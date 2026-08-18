import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { validateSchema } from '../src/lib/qualification/schema-validator.mjs';

const root = join(import.meta.dirname, '..', 'doctrine', 'architecture');
const text = (path) => readFileSync(join(root, path), 'utf8');
const json = (path) => JSON.parse(text(path));
const has = (body, values) => values.forEach((value) => assert.match(body, new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'), value));
const noLaterStageClaims = (body) => {
  // Later stages may be named as owners, but S02 cannot claim their runtime paths.
  assert.doesNotMatch(body, /(?:packages\/arcane|tools\/rhook|lib\/budget-governance-store)/i);
};
const requiredItemAdmitted = (item) => item.disposition !== 'REQUIRED'
  || Boolean(item.observable_acceptance_surface && item.verification_method);
const reviewContractAdmitted = (contract) => JSON.stringify(contract.admission_gates) === JSON.stringify([
  'process', 'reachability', 'control', 'real_impact', 'reproduction', 'bounds', 'environment',
]) && contract.first_failed_gate_dismisses === true
  && contract.clean_claim.meaning === 'configured_gates_passed'
  && ['scope_binding', 'state_binding', 'freshness_binding'].every((key) => Boolean(contract.clean_claim[key]));
const childBudgetAdmitted = (child, parent) => child.objective_lineage_id === parent.objective_lineage_id
  && child.wall_clock_budget_ms <= parent.wall_clock_budget_ms
  && child.active_time_budget_ms <= parent.active_time_budget_ms
  && child.design_round_budget <= parent.design_round_budget
  && child.review_budget <= parent.review_budget
  && child.contract_version_budget <= parent.contract_version_budget;
const retryAdmitted = ({ retryable, finite, materialDelta, identicalFingerprint, budgetRemaining }) => retryable
  && finite && materialDelta && !identicalFingerprint && budgetRemaining;
const debtAdmitted = ({ required, protectedClass, missingEvidence, missingAuthority }) => !required
  && !protectedClass && !missingEvidence && !missingAuthority;
const closureEligible = ({ acceptanceSurface, fresh, exactState, reachableSeal, inspectionCount, machineryTookScope }) => acceptanceSurface
  && fresh && exactState && reachableSeal && inspectionCount > 0 && !machineryTookScope;
const retirementAdmitted = ({ migrated, obligations, consumers, conformance }) => migrated
  && obligations.length === 0 && consumers.length === 0 && conformance === 'PASS';
const completionAdmitted = ({ actor, requiredFreshProof }) => actor === 'acceptance_closure' && requiredFreshProof;

const fingerprint = 'sha256:' + 'a'.repeat(64);
const requiredLedger = () => ({
  schema: 'acceptance-ledger.v2', ledger_version: 1, intent_epoch: 1, acceptance_manifest_fingerprint: fingerprint,
  schedule_fingerprint: fingerprint, schedule: { schedule_version: 1, waves: [['AC-1']] },
  frozen_at: '2026-08-13T00:00:00Z', items: [{ id: 'AC-1', disposition: 'REQUIRED', source: 'user', requirement: 'deliver', observable_acceptance_surface: 'visible result', verification_method: 'node --test', owner: 'owner', dependencies: [], item_fingerprint: fingerprint, result: 'OPEN', evidence: [] }],
});
const budgetFixture = () => ({
  objective_lineage_id: 'OL-1', intent_epoch: 1, parent_budget_ref: 'parent-1', wall_clock_budget_ms: 1, active_time_budget_ms: 1, design_round_budget: 1, review_budget: 1, contract_version_budget: 1,
  attention_budget: { independent_ready_tasks: 1, available_agent_slots: 1, integration_owner_review_capacity: 1, shared_state_writer_constraints: 1, context_and_evidence_merge_budget: 1, admitted_concurrency: 1 },
  control_plane_budget: { parent_budget_ref: 'parent-1', wall_clock_budget_ms: 1, active_time_budget_ms: 1, hook_chain_count_cap: 1, consecutive_hook_block_cap: 1, subagent_count_cap: 1, subagent_concurrency_cap: 1, worker_batch_count_cap: 1, nesting_depth_cap: 1, spawn_depth_cap: 1, wait_monitor_iteration_cap: 1, recovery_iteration_cap: 1, subprocess_count_cap: 1, subprocess_timeout_ms: 1 }, terminal_state: 'ACTIVE',
});

test('S02-01 frozen acceptance ledger admits valid fixture & rejects unauthorized REQUIRED mutation', () => {
  const schema = json('schemas/acceptance-ledger.schema.json');
  assert.deepEqual(validateSchema(schema, requiredLedger()), []);
  const invalid = requiredLedger(); delete invalid.items[0].observable_acceptance_surface;
  assert.equal(requiredItemAdmitted(requiredLedger().items[0]), true);
  assert.equal(requiredItemAdmitted(invalid.items[0]), false);
  const body = text('controls/acceptance-ledger.md');
  has(body, ['REQUIRED', 'DEFERRED', 'OUT_OF_SCOPE', 'immutable', 'item_fingerprint', 'acceptance_manifest_fingerprint', 'schedule_fingerprint', 'schedule-only change invalidates no acceptance evidence', 'later explicit user intent', 'unauthorized required mutation is rejected']);
  noLaterStageClaims(body);
  has(text('templates/acceptance-ledger.md'), ['ledger_version', 'intent_epoch', 'acceptance_manifest_fingerprint', 'schedule_fingerprint', 'item_fingerprint', 'observable_acceptance_surface', 'verification_method']);
});

test('S02-02 reviewer non-expansion admits scoped finding/CLEAN & rejects scope expansion or overbroad CLEAN', () => {
  const contract = { schema: 'review-module-contract.v1', module_id: 'scope', module_version: '1', when_to_use: ['mapped review'], when_not_to_use: ['unmapped'], configured_scope: 'AC-1', eligibility_filter: 'mapped', admission_gates: ['process', 'reachability', 'control', 'real_impact', 'reproduction', 'bounds', 'environment'], first_failed_gate_dismisses: true, claim_language_policy: 'scoped', remediation_proportionality_check: 'yes', calibration_table_version: 'v1', clean_claim: { meaning: 'configured_gates_passed', scope_binding: 'AC-1', state_binding: 'sha', freshness_binding: 'fresh' } };
  assert.deepEqual(validateSchema(json('schemas/review-module-contract.schema.json'), contract), []);
  assert.equal(reviewContractAdmitted(contract), true);
  const bad = structuredClone(contract); bad.clean_claim.meaning = 'perfect safety'; assert.ok(validateSchema(json('schemas/review-module-contract.schema.json'), bad).length);
  const reordered = structuredClone(contract); [reordered.admission_gates[0], reordered.admission_gates[1]] = [reordered.admission_gates[1], reordered.admission_gates[0]]; assert.equal(reviewContractAdmitted(reordered), false);
  const finding = { finding_id: 'F-1', fingerprint: 'fp', verdict: 'true_positive', triage_path: 'process', dismissal_gate: 'none', dismissal_evidence: ['e'], kind: 'risk', severity: 'blocker', confidence: 'high', reachability: 'reachable', control: 'attacker_or_user_controlled', impact: 'demonstrated', disposition: 'valid', blocker_mapping: 'FAILED_ACCEPTANCE', evidence: ['e'], anchors: ['a'], negative_evidence: [], affected_decision_ids: [], first_observed_at: 't', last_observed_at: 't', status: 'open', invalidation_cause: 'none', invalidation_scope: 'none', owner: 'oracle', frozen_acceptance_or_invariant_id: 'AC-1', minimum_correction: 'fix' };
  assert.deepEqual(validateSchema(json('schemas/architecture-review-finding.schema.json'), finding), []);
  has(text('controls/reviewer-scope.md'), ['cannot create acceptance', 'DEFERRED', 'OUT_OF_SCOPE', 'FAILED_ACCEPTANCE']);
  has(text('reviews/review-gates.md'), ['Dismiss first', 'first failed gate', 'CLEAN', 'uninspected']);
  noLaterStageClaims(text('controls/reviewer-scope.md'));
});

test('S02-03 bounded clarification converges at material frontier & rejects scheduled/blocking FOG', () => {
  const body = text('controls/clarification-convergence.md');
  has(body, ['frontier', 'candidate ranking', 'MUST_DECIDE_NOW', 'ASSUMPTION_TO_TEST', 'DEFER_TO_LATER_SLICE', 'ACCEPTED_RISK', 'OUT_OF_SCOPE', 'EXTERNAL_BLOCKER', 'FOG is not', 'scheduled work', 'blocker']);
  noLaterStageClaims(body);
});

test('S02-04 ADR admission admits all predicates & rejects low-worth ADR', () => {
  const body = text('controls/adr-admission.md');
  has(body, ['hard or costly to reverse', 'surprising', 'real trade-off', 'If any fails, reject ADR', 'Reversible local work', 'no ADR']);
  noLaterStageClaims(body);
});

test('S02-05 finite lineage/control-plane budget admits bounded fixture & rejects reset, omission, or child expansion', () => {
  const schema = json('schemas/objective-lineage-budget.schema.json');
  assert.deepEqual(validateSchema(schema, budgetFixture()), []);
  const missing = budgetFixture(); delete missing.control_plane_budget.spawn_depth_cap; assert.ok(validateSchema(schema, missing).length);
  const parent = budgetFixture(); parent.wall_clock_budget_ms = 10; parent.active_time_budget_ms = 10;
  const child = budgetFixture(); assert.equal(childBudgetAdmitted(child, parent), true);
  child.design_round_budget = 2; assert.equal(childBudgetAdmitted(child, parent), false);
  child.design_round_budget = 1; child.objective_lineage_id = 'reset-lineage'; assert.equal(childBudgetAdmitted(child, parent), false);
  const body = text('controls/objective-lineage-budgets.md') + text('controls/control-plane-budgets.md');
  has(body, ['finite', 'new identifier never resets', 'child may receive no more remaining budget', 'may not mint a lineage', 'child expansion rejects']);
  noLaterStageClaims(body);
});

test('S02-06 material-delta retry is admitted & identical/nonretryable attempts reject', () => {
  const body = text('controls/retry-semantics.md') + text('controls/intent-cancellation.md') + text('canon-map.md');
  has(body, ['material input, method, or state delta', 'non-retryable', 'Second identical fingerprint terminates', 'attempts greater than three mismatch', 'doctrine-recorded drift only', 'runtime repair']);
  assert.equal(retryAdmitted({ retryable: true, finite: true, materialDelta: true, identicalFingerprint: false, budgetRemaining: true }), true);
  assert.equal(retryAdmitted({ retryable: true, finite: true, materialDelta: false, identicalFingerprint: true, budgetRemaining: true }), false);
  assert.equal(retryAdmitted({ retryable: false, finite: true, materialDelta: true, identicalFingerprint: false, budgetRemaining: true }), false);
  assert.doesNotMatch(text('controls/retry-semantics.md'), /implements?|repairs? runtime/i);
  noLaterStageClaims(text('controls/retry-semantics.md'));
});

test('S02-07 owned nonrequired debt acknowledges & required item cannot convert to debt', () => {
  const deficit = json('schemas/delivery-deficit.schema.json');
  const valid = { schema: 'delivery-deficit.v1', deficit_id: 'D-1', origin_acceptance_id: 'AC-optional', kind: 'optional_gap', severity: 'follow_up', status: 'open', owner: 'owner', affected_tasks: [], affected_claim_levels: ['partial'], missing_or_degraded_behavior: 'optional polish', evidence: [], trigger: 'next slice', expiry: '2027-01-01', downstream_acknowledgements: [] };
  assert.deepEqual(validateSchema(deficit, valid), []);
  const ack = json('schemas/downstream-acknowledgement.schema.json');
  assert.equal(ack.properties.disposition.enum.includes('compatible'), true);
  assert.equal(debtAdmitted({ required: false, protectedClass: false, missingEvidence: false, missingAuthority: false }), true);
  assert.equal(debtAdmitted({ required: true, protectedClass: false, missingEvidence: false, missingAuthority: false }), false);
  has(text('controls/delivery-deficits.md'), ['`REQUIRED` acceptance', 'never becomes debt automatically', 'acknowledge', 'compatible', 'workaround', 'blocked', 'replan']);
  has(text('templates/delivery-deficit.md'), ['origin_acceptance_id', 'downstream', 'acknowledgement']);
  noLaterStageClaims(text('controls/delivery-deficits.md'));
});

test('S02-08 fresh reachable evidence is closure-eligible & proxy, stale, zero-inspection, or gate takeover reject', () => {
  const body = ['controls/evidence-freshness.md', 'controls/seal-reachability.md', 'controls/gate-validity.md', 'controls/machinery-defect-isolation.md'].map(text).join('\n');
  has(body, ['exact integrated-state identity', 'proxy', 'UNSOUND_SEAL', 'Zero eligible inspected items', 'OUT_OF_SCOPE_MACHINERY_DEFECT', 'cannot silently replace product task']);
  assert.equal(closureEligible({ acceptanceSurface: true, fresh: true, exactState: true, reachableSeal: true, inspectionCount: 1, machineryTookScope: false }), true);
  assert.equal(closureEligible({ acceptanceSurface: false, fresh: true, exactState: true, reachableSeal: true, inspectionCount: 1, machineryTookScope: false }), false);
  assert.equal(closureEligible({ acceptanceSurface: true, fresh: false, exactState: true, reachableSeal: true, inspectionCount: 0, machineryTookScope: true }), false);
  noLaterStageClaims(body);
});

test('S02-09 fully migrated control retires & silent deletion or stranded deprecation reject', () => {
  const schema = json('schemas/control-lifecycle.schema.json');
  const valid = { schema: 'architecture-control-lifecycle.v1', control_id: 'c-1', status: 'RETIRED', canonical_owner: 'owner', rationale: 'replaced', live_acceptance_or_safety_obligations: [], live_consumers: [], replacement_or_supersession: 'c-2', migration_plan: 'migrated', schema_eval_metric_doc_updates: ['test'], retirement_evidence: ['proof'], conformance_result: 'PASS', changed_at: '2026-08-13T00:00:00Z' };
  assert.deepEqual(validateSchema(schema, valid), []);
  assert.equal(retirementAdmitted({ migrated: true, obligations: [], consumers: [], conformance: 'PASS' }), true);
  const bad = structuredClone(valid); bad.live_consumers = ['stranded'];
  assert.equal(retirementAdmitted({ migrated: true, obligations: [], consumers: bad.live_consumers, conformance: 'PASS' }), false);
  has(text('controls/control-lifecycle.md'), ['PROPOSED', 'ACTIVE', 'DEPRECATED', 'RETIRED', 'SUPERSEDED', 'Silent deletion', 'consumer-stranding']);
  has(text('templates/control-lifecycle.md'), ['canonical_owner', 'retirement_evidence', 'conformance_result']);
  noLaterStageClaims(text('controls/control-lifecycle.md'));
});

test('S02-10 typed readiness/execution/completion axes admit separation & reject generic collapse or implementer COMPLETE', () => {
  const body = text('controls/terminal-states.md');
  has(body, ['readiness, execution episode, implementer outcome, & acceptance completion distinct', 'READY_TO_EXECUTE', 'PENDING', 'SUCCEEDED', 'CANDIDATE', 'neither episode success nor implementer output mints `COMPLETE`', 'Generic “done”, collapsed axes']);
  assert.equal(completionAdmitted({ actor: 'acceptance_closure', requiredFreshProof: true }), true);
  assert.equal(completionAdmitted({ actor: 'implementer', requiredFreshProof: true }), false);
  assert.equal(completionAdmitted({ actor: 'acceptance_closure', requiredFreshProof: false }), false);
  noLaterStageClaims(body);
});
