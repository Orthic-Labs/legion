import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { digestValue } from '../src/lib/contracts/arcane/canonical.mjs';
import { WorkflowContinuityStore, cancelProcessGroup, executionTrajectoryPayload } from '../src/lib/host/arcane/continuity.mjs';
import { RunLedger, RuntimeAdmission } from '../src/lib/core/execute-plan.mjs';
import { normalizeExecutorAction, runExternal } from '../src/lib/providers/executor/external-process.mjs';
import { ARCHITECTURE_EVENT_BOUND_FIELDS } from '../src/lib/verification/arcane/architecture-event-store.mjs';
import { HostEventLedger, ObservationOutbox } from '../src/lib/host/arcane/host-event-ledger.mjs';
import { TriggerStore } from '../src/lib/cli/commands/schedule.mjs';
import { probeCapability } from '../src/lib/capabilities/probe.mjs';
import { compileArcaneRoute, runFalsificationPass } from '../src/lib/cognitive/arcane/route-envelope.mjs';
import { selectStrongerWorkingModel } from '../src/lib/host/arcane/codex-escalation.mjs';
import { DependencyLedger } from '../src/lib/verification/arcane/invalidation.mjs';

const temp = () => mkdtempSync(join(tmpdir(), 'legion-unresolved-'));
const withTemp = (fn) => async () => { const root = temp(); try { await fn(root); } finally { rmSync(root, { recursive: true, force: true }); } };
const fingerprint = digestValue('workflow');

test('LEG-017 durable checkpoint resumes unfinished work & deduplicates effects', withTemp((root) => {
  const store = new WorkflowContinuityStore({ root });
  store.checkpoint({ runId: 'run-17', fingerprint, nodes: [{ id: 'done', state: 'SUCCEEDED' }, { id: 'open', dependencies: ['done'] }], completedEffects: ['effect-1'], completedOutputs: { done: digestValue('output') } });
  const resumed = new WorkflowContinuityStore({ root }).resume({ runId: 'run-17', fingerprint });
  assert.deepEqual(resumed.unfinished.map(({ id }) => id), ['open']);
  assert.deepEqual(resumed.completedEffects, ['effect-1']);
}));

test('LEG-018 named pause binds operator direction & advances continuation', withTemp((root) => {
  const store = new WorkflowContinuityStore({ root });
  store.checkpoint({ runId: 'run-18', fingerprint });
  store.pause({ runId: 'run-18', decisionId: 'decision-1', phase: 'execute', choices: ['retry', 'stop'], contextFingerprint: digestValue('context'), continuationToken: 'token-1' });
  const resumed = store.applyDirection({ runId: 'run-18', decisionId: 'decision-1', choice: 'retry', response: 'retry safely' });
  assert.equal(resumed.continuationEpoch, 2); assert.equal(resumed.pause.chosen, 'retry');
}));

test('LEG-019 unified run ledger stops on ceiling & process group quiesces', async () => {
  const ledger = new RunLedger({ maxSteps: 1, maxCalls: 1, maxSpendMicros: 5, maxWallTimeMs: 1000, clock: () => 0 });
  ledger.reserve({ steps: 1, calls: 1, spendMicros: 5 });
  assert.throws(() => ledger.reserve({ steps: 1 }), { code: 'LEGION_RUN_BUDGET' });
  const result = await cancelProcessGroup({ group_id: 'group', terminate: async () => {}, alive: async () => [] });
  assert.equal(result.process_group_quiescent, true);
});

test('LEG-020 replan replaces remaining DAG & preserves completed outputs', withTemp((root) => {
  const store = new WorkflowContinuityStore({ root });
  store.checkpoint({ runId: 'run-20', fingerprint, nodes: [{ id: 'done', state: 'SUCCEEDED' }, { id: 'failed', dependencies: ['done'], state: 'FAILED' }], completedOutputs: { done: digestValue('kept') } });
  const replanned = store.replan({ runId: 'run-20', failure: { node: 'failed' }, replacementNodes: [{ id: 'replacement', dependencies: ['done'] }] });
  assert.deepEqual(replanned.nodes.map(({ id }) => id), ['done', 'replacement']); assert.equal(replanned.completedOutputs.done, digestValue('kept'));
}));

test('LEG-021 executor action normalization gives one correction before effects', async () => {
  assert.deepEqual(normalizeExecutorAction({ operation: ' inspect ', effectClass: 'command_exec', target: ' workspace ', arguments: {} }), { operation: 'inspect', effectClass: 'COMMAND_EXEC', target: 'workspace', arguments: {} });
  assert.throws(() => normalizeExecutorAction({ operation: 'inspect' }), (error) => error.code === 'LEGION_ACTION_MALFORMED' && error.guidance.path === '$.effectClass');
  const result = await runExternal({ executable: process.execPath, args: ['-e', 'process.stdout.write("bad")'], parseOutput: () => { throw new Error('bad'); }, parseAction: true, correctMalformedOutput: async () => ({ operation: 'inspect', effectClass: 'COMMAND_EXEC', target: 'workspace', arguments: {} }) }, { allowedExecutables: new Set([process.execPath]), env: {}, artifactStore: { writeBytes: async (_path, _bytes, receipt) => ({ ...receipt, immutable: true }) }, processTree: { hardKill: async () => {}, receipt: { bounded: true } }, clock: { now: () => 1 } });
  assert.equal(result.correction.attempts, 1); assert.equal(result.spawnStatus, 'completed');
});

test('LEG-022 trajectory schema binds parent, node, dependencies, submission & terminal state', () => {
  const fields = ['parent_execution_id', 'work_node_id', 'dependency_ids', 'submission_state', 'submitted_at', 'terminal_state'];
  const payload = executionTrajectoryPayload({ eventId: 'event-22', eventType: 'stop', time: '2026-08-31T00:00:00.000Z', extensions: { parentExecutionId: 'parent', workNodeId: 'node', dependencyIds: ['dependency'] } }, { to: 'SUCCEEDED' });
  for (const field of fields) { assert.ok(Object.hasOwn(payload, field)); assert.equal(ARCHITECTURE_EVENT_BOUND_FIELDS.includes(field), false); }
  assert.deepEqual(payload.dependency_ids, ['dependency']); assert.equal(payload.terminal_state, 'SUCCEEDED');
});

test('LEG-023 usage is attributed to run/work unit & aggregated without estimation', withTemp((root) => {
  const outbox = new ObservationOutbox({ root });
  outbox.enqueue({ eventId: 'usage-1', runId: 'run-23', taskId: 'node-1', usage: { calls: 1, inputTokens: 10, outputTokens: 5, costMicros: 7, complete: true } });
  assert.deepEqual(outbox.aggregateUsage({ runId: 'run-23', taskId: 'node-1' }), { calls: 1, inputTokens: 10, outputTokens: 5, costMicros: 7, incomplete: false });
}));

test('LEG-024 durable trigger identity deduplicates workflow enqueue', withTemp((root) => {
  const store = new TriggerStore({ root });
  const trigger = { triggerId: 'trigger-1', type: 'schedule', source: 'cron', target: 'workflow-1', idempotencyKey: 'once', runArgs: ['open'] };
  assert.equal(store.enqueue(trigger).deduplicated, false); assert.equal(store.markStarted('trigger-1', { exitCode: 0 }).state, 'STARTED'); assert.equal(store.enqueue(trigger).deduplicated, true);
}));

test('LEG-025 runtime quiescing rejects admission, drains & reports forced count', async () => {
  const admission = new RuntimeAdmission(); const release = admission.admit('work-1');
  const result = await admission.quiesce({ deadlineMs: 0, hardKill: async () => {} }); release();
  assert.deepEqual(result, { state: 'STOPPED', drained: false, forced: 1 }); assert.throws(() => admission.admit('work-2'), { code: 'LEGION_QUIESCING' });
});

test('LEG-026 outbox bounds batches, dead-letters & redrives by stable id', withTemp((root) => {
  const outbox = new ObservationOutbox({ root, maxAttempts: 1 }); outbox.enqueue({ eventId: 'event-1' });
  assert.equal(outbox.nextBatch({ maxCount: 1 }).entries.length, 1); outbox.fail(['event-1'], 'offline'); assert.equal(outbox.inspect().deadLetter, 1); outbox.redrive(['event-1']); assert.equal(outbox.inspect().pending, 1);
}));

test('LEG-027 capability attestation reports verified, unavailable & unknown trust', () => {
  const registry = { capabilities: { yes: { kind: 'tool', summary: 'yes', degradation: 'none', probe: { kind: 'env', env: 'YES' } }, no: { kind: 'tool', summary: 'no', degradation: 'skip', probe: { kind: 'env', env: 'NO' } }, maybe: { kind: 'tool', summary: 'maybe', degradation: 'skip' } } };
  assert.equal(probeCapability('yes', { registry, env: { YES: '1' }, identity: 'release-1', sign: () => 'signature' }).attestation.trust, 'VERIFIED');
  assert.equal(probeCapability('no', { registry, env: {} }).attestation.trust, 'UNAVAILABLE'); assert.equal(probeCapability('maybe', { registry, env: {} }).attestation.trust, 'UNKNOWN');
});

test('ARC-001 live route compiles seven minimum policy stages', () => {
  const route = compileArcaneRoute({ prompt: 'Implement bounded production behavior with evidence.', requiredStages: ['verification'] });
  assert.deepEqual(Object.keys(route.stages), ['context', 'cognition', 'grounding', 'compute', 'challenge', 'verification', 'response']);
});

test('ARC-002 trivial route is near-empty & makes zero model calls', () => {
  const route = compileArcaneRoute({ prompt: 'status?' }); assert.equal(route.mode, 'TRIVIAL'); assert.equal(route.modelCalls, 0); assert.deepEqual(Object.keys(route.stages), ['response']);
});

test('ARC-005 falsification is one evidence-directed KEEP/NARROW/REVISE pass', async () => {
  const result = await runFalsificationPass({ claim: 'claim', evidence: ['source'], evaluate: async () => ({ result: 'REVISE', reason: 'counterexample' }) });
  assert.equal(result.result, 'REVISE'); await assert.rejects(() => runFalsificationPass({ claim: 'claim', evidence: ['source'], passCount: 1, evaluate: async () => ({ result: 'KEEP' }) }), { code: 'ARC_CHALLENGE_RECURSION' });
});

test('ARC-006 uncertain route selects stronger model once & no workflow artifact', () => {
  assert.deepEqual(selectStrongerWorkingModel({ uncertain: true, currentTier: 'balanced' }), { escalated: true, modelTier: 'strong', executions: 1, workflowArtifact: false, responseMode: 'DIRECT' });
  assert.throws(() => selectStrongerWorkingModel({ uncertain: true, priorEscalations: 1 }), { code: 'ARC_ESCALATION_RECURSION' });
});

test('ARC-009 unavailable optional stages degrade while ambient route continues', () => {
  const route = compileArcaneRoute({ prompt: 'Perform useful ambient work.' }, { grounding: false, challenge: false }); assert.equal(route.stages.grounding.state, 'DEGRADED'); assert.equal(route.stages.response.state, 'ACTIVE');
});

test('GRD-009 durable dependency ledger invalidates completion freshness', withTemp((root) => {
  const ledger = new DependencyLedger({ root }); ledger.register('evidence-1', [{ dimension: 'source-digest', ref: 'src/a.mjs', digest: digestValue('old') }]); ledger.link('evidence-1', { criterionId: 'criterion-1' });
  new DependencyLedger({ root }).observeChange({ dimension: 'source-digest', ref: 'src/a.mjs', digest: digestValue('new') });
  assert.equal(new DependencyLedger({ root }).proofEligibility('criterion-1').status, 'unproven');
}));

void HostEventLedger;
