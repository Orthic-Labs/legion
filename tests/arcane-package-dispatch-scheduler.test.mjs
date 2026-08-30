import assert from 'node:assert/strict';
import test from 'node:test';

import { PacketDispatchRegistry, admitCapacity, admitTaskPhase, assessRealization, classifyHandoff, consumeForwardedWorkloadReceipt, forwardRequestedWorkload } from '../src/lib/cli/commands/governance/delivery/dispatch-scheduler.mjs';
import { admitLocalRepair } from '../src/lib/cli/commands/governance/delivery/delivery-guard.mjs';
import { digestValue } from '../src/lib/contracts/arcane/canonical.mjs';
import { generateTestKeyRing } from '../src/lib/guard/compat/host/keys.mjs';

test('scheduler caps ready work at narrowest active capacity', () => {
  const result = admitCapacity({ readyTasks: ['a', 'b', 'c'], constraints: [{ name: 'integration-review', capacity: 1 }, { name: 'evidence-merge', capacity: 2 }, { name: 'inactive', capacity: 0, active: false }] });
  assert.equal(result.outcome, 'CAPACITY_ADMITTED');
  assert.equal(result.limit, 1);
  assert.deepEqual(result.narrowestActiveConstraints, ['integration-review']);
  assert.deepEqual(result.admitted, ['a']);
  assert.deepEqual(result.deferred, ['b', 'c']);
});

test('preparation may run before producer proof but activation cannot', () => {
  assert.equal(admitTaskPhase({ phase: 'preparation', requiredProducerProofs: ['producer-runtime'] }).outcome, 'PREPARATION_ADMITTED');
  const denied = admitTaskPhase({ phase: 'activation', requiredProducerProofs: ['producer-runtime'] });
  assert.equal(denied.code, 'ARC_PRODUCER_PROOF_MISSING');
  assert.deepEqual(denied.missingProducerProofs, ['producer-runtime']);
  assert.equal(admitTaskPhase({ phase: 'integration', requiredProducerProofs: ['producer-runtime'], producerProofs: [{ producerId: 'producer-runtime' }] }).outcome, 'ACTIVATION_ADMITTED');
});

test('packet digest replay is denied without dispatching a second packet', () => {
  const registry = new PacketDispatchRegistry();
  assert.equal(registry.admit({ packetDigest: 'sha256:packet' }).outcome, 'PACKET_ADMITTED');
  const replay = registry.admit({ packetDigest: 'sha256:packet' });
  assert.equal(replay.outcome, 'PACKET_REPLAY_DENIED');
  assert.equal(replay.code, 'ARC_PACKET_DIGEST_REPLAY');
});

test('assumption handoffs remain ready with Alchemist testing responsibility', () => {
  const result = classifyHandoff({ assumptions: ['tracer does not alter writes'] });
  assert.equal(result.status, 'READY_WITH_ASSUMPTIONS');
  assert.equal(result.activationOwner, 'alchemist');
  assert.equal(result.requiredAction, 'test_assumptions');
});

test('frozen decision divergence preserves decision & routes local correction', () => {
  const result = assessRealization({ decisionStatus: 'frozen', intendedDigest: 'sha256:intended', realizedDigest: 'sha256:actual' });
  assert.equal(result.decisionStatus, 'frozen');
  assert.equal(result.realizationStatus, 'diverged');
  assert.equal(result.correctionRoute, 'alchemist');
  assert.equal(result.decisionMutation, 'none');
});

test('first-fix owner can repair locally without rewriting canonical ownership', () => {
  const result = admitLocalRepair({ firstFixOwner: 'maintainer', canonicalOwner: 'package', requester: 'maintainer', repairScope: ['packages/arcane/lib/x.mjs'] });
  assert.equal(result.outcome, 'LOCAL_REPAIR_PERMITTED');
  assert.equal(result.canonicalOwner, 'package');
  assert.equal(result.canonicalOwnershipRewrite, false);
});

test('forward workload signs requested-workflow completion despite machinery defect', () => {
  const keyRing = generateTestKeyRing(['scheduler']);
  const requestedWorkflow = { id: 'representative-workload', digest: digestValue({ id: 'representative-workload', input: 'fixture' }) };
  let executed = false;
  const receipt = forwardRequestedWorkload({
    runId: 'run-1', taskId: 'task-1', contractId: 'contract-1', requestedWorkflow,
    machineryDefect: { code: 'ARC_GATE_INVALID', classification: 'OUT_OF_SCOPE_MACHINERY_DEFECT' },
    executeRequestedWorkflow: ({ id }) => { executed = true; return { workflowId: id, executionState: 'COMPLETED', output: { produced: 'requested artifact' } }; },
    observedAt: '2026-08-15T00:00:00.000Z',
  }, { keyRing, keyId: 'scheduler' });
  assert.equal(executed, true);
  const consumed = consumeForwardedWorkloadReceipt(receipt, { runId: 'run-1', taskId: 'task-1', contractId: 'contract-1', requestedWorkflowId: requestedWorkflow.id, requestedWorkflowDigest: requestedWorkflow.digest }, { keyRing });
  assert.equal(consumed.allowed, true);
  assert.equal(consumed.detail.continuation, 'CONTINUED_DESPITE_MACHINERY_DEFECT');
  assert.equal(consumed.detail.execution.output.produced, 'requested artifact');
});

test('forward workload consumer rejects forged or mismatched receipts', () => {
  const keyRing = generateTestKeyRing(['scheduler']);
  const requestedWorkflow = { id: 'representative-workload', digest: digestValue({ input: 'fixture' }) };
  const receipt = forwardRequestedWorkload({ runId: 'run-1', taskId: 'task-1', contractId: 'contract-1', requestedWorkflow, machineryDefect: { code: 'ARC_GATE_INVALID', classification: 'OUT_OF_SCOPE_MACHINERY_DEFECT' }, executeRequestedWorkflow: ({ id }) => ({ workflowId: id, executionState: 'COMPLETED', output: { done: true } }), observedAt: '2026-08-15T00:00:00.000Z' }, { keyRing, keyId: 'scheduler' });
  assert.equal(consumeForwardedWorkloadReceipt({ ...receipt, requestedWorkflowId: 'other' }, {}, { keyRing }).code, 'ARC_AUTH_FORGED');
  assert.equal(consumeForwardedWorkloadReceipt(receipt, { taskId: 'other' }, { keyRing }).code, 'ARC_BINDING_MISMATCH');
});
