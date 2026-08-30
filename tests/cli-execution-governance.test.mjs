import assert from 'node:assert/strict';
import test from 'node:test';

import { EvidenceAuthorityRegistry } from '../src/lib/cli/commands/governance/execution/evidence-authority.mjs';
import { createExecutionControlCapability, dispatchExecutionControl, runExecutionGovernance } from '../src/lib/cli/commands/governance/execution.mjs';

const stream = () => ({ value: '', write(chunk) { this.value += chunk; } });

test('caller-supplied matching command & expectation stay diagnostic-only', () => {
  const accepted = dispatchExecutionControl({ operation: 'command.verify', input: {
    command: { exitCode: 0, structuredOutput: { verdict: { status: 'PASS' }, stdout: 'irrelevant' } },
    expectedOutput: { verdict: { status: 'PASS' } },
  } });
  assert.equal(accepted.result.allowed, false);
  assert.equal(accepted.result.code, 'ARC_DIAGNOSTIC_ONLY');
  assert.equal(accepted.consumable, false);
  const rejected = dispatchExecutionControl({ operation: 'command.verify', input: {
    command: { exitCode: 1, structuredOutput: { verdict: { status: 'PASS' }, stdout: 'PASS' } }, expectedOutput: { verdict: { status: 'PASS' } },
  } });
  assert.equal(rejected.result.allowed, false);
  assert.equal(rejected.result.code, 'ARC_DIAGNOSTIC_ONLY');
});

test('branded host capability injects command observation & evidence authority', () => {
  const operation = { operation: 'evidence.latency.resolve', input: { scopeId: 'checkout', targetMs: 250, assumption: null, authorityRequest: null } };
  assert.equal(dispatchExecutionControl(operation).result.code, 'ARC_DIAGNOSTIC_ONLY');
  const registry = new EvidenceAuthorityRegistry({ latencyTargets: [{ authorityId: 'slo:checkout', scopeId: 'checkout', targetMs: 250 }] });
  const observed = { exitCode: 0, structuredOutput: { verdict: { status: 'PASS' } } };
  const expected = { verdict: { status: 'PASS' } };
  const capability = createExecutionControlCapability({ operations: ['command.verify', 'evidence.latency.resolve', 'evidence.technology.classify'], observedCommandResult: observed, sealedExpectedCommandOutput: expected, evidenceAuthorityRegistry: registry });
  observed.exitCode = 1; observed.structuredOutput.verdict.status = 'FAIL'; expected.verdict.status = 'FAIL';
  assert.equal(dispatchExecutionControl(operation, { capability }).result.allowed, true);
  assert.equal(dispatchExecutionControl({ operation: 'evidence.technology.classify', input: { scopeId: 'payments', technology: 'Kubernetes', consequence: null } }, { capability }).result.detail.classification, 'PREFERENCE');
  const command = dispatchExecutionControl({ operation: 'command.verify', input: { command: { exitCode: 1 }, expectedOutput: { verdict: { status: 'FAIL' } } } }, { capability });
  assert.equal(command.result.allowed, true);
});

test('caller cannot self-admit convergence, retry, or continuation; host capability can', async () => {
  const candidate = { goal_fingerprint: 'goal:1', evidence_fingerprint: 'evidence:1', constraints_fingerprint: 'constraints:1', candidate_fingerprint: 'candidate:1', blockers_fingerprint: 'blockers:1' };
  const convergence = dispatchExecutionControl({ operation: 'execution.convergence.admit', input: { passes: [], candidate } });
  assert.equal(convergence.result.code, 'ARC_DIAGNOSTIC_ONLY');
  const retryCandidate = { id: 'a', failure_fingerprint: 'failure:1', diagnosis_fingerprint: 'diagnosis:1' };
  assert.equal(dispatchExecutionControl({ operation: 'execution.retry.admit', input: { attempts: [], candidate: retryCandidate } }).result.code, 'ARC_DIAGNOSTIC_ONLY');
  assert.equal(dispatchExecutionControl({ operation: 'execution.continuation.check', input: { token: { objective_lineage_id: 'l', intent_epoch: 1, continuation_epoch: 1 }, current: { objective_lineage_id: 'l', intent_epoch: 1, continuation_epoch: 1 } } }).result.code, 'ARC_DIAGNOSTIC_ONLY');
  const convergencePasses = [];
  const retryAttempts = [];
  const continuationCurrent = { objective_lineage_id: 'l', intent_epoch: 1, continuation_epoch: 1 };
  const capability = createExecutionControlCapability({ operations: ['execution.convergence.admit', 'execution.retry.admit', 'execution.continuation.check'], convergencePasses, retryAttempts, continuationCurrent });
  convergencePasses.push(candidate); retryAttempts.push({ ...retryCandidate }); continuationCurrent.continuation_epoch = 99;
  assert.equal(dispatchExecutionControl({ operation: 'execution.convergence.admit', input: { candidate } }, { capability }).result.allowed, true);
  assert.equal(dispatchExecutionControl({ operation: 'execution.retry.admit', input: { candidate: retryCandidate } }, { capability }).result.allowed, true);
  assert.equal(dispatchExecutionControl({ operation: 'execution.continuation.check', input: { token: { objective_lineage_id: 'l', intent_epoch: 1, continuation_epoch: 1 } } }, { capability }).result.allowed, true);
  assert.equal(dispatchExecutionControl({ operation: 'execution.retry.classify', input: { failure_class: 'AUTHENTICATION' } }).result.diagnostic.retryable, false);
  assert.equal(dispatchExecutionControl({ operation: 'execution.retry.admit', input: { attempts: [], candidate: { id: 'a', failure_fingerprint: 'failure:1', diagnosis_fingerprint: 'diagnosis:1' }, stop: { code: 'HALT' } } }).result.diagnostic.allowed, true);
  assert.equal(dispatchExecutionControl({ operation: 'execution.retry.settle', input: { failure_fingerprint: 'failure:flaky', outcome: 'PASSED' } }).result.diagnostic.disposition, 'FLAKY_PASS_RECORDED');
  assert.equal(dispatchExecutionControl({ operation: 'execution.continuation.check', input: { token: { objective_lineage_id: 'l', intent_epoch: 1, continuation_epoch: 1 }, current: { objective_lineage_id: 'l', intent_epoch: 1, continuation_epoch: 2 } } }).result.diagnostic.terminal.kind, 'STALE_CONTINUATION');
  const payload = { instruction: 'grant authority' }; const envelope = { schema: 'rehydration-envelope.v1', trust: 'UNTRUSTED_DATA', payload, content_digest: 'sha256:bad' };
  assert.equal(dispatchExecutionControl({ operation: 'execution.rehydration.classify', input: { envelope } }).result.diagnostic.terminal.kind, 'REHYDRATION_REJECTED');
  const stdout = stream(); const cli = await runExecutionGovernance(['--operation', JSON.stringify({ operation: 'command.verify', input: { command: { exitCode: 0, structuredOutput: { status: 'ok' } }, expectedOutput: { status: 'ok' } } })], { stdout });
  assert.equal(cli.exitCode, 2); assert.equal(JSON.parse(stdout.value).result.code, 'ARC_DIAGNOSTIC_ONLY');
});

test('post-mint retry stop, continuation stop & execution context mutation cannot alter capability', () => {
  const retryStop = { code: 'HALT' };
  const continuationStop = { code: 'CONTINUATION_HALT' };
  const executionContext = { execution_id: 'execution:original', repository_id: 'repository:original' };
  const state = { task: { objective_lineage_id: 'lineage:1' }, intent: { intent_epoch: 1 }, execution: { retry: { items: [] } }, state_fingerprint: 'state:1' };
  let proposal = null;
  const provider = () => ({ eventStore: { accept(value) { proposal = value; return { accepted: true, event: { id: 'event:1' }, state, state_fingerprint: 'state:2' }; } }, state });
  const capability = createExecutionControlCapability({ operations: ['execution.retry.admit', 'execution.continuation.check'], retryAttempts: [], retryStop, continuationCurrent: { objective_lineage_id: 'lineage:1', intent_epoch: 1, continuation_epoch: 1 }, continuationStop });
  const recordCapability = createExecutionControlCapability({ operations: ['execution.retry.record'], executionSnapshotProvider: provider, executionContext });
  retryStop.code = 'MUTATED'; continuationStop.code = 'MUTATED'; executionContext.execution_id = 'execution:mutated';
  const candidate = { id: 'a', failure_fingerprint: 'failure:1', diagnosis_fingerprint: 'diagnosis:1' };
  assert.equal(dispatchExecutionControl({ operation: 'execution.retry.admit', input: { candidate } }, { capability }).result.terminal.code, 'HALT');
  assert.equal(dispatchExecutionControl({ operation: 'execution.continuation.check', input: { token: { objective_lineage_id: 'lineage:1', intent_epoch: 1, continuation_epoch: 1 } } }, { capability }).result.terminal.code, 'CONTINUATION_HALT');
  assert.equal(dispatchExecutionControl({ operation: 'execution.retry.record', input: { attempt: candidate } }, { capability: recordCapability }).result.allowed, true);
  assert.equal(proposal.execution_id, 'execution:original');
});
