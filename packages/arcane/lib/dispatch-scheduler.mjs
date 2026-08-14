// Deterministic dispatch admission. This module has no effect authority: callers
// must still acquire delivery ownership before integration, commit, pin, or push.

import { digestValue, isDigest } from './canonical.mjs';
import { decision } from './errors.mjs';
import { signRecord, verifyRecord } from './receipt-auth.mjs';

function readonly(value) { return Object.freeze(value); }
function list(value) { return Array.isArray(value) ? value : []; }
function unique(values) { return [...new Set(values)]; }
function record(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }

const WORKFLOW_MAC_DOMAIN = 'arcane-requested-workflow-execution-v1';
export const REQUESTED_WORKFLOW_EXECUTION_RECEIPT_BOUND_FIELDS = Object.freeze([
  'schemaVersion', 'kind', 'receiptId', 'runId', 'taskId', 'contractId',
  'requestedWorkflowId', 'requestedWorkflowDigest', 'machineryDefect',
  'execution', 'continuation', 'observedAt',
]);

function deny(code, message, detail = {}) { return decision({ allowed: false, code, message, detail }); }

function validExecution(execution, requestedWorkflowId) {
  return record(execution)
    && execution.workflowId === requestedWorkflowId
    && execution.executionState === 'COMPLETED'
    && record(execution.output);
}

function validMachineryDefect(machineryDefect) {
  return record(machineryDefect)
    && machineryDefect.classification === 'OUT_OF_SCOPE_MACHINERY_DEFECT'
    && typeof machineryDefect.code === 'string'
    && machineryDefect.code.length > 0;
}

function validRequestedWorkflowReceipt(receipt) {
  const keys = [...REQUESTED_WORKFLOW_EXECUTION_RECEIPT_BOUND_FIELDS, 'authentication'];
  return record(receipt)
    && Object.keys(receipt).length === keys.length
    && keys.every((key) => Object.hasOwn(receipt, key))
    && receipt.schemaVersion === 1
    && receipt.kind === 'arcane-requested-workflow-execution'
    && isDigest(receipt.receiptId)
    && typeof receipt.runId === 'string' && receipt.runId.length > 0
    && typeof receipt.taskId === 'string' && receipt.taskId.length > 0
    && typeof receipt.contractId === 'string' && receipt.contractId.length > 0
    && typeof receipt.requestedWorkflowId === 'string' && receipt.requestedWorkflowId.length > 0
    && isDigest(receipt.requestedWorkflowDigest)
    && validMachineryDefect(receipt.machineryDefect)
    && validExecution(receipt.execution, receipt.requestedWorkflowId)
    && receipt.continuation === 'CONTINUED_DESPITE_MACHINERY_DEFECT'
    && Number.isFinite(Date.parse(receipt.observedAt));
}

/**
 * Execute requested work after an out-of-scope machinery defect, then bind its
 * structured completion to a signed receipt. The callback is deliberately the
 * only execution seam: text output cannot stand in for requested work.
 */
export function forwardRequestedWorkload({ runId, taskId, contractId, requestedWorkflow, machineryDefect, executeRequestedWorkflow, observedAt = new Date().toISOString() } = {}, { keyRing, keyId } = {}) {
  if (!record(requestedWorkflow) || typeof requestedWorkflow.id !== 'string' || !requestedWorkflow.id || !isDigest(requestedWorkflow.digest)) {
    throw Object.assign(new TypeError('requested workflow requires id and digest'), { code: 'ARC_SCHEMA_INVALID' });
  }
  if (!validMachineryDefect(machineryDefect) || typeof executeRequestedWorkflow !== 'function' || ![runId, taskId, contractId].every((value) => typeof value === 'string' && value.length > 0) || !Number.isFinite(Date.parse(observedAt))) {
    throw Object.assign(new TypeError('requested workflow forwarding ingress is invalid'), { code: 'ARC_SCHEMA_INVALID' });
  }
  const execution = executeRequestedWorkflow(Object.freeze({ id: requestedWorkflow.id, digest: requestedWorkflow.digest }));
  if (!validExecution(execution, requestedWorkflow.id)) {
    throw Object.assign(new TypeError('requested workflow did not produce structured completion'), { code: 'ARC_EVIDENCE_INSUFFICIENT' });
  }
  const unsigned = {
    schemaVersion: 1,
    kind: 'arcane-requested-workflow-execution',
    runId,
    taskId,
    contractId,
    requestedWorkflowId: requestedWorkflow.id,
    requestedWorkflowDigest: requestedWorkflow.digest,
    machineryDefect: Object.freeze({ code: machineryDefect.code, classification: machineryDefect.classification }),
    execution: Object.freeze({ workflowId: execution.workflowId, executionState: execution.executionState, output: execution.output }),
    continuation: 'CONTINUED_DESPITE_MACHINERY_DEFECT',
    observedAt,
  };
  const receipt = { ...unsigned, receiptId: digestValue(unsigned) };
  return Object.freeze({ ...receipt, authentication: signRecord(receipt, { keyRing, keyId, boundFields: REQUESTED_WORKFLOW_EXECUTION_RECEIPT_BOUND_FIELDS, macDomain: WORKFLOW_MAC_DOMAIN }) });
}

/** Verify receipt authenticity & consume its structured continuation evidence. */
export function consumeForwardedWorkloadReceipt(receipt, expected = {}, { keyRing } = {}) {
  if (!validRequestedWorkflowReceipt(receipt)) return deny('ARC_AUTH_FORGED', 'requested workflow execution receipt is malformed');
  const authentication = verifyRecord(receipt, receipt.authentication, { keyRing, boundFields: REQUESTED_WORKFLOW_EXECUTION_RECEIPT_BOUND_FIELDS, expectedBinding: expected, macDomain: WORKFLOW_MAC_DOMAIN });
  if (!authentication.allowed) return authentication;
  for (const field of ['runId', 'taskId', 'contractId', 'requestedWorkflowId', 'requestedWorkflowDigest']) {
    if (expected[field] !== undefined && receipt[field] !== expected[field]) return deny('ARC_BINDING_MISMATCH', 'requested workflow execution receipt differs from expected workflow', { field });
  }
  return decision({ allowed: true, detail: {
    receiptId: receipt.receiptId,
    requestedWorkflowId: receipt.requestedWorkflowId,
    requestedWorkflowDigest: receipt.requestedWorkflowDigest,
    machineryDefect: receipt.machineryDefect,
    continuation: receipt.continuation,
    execution: receipt.execution,
  } });
}

function constraintsOf(constraints) {
  const entries = Array.isArray(constraints)
    ? constraints
    : Object.entries(constraints ?? {}).map(([name, capacity]) => ({ name, capacity }));
  return entries
    .filter((constraint) => constraint?.active !== false)
    .map((constraint) => ({ name: String(constraint.name), capacity: Number(constraint.capacity) }))
    .filter((constraint) => constraint.name && Number.isInteger(constraint.capacity) && constraint.capacity >= 0);
}

/**
 * Admit ready tasks up to the narrowest currently-active capacity constraint.
 * Ordering is caller supplied so an orchestrator can make priority explicit.
 */
export function admitCapacity({ readyTasks = [], constraints = [] } = {}) {
  const activeConstraints = constraintsOf(constraints);
  const limit = activeConstraints.length ? Math.min(...activeConstraints.map(({ capacity }) => capacity)) : readyTasks.length;
  const narrowest = activeConstraints.filter(({ capacity }) => capacity === limit).map(({ name }) => name);
  const admitted = list(readyTasks).slice(0, limit);
  return readonly({
    outcome: 'CAPACITY_ADMITTED',
    limit,
    narrowestActiveConstraints: readonly(narrowest),
    admitted: readonly(admitted),
    deferred: readonly(list(readyTasks).slice(limit)),
  });
}

function proofKey(proof) {
  if (typeof proof === 'string') return proof;
  return proof?.producerId ?? proof?.producer_id ?? proof?.id ?? null;
}

/** Preparation can overlap its producer. Activation cannot consume an absent proof. */
export function admitTaskPhase({ phase, requiredProducerProofs = [], producerProofs = [] } = {}) {
  const required = unique(list(requiredProducerProofs));
  const present = new Set(list(producerProofs).map(proofKey).filter(Boolean));
  const missing = required.filter((id) => !present.has(id));
  if (phase === 'activation' || phase === 'integration') {
    if (missing.length) return readonly({ outcome: 'ACTIVATION_DENIED', code: 'ARC_PRODUCER_PROOF_MISSING', phase, missingProducerProofs: readonly(missing) });
    return readonly({ outcome: 'ACTIVATION_ADMITTED', phase, requiredProducerProofs: readonly(required) });
  }
  return readonly({ outcome: 'PREPARATION_ADMITTED', phase: phase ?? 'preparation', requiredProducerProofs: readonly(required) });
}

/** A packet digest is single-dispatch material within one scheduler scope. */
export class PacketDispatchRegistry {
  #digests = new Set();

  admit({ packetDigest } = {}) {
    if (typeof packetDigest !== 'string' || !packetDigest) {
      return readonly({ outcome: 'PACKET_DENIED', code: 'ARC_PACKET_DIGEST_REQUIRED', packetDigest: packetDigest ?? null });
    }
    if (this.#digests.has(packetDigest)) {
      return readonly({ outcome: 'PACKET_REPLAY_DENIED', code: 'ARC_PACKET_DIGEST_REPLAY', packetDigest });
    }
    this.#digests.add(packetDigest);
    return readonly({ outcome: 'PACKET_ADMITTED', packetDigest });
  }
}

/** Safe handoffs with declared assumptions explicitly transfer test responsibility to Alchemist. */
export function classifyHandoff({ assumptions = [], safe = true } = {}) {
  const declared = unique(list(assumptions));
  if (!safe) return readonly({ status: 'BLOCKED', code: 'ARC_HANDOFF_UNSAFE', assumptions: readonly(declared), activationOwner: null });
  if (declared.length) return readonly({ status: 'READY_WITH_ASSUMPTIONS', assumptions: readonly(declared), activationOwner: 'alchemist', requiredAction: 'test_assumptions' });
  return readonly({ status: 'READY', assumptions: readonly([]), activationOwner: 'alchemist', requiredAction: null });
}

/** Realization records never alter a frozen decision; correction is executable work. */
export function assessRealization({ decisionStatus, intendedDigest, realizedDigest, correctionRoute = 'alchemist' } = {}) {
  const diverged = decisionStatus === 'frozen' && intendedDigest !== realizedDigest;
  return readonly({
    decisionStatus,
    realizationStatus: diverged ? 'diverged' : 'aligned',
    correctionRoute: diverged ? correctionRoute : null,
    decisionMutation: 'none',
  });
}
