// Bounded production dispatch for execution-control decisions.  Operations
// are typed JSON; no caller supplied prose, case id, or fixture selects a path.
import { parseArgs } from 'node:util';

import { EXIT, LegionError } from '../../../errors.mjs';
import { decision } from '../../../contracts/arcane/errors.mjs';
import { verifyCommandResult } from './execution/command-verifier.mjs';
import { EvidenceAuthorityRegistry, classifyTechnologyRequirement, resolveLatencyTarget } from './execution/evidence-authority.mjs';
import {
  admitConvergencePass,
  admitRetry,
  classifyRehydratedInput,
  classifyRetryFailure,
  denyStaleContinuation,
  recordAttempt,
  settleFlakyRetry,
} from './execution/execution-governance.mjs';

export const EXECUTION_CONTROL_OPERATIONS = Object.freeze([
  'command.verify',
  'evidence.latency.resolve',
  'evidence.technology.classify',
  'execution.convergence.admit',
  'execution.retry.classify',
  'execution.retry.admit',
  'execution.retry.settle',
  'execution.retry.record',
  'execution.continuation.check',
  'execution.rehydration.classify',
]);

const exactOperation = (value) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === 2 && typeof value.operation === 'string'
  && Object.hasOwn(value, 'input') && value.input && typeof value.input === 'object' && !Array.isArray(value.input);
const refusal = (reason) => decision({ allowed: false, code: 'ARC_SCHEMA_INVALID', message: 'execution control operation is invalid', detail: { reason } });
const capabilityBrand = Symbol('arcane.execution-control-capability');
const allowedOperations = new Set(EXECUTION_CONTROL_OPERATIONS);
const capabilityState = new WeakMap();
const cloneFrozen = (value) => {
  if (value === null || value === undefined) return value;
  const copy = structuredClone(value);
  const freeze = (current, seen = new WeakSet()) => {
    if (!current || typeof current !== 'object' || seen.has(current)) return current;
    seen.add(current);
    for (const key of Reflect.ownKeys(current)) freeze(current[key], seen);
    return Object.freeze(current);
  };
  return freeze(copy);
};
const diagnostic = (operation, result) => Object.freeze({
  allowed: false,
  code: 'ARC_DIAGNOSTIC_ONLY',
  message: 'caller-controlled execution control result is not consumable',
  detail: Object.freeze({ operation, observedAllowed: result.allowed === true }),
  consumable: false,
  diagnostic: Object.freeze(result),
});
const output = (operation, result, consumable = false) => Object.freeze({ kind: 'arcane-execution-control-decision', operation, consumable, result: Object.freeze(result) });
const trusted = (capability, operation) => Boolean(capability?.[capabilityBrand] === true && capabilityState.get(capability)?.operations.includes(operation));
const capabilityValue = (capability, field) => capabilityState.get(capability)?.[field];

/**
 * Host factory for a non-JSON capability.  Only this branded object can make
 * a handler result consumable.  JSON can describe a candidate, never its
 * observations, expectation, projected state, or authority.
 */
export function createExecutionControlCapability({
  operations = [], observedCommandResult = null, sealedExpectedCommandOutput = null,
  evidenceAuthorityRegistry = null, convergencePasses = null, retryAttempts = null,
  retryStop = null, retryMaxIdenticalAttempts = 3, continuationCurrent = null,
  continuationStop = null, executionSnapshotProvider = null, executionContext = null,
} = {}) {
  if (!Array.isArray(operations) || !operations.length || operations.some((operation) => !allowedOperations.has(operation))) throw new TypeError('invalid execution control capability operations');
  if (executionSnapshotProvider !== null && typeof executionSnapshotProvider !== 'function') throw new TypeError('execution snapshot provider must be a function');
  const capability = Object.freeze({ [capabilityBrand]: true });
  capabilityState.set(capability, Object.freeze({
    operations: Object.freeze([...operations]), observedCommandResult: cloneFrozen(observedCommandResult), sealedExpectedCommandOutput: cloneFrozen(sealedExpectedCommandOutput),
    evidenceAuthorityRegistry, convergencePasses: cloneFrozen(convergencePasses), retryAttempts: cloneFrozen(retryAttempts), retryStop: cloneFrozen(retryStop),
    retryMaxIdenticalAttempts, continuationCurrent: cloneFrozen(continuationCurrent), continuationStop: cloneFrozen(continuationStop),
    executionSnapshotProvider, executionContext: cloneFrozen(executionContext),
  }));
  return capability;
}

/**
 * Dispatch one typed control operation. Host-owned collaborators deliberately
 * arrive through context, never through operation JSON.
 */
export function dispatchExecutionControl(operation, context = {}) {
  if (!exactOperation(operation)) return output(null, refusal('INVALID_OPERATION'));
  const { input } = operation;
  const capability = context.capability;
  const consume = (result) => output(operation.operation, trusted(capability, operation.operation) ? result : diagnostic(operation.operation, result), trusted(capability, operation.operation));
  let result;
  switch (operation.operation) {
    case 'command.verify':
      result = verifyCommandResult(capabilityValue(capability, 'observedCommandResult'), { expectedOutput: capabilityValue(capability, 'sealedExpectedCommandOutput') });
      break;
    case 'evidence.latency.resolve':
      if (!(capabilityValue(capability, 'evidenceAuthorityRegistry') instanceof EvidenceAuthorityRegistry)) return consume(refusal('HOST_EVIDENCE_AUTHORITY_REQUIRED'));
      result = resolveLatencyTarget(input, { registry: capabilityValue(capability, 'evidenceAuthorityRegistry') });
      break;
    case 'evidence.technology.classify':
      if (!(capabilityValue(capability, 'evidenceAuthorityRegistry') instanceof EvidenceAuthorityRegistry)) return consume(refusal('HOST_EVIDENCE_AUTHORITY_REQUIRED'));
      result = classifyTechnologyRequirement(input, { registry: capabilityValue(capability, 'evidenceAuthorityRegistry') });
      break;
    case 'execution.convergence.admit': result = admitConvergencePass({ passes: capabilityValue(capability, 'convergencePasses'), candidate: input.candidate }); break;
    case 'execution.retry.classify': result = classifyRetryFailure(input); break;
    case 'execution.retry.admit': result = admitRetry({ attempts: capabilityValue(capability, 'retryAttempts'), candidate: input.candidate, stop: capabilityValue(capability, 'retryStop'), max_identical_attempts: capabilityValue(capability, 'retryMaxIdenticalAttempts') }); break;
    case 'execution.retry.settle': result = settleFlakyRetry(input); break;
    case 'execution.continuation.check': result = denyStaleContinuation({ token: input.token, current: capabilityValue(capability, 'continuationCurrent'), stop: capabilityValue(capability, 'continuationStop') }); break;
    case 'execution.rehydration.classify': result = classifyRehydratedInput(input); break;
    case 'execution.retry.record': {
      const provider = capabilityValue(capability, 'executionSnapshotProvider');
      const executionContext = capabilityValue(capability, 'executionContext');
      if (!provider || !executionContext) return consume(refusal('HOST_EXECUTION_STATE_REQUIRED'));
      let snapshot;
      try { snapshot = provider(); }
      catch { return consume(refusal('HOST_EXECUTION_STATE_REQUIRED')); }
      if (!snapshot?.eventStore || !snapshot?.state) return consume(refusal('HOST_EXECUTION_STATE_REQUIRED'));
      result = recordAttempt({ eventStore: snapshot.eventStore, state: cloneFrozen(snapshot.state), context: executionContext, attempt: input.attempt, stop: capabilityValue(capability, 'retryStop'), max_identical_attempts: capabilityValue(capability, 'retryMaxIdenticalAttempts') });
      break;
    }
    default: return consume(refusal('UNKNOWN_OPERATION'));
  }
  return consume(result);
}

export async function runExecutionGovernance(argv, { stdout, host = {} }) {
  let values;
  try { ({ values } = parseArgs({ args: argv, allowPositionals: false, strict: true, options: { operation: { type: 'string' } } })); }
  catch (error) { throw new LegionError(error.message, { code: 'USAGE', exitCode: EXIT.USAGE }); }
  if (!values.operation) throw new LegionError('execution governance requires --operation <json>', { code: 'USAGE', exitCode: EXIT.USAGE });
  let operation;
  try { operation = JSON.parse(values.operation); }
  catch { throw new LegionError('execution governance operation must be JSON', { code: 'USAGE', exitCode: EXIT.USAGE }); }
  const result = dispatchExecutionControl(operation, {
    capability: host.executionControlCapability,
  });
  stdout.write(`${JSON.stringify(result)}\n`);
  return { exitCode: result.result.allowed ? EXIT.PASS : EXIT.INCOMPLETE };
}
