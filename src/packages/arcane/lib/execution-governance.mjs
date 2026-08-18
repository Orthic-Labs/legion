// Execution retry, stop, continuation, & rehydration governance.
//
// This module deliberately consumes only projected, authenticated trajectory
// state.  It does not infer permission from an error string, a retry message,
// or rehydrated content.

import { rehydrateUntrustedData } from './continuity.mjs';
import { digestValue } from './canonical.mjs';

export const EXECUTION_GOVERNANCE_TERMINALS = Object.freeze([
  'BUDGET_STOP', 'STALE_CONTINUATION', 'REHYDRATION_REJECTED',
]);

const frozen = (value) => Object.freeze(value);
const terminal = (kind, code, detail = {}) => frozen({ allowed: false, terminal: frozen({ kind, code, detail: frozen({ ...detail }) }) });
const allowed = (detail = {}) => frozen({ allowed: true, terminal: null, detail: frozen({ ...detail }) });
const nonEmpty = (value) => typeof value === 'string' && value.length > 0;
const clone = (value) => structuredClone(value);
const RETRY_BLOCKERS = Object.freeze({
  AUTHENTICATION: 'AUTHENTICATION_REQUIRED',
  MISSING_RESOURCE: 'RESOURCE_UNAVAILABLE',
  INVALID_CONTRACT: 'CONTRACT_INVALID',
  CONTEXT_FAILURE: 'CONTEXT_INVALID',
});

/** Stable structured signature for a convergence pass; text is never parsed. */
export function fingerprintConvergenceInput(input = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return null;
  const fields = ['goal_fingerprint', 'evidence_fingerprint', 'constraints_fingerprint', 'candidate_fingerprint', 'blockers_fingerprint'];
  if (fields.some((field) => !nonEmpty(input[field]))) return null;
  return digestValue(Object.fromEntries(fields.map((field) => [field, input[field]])));
}

/** Equivalent projected convergence input terminates instead of starting a pass. */
export function admitConvergencePass({ passes = [], candidate } = {}) {
  const fingerprint = fingerprintConvergenceInput(candidate);
  if (!fingerprint) return terminal('BUDGET_STOP', 'INVALID_CONVERGENCE_INPUT');
  const prior_count = passes.map(fingerprintConvergenceInput).filter((value) => value === fingerprint).length;
  return prior_count
    ? terminal('BUDGET_STOP', 'LOOP_VIOLATION', { input_fingerprint: fingerprint, prior_count })
    : allowed({ input_fingerprint: fingerprint, prior_count: 0 });
}

/** Classify retry eligibility from a closed, structured failure class. */
export function classifyRetryFailure({ failure_class } = {}) {
  if (typeof failure_class !== 'string' || !failure_class) return terminal('BUDGET_STOP', 'INVALID_FAILURE_CLASS');
  const blocker = RETRY_BLOCKERS[failure_class];
  return blocker
    ? frozen({ retryable: false, terminal: frozen({ kind: 'BUDGET_STOP', code: 'NON_RETRYABLE', detail: frozen({ failure_class, blocker }) }) })
    : frozen({ retryable: true, terminal: null, detail: frozen({ failure_class }) });
}

/** Preserve observed failure signature when a later attempt passes. */
export function settleFlakyRetry({ failure_fingerprint, outcome, best_artifact_ref = null } = {}) {
  if (!nonEmpty(failure_fingerprint) || !['PASSED', 'FAILED'].includes(outcome)) return terminal('BUDGET_STOP', 'INVALID_RETRY_DISPOSITION');
  return frozen({
    allowed: true,
    terminal: null,
    disposition: outcome === 'PASSED' ? 'FLAKY_PASS_RECORDED' : 'FAILURE_RECORDED',
    failure_fingerprint,
    pass_recorded: outcome === 'PASSED',
    best_artifact_ref,
  });
}

function normalizedAttempt(attempt) {
  if (!attempt || typeof attempt !== 'object' || Array.isArray(attempt)) return null;
  const id = attempt.id ?? attempt.attempt_id;
  if (!nonEmpty(id) || !nonEmpty(attempt.failure_fingerprint) || !nonEmpty(attempt.diagnosis_fingerprint)) return null;
  return frozen({
    id,
    failure_fingerprint: attempt.failure_fingerprint,
    diagnosis_fingerprint: attempt.diagnosis_fingerprint,
    input_fingerprint: attempt.input_fingerprint ?? null,
    method_fingerprint: attempt.method_fingerprint ?? null,
    retry_class: attempt.retry_class ?? 'changed_method',
    failure_class: attempt.failure_class ?? null,
  });
}

/**
 * A retry needs a materially new diagnosis for an already-observed failure.
 * Fingerprints are supplied by callers from structured observations; prose is
 * intentionally never inspected.
 */
export function requireDiagnosisDelta({ attempts = [], candidate } = {}) {
  const next = normalizedAttempt(candidate);
  if (!next) return terminal('BUDGET_STOP', 'INVALID_RETRY_ATTEMPT');
  const prior = attempts.map(normalizedAttempt).filter(Boolean)
    .filter((attempt) => attempt.failure_fingerprint === next.failure_fingerprint);
  if (!prior.length) return allowed({ diagnosis_delta: true, prior_count: 0 });
  const diagnosis_delta = prior.every((attempt) => attempt.diagnosis_fingerprint !== next.diagnosis_fingerprint);
  return diagnosis_delta
    ? allowed({ diagnosis_delta: true, prior_count: prior.length })
    : terminal('BUDGET_STOP', 'IDENTICAL_RETRY', { failure_fingerprint: next.failure_fingerprint, diagnosis_fingerprint: next.diagnosis_fingerprint, prior_count: prior.length });
}

function behavioralLoop({ attempts = [], candidate }) {
  const next = normalizedAttempt(candidate);
  if (!next) return null;
  const prior = attempts.map(normalizedAttempt).filter(Boolean)
    .filter((attempt) => attempt.failure_fingerprint === next.failure_fingerprint
      && attempt.input_fingerprint === next.input_fingerprint);
  const methods = new Set([...prior.map((attempt) => attempt.method_fingerprint), next.method_fingerprint]);
  if (!prior.length || prior.some((attempt) => attempt.diagnosis_fingerprint === next.diagnosis_fingerprint) || methods.size < 2) return null;
  return terminal('BUDGET_STOP', 'LOOP_VIOLATION', {
    failure_fingerprint: next.failure_fingerprint,
    input_fingerprint: next.input_fingerprint,
    method_fingerprints: [...methods].sort(),
    prior_count: prior.length,
  });
}

/** Stop is terminal & wins over any retry delta or continuation request. */
export function admitRetry({ attempts = [], candidate, stop = null, max_identical_attempts = 3 } = {}) {
  if (stop) return terminal('BUDGET_STOP', stop.code ?? 'STOP_PRECEDENCE', { stop: clone(stop) });
  if (!Number.isInteger(max_identical_attempts) || max_identical_attempts < 1) return terminal('BUDGET_STOP', 'INVALID_RETRY_LIMIT');
  const classification = candidate?.failure_class == null ? null : classifyRetryFailure(candidate);
  if (classification && !classification.retryable) return classification;
  const delta = requireDiagnosisDelta({ attempts, candidate });
  if (!delta.allowed) return delta;
  const loop = behavioralLoop({ attempts, candidate });
  if (loop) return loop;
  const next = normalizedAttempt(candidate);
  const identical = attempts.map(normalizedAttempt).filter(Boolean)
    .filter((attempt) => attempt.failure_fingerprint === next.failure_fingerprint).length;
  if (identical >= max_identical_attempts) return terminal('BUDGET_STOP', 'RETRY_LIMIT', { failure_fingerprint: next.failure_fingerprint, attempts: identical, max_identical_attempts });
  return allowed({ retry_class: next.retry_class, diagnosis_delta: true, prior_identical_failures: identical });
}

/** Reject a continuation unless lineage & both epochs still equal projection. */
export function denyStaleContinuation({ token, current, stop = null } = {}) {
  if (stop) return terminal('BUDGET_STOP', stop.code ?? 'STOP_PRECEDENCE', { stop: clone(stop) });
  if (!token || !current) return terminal('STALE_CONTINUATION', 'CONTINUATION_BINDING_MISSING');
  const fields = ['objective_lineage_id', 'intent_epoch', 'continuation_epoch'];
  const mismatches = fields.filter((field) => token[field] !== current[field]);
  return mismatches.length
    ? terminal('STALE_CONTINUATION', 'CONTINUATION_STALE', { mismatches })
    : allowed({ continuation: 'CURRENT' });
}

/**
 * Keeps rehydrated payloads as data only.  Embedded instructions, authority,
 * approvals, or effect claims never alter classification.
 */
export function classifyRehydratedInput({ envelope } = {}) {
  try {
    const rehydrated = rehydrateUntrustedData(envelope);
    return frozen({
      allowed: true,
      terminal: null,
      classification: 'UNTRUSTED_DATA',
      authority_granted: false,
      instruction_status: 'DATA_ONLY',
      effect_downgrade_allowed: false,
      data: rehydrated.data,
    });
  } catch {
    return terminal('REHYDRATION_REJECTED', 'INVALID_REHYDRATION_ENVELOPE');
  }
}

function proposalFor(state, context, attempt) {
  return {
    objective_lineage_id: state.task.objective_lineage_id,
    intent_epoch: state.intent.intent_epoch,
    execution_id: context.execution_id,
    repository_id: context.repository_id,
    actor_role: context.actor_role ?? 'alchemist', phase: 'execute', event_type: 'RETRY_RECORDED',
    payload: clone(attempt), acceptance_ids: [], decision_ids: [], finding_ids: [],
    input_fingerprint: attempt.input_fingerprint, output_refs: [], checkpoint_ref: null,
    cost_delta: {}, retry_class: attempt.retry_class, terminal_reason: null, privacy_class: 'metadata',
  };
}

/**
 * Append an authenticated RETRY_RECORDED event only after admission.  Caller
 * supplies a state projected by ArchitectureEventStore.replay(), preserving
 * its optimistic-concurrency fingerprint.
 */
export function recordAttempt({ eventStore, state, context, attempt, stop = null, max_identical_attempts = 3 } = {}) {
  if (!eventStore || typeof eventStore.accept !== 'function' || !state?.execution?.retry || !context || !nonEmpty(context.execution_id) || !nonEmpty(context.repository_id)) return terminal('BUDGET_STOP', 'RETRY_RECORDING_UNAVAILABLE');
  const candidate = normalizedAttempt(attempt);
  const admission = admitRetry({ attempts: state.execution.retry.items, candidate, stop, max_identical_attempts });
  if (!admission.allowed) return admission;
  const accepted = eventStore.accept(proposalFor(state, context, candidate), { expected_state_fingerprint: state.state_fingerprint });
  if (!accepted.accepted) return frozen({ allowed: false, terminal: frozen({ kind: 'BUDGET_STOP', code: accepted.decision.code, detail: accepted.decision.detail }), decision: accepted.decision });
  return frozen({ allowed: true, terminal: null, attempt: candidate, event: accepted.event, state: accepted.state, state_fingerprint: accepted.state_fingerprint });
}
