import { ArcaneError } from './errors.mjs';

const SCHEMA = 'arcane.control-lifecycle-assessment.v1';
const TERMINAL = new Set(['RETIRED', 'SUPERSEDED']);

function object(value, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ArcaneError('ARC_SCHEMA_INVALID', `${name} must be an object`, { name });
  return value;
}

function passingEval(proof) { return proof?.status === 'PASS' && proof?.fresh === true; }

/**
 * Decide whether a lifecycle record can enter a terminal status.  A denial
 * deliberately returns ACTIVE/DEPRECATED rather than silently deleting state.
 */
export function assessControlRetirement({ record, consumerScan, obligationDisposition, migrationEvidence, evalProof }) {
  object(record, 'record');
  if (!TERMINAL.has(record.status)) throw new ArcaneError('ARC_SCHEMA_INVALID', 'record.status must be RETIRED or SUPERSEDED', { status: record.status });
  object(consumerScan, 'consumerScan'); object(obligationDisposition, 'obligationDisposition');
  const failures = [];
  if (consumerScan.complete !== true) failures.push({ code: 'ARC_RETIREMENT_CONSUMER_SCAN_MISSING' });
  if (!Array.isArray(consumerScan.liveConsumers) || consumerScan.liveConsumers.length !== 0) failures.push({ code: 'ARC_RETIREMENT_LIVE_CONSUMERS', consumers: consumerScan.liveConsumers ?? null });
  if (obligationDisposition.complete !== true || !Array.isArray(obligationDisposition.open) || obligationDisposition.open.length !== 0) failures.push({ code: 'ARC_RETIREMENT_OBLIGATIONS_OPEN', obligations: obligationDisposition.open ?? null });
  if (migrationEvidence?.completed !== true) failures.push({ code: 'ARC_RETIREMENT_MIGRATION_EVIDENCE_MISSING' });
  if (!passingEval(evalProof)) failures.push({ code: 'ARC_RETIREMENT_EVAL_PROOF_MISSING' });
  const allowed = failures.length === 0;
  const retainedStatus = record.status === 'SUPERSEDED' ? 'DEPRECATED' : 'ACTIVE';
  return Object.freeze({
    schema: SCHEMA, allowed, code: allowed ? 'ARC_RETIREMENT_ALLOWED' : 'ARC_RETIREMENT_DENIED',
    controlId: record.control_id, status: allowed ? record.status : retainedStatus,
    failures: Object.freeze(failures),
  });
}
