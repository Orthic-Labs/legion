// AI-quality contracts: enums, id/digest helpers, and the evaluation-receipt
// shape assertion. Deliberately self-contained — this module imports nothing
// from providers/security/** (and nothing from providers/security/** imports
// this module). AI quality and AI security are structurally separate
// artifact kinds ('ai-quality-evaluation-receipt' vs. 'security-candidate' /
// 'security-verdict'); neither reads or substitutes for the other's verdict.

import { createHash } from 'node:crypto';

// 17 declared AI-quality evaluation dimensions (Security Appendix / quality
// assurance backlog): declared-task correctness, groundedness/faithfulness,
// retrieval quality, structured-output and tool correctness, calibration and
// fallback behaviour, drift/reproducibility, operational cost, and
// human/feedback governance.
export const AI_QUALITY_METRICS = Object.freeze([
  'declared-task-eval',
  'groundedness',
  'citation-faithfulness',
  'retrieval-relevance',
  'structured-output-validity',
  'tool-selection-argument-correctness',
  'uncertainty-abstention-calibration',
  'refusal-fallback',
  'context-truncation',
  'prompt-robustness',
  'model-provider-version-drift',
  'reproducibility',
  'latency',
  'cost',
  'human-override',
  'feedback-loop',
  'subgroup-fairness',
]);

// A quality verdict is never a security verdict: no TRUE_POSITIVE, no
// HARDENING_GAP, no MISUSE_HAZARD. Quality results are pass/fail against a
// declared denominator, or explicitly unproven/review-required when
// evaluation evidence is missing or incomplete.
export const AI_QUALITY_VERDICTS = Object.freeze(['pass', 'fail', 'review-required', 'unproven']);

export const AI_QUALITY_SCHEMA_VERSIONS = Object.freeze({ 'ai-quality-evaluation-receipt': Object.freeze([1]) });

export function assertMetric(value) {
  if (!AI_QUALITY_METRICS.includes(value)) throw new TypeError(`unknown ai-quality metric: ${String(value)}`);
  return value;
}

export function assertQualityVerdict(value) {
  if (!AI_QUALITY_VERDICTS.includes(value)) throw new TypeError(`unknown ai-quality verdict: ${String(value)}`);
  return value;
}

export function requireObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`${label} must be an object`);
  return value;
}

export function requireString(value, label) {
  if (typeof value !== 'string' || value.length === 0) throw new TypeError(`${label} must be a non-empty string`);
  return value;
}

export function requireArray(value, label) {
  if (!Array.isArray(value)) throw new TypeError(`${label} must be an array`);
  return value;
}

export function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  }
  return value;
}

export function stableId(namespace, value) {
  const body = JSON.stringify(canonicalize(value));
  return `sha256:${createHash('sha256').update(`${namespace}\0${body}`).digest('hex')}`;
}

export function digest(value) {
  return stableId('digest', value);
}

// Same binding shape/semantics as the security binding (frozen plan +
// repository revision + Blueprint generation + registry digest), reimplemented
// locally rather than imported, so ai-quality has zero coupling to
// providers/security/**.
export function assertBinding(binding) {
  requireObject(binding, 'binding');
  for (const key of ['planDigest', 'repositoryRevision', 'blueprintGenerationId', 'blueprintManifestDigest', 'registryDigest']) {
    requireString(binding[key], `binding.${key}`);
  }
  if (binding.dirtyPatchDigest !== null) requireString(binding.dirtyPatchDigest, 'binding.dirtyPatchDigest');
  return binding;
}

export function assertEvaluationReceipt(receipt) {
  requireObject(receipt, 'evaluation receipt');
  if (receipt.schemaVersion !== 1) throw new Error(`ai-quality-evaluation-receipt unsupported schemaVersion: ${receipt.schemaVersion}`);
  if (receipt.kind !== 'ai-quality-evaluation-receipt') throw new Error(`unexpected kind: ${receipt.kind}`);
  requireString(receipt.id, 'receipt.id');
  assertMetric(receipt.metric);
  requireString(receipt.metricVersion, 'receipt.metricVersion');
  assertQualityVerdict(receipt.verdict);
  requireObject(receipt.modelIdentity, 'receipt.modelIdentity');
  requireObject(receipt.promptIdentity, 'receipt.promptIdentity');
  requireObject(receipt.datasetVersion, 'receipt.datasetVersion');
  requireObject(receipt.runConditions, 'receipt.runConditions');
  requireObject(receipt.judgeIdentity, 'receipt.judgeIdentity');
  requireObject(receipt.denominator, 'receipt.denominator');
  requireObject(receipt.measurement, 'receipt.measurement');
  requireArray(receipt.limitations, 'receipt.limitations');
  requireArray(receipt.uncertainty, 'receipt.uncertainty');
  requireArray(receipt.evidenceRefs, 'receipt.evidenceRefs');
  assertBinding(receipt.binding);
  // A candidate never carries a verdict; a quality receipt is the opposite —
  // it is nothing BUT a verdict against a bound denominator. It must never
  // carry a security-shaped field.
  for (const forbidden of ['severity', 'severityHint', 'evidenceStrength', 'candidateClass', 'adjudicationRequired']) {
    if (forbidden in receipt) throw new Error(`ai-quality-evaluation-receipt must not carry security-shaped field ${forbidden}`);
  }
  return true;
}
