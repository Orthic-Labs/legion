// Finding lifecycle primitives operate on typed identities and evidence digests.
// They deliberately never inspect a finding's prose, line anchor, or narrative.
import { digestValue } from './canonical.mjs';
import { decision } from './errors.mjs';

const SEVERITY = Object.freeze({ informational: 0, low: 1, medium: 2, high: 3, critical: 4 });
const id = (value, camel, snake) => value?.[camel] ?? value?.[snake] ?? null;
const freeze = (value) => Object.freeze(value);

function required(value, name) {
  if (typeof value !== 'string' || !value) throw new TypeError(`${name} is required`);
  return value;
}

function findingIdentity(finding) {
  const controlId = id(finding, 'controlId', 'control_id') ?? id(finding, 'ruleId', 'rule_id');
  const subjectId = id(finding, 'subjectId', 'subject_id') ?? finding?.file ?? finding?.path;
  const semanticKey = id(finding, 'semanticKey', 'semantic_key')
    ?? id(finding, 'conditionFingerprint', 'condition_fingerprint') ?? null;
  required(controlId, 'finding controlId or ruleId');
  required(subjectId, 'finding subjectId');
  return semanticKey === null
    ? { control_id: controlId, subject_id: subjectId }
    : { control_id: controlId, subject_id: subjectId, semantic_key: semanticKey };
}

/** Stable identity for a finding. Presentation text & source line anchors are excluded. */
export function fingerprintFinding(finding) {
  return digestValue(findingIdentity(finding));
}

export const stableFindingFingerprint = fingerprintFinding;

function event(event_type, payload) {
  return freeze({ event_type, payload: freeze(payload) });
}

/**
 * Upsert a finding by its stable fingerprint. Existing records retain their
 * originating review round; only current structured observation changes.
 */
export function upsertFinding({ records = [], finding, reviewRoundId, review_round_id: reviewRoundIdSnake }) {
  const stable_fingerprint = fingerprintFinding(finding);
  const round = reviewRoundId ?? reviewRoundIdSnake;
  required(round, 'reviewRoundId');
  const existing = records.find((record) => record.stable_fingerprint === stable_fingerprint
    || record.stableFingerprint === stable_fingerprint);
  const observation = freeze({ ...findingIdentity(finding), stable_fingerprint });
  const record = freeze({
    id: existing?.id ?? stable_fingerprint,
    stable_fingerprint,
    review_round_id: existing?.review_round_id ?? existing?.reviewRoundId ?? round,
    status: existing?.status ?? 'OPEN',
    observation,
  });
  const next = existing
    ? records.map((item) => (item === existing ? record : item))
    : [...records, record];
  return freeze({
    records: freeze(next),
    record,
    disposition: existing ? 'EXISTING_RECORD' : 'NEW_RECORD',
    event: event('FINDING_UPSERTED', record),
  });
}

export class FindingLifecycleStore {
  #records = [];

  records() { return freeze([...this.#records]); }

  upsert(input) {
    const result = upsertFinding({ ...input, records: this.#records });
    this.#records = [...result.records];
    return result;
  }
}

function evidenceValue(evidence, camel, snake) { return evidence?.[camel] ?? evidence?.[snake] ?? null; }

/**
 * A closure must be based on fresh artifact evidence produced by someone other
 * than fix author. Narrative claims are intentionally not part of this check.
 */
export function verifyFindingClosure({ finding, closure, evidence }) {
  const finding_fingerprint = fingerprintFinding(finding);
  const fix_author_id = id(closure, 'fixAuthorId', 'fix_author_id');
  const reviewer_id = id(closure, 'reviewerId', 'reviewer_id');
  const evidence_reviewer_id = evidenceValue(evidence, 'reviewerId', 'reviewer_id');
  const evidence_finding_fingerprint = evidenceValue(evidence, 'findingFingerprint', 'finding_fingerprint');
  const evidence_id = evidenceValue(evidence, 'evidenceId', 'evidence_id');
  const expected_artifact_fingerprint = evidenceValue(closure, 'artifactFingerprint', 'artifact_fingerprint');
  const observed_artifact_fingerprint = evidenceValue(evidence, 'artifactFingerprint', 'artifact_fingerprint');
  if (!fix_author_id || !reviewer_id || !evidence_reviewer_id || !evidence_finding_fingerprint || !evidence_id
    || !expected_artifact_fingerprint || !observed_artifact_fingerprint) {
    return decision({ allowed: false, code: 'ARC_EVIDENCE_INSUFFICIENT', message: 'fresh independent evidence is required for finding closure', detail: { finding_fingerprint } });
  }
  if (fix_author_id === reviewer_id || fix_author_id === evidence_reviewer_id) {
    return decision({ allowed: false, code: 'ARC_SELF_CERTIFICATION', message: 'fix author cannot close own finding; fresh independent evidence is required', detail: { finding_fingerprint, fix_author_id } });
  }
  if (reviewer_id !== evidence_reviewer_id || evidence_finding_fingerprint !== finding_fingerprint
    || expected_artifact_fingerprint !== observed_artifact_fingerprint) {
    return decision({ allowed: false, code: 'ARC_BINDING_MISMATCH', message: 'closure evidence does not match finding or observed artifact', detail: { finding_fingerprint } });
  }
  const payload = freeze({ id: finding_fingerprint, finding_fingerprint, status: 'VERIFIED_CLOSED', artifact_fingerprint: observed_artifact_fingerprint, reviewer_id, evidence_id });
  return decision({ allowed: true, message: 'finding closure verified from independent artifact evidence', detail: { finding: payload, event: event('FINDING_UPSERTED', payload) } });
}

function severityValue(finding) {
  const value = finding?.severity;
  if (Number.isInteger(value) && value >= 0) return value;
  if (typeof value === 'string' && Object.hasOwn(SEVERITY, value.toLowerCase())) return SEVERITY[value.toLowerCase()];
  throw new TypeError('finding severity must be a non-negative integer or known severity');
}

/** Retain every discovery; only deterministic severity threshold decides blocking. */
export function filterFindingsByThreshold({ findings = [], threshold }) {
  if (!Number.isInteger(threshold) || threshold < 0) throw new TypeError('threshold must be a non-negative integer');
  const retained = findings.map((finding) => freeze({ ...finding, disposition: severityValue(finding) >= threshold ? 'BLOCKING' : 'INFORMATIONAL' }));
  return freeze({
    findings: freeze(retained),
    blocking: freeze(retained.filter((finding) => finding.disposition === 'BLOCKING')),
    informational: freeze(retained.filter((finding) => finding.disposition === 'INFORMATIONAL')),
    deterministic_filter: freeze({ severity_threshold: threshold }),
  });
}

/**
 * Scoped rechecks close only explicitly selected open findings. Other newly
 * observed items stay visible as deferred informational work; no full loop.
 */
export function applyScopedRecheck({ records = [], targetFindingFingerprints, target_finding_fingerprints: targetSnake, closures = [], discoveredFindings = [] }) {
  const targets = new Set(targetFindingFingerprints ?? targetSnake ?? []);
  if (!targets.size) throw new TypeError('scoped recheck requires targetFindingFingerprints');
  const closureByFingerprint = new Map(closures.map((closure) => [closure.finding_fingerprint ?? closure.findingFingerprint, closure]));
  const updated = records.map((record) => {
    const fingerprint = record.stable_fingerprint ?? record.stableFingerprint;
    if (!targets.has(fingerprint)) return record;
    const closure = closureByFingerprint.get(fingerprint);
    if (!closure?.allowed) return record;
    return freeze({ ...record, status: 'VERIFIED_CLOSED', closure_event: closure.detail?.event ?? null });
  });
  const closed = updated.filter((record) => targets.has(record.stable_fingerprint ?? record.stableFingerprint) && record.status === 'VERIFIED_CLOSED');
  const deferred = discoveredFindings.map((finding) => freeze({ ...finding, disposition: 'DEFERRED_INFORMATIONAL' }));
  return freeze({
    records: freeze(updated),
    closed: freeze(closed),
    deferred: freeze(deferred),
    events: freeze(closed.map((record) => event('FINDING_UPSERTED', { id: record.id, stable_fingerprint: record.stable_fingerprint, status: record.status }))),
  });
}
