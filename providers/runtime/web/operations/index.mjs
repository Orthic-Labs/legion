import { createHash, verify as verifySignature } from 'node:crypto';
import { isCanonicalBase64, sanitizeProducedArtifact, sanitizeSensitiveValue } from '../../../../lib/platform/artifact-sanitize.mjs';
import { denominator, exactBinding, finalize, sameBinding, sortById } from '../shared.mjs';

const OPERATION_IDS = Object.freeze(['alerts', 'backlog', 'backup', 'capacity', 'containment', 'cost', 'dashboards', 'health', 'incidents', 'load', 'provider', 'quota', 'region', 'restore', 'rollback', 'rpo', 'rto', 'slo', 'support']);
const RESULT_STATUSES = new Set(['pass', 'fail', 'partial', 'unproven', 'blocked', 'error']);
const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/;
const utcMillis = (value) => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value) && Number.isFinite(Date.parse(value)) ? Date.parse(value) : null;
const safePath = (value) => { if (typeof value !== 'string' || !value || value.includes('\\') || value.startsWith('/') || /^[A-Za-z]:/.test(value)) return false; const segments = value.split('/'); return segments.length > 1 && segments.every((segment) => /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(segment) && segment !== '.' && segment !== '..') && segments.join('/') === value; };
const validArtifact = (artifact, binding) => {
  if (!artifact || !safePath(artifact.path) || !sameBinding(binding, artifact.binding ?? {})) return false;
  return sanitizeProducedArtifact(artifact).valid;
};

function unwrap(envelope, trustedProducers) {
  const gaps = [];
  const trusted = trustedProducers.find((item) => item.id === envelope?.producer);
  let record = envelope;
  if (!trusted || typeof envelope?.signedContent !== 'string' || typeof envelope?.signature !== 'string') gaps.push('signature-unproven');
  else if (!isCanonicalBase64(envelope.signature)) gaps.push('signature-noncanonical');
  else { try { if (!verifySignature(null, Buffer.from(envelope.signedContent), trusted.publicKey, Buffer.from(envelope.signature, 'base64'))) gaps.push('signature-invalid'); else record = JSON.parse(envelope.signedContent); } catch { gaps.push('signature-invalid'); } }
  if (record?.producer && record.producer !== envelope?.producer) gaps.push('producer-mismatch');
  const originalArtifacts = record?.artifacts;
  if (originalArtifacts !== undefined && (!Array.isArray(originalArtifacts) || !originalArtifacts.every((artifact) => validArtifact(artifact, record?.binding ?? {})))) gaps.push('operation-artifact-invalid');
  const sanitized = sanitizeSensitiveValue(record);
  const artifactAdmissions = Array.isArray(originalArtifacts) ? originalArtifacts.map((artifact) => sanitizeProducedArtifact(artifact)) : [];
  const sanitizedArtifacts = Array.isArray(originalArtifacts) ? artifactAdmissions.filter((item) => item.valid && item.artifact).map((item) => item.artifact) : originalArtifacts;
  if (artifactAdmissions.some((item) => item.sensitive)) gaps.push('operation-artifact-sanitized');
  if (sanitized.sensitive) gaps.push('operation-sensitive-data');
  record = sanitized.value && typeof sanitized.value === 'object' ? { ...sanitized.value, ...(originalArtifacts !== undefined ? { artifacts: sanitizedArtifacts } : {}) } : sanitized.value;
  return { id: record?.id ?? envelope?.id, record, producer: envelope?.producer ?? null, evidenceDigest: envelope?.signedContent ? `sha256:${createHash('sha256').update(envelope.signedContent).digest('hex')}` : null, gaps };
}

export function verifyOperationsExercise({ binding = {}, exercises = [], trustedProducers = [], now = null, maxAgeMs = null } = {}) {
  if (!Array.isArray(exercises) || !Array.isArray(trustedProducers) || exercises.some((item) => !item || typeof item !== 'object') || trustedProducers.some((item) => !item || typeof item !== 'object')) return finalize('nemesis-web-operations-exercise', { status: 'error', terminal: true, binding, denominator: denominator([], []), receipts: [], coverageGaps: ['operations-collections-invalid'] });
  const identifiers = [...exercises.flatMap((item) => [item.id, item.producer].filter((value) => value !== undefined)), ...trustedProducers.map((item) => item.id)];
  if (identifiers.some((id) => typeof id !== 'string' || !SAFE_IDENTIFIER.test(id))) return finalize('nemesis-web-operations-exercise', { status: 'error', terminal: true, binding, denominator: denominator([], []), receipts: [], coverageGaps: ['operations-identifiers-invalid'] });
  const verified = sortById(exercises.map((item) => unwrap(item, trustedProducers)));
  const grouped = new Map();
  for (const item of verified) { if (!grouped.has(item.id)) grouped.set(item.id, []); grouped.get(item.id).push(item); }
  const globalGaps = [];
  for (const [id, rows] of grouped) {
    if (!OPERATION_IDS.includes(id)) globalGaps.push(`operation-unplanned:${id ?? 'missing'}`);
    if (rows.length > 1) globalGaps.push(`operation-id-duplicate:${id}`);
    if (rows.some((row) => row.gaps.includes('signature-unproven'))) globalGaps.push(`operation-signature-unproven:${id}`);
    if (rows.some((row) => row.gaps.includes('signature-noncanonical'))) globalGaps.push(`operation-signature-noncanonical:${id}`);
    if (rows.some((row) => row.gaps.includes('signature-invalid'))) globalGaps.push(`operation-signature-invalid:${id}`);
  }
  const receipts = OPERATION_IDS.map((id) => {
    const rows = grouped.get(id) ?? [];
    if (!rows.length) return { id, status: 'unproven', terminal: true, coverageGaps: ['operation-missing'] };
    const selected = rows[0], item = selected.record ?? {}, gaps = [...selected.gaps];
    if (item.id !== id) gaps.push('operation-id-mismatch');
    if (item.exercised !== true) gaps.push('configured-not-exercised');
    const statusValid = RESULT_STATUSES.has(item.status);
    if (!statusValid) gaps.push(`operation-status-invalid:${item.status ?? 'missing'}`);
    if (item.terminal !== true) gaps.push('operation-nonterminal');
    if (item.outcome?.executed !== true) gaps.push('operation-outcome-unexecuted');
    if (statusValid && item.status !== 'pass') gaps.push(`operation-status-${item.status}`);
    if (!sameBinding(binding, item.binding ?? {})) gaps.push('binding-mismatch');
    for (const key of ['workload', 'dataset', 'region', 'providerLimits', 'cost', 'assumptions', 'alert', 'action', 'recovery', 'residualDamage']) if (item[key] === undefined || item[key] === null) gaps.push(`missing-${key}`);
    for (const key of ['alert', 'action', 'recovery']) if (item[key] !== true) gaps.push(`${key}-not-observed`);
    if (item.residualDamage?.length) gaps.push('residual-damage-present');
    const issued = utcMillis(item.issuedAt), checked = utcMillis(item.checkedAt), current = utcMillis(now), expires = utcMillis(item.expiresAt);
    for (const [key, value] of [['issuedAt', issued], ['checkedAt', checked], ['now', current], ['expiresAt', expires]]) if (value === null) gaps.push(`${key}-timestamp-invalid`);
    if ([issued, checked, current, expires].some((value) => value === null)) gaps.push('freshness-unbound');
    if (!Number.isFinite(maxAgeMs) || maxAgeMs < 0) gaps.push('freshness-window-invalid');
    if (issued !== null && checked !== null && issued > checked) gaps.push('issued-after-checked');
    if (checked !== null && current !== null && checked > current) gaps.push('checked-in-future');
    if (checked !== null && expires !== null && checked > expires) gaps.push('checked-after-expiry');
    if (current !== null && expires !== null && current > expires) gaps.push('evidence-expired');
    if (checked !== null && current !== null && Number.isFinite(maxAgeMs) && current - checked > maxAgeMs) gaps.push('evidence-stale');
    const status = !statusValid || item.terminal !== true ? 'error' : item.status !== 'pass' ? item.status : gaps.length ? 'unproven' : 'pass';
    return { id, producer: selected.producer, evidenceDigest: selected.evidenceDigest, record: item, status, terminal: true, coverageGaps: [...new Set(gaps)].sort() };
  });
  const counts = denominator(OPERATION_IDS, receipts);
  const gaps = [...globalGaps, ...exactBinding(binding).gaps.map((key) => `binding-missing:${key}`), ...OPERATION_IDS.filter((id) => !grouped.has(id)).map((id) => `operation-omitted:${id}`), ...receipts.flatMap((item) => item.coverageGaps.map((gap) => `${item.id}:${gap}`))];
  if (exercises.length === 0) gaps.push('operations-denominator-empty');
  const terminalStatuses = receipts.map((item) => item.status);
  const status = ['error', 'fail', 'blocked', 'partial', 'unproven'].find((candidate) => terminalStatuses.includes(candidate)) ?? (gaps.length ? 'unproven' : 'pass');
  return finalize('nemesis-web-operations-exercise', { status, terminal: true, claimLevel: 'external', suppliedOnly: true, networkAttempted: false, binding, denominator: counts, receipts, coverageGaps: [...new Set(gaps)].sort() });
}
