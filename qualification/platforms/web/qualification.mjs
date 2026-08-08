import { createHash } from 'node:crypto';
import { sanitizeProducedArtifact, sanitizeSensitiveValue } from '../../../lib/platform/artifact-sanitize.mjs';
import { denominator, digest, finalize, sameBinding, sortById } from '../../../providers/runtime/web/shared.mjs';
import { integrateWebEvidence } from '../../../providers/runtime/web/integration/index.mjs';

const safeArtifactPath = (value) => {
  if (typeof value !== 'string' || !value || value.includes('\\') || value.startsWith('/') || /^[A-Za-z]:/.test(value)) return false;
  const segments = value.split('/');
  return segments.length > 1 && segments.every((segment) => /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(segment) && segment !== '.' && segment !== '..') && segments.join('/') === value;
};
function typedCanonical(value, seen = new Map()) {
  if (value === null) return 'null';
  if (typeof value === 'string') return `string:${value}`;
  if (typeof value === 'number') return `number:${Number.isNaN(value) ? 'nan' : Object.is(value, -0) ? '-0' : String(value)}`;
  if (typeof value === 'bigint') return `bigint:${value.toString()}`;
  if (typeof value === 'boolean' || typeof value === 'undefined') return `${typeof value}:${String(value)}`;
  if (typeof value === 'symbol') return `symbol:${Symbol.keyFor(value) ?? value.description ?? ''}`;
  if (typeof value === 'function') return `function:${value.name}:${value.length}`;
  if (seen.has(value)) return `ref:${seen.get(value)}`;
  const index = seen.size; seen.set(value, index);
  if (Array.isArray(value)) return `array:${index}:[${value.map((item) => typedCanonical(item, seen)).join(',')}]`;
  return `object:${index}:{${Object.keys(value).sort().map((key) => `${typedCanonical(key, seen)}=${typedCanonical(value[key], seen)}`).join(',')}}`;
}
const safeIdentifier = (value) => {
  if (typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/.test(value)) return value;
  let normalized;
  try { normalized = typedCanonical(value); } catch { normalized = `invalid:${typeof value}`; }
  return `opaque-${createHash('sha256').update(normalized).digest('hex').slice(0, 24)}`;
};
const identifierKey = (key) => key === 'id' || key === 'ids' || /(?:Id|Ids|ID|IDs)$/.test(key) || /(?:^|[_-])ids?$/i.test(key);
const identifiersKey = (key) => key === 'ids' || /(?:Ids|IDs)$/.test(key) || /(?:^|[_-])ids$/i.test(key);
function safeIdentifierFields(value, key = '', seen = new WeakSet()) {
  if (identifierKey(key)) return identifiersKey(key) && Array.isArray(value) ? value.map(safeIdentifier) : safeIdentifier(value);
  if (Array.isArray(value)) return value.map((item) => safeIdentifierFields(item, '', seen));
  if (!value || typeof value !== 'object') return value;
  if (seen.has(value)) return '[CIRCULAR-OMITTED]';
  seen.add(value);
  const result = Object.fromEntries(Object.keys(value).sort().map((childKey) => { try { return [childKey, safeIdentifierFields(value[childKey], childKey, seen)]; } catch { return [childKey, '[UNREADABLE-OMITTED]']; } }));
  seen.delete(value);
  return result;
}
const safeGap = (value) => typeof value === 'string' ? sanitizeSensitiveValue(value).value : 'qualification-gap-invalid';
const safeArtifactIdentifiers = (artifact, controlId) => safeIdentifierFields({ ...artifact, controlId });
const rejectedMetadata = (artifact) => { const { content: _content, bytesBase64: _bytesBase64, ...metadata } = artifact; return sanitizeSensitiveValue(metadata).value; };

export function qualifyWebPlatform({ binding = {}, fixtures = [] } = {}) {
  binding = safeIdentifierFields(binding);
  if (!Array.isArray(fixtures) || fixtures.some((item) => !item || typeof item !== 'object')) return finalize('nemesis-web-platform-qualification', { status: 'error', terminal: true, provisional: true, claimLevel: 'source', binding, denominator: denominator([], []), receipts: [], rawArtifacts: [], rejectedArtifacts: [], coverageGaps: ['qualification-fixtures-invalid'] });
  const receipts = [];
  const rawArtifacts = new Map();
  const rejectedArtifacts = [];
  const fixtureGroups = new Map();
  for (const fixture of sortById(fixtures.map((item) => ({ ...safeIdentifierFields(item), id: safeIdentifier(item.id) })))) { if (!fixtureGroups.has(fixture.id)) fixtureGroups.set(fixture.id, []); fixtureGroups.get(fixture.id).push(fixture); }
  const qualificationGaps = [];
  if (fixtures.length === 0) qualificationGaps.push('fixture-denominator-empty');
  for (const [id, rows] of fixtureGroups) if (rows.length > 1) qualificationGaps.push(`fixture-id-duplicate:${id}`);
  const selectedFixtures = sortById([...fixtureGroups].map(([, rows]) => sortById(rows)[0]));
  for (const fixture of selectedFixtures) {
    const fixtureReceiptsValid = Array.isArray(fixture.receipts)
      && fixture.receipts.every((receipt) => receipt && typeof receipt === 'object' && !Array.isArray(receipt))
      && fixture.receipts.every((receipt) => Array.isArray(receipt.artifacts) && receipt.artifacts.every((artifact) => artifact && typeof artifact === 'object' && !Array.isArray(artifact)));
    if (!fixtureReceiptsValid) {
      receipts.push({ id: fixture.id, status: 'error', terminal: true, coverageGaps: ['fixture-rejected', Array.isArray(fixture.receipts) && fixture.receipts.every((receipt) => receipt && typeof receipt === 'object' && !Array.isArray(receipt)) ? 'fixture-receipt-artifacts-invalid' : 'fixture-receipts-invalid'] });
      continue;
    }
    const applicable = Array.isArray(fixture.applicableControls) ? fixture.applicableControls.map(safeIdentifier) : [];
    const fixtureReceipts = fixture.receipts.map((receipt) => {
      const controlId = safeIdentifier(receipt.controlId);
      return { ...receipt, ...(Object.hasOwn(receipt, 'id') ? { id: safeIdentifier(receipt.id) } : {}), controlId, artifacts: receipt.artifacts.map((artifact) => safeArtifactIdentifiers(artifact, controlId)) };
    });
    const candidates = fixtureReceipts.flatMap((receipt) => receipt.artifacts.map((artifact) => ({ artifact, receipt, admission: sanitizeProducedArtifact(artifact) })));
    const produced = candidates.filter(({ artifact, receipt, admission }) => applicable.includes(receipt.controlId) && receipt.targetId === binding.targetId && sameBinding(binding, receipt.binding ?? {}) && fixture.family === 'web' && safeArtifactPath(artifact.path) && artifact.family === 'web' && sameBinding(binding, artifact.binding ?? {}) && admission.valid && admission.artifact);
    for (const { artifact } of candidates.filter((item) => !produced.includes(item))) rejectedArtifacts.push(rejectedMetadata(artifact));
    for (const { admission } of produced) rawArtifacts.set(digest(admission.artifact), admission.artifact);
    const artifactGap = [...(produced.length ? [] : [candidates.length ? 'produced-artifact-invalid' : 'produced-artifact-missing']), ...(produced.some(({ admission }) => admission.sensitive) ? ['produced-artifact-sensitive-data'] : [])];
    if (!Array.isArray(fixture.receipts)) artifactGap.push('fixture-receipts-missing');
    if (!applicable.length) artifactGap.push('fixture-applicability-empty');
    if (fixture.family !== 'web') artifactGap.push('fixture-family-invalid');
    if (fixtureReceipts.some((receipt) => !applicable.includes(receipt.controlId))) artifactGap.push('fixture-non-applicable-receipt');
    try { const integrated = integrateWebEvidence({ binding, applicableControls: applicable, receipts: fixtureReceipts }); const integratedGap = integrated.status === 'pass' ? [] : [`integrated-status:${integrated.status}`]; receipts.push({ id: fixture.id, status: integrated.status, terminal: true, digest: integrated.digest, coverageGaps: [...integrated.coverageGaps.map(safeGap), ...integratedGap, ...artifactGap] }); }
    catch { receipts.push({ id: fixture.id, status: 'error', terminal: true, error: { code: 'qualification-integration-error', type: 'integration-rejected', message: 'fixture integration rejected' }, coverageGaps: ['fixture-rejected'] }); }
  }
  const counts = denominator([...fixtureGroups.keys()], receipts);
  const gaps = [...qualificationGaps, ...counts.missing.map((id) => `fixture-missing:${safeIdentifier(id)}`), ...receipts.flatMap((item) => item.coverageGaps.map((gap) => `${safeIdentifier(item.id)}:${safeGap(gap)}`))];
  return finalize('nemesis-web-platform-qualification', { status: receipts.some((item) => item.status === 'error') ? 'error' : gaps.length ? 'partial' : 'pass', terminal: true, provisional: true, claimLevel: 'source', binding, denominator: counts, receipts, rawArtifacts: [...rawArtifacts.entries()].sort(([left], [right]) => left.localeCompare(right)).map(([, artifact]) => artifact), rejectedArtifacts: sortById(rejectedArtifacts.map((artifact) => ({ id: `${artifact.family ?? 'unknown'}:${artifact.path ?? 'unknown'}`, artifact }))).map((item) => item.artifact), coverageGaps: gaps.sort() });
}
