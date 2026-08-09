import { createHash } from 'node:crypto';
import { sanitizeArtifactContent } from '../../../../lib/platform/artifact-sanitize.mjs';
import { canonicalize, denominator, exactBinding, finalize, sameBinding, sortById } from '../shared.mjs';

const ACCEPTED = new Set(['pass', 'fail', 'partial', 'unproven', 'blocked', 'error']);
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const safePath = (value) => { if (typeof value !== 'string' || !value || value.includes('\\') || value.startsWith('/') || /^[A-Za-z]:/.test(value)) return false; const segments = value.split('/'); return segments.length > 1 && segments.every((segment) => /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(segment) && segment !== '.' && segment !== '..') && segments.join('/') === value; };
const validArtifact = (artifact, binding, controlId) => {
  if (!artifact || typeof artifact !== 'object' || Array.isArray(artifact) || !safePath(artifact.path) || artifact.family !== 'web' || artifact.targetId !== binding.targetId || artifact.environment !== binding.environment || artifact.sourceRevision !== binding.sourceRevision || artifact.controlId !== controlId || !sameBinding(binding, artifact.binding ?? {})) return false;
  if (sanitizeArtifactContent(artifact, artifact.sensitiveFields ?? []).sensitive) return false;
  const hasContent = typeof artifact.content === 'string', hasBytes = typeof artifact.bytesBase64 === 'string';
  if (hasContent === hasBytes) return false;
  const bytes = hasContent ? Buffer.from(artifact.content, 'utf8') : BASE64.test(artifact.bytesBase64) ? Buffer.from(artifact.bytesBase64, 'base64') : null;
  return Boolean(bytes?.length) && artifact.digest === `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
};
const artifactKey = (artifact) => JSON.stringify(canonicalize(typeof artifact === 'string' ? { binding: null, digest: null, family: null, id: null, path: artifact } : { binding: artifact?.binding ?? null, digest: artifact?.digest ?? null, family: artifact?.family ?? null, id: artifact?.id ?? null, path: artifact?.path ?? null }));
const normalizeArtifacts = (values) => {
  if (!Array.isArray(values)) return { artifacts: [], duplicates: [] };
  const rows = values.map((artifact) => ({ artifact, key: artifactKey(artifact), value: JSON.stringify(canonicalize(artifact)) })).sort((left, right) => left.key.localeCompare(right.key) || left.value.localeCompare(right.value));
  const duplicates = [];
  const artifacts = [];
  for (const row of rows) {
    if (artifacts.length && artifactKey(artifacts.at(-1)) === row.key) { duplicates.push(row.key); continue; }
    artifacts.push(row.artifact);
  }
  return { artifacts, duplicates: [...new Set(duplicates)].sort() };
};

export function integrateWebEvidence({ binding = {}, applicableControls = [], receipts = [] } = {}) {
  if (!Array.isArray(applicableControls) || !Array.isArray(receipts) || receipts.some((item) => !item || typeof item !== 'object')) return finalize('legion-web-integrated-evidence', { status: 'error', terminal: true, provisional: true, claimLevel: 'source', binding, denominator: denominator([], []), receipts: [], rawArtifacts: [], coverageGaps: ['integration-collections-invalid'] });
  const expected = [...new Set(applicableControls)].sort();
  for (const receipt of receipts) if (receipt.targetId !== binding.targetId) throw new Error(`cross-target evidence rejected: ${receipt.controlId}`);
  const byControl = new Map();
  const duplicateArtifactKeys = [];
  for (const receipt of sortById(receipts)) {
    if (!expected.includes(receipt.controlId)) continue;
    if (byControl.has(receipt.controlId)) throw new Error(`duplicate terminal receipt: ${receipt.controlId}`);
    byControl.set(receipt.controlId, receipt);
  }
  const terminal = expected.map((controlId) => {
    const receipt = byControl.get(controlId);
    if (!receipt) return { controlId, targetId: binding.targetId, status: 'unproven', terminal: true, binding, artifacts: [], synthesized: true };
    if (receipt.terminal !== true || !ACCEPTED.has(receipt.status)) return { ...receipt, status: 'unproven', terminal: true, invalidTerminal: true, bindingMismatch: !sameBinding(binding, receipt.binding ?? {}) };
    if (!sameBinding(binding, receipt.binding ?? {})) return { ...receipt, status: 'unproven', terminal: true, bindingMismatch: true };
    const candidates = receipt.artifacts === undefined ? [] : Array.isArray(receipt.artifacts) ? receipt.artifacts : [receipt.artifacts];
    const admitted = candidates.filter((artifact) => validArtifact(artifact, binding, receipt.controlId));
    const artifactInvalid = admitted.length !== candidates.length;
    const normalized = normalizeArtifacts(admitted);
    duplicateArtifactKeys.push(...normalized.duplicates.map((key) => `${receipt.controlId}:${key}`));
    return { ...receipt, artifacts: normalized.artifacts, ...(artifactInvalid ? { artifactInvalid: true } : {}) };
  });
  const counts = denominator(expected, terminal);
  const gaps = exactBinding(binding).gaps.map((key) => `binding-missing:${key}`);
  if (expected.length === 0) gaps.push('integration-denominator-empty');
  const nonApplicable = receipts.filter((item) => !expected.includes(item.controlId));
  gaps.push(...nonApplicable.map((item) => `non-applicable-receipt:${item.controlId}`));
  for (const receipt of terminal) {
    if (receipt.synthesized) gaps.push(`missing-terminal-receipt:${receipt.controlId}`);
    if (receipt.bindingMismatch) gaps.push(`binding-mismatch:${receipt.controlId}`);
    if (receipt.invalidTerminal) gaps.push(`invalid-terminal-receipt:${receipt.controlId}`);
    if (receipt.artifactInvalid) gaps.push(`artifact-invalid:${receipt.controlId}`);
  }
  const aggregateArtifacts = normalizeArtifacts(terminal.filter((item) => !item.synthesized && !item.bindingMismatch && !item.invalidTerminal).flatMap((item) => item.artifacts ?? []));
  duplicateArtifactKeys.push(...aggregateArtifacts.duplicates);
  gaps.push(...[...new Set(duplicateArtifactKeys)].sort().map((key) => `artifact-identity-duplicate:${key}`));
  const statuses = new Set(terminal.map((item) => item.status));
  const status = statuses.size === 1 && statuses.has('pass') && gaps.length === 0 ? 'pass' : statuses.has('error') ? 'error' : statuses.has('fail') ? 'partial' : 'partial';
  return finalize('legion-web-integrated-evidence', { status: gaps.length && status === 'pass' ? 'partial' : status, terminal: true, provisional: true, claimLevel: 'source', binding, denominator: counts, receipts: terminal, rawArtifacts: aggregateArtifacts.artifacts, coverageGaps: gaps.sort() });
}
