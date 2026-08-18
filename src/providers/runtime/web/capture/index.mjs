import { exactBinding, finalize, sameBinding, sortById } from '../shared.mjs';
import { WEB_JOURNEYS, webJourneySurfaceMatches } from '../journey-plan.mjs';
import { isWebMatrixCombinationId } from '../matrix/index.mjs';
import { sanitizeSensitiveValue } from '../../../../lib/platform/artifact-sanitize.mjs';

const REQUIRED = ['screenshot', 'dom', 'accessibilityTree', 'style', 'geometry', 'trace', 'performance'];
const PERFORMANCE_REQUIRED = ['longTasks', 'layoutShifts', 'paints', 'memory', 'userTimings'];
const nonnegativeMetric = (value) => typeof value === 'number' ? Number.isFinite(value) && value >= 0 : Array.isArray(value) && value.length > 0 && value.every((item) => typeof item === 'number' && Number.isFinite(item) && item >= 0);

export function captureWebEvidence({ binding = {}, surface = {}, tool = {}, captures = [] } = {}) {
  if (!surface || typeof surface !== 'object' || Array.isArray(surface)) return finalize('legion-web-capture-evidence', { status: 'error', terminal: true, verdict: 'unproven', binding, captures: [], coverageGaps: ['capture-surface-invalid'] });
  if (!tool || typeof tool !== 'object' || Array.isArray(tool)) return finalize('legion-web-capture-evidence', { status: 'error', terminal: true, verdict: 'unproven', binding, captures: [], coverageGaps: ['capture-tool-invalid'] });
  if (!Array.isArray(captures) || captures.some((item) => !item || typeof item !== 'object')) return finalize('legion-web-capture-evidence', { status: 'error', terminal: true, verdict: 'unproven', binding, captures: [], coverageGaps: ['capture-collection-invalid'] });
  const ordered = sortById(captures.map((item) => ({ id: String(item.repeat), ...item })));
  const gaps = exactBinding(binding).gaps.map((key) => `binding-missing:${key}`);
  const sanitized = sanitizeSensitiveValue({ binding, surface, tool, captures: ordered });
  if (sanitized.sensitive) gaps.push('capture-sensitive-data-sanitized');
  if (!surface.id || !surface.route || !(surface.componentIds?.length)) gaps.push('surface-binding-incomplete');
  if (typeof surface.journeyId !== 'string' || !surface.journeyId) gaps.push('capture-journey-id-missing');
  if (typeof surface.stateId !== 'string' || !surface.stateId) gaps.push('capture-state-binding-missing');
  if (typeof surface.matrixCombinationId !== 'string' || !surface.matrixCombinationId) gaps.push('capture-matrix-combination-binding-missing');
  if (typeof surface.matrixCombinationId === 'string' && surface.matrixCombinationId && !isWebMatrixCombinationId(surface.matrixCombinationId)) gaps.push('capture-matrix-combination-unplanned');
  if (typeof surface.route === 'string' && surface.route && typeof surface.stateId === 'string' && surface.stateId && typeof surface.matrixCombinationId === 'string' && surface.matrixCombinationId && !webJourneySurfaceMatches(surface)) gaps.push('capture-journey-binding-unplanned');
  const journey = WEB_JOURNEYS.find((row) => row.id === surface.journeyId && row.applicable === true);
  if (surface.journeyId && !journey) gaps.push('capture-journey-id-unplanned');
  if (journey) {
    if (surface.id !== journey.id) gaps.push('capture-surface-id-mismatch');
    if (surface.controlId !== journey.controlId) gaps.push('capture-control-binding-mismatch');
    if (surface.routeId !== journey.routeId) gaps.push('capture-route-id-binding-mismatch');
    if (surface.route !== journey.route) gaps.push('capture-route-binding-mismatch');
    if (surface.stateId !== journey.stateId) gaps.push('capture-state-binding-mismatch');
    if (surface.actionId !== journey.actionId) gaps.push('capture-action-binding-mismatch');
    if (!journey.protocolIds.includes(surface.protocolId)) gaps.push('capture-protocol-binding-mismatch');
    if (surface.directApplicable !== journey.directApplicable) gaps.push('capture-direct-applicability-mismatch');
    if (surface.deepApplicable !== journey.deepApplicable) gaps.push('capture-deep-applicability-mismatch');
    if (surface.matrixCombinationId !== journey.matrixCombinationId) gaps.push('capture-matrix-combination-binding-mismatch');
    if (!sameBinding(binding, surface.binding ?? {})) gaps.push('capture-surface-binding-mismatch');
  }
  if (!tool.name || !tool.version) gaps.push('capture-tool-unversioned');
  if (!tool.accessibilityEngine || !tool.accessibilityEngineVersion) gaps.push('accessibility-engine-unversioned');
  const repeatIds = ordered.map((item) => item.repeat ?? item.sampleId).filter((value) => value !== undefined && value !== null);
  if (ordered.length < 2 || new Set(repeatIds.map(String)).size < 2) gaps.push('capture-repeats-insufficient');
  if (repeatIds.length !== ordered.length || new Set(repeatIds.map(String)).size !== repeatIds.length) gaps.push('capture-repeat-identities-not-unique');
  for (const capture of ordered) { for (const key of REQUIRED.filter((key) => key !== 'performance')) if (typeof capture[key] !== 'string' || capture[key].length === 0) gaps.push(`capture-${key}-invalid:${capture.id}`); if (!capture.performance || typeof capture.performance !== 'object') gaps.push(`capture-performance-invalid:${capture.id}`); for (const key of PERFORMANCE_REQUIRED.filter((key) => key !== 'memory')) if (capture.performance?.[key] === undefined || capture.performance?.[key] === null) gaps.push(`capture-performance-${key}-missing:${capture.id}`); else if (!nonnegativeMetric(capture.performance[key])) gaps.push(`capture-performance-${key}-invalid:${capture.id}`); for (const key of ['memory', 'lcp']) if (capture.performance?.[key] === undefined || capture.performance?.[key] === null) gaps.push(`capture-performance-${key}-missing:${capture.id}`); else if (typeof capture.performance[key] !== 'number' || !nonnegativeMetric(capture.performance[key])) gaps.push(`capture-performance-${key}-invalid:${capture.id}`); }
  const evidenceIds = ordered.map((item) => JSON.stringify([item.screenshot, item.dom, item.accessibilityTree, item.style, item.geometry, item.trace, item.performance]));
  if (new Set(evidenceIds).size !== evidenceIds.length) gaps.push('capture-evidence-identities-not-unique');
  const p75Inputs = ordered.map((item) => item.performance?.lcp).filter(Number.isFinite).sort((a, b) => a - b);
  const p75 = p75Inputs.length ? p75Inputs[Math.ceil(p75Inputs.length * 0.75) - 1] : null;
  const variance = p75Inputs.length ? Math.max(...p75Inputs) - Math.min(...p75Inputs) : null;
  if (p75 === null) gaps.push('capture-performance-p75-missing');
  return finalize('legion-web-capture-evidence', { status: gaps.length ? 'partial' : 'pass', terminal: true, verdict: 'unproven', binding: sanitized.value.binding, captureBinding: { route: sanitized.value.surface.route ?? null, stateId: sanitized.value.surface.stateId ?? null, matrixCombinationId: sanitized.value.surface.matrixCombinationId ?? null }, surface: sanitized.value.surface, tool: sanitized.value.tool, captures: sanitized.value.captures, performance: { p75Inputs, p75, variance }, coverageGaps: [...new Set(gaps)].sort() });
}
