import { captureWebEvidence } from '../capture/index.mjs';
import { denominator, finalize, sameBinding, sortById } from '../shared.mjs';

export function verifyWebAccessibility(input = {}) {
  if (!Array.isArray(input.captures) || !Array.isArray(input.inspections) || input.captures.some((item) => !item || typeof item !== 'object') || input.inspections.some((item) => !item || typeof item !== 'object')) return finalize('nemesis-web-accessibility-evidence', { provider: 'runtime.web.accessibility', status: 'error', terminal: true, binding: input.binding ?? {}, denominator: denominator([], []), inspections: [], violationCount: 0, coverageGaps: ['accessibility-collections-invalid'] });
  const capture = captureWebEvidence(input);
  const expected = [...new Set(input.captures.map((item) => String(item.repeat ?? item.sampleId)))].sort();
  const inspections = sortById(input.inspections.map((item) => ({ id: String(item.repeat ?? item.sampleId), ...item })));
  const counts = denominator(expected, inspections);
  const gaps = [...capture.coverageGaps, ...counts.missing.map((id) => `accessibility-inspection-missing:${id}`)];
  const inspectionIds = inspections.map((item) => item.id);
  for (const id of new Set(inspectionIds)) if (inspectionIds.filter((value) => value === id).length > 1) gaps.push(`accessibility-inspection-duplicate:${id}`);
  for (const id of inspectionIds.filter((id) => !expected.includes(id))) gaps.push(`accessibility-inspection-unplanned:${id}`);
  for (const inspection of inspections) { if (!Array.isArray(inspection.violations)) gaps.push(`violations-unbound:${inspection.id}`); if (!sameBinding(input.binding ?? {}, inspection.binding ?? {})) gaps.push(`accessibility-binding-mismatch:${inspection.id}`); if (inspection.terminal !== true) gaps.push(`accessibility-nonterminal:${inspection.id}`); if (inspection.status !== 'pass') gaps.push(`accessibility-status-${inspection.status ?? 'missing'}:${inspection.id}`); if (typeof inspection.screenshot !== 'string' || inspection.screenshot.length === 0) gaps.push(`accessibility-screenshot-invalid:${inspection.id}`); }
  const violationCount = inspections.reduce((sum, item) => sum + (item.violations?.length ?? 0), 0);
  return finalize('nemesis-web-accessibility-evidence', { provider: 'runtime.web.accessibility', status: violationCount ? 'fail' : gaps.length ? 'unproven' : 'pass', terminal: true, claimLevel: 'runtime', evidenceClass: 'measured', binding: input.binding ?? {}, engine: { name: input.tool?.accessibilityEngine ?? null, version: input.tool?.accessibilityEngineVersion ?? null }, denominator: counts, inspections, violationCount, captureDigest: capture.digest, coverageGaps: [...new Set(gaps)].sort() });
}
