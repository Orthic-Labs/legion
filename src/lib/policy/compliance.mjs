// Compliance control mapping per PR41. Maps established findings/evidence to
// optional compliance controls; absence of a finding is never compliance
// evidence.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const DEFAULT_REGISTRY = fileURLToPath(new URL('../../registry/compliance/controls.json', import.meta.url));

export function loadControls(path = DEFAULT_REGISTRY) {
  return JSON.parse(readFileSync(path, 'utf8')).controls;
}

export function mapEvidenceToControls({ report, controls }) {
  const findings = report?.findings ?? [];
  const coverageGaps = report?.coverage_gaps ?? [];
  return (controls ?? []).map((control) => {
    const supporting = findings.filter((finding) => (control.evidenceKinds ?? []).some((kind) => {
      const rule = String(finding.ruleId ?? '').toLowerCase();
      const keyword = kind.replace(/^control\./, '').split('-')[0].toLowerCase();
      return rule.includes(keyword);
    }));
    const unproven = (control.evidenceKinds ?? []).some((kind) => {
      const keyword = kind.replace(/^control\./, '').split('-')[0].toLowerCase();
      return coverageGaps.some((gap) => JSON.stringify(gap).toLowerCase().includes(keyword));
    });
    return {
      controlId: control.id,
      status: supporting.length > 0 ? 'supported' : unproven ? 'unproven' : 'not-applicable',
      supportingFindingIds: supporting.map((finding) => finding.id).sort(),
      // Absence of a finding is explicitly NOT compliance evidence.
      absenceIsEvidence: false,
    };
  });
}
