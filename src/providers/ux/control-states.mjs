export function analyzeControlStates({ controls = [] } = {}) {
  if (!controls.length) return { provider: 'ux.control-states', status: 'unproven', complete: false, applicability: {}, findings: [], coverageGaps: ['zero-control-denominator'] };
  const applicability = {};
  const findings = [];
  for (const control of controls) {
    const applicable = [...new Set(control.applicableStates ?? ['default'])];
    const observed = new Set(control.observedStates ?? []);
    const missingStates = applicable.filter((state) => !observed.has(state));
    applicability[control.id] = applicable;
    if (missingStates.length) findings.push({ ruleId: 'ux.control-state-missing', controlId: control.id, role: control.role, accessibleName: control.accessibleName ?? null, missingStates, links: ['accessibility', 'visual', 'copy', 'runtime'] });
    if (control.disabledInteractive) findings.push({ ruleId: 'ux.control-disabled-interactive', controlId: control.id, role: control.role, accessibleName: control.accessibleName ?? null });
    if (control.doubleSubmitRisk) findings.push({ ruleId: 'ux.control-double-submit', controlId: control.id, role: control.role, accessibleName: control.accessibleName ?? null });
  }
  return { provider: 'ux.control-states', status: findings.length ? 'candidates' : 'pass', complete: findings.every((item) => item.ruleId !== 'ux.control-state-missing'), applicability, findings };
}
