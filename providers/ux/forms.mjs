export function analyzeForms({ forms = [] } = {}) {
  const fields = forms.flatMap((form) => (form.fields ?? []).map((field) => ({ form, field })));
  if (!fields.length) return { provider: 'ux.forms', status: 'unproven', fieldDenominator: 0, findings: [], coverageGaps: ['zero-field-denominator'], serverSecurityProven: false, sensitiveFieldAssumptions: [] };
  const findings = [];
  for (const { form, field } of fields) {
    if (!field.label) findings.push({ ruleId: 'ux.forms-label-missing', formId: form.id, fieldId: field.id });
    const missingStates = (field.applicableStates ?? []).filter((state) => !(field.observedStates ?? []).includes(state));
    if (missingStates.length) findings.push({ ruleId: 'ux.forms-state-missing', formId: form.id, fieldId: field.id, missingStates });
    if (field.losesInput) findings.push({ ruleId: 'ux.forms-input-loss', formId: form.id, fieldId: field.id });
    for (const [flag, ruleId] of Object.entries({ prematureValidation: 'ux.forms-premature-validation', hiddenRequirement: 'ux.forms-hidden-requirement', inaccessibleError: 'ux.forms-error-association', ambiguousSelect: 'ux.forms-select-ambiguous' })) if (field[flag]) findings.push({ ruleId, formId: form.id, fieldId: field.id });
  }
  for (const form of forms) for (const [flag, ruleId] of Object.entries({ destructiveReset: 'ux.forms-destructive-reset', doubleSubmit: 'ux.forms-double-submit', unrecoverableStep: 'ux.forms-multistep-unrecoverable' })) if (form[flag]) findings.push({ ruleId, formId: form.id, fieldId: null });
  return { provider: 'ux.forms', status: findings.length ? 'candidates' : 'pass', fieldDenominator: fields.length, findings,
    serverSecurityProven: forms.some((form) => form.serverValidationEvidence) && forms.every((form) => !form.clientValidation || form.serverValidationEvidence),
    sensitiveFieldAssumptions: forms.flatMap((form) => form.sensitiveFieldAssumptions ?? []) };
}
