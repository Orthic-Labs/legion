export function analyzeRecovery({ actions = [] } = {}) {
  const normalized = actions.map((action) => ({ ...action, irreversible: action.sideEffectEvidence ? Boolean(action.claimedIrreversible) : 'unproven' }));
  const findings = [];
  const coverageGaps = actions.length ? [] : ['action-denominator-missing'];
  for (const action of normalized) {
    if (action.risk === 'high' && action.confirmation !== true) findings.push({ ruleId: 'ux.recovery-confirmation-missing', actionId: action.id, actionRisk: action.risk, recoveryEvidence: action.undoEvidence ?? action.recoveryPath ?? 'missing' });
    if (action.progress && !action.terminalEvidence) findings.push({ ruleId: 'ux.recovery-terminal-state-missing', actionId: action.id, actionRisk: action.risk, recoveryEvidence: action.recoveryPath ?? 'missing' });
    if (action.policyRequiresUndo && !action.undoEvidence) findings.push({ ruleId: 'ux.recovery-undo-missing', actionId: action.id, actionRisk: action.risk, recoveryEvidence: 'missing' });
    if (action.feedbackAssistive === false) findings.push({ ruleId: 'ux.recovery-feedback-inaccessible', actionId: action.id, actionRisk: action.risk, recoveryEvidence: action.recoveryPath ?? 'missing' });
    if (action.errorLosesWork) findings.push({ ruleId: 'ux.recovery-work-loss', actionId: action.id, actionRisk: action.risk, recoveryEvidence: action.recoveryPath ?? 'missing' });
  }
  return { provider: 'ux.recovery', status: findings.length ? 'candidates' : normalized.some((item) => item.irreversible === 'unproven') || coverageGaps.length ? 'unproven' : 'pass', actions: normalized, findings, coverageGaps };
}
