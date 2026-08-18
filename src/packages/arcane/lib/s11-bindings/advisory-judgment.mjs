const ADVISORY_IDS = Object.freeze([
  'AE-ADR-ADMISSION-001', 'AE-ADR-ADMISSION-002',
  'AE-ADVERSARIAL-001', 'AE-ADVERSARIAL-002', 'AE-ADVERSARIAL-003',
  'AE-ADVERSARIAL-004', 'AE-ADVERSARIAL-005', 'AE-ADVERSARIAL-006',
  'AE-ADVERSARIAL-007', 'AE-ADVERSARIAL-009', 'AE-ADVERSARIAL-010',
  'AE-CANDIDATE-QUALITY-001', 'AE-CANDIDATE-QUALITY-002',
  'AE-CANDIDATE-QUALITY-004', 'AE-CANDIDATE-QUALITY-005',
  'AE-CANDIDATE-QUALITY-006', 'AE-CANON-DRIFT-001', 'AE-CANON-DRIFT-002',
  'AE-CLARIFICATION-CONVERGENCE-001', 'AE-CLARIFICATION-CONVERGENCE-002',
  'AE-CONCURRENCY-ATTENTION-002', 'AE-CONCURRENCY-ATTENTION-006',
  'AE-CONTROL-PLANE-BUDGETS-002', 'AE-CONVERGENCE-001',
  'AE-CONVERGENCE-003', 'AE-HANDOFF-002', 'AE-HANDOFF-004',
  'AE-NEGATIVE-TRIGGERS-001', 'AE-NEGATIVE-TRIGGERS-003',
  'AE-NEGATIVE-TRIGGERS-004', 'AE-REVIEW-ADMISSION-001',
  'AE-REVIEW-VERDICT-SECURITY-002', 'AE-REVIEW-VERDICT-SECURITY-005',
  'AE-REVIEW-VERDICT-SECURITY-006', 'AE-SCOPE-AUTHORITY-001',
]);

function pending(row) {
  return Object.freeze({
    allowed: false,
    code: 'ARC_EVIDENCE_INSUFFICIENT',
    detail: Object.freeze({
      disposition: 'PENDING',
      reason: 'requires pre-existing externally authenticated Sage+Oracle judgments',
      caseId: typeof row?.id === 'string' ? row.id : null,
    }),
  });
}

export const advisoryJudgmentBindings = Object.freeze(
  Object.fromEntries(ADVISORY_IDS.map((id) => [id, pending])),
);

// A pending observation is never valid completion evidence. A future live
// consumer must replace this with authenticated, case-bound record loading.
export function validateAdvisoryJudgmentObservation() { return false; }

export function advisoryJudgmentRuntimeIds() { return ADVISORY_IDS; }
