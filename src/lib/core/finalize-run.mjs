// Finalization applies the exit taxonomy only after the final audit status is
// known. quality_gate stays separate from audit_status and from process
// execution status.

import { EXIT } from '../errors.mjs';

export async function finalizeRun({ plan, facts, results, policy }, host) {
  const { finalizeAudit } = await import('../../../tools/audit/audit-finalize.mjs');
  const report = finalizeAudit({
    facts: { ...facts, plan },
    candidates: { candidates: results?.securityCandidates ?? [] },
    adjudication: results?.adjudication ?? { complete: true, verdicts: [] },
  });
  report.generated_at = host.clock.now().toISOString();
  report.exit_code = exitCodeForReport(report);
  return report;
}

export function exitCodeForReport(report) {
  if (report?.integrity?.valid === false || report?.gates?.plan_binding === 'fail') {
    return EXIT.INTEGRITY;
  }
  if (report?.incomplete || report?.audit_status === 'incomplete') return EXIT.INCOMPLETE;
  if (report?.audit_status === 'fail' || report?.quality_gate === 'fail') return EXIT.POLICY_FAIL;
  if (report?.audit_status === 'pass') return EXIT.PASS;
  return EXIT.INTERNAL_ERROR;
}
