// Canonical CLI exit taxonomy. Completion, policy, incompleteness, internal
// failure, usage, and integrity are distinct — an incomplete run must never
// return 0 even when it found zero issues.

export const EXIT = Object.freeze({
  PASS: 0,
  POLICY_FAIL: 1,
  INCOMPLETE: 2,
  INTERNAL_ERROR: 3,
  USAGE: 4,
  INTEGRITY: 5,
});

export class NemesisError extends Error {
  constructor(message, { code = 'NEMESIS_ERROR', exitCode = EXIT.INTERNAL_ERROR, cause } = {}) {
    super(message, { cause });
    this.name = 'NemesisError';
    this.code = code;
    this.exitCode = exitCode;
  }
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
