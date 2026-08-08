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
export class UsageError extends NemesisError { constructor(message,options={}){super(message,{...options,code:'USAGE',exitCode:EXIT.USAGE});this.name='UsageError';} }
export class IntegrityError extends NemesisError { constructor(message,options={}){super(message,{...options,code:'INTEGRITY',exitCode:EXIT.INTEGRITY});this.name='IntegrityError';} }
export class IncompleteError extends NemesisError { constructor(message,options={}){super(message,{...options,code:'INCOMPLETE',exitCode:EXIT.INCOMPLETE});this.name='IncompleteError';} }
export class PolicyError extends NemesisError { constructor(message,options={}){super(message,{...options,code:'POLICY_FAIL',exitCode:EXIT.POLICY_FAIL});this.name='PolicyError';} }

export function exitCodeForReport(report) {
  if (report?.integrity?.valid === false || report?.gates?.plan_binding === 'fail') {
    return EXIT.INTEGRITY;
  }
  if (report?.incomplete || report?.audit_status === 'incomplete') return EXIT.INCOMPLETE;
  if (report?.audit_status === 'fail' || report?.quality_gate === 'fail') return EXIT.POLICY_FAIL;
  if (report?.audit_status === 'pass') return EXIT.PASS;
  return EXIT.INTERNAL_ERROR;
}
