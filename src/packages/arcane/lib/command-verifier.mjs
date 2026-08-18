// Structured subprocess verdicts. stdout/stderr are intentionally excluded:
// prose success markers are not verification evidence.
import { decision } from './errors.mjs';

function record(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function readonly(value) { return Object.freeze(value); }

function matchesExpected(actual, expected) {
  if (Object.is(actual, expected)) return true;
  if (!record(actual) || !record(expected)) return false;
  return Object.entries(expected).every(([key, value]) => Object.hasOwn(actual, key) && matchesExpected(actual[key], value));
}

/**
 * Accept a command only when it exited successfully & emitted an expected
 * structured API result. This never inspects stdout, stderr, or marker text.
 */
export function verifyCommandResult({ exitCode, structuredOutput } = {}, { expectedOutput } = {}) {
  if (exitCode !== 0) return readonly(decision({ allowed: false, code: 'ARC_EVIDENCE_INSUFFICIENT', message: 'command exit status is not successful', detail: { exitCode: exitCode ?? null } }));
  if (!record(expectedOutput)) return readonly(decision({ allowed: false, code: 'ARC_SCHEMA_INVALID', message: 'expected command output must be structured', detail: {} }));
  if (!record(structuredOutput)) return readonly(decision({ allowed: false, code: 'ARC_EVIDENCE_INSUFFICIENT', message: 'command did not emit structured output', detail: {} }));
  if (!matchesExpected(structuredOutput, expectedOutput)) return readonly(decision({ allowed: false, code: 'ARC_EVIDENCE_INSUFFICIENT', message: 'command structured output does not satisfy expectation', detail: {} }));
  return readonly(decision({ allowed: true, detail: { exitCode, structuredOutput } }));
}
