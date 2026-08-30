import assert from 'node:assert/strict';
import test from 'node:test';

import { verifyCommandResult } from '../src/lib/cli/commands/governance/execution/command-verifier.mjs';

test('command verification requires zero exit code & expected structured output', () => {
  const result = verifyCommandResult({ exitCode: 0, structuredOutput: { verdict: { status: 'PASS' }, artifact: { id: 'receipt-1' } } }, { expectedOutput: { verdict: { status: 'PASS' } } });
  assert.equal(result.allowed, true);
  assert.equal(result.detail.structuredOutput.artifact.id, 'receipt-1');
});

test('success marker text cannot override a nonzero command exit', () => {
  const result = verifyCommandResult({ exitCode: 1, structuredOutput: { verdict: { status: 'PASS' }, stdout: 'PASS' } }, { expectedOutput: { verdict: { status: 'PASS' } } });
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'ARC_EVIDENCE_INSUFFICIENT');
});

test('missing or mismatched structured output is rejected without prose matching', () => {
  assert.equal(verifyCommandResult({ exitCode: 0, structuredOutput: 'PASS' }, { expectedOutput: { verdict: { status: 'PASS' } } }).allowed, false);
  assert.equal(verifyCommandResult({ exitCode: 0, structuredOutput: { verdict: { status: 'FAIL' } } }, { expectedOutput: { verdict: { status: 'PASS' } } }).allowed, false);
});
