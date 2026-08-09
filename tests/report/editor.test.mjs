import assert from 'node:assert/strict';
import test from 'node:test';
import { editorDiagnostics } from '../../lib/report/editor/index.mjs';

test('editor diagnostics map findings to stable diagnostics', () => {
  const diagnostics = editorDiagnostics({
    runDir: '/run',
    report: {
      findings: [
        { id: 'f1', ruleId: 'r1', severity: 'critical', title: 'Credential', file: 'a.ts', line: 3 },
        { id: 'f2', ruleId: 'r2', severity: 'medium', title: 'Warning', file: 'b.ts', line: 9 },
      ],
    },
  });
  assert.equal(diagnostics.length, 2);
  assert.equal(diagnostics[0].kind, 'legion-editor-diagnostic');
  assert.equal(diagnostics[0].severity, 1);
  assert.equal(diagnostics[1].severity, 2);
  assert.equal(diagnostics[0].file, 'a.ts');
  assert.ok(diagnostics[0].codeActions.some((action) => action.kind === 'explain'));
});

test('diagnostics carry stable fingerprints, never line-bound identity', () => {
  const a = editorDiagnostics({ report: { findings: [{ id: 'f1', ruleId: 'r', file: 'a.ts', line: 3, fingerprint: 'sha256:fp' }] } });
  const b = editorDiagnostics({ report: { findings: [{ id: 'f1', ruleId: 'r', file: 'a.ts', line: 99, fingerprint: 'sha256:fp' }] } });
  assert.equal(a[0].fingerprint, b[0].fingerprint);
  assert.notEqual(a[0].line, b[0].line);
});

test('diagnostics never create a second rule engine', () => {
  // The diagnostic code is the finding's canonical rule ID.
  const diagnostics = editorDiagnostics({ report: { findings: [{ id: 'f1', ruleId: 'credentials.format', file: 'a.ts', line: 1 }] } });
  assert.equal(diagnostics[0].code, 'credentials.format');
});
