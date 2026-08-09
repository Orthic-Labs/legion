import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

test('B8-007 HTML report: real CSP hash, evidence navigation, no external resources', async () => {
  const { renderHtmlReport } = await import('../lib/report/html/index.mjs');
  const html = renderHtmlReport({
    audit_status: 'fail',
    quality_gate: 'fail',
    findings: [
      { id: 'finding-1', ruleId: 'xss', severity: 'high', title: '<img src=x onerror=alert(1)>', file: 'src/a.js', evidence: [{ id: 'evidence-1', detail: 'proof' }] },
      { id: 'finding-2', ruleId: 'sql', severity: 'medium', title: 'Query built by concatenation', file: 'src/db.js', evidence: [{ id: 'evidence-2' }, { id: 'evidence-1' }] },
    ],
    familyCoverage: [{ id: 'security', status: 'partial', evidenceIds: ['evidence-1'] }],
    coverage_gaps: [{ id: 'gap-1', kind: 'runtime', detail: 'device absent' }],
    flows: [{ id: 'flow-1', evidenceIds: ['evidence-1'], title: 'login' }],
  });
  assert.doesNotMatch(html, /PLACEHOLDER|<img src=x/);
  assert.match(html, /Content-Security-Policy/);
  const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
  const hash = createHash('sha256').update(script).digest('base64');
  assert.match(html, new RegExp(`script-src 'sha256-${hash.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}'`));
  // Canonical evidence anchors and finding rows navigate to them.
  assert.match(html, /id="evidence-evidence-1"/);
  assert.match(html, /id="evidence-evidence-2"/);
  assert.match(html, /href="#evidence-evidence-1"/);
  assert.match(html, /href="#evidence-evidence-2"/);
  // Untrusted content stays escaped; no external resources anywhere.
  assert.ok(!html.includes('<img src=x'));
  assert.ok(html.includes('&lt;img src=x'));
  assert.doesNotMatch(html, /https?:\/\//);
  assert.match(html, /type="search"/);
  assert.match(html, /data-kind="flow-diagrams"/);
  // Family coverage links resolve to the same evidence anchors.
  assert.match(html, /security: partial <a href="#evidence-evidence-1">evidence-1<\/a>/);
});

test('B8-008 editor diagnostics: canonical ranges, lineage, gaps, preview binding', async () => {
  const { editorDiagnostics } = await import('../lib/report/editor/index.mjs');
  const diagnostics = editorDiagnostics({
    report: {
      findings: [
        {
          id: 'finding-1',
          fingerprint: 'sha256:f',
          family: 'security',
          evidenceClass: 'static',
          severity: 'high',
          title: 'Unsafe call',
          file: 'src/a.js',
          range: { start: { line: 4, column: 2 }, end: { line: 4, column: 9 } },
          lineage: { state: 'moved', priorRange: { start: { line: 2, column: 1 }, end: { line: 2, column: 8 } } },
          remediation: {
            id: 'proposal-1',
            qualified: true,
            findingFingerprint: 'sha256:f',
            findingIds: ['finding-1'],
            patch: { path: 'patches/p.patch', digest: `sha256:${'a'.repeat(64)}` },
          },
        },
        { id: 'finding-2', ruleId: 'r2', severity: 'medium', file: 'b.ts', line: 9, endLine: 12 },
      ],
      coverage_gaps: [{ id: 'gap-1', family: 'runtime', reviewRequired: true, detail: 'device absent' }],
    },
    runDir: 'run',
  });
  assert.equal(diagnostics.length, 3);
  const [primary, legacy, gap] = diagnostics;
  // Canonical range is preserved verbatim, not recomputed.
  assert.deepEqual(primary.range, { start: { line: 4, column: 2 }, end: { line: 4, column: 9 } });
  assert.equal(primary.line, 4);
  assert.equal(primary.column, 2);
  assert.equal(primary.fingerprint, 'sha256:f');
  assert.equal(primary.family, 'security');
  assert.equal(primary.evidenceClass, 'static');
  assert.deepEqual(primary.lineage, { state: 'moved', priorRange: { start: { line: 2, column: 1 }, end: { line: 2, column: 8 } } });
  assert.equal(primary.codeActions[0].kind, 'preview');
  assert.equal(primary.codeActions[0].previewOnly, true);
  assert.equal(primary.codeActions[0].proposalId, 'proposal-1');
  assert.equal(primary.codeActions[0].findingId, 'finding-1');
  assert.equal(primary.codeActions[0].patch.digest, `sha256:${'a'.repeat(64)}`);
  // Legacy single-position findings map onto a canonical range.
  assert.deepEqual(legacy.range, { start: { line: 9, column: 0 }, end: { line: 12, column: 0 } });
  assert.equal(gap.coverageIncomplete, true);
  assert.equal(gap.code, 'legion.coverage-gap');
  assert.equal(gap.lineage.state, 'current');
  // Unqualified or unbound remediation never surfaces a preview action.
  const unbound = editorDiagnostics({ report: { findings: [{ id: 'f', ruleId: 'r', remediation: { id: 'p', qualified: true, findingIds: ['other'], patch: { digest: 'sha256:p' } } }] } });
  assert.equal(unbound[0].codeActions.some(({ kind }) => kind === 'preview'), false);
  const unqualified = editorDiagnostics({ report: { findings: [{ id: 'f', ruleId: 'r', remediation: { id: 'p', qualified: false, findingIds: ['f'], patch: { digest: `sha256:${'b'.repeat(64)}` } } }] } });
  assert.equal(unqualified[0].codeActions.some(({ kind }) => kind === 'preview'), false);
  // Coverage gaps not marked review-required are omitted.
  const skipped = editorDiagnostics({ report: { findings: [], coverage_gaps: [{ id: 'g', reviewRequired: false }] } });
  assert.equal(skipped.length, 0);
});
