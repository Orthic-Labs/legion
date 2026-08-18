import assert from 'node:assert/strict';
import test from 'node:test';
import { cspMeta, escapeHtml, renderHtmlReport } from '../../src/lib/report/html/index.mjs';

test('escapeHtml escapes all dangerous characters', () => {
  assert.equal(escapeHtml('<script>alert("x")&\'y\'</script>'), '&lt;script&gt;alert(&quot;x&quot;)&amp;&#39;y&#39;&lt;/script&gt;');
  assert.equal(escapeHtml('plain'), 'plain');
});

test('CSP meta uses restrictive policy with generated script hash', () => {
  const meta = cspMeta('abc123');
  assert.match(meta, /default-src 'none'/);
  assert.match(meta, /script-src 'sha256-abc123'/);
  assert.match(meta, /img-src data:/);
});

test('renderHtmlReport produces a self-contained document', () => {
  const html = renderHtmlReport({
    audit_status: 'fail',
    quality_gate: 'blocked',
    findings: [
      { id: 'f1', ruleId: 'r1', severity: 'high', title: '<img onerror=x>', file: 'a.ts' },
    ],
    coverage_gaps: [{ kind: 'provider-incomplete', detail: { provider: 'x' } }],
  });
  assert.match(html, /<!DOCTYPE html>/);
  assert.match(html, /Content-Security-Policy/);
  // Untrusted content is escaped.
  assert.ok(!html.includes('<img onerror=x>'));
  assert.ok(html.includes('&lt;img onerror=x&gt;'));
  // No external resources.
  assert.ok(!html.includes('http://'));
  assert.ok(!html.includes('https://'));
  // Coverage gaps are visible.
  assert.ok(html.includes('provider-incomplete'));
});

test('renderHtmlReport handles empty reports', () => {
  const html = renderHtmlReport({ audit_status: 'pass', findings: [], coverage_gaps: [] });
  assert.match(html, /No findings/);
  assert.match(html, /None/);
});
