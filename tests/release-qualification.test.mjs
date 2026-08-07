import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { renderMarkdownReport } from '../lib/report/markdown/index.mjs';
import { runQualification } from '../scripts/qualify-release.mjs';

test('markdown is a deterministic escaped report projection', () => {
  const markdown = renderMarkdownReport({ findings: [{ id: 'b', title: '<script>', file: 'b|c' }, { id: 'a' }], coverage_gaps: [{ kind: 'missing' }] });
  assert.ok(markdown.indexOf('| a ') < markdown.indexOf('| b '));
  assert.match(markdown, /&lt;script&gt;/);
  assert.match(markdown, /b\\\|c/);
});

test('release qualification reads evidence from supplied base', () => {
  const base = mkdtempSync(join(tmpdir(), 'nemesis-qualification-'));
  const outDir = join(base, 'out');
  try {
    writeFileSync(join(base, 'release-manifest.json'), '{}');
    const { bundle } = runQualification({ base, outDir, sourceCommit: 'revision' });
    assert.equal(bundle.evidence.find((entry) => entry.id === 'release-manifest').present, true);
    assert.equal(bundle.decision, 'BLOCKED');
  } finally { rmSync(base, { recursive: true, force: true }); }
});
