import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { runAccessibilitySuite } from '../providers/accessibility-suite.mjs';

function fixture(files) {
  const root = mkdtempSync(join(tmpdir(), 'audit-a11y-'));
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(join(root, path, '..'), { recursive: true });
    writeFileSync(join(root, path), content);
  }
  return root;
}

test('accessibility provider detects deterministic source violations', () => {
  const root = fixture({
    'src/App.tsx': '<div onClick={open}><img src="x.png"/><button></button></div>',
    'src/app.css': 'button:focus { outline: none; } .spin { animation: spin 1s infinite; }',
  });
  try {
    const result = runAccessibilitySuite({ root, files: ['src/App.tsx', 'src/app.css'] });
    const ids = new Set(result.findings.map((finding) => finding.ruleId));
    assert.ok(ids.has('a11y.image-alt'));
    assert.ok(ids.has('a11y.empty-button-name'));
    assert.ok(ids.has('a11y.pointer-only-handler'));
    assert.ok(ids.has('a11y.focus-outline-removed'));
    assert.ok(ids.has('a11y.reduced-motion'));
    assert.equal(result.complete, true);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('accessible source fixture remains clean', () => {
  const root = fixture({
    'src/App.tsx': '<button aria-label="Open settings" onClick={open}><img alt="" src="icon.png"/></button>',
    'src/app.css': '@media (prefers-reduced-motion: reduce) { * { animation: none; } }',
  });
  try {
    const result = runAccessibilitySuite({ root, files: ['src/App.tsx', 'src/app.css'] });
    assert.equal(result.status, 'pass');
    assert.deepEqual(result.findings, []);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
