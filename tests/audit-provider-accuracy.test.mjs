import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { gitleaksCandidates } from '../tools/audit/collect-facts.mjs';
import { runAccessibilitySuite } from '../src/providers/accessibility-suite.mjs';

function fixture(files) {
  const root = mkdtempSync(join(tmpdir(), 'audit-accuracy-'));
  for (const [path, content] of Object.entries(files)) {
    const abs = join(root, path);
    mkdirSync(abs.slice(0, abs.lastIndexOf('/')), { recursive: true });
    writeFileSync(abs, content);
  }
  return root;
}

// ---- T3a: gitleaks JSON -> secret-free redacted candidate records ----

test('gitleaksCandidates keeps digest, rule, file, line and drops every secret value', () => {
  const raw = JSON.stringify([
    {
      RuleID: 'aws-access-key-id', Description: 'AWS Access Key',
      StartLine: 42, EndLine: 42, StartColumn: 5, EndColumn: 30,
      Match: 'AKIAIOSFODNN7EXAMPLE', Secret: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCY',
      File: 'src/config.ts', SymlinkFile: '', Commit: 'abc123', Entropy: 3.5,
      Author: 'dev', Email: 'dev@example.com', Date: '2026-01-01', Message: 'add config',
      Tags: [], Fingerprint: 'abc123:src/config.ts:aws-access-key-id:42',
    },
  ]);
  const candidates = gitleaksCandidates(raw);
  assert.equal(candidates.length, 1);
  const c = candidates[0];
  assert.equal(c.digest, 'abc123:src/config.ts:aws-access-key-id:42');
  assert.equal(c.rule, 'aws-access-key-id');
  assert.equal(c.file, 'src/config.ts');
  assert.equal(c.line, 42);
  // No field of any record may carry secret or match material.
  const serialized = JSON.stringify(candidates);
  assert.ok(!serialized.includes('wJalrXUtnFEMI'));
  assert.ok(!serialized.includes('AKIAIOSFODNN7EXAMPLE'));
  assert.ok(!serialized.toLowerCase().includes('secret') && !serialized.toLowerCase().includes('"match"'));
  assert.ok(!('Secret' in c) && !('Match' in c));
});

test('gitleaksCandidates derives a stable sha256 digest when Fingerprint is absent', () => {
  const candidates = gitleaksCandidates(JSON.stringify([
    { RuleID: 'github-pat', File: '.env.local', StartLine: 7 },
    { RuleID: 'github-pat', File: '.env.local', StartLine: 7 },
  ]));
  assert.match(candidates[0].digest, /^sha256:[0-9a-f]{64}$/);
  // Same rule/file/line => identical digest (stable adjudication key); no Fingerprint needed.
  assert.equal(candidates[0].digest, candidates[1].digest);
});

test('gitleaksCandidates throws on unparseable reports so callers never fake a clean scan', () => {
  assert.throws(() => gitleaksCandidates('<html>gateway timeout</html>'), /not valid JSON/);
  assert.throws(() => gitleaksCandidates(JSON.stringify({ error: 'nope' })), /not a JSON array/);
});

// ---- T3b: contextual focus-outline check ----

test('outline removal with NO replacement anywhere still produces a11y.focus-outline-removed', () => {
  const root = fixture({ 'src/app.css': '.card { outline: none; }' });
  try {
    const result = runAccessibilitySuite({ root, files: ['src/app.css'] });
    assert.ok(result.findings.some((f) => f.ruleId === 'a11y.focus-outline-removed'));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('outline:none reset inside a :focus block that also paints box-shadow is suppressed', () => {
  const root = fixture({
    'src/app.css': '.btn:focus { outline: none; box-shadow: 0 0 0 3px #4a90d9; }',
  });
  try {
    const result = runAccessibilitySuite({ root, files: ['src/app.css'] });
    assert.deepEqual(result.findings.filter((f) => f.ruleId === 'a11y.focus-outline-removed'), []);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('global :focus-visible restore suppresses outline resets elsewhere in the same stylesheet', () => {
  const root = fixture({
    'src/theme.css': '*:focus-visible { outline: 2px solid rebeccapurple; }\n.x { outline: none; }',
  });
  try {
    const result = runAccessibilitySuite({ root, files: ['src/theme.css'] });
    assert.deepEqual(result.findings.filter((f) => f.ruleId === 'a11y.focus-outline-removed'), []);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('Tailwind outline-none paired with a visible focus utility on the same element is suppressed', () => {
  const root = fixture({
    'src/App.tsx': '<button className="rounded outline-none focus-visible:ring-2 focus-visible:ring-blue-500">Hi</button>',
  });
  try {
    const result = runAccessibilitySuite({ root, files: ['src/App.tsx'] });
    assert.deepEqual(result.findings.filter((f) => f.ruleId === 'a11y.focus-outline-removed'), []);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('outline-none alone on an element (focus:outline-none style reset only) is still flagged', () => {
  const root = fixture({
    'src/Bare.tsx': '<button className="outline-none">Hi</button>',
  });
  try {
    const result = runAccessibilitySuite({ root, files: ['src/Bare.tsx'] });
    assert.ok(result.findings.some((f) => f.ruleId === 'a11y.focus-outline-removed'));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

// ---- T3b: Remotion / non-DOM media exclusion ----

test('files under a remotion path are excluded from all DOM-focus findings', () => {
  const root = fixture({
    'video/remotion/TitleCard.tsx': '<img src="x.png"/><div style={{ outline: "none" }}/>',
  });
  try {
    const result = runAccessibilitySuite({ root, files: ['video/remotion/TitleCard.tsx'] });
    assert.equal(result.applicable, false);
    assert.equal(result.coverage.scannedFiles, 0);
    assert.deepEqual(result.findings, []);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('files importing remotion are excluded even outside remotion-named paths', () => {
  const root = fixture({
    'src/clips/Card.tsx': "import { Video } from 'remotion';\n<img src=\"x.png\"/>",
  });
  try {
    const result = runAccessibilitySuite({ root, files: ['src/clips/Card.tsx'] });
    assert.equal(result.coverage.scannedFiles, 0);
    assert.deepEqual(result.findings, []);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('regular DOM components next to media code keep full coverage', () => {
  const root = fixture({
    'src/remotion-helper.ts': "export const fps = 30;", // path mentions remotion but is not scanned as source anyway
    'src/Dom.tsx': '<div onClick={open}><img src="x.png"/></div>',
  });
  try {
    const result = runAccessibilitySuite({ root, files: ['src/Dom.tsx'] });
    const ids = new Set(result.findings.map((f) => f.ruleId));
    assert.ok(ids.has('a11y.image-alt'));
    assert.ok(ids.has('a11y.pointer-only-handler'));
    assert.equal(result.complete, true);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
