import assert from 'node:assert/strict';
import test from 'node:test';
import {
  capabilityReceipt,
  commandContract,
  normalizeMatch,
  normalizeStream,
  rewritePreview,
  stableFingerprint,
} from '../../../providers/ast-grep/index.mjs';

test('normalizeMatch produces a stable structural match', () => {
  const match = normalizeMatch(
    { file: 'src/a.ts', line: 3, column: 5, endLine: 3, endColumn: 20, message: 'raw html', severity: 'error', structuralDigest: 'sha256:d' },
    { ruleId: 'no-inner-html', severity: 'error' },
  );
  assert.equal(match.ruleId, 'no-inner-html');
  assert.equal(match.severity, 'error');
  assert.equal(match.file, 'src/a.ts');
  assert.equal(match.range.start.line, 3);
  assert.equal(match.range.start.column, 5);
  assert.ok(match.fingerprint.startsWith('sha256:'));
});

test('stable fingerprint is deterministic and range-bound per contract', () => {
  const base = { ruleId: 'r', file: 'a.ts', range: { start: { line: 3, column: 0 }, end: { line: 3, column: 10 } }, structuralDigest: 'sha256:s' };
  // The fingerprint contract includes ruleId/file/range/structuralDigest, so
  // identical input yields identical fingerprints (deterministic)...
  assert.equal(stableFingerprint(base), stableFingerprint({ ...base }));
  // ...and a different location is a different match identity.
  const moved = { ...base, range: { start: { line: 40, column: 0 }, end: { line: 40, column: 10 } } };
  assert.notEqual(stableFingerprint(base), stableFingerprint(moved));
});

test('normalizeStream filters lines without files', () => {
  const matches = normalizeStream(
    [{ file: 'a.ts', line: 1 }, { message: 'no file' }],
    { ruleId: 'r' },
  );
  assert.equal(matches.length, 1);
  assert.equal(matches[0].file, 'a.ts');
});

test('commandContract uses the pinned executable and frozen paths', () => {
  const contract = commandContract({
    resolvedAstGrep: '/opt/ast-grep/sg', packPath: '/packs/core.yml', frozenPaths: ['src/'],
    repositoryRoot: '/repo', policy: { providerTimeoutMs: 60000, maxOutputBytes: 1024 },
  });
  assert.equal(contract.executable, '/opt/ast-grep/sg');
  assert.deepEqual(contract.args.slice(0, 4), ['scan', '--config', '/packs/core.yml', '--json=stream']);
  assert.equal(contract.cwd, '/repo');
  assert.equal(contract.timeoutMs, 60000);
  assert.ok(contract.environmentKeys.includes('PATH'));
});

test('rewritePreview is preview-only and never applied', () => {
  const preview = rewritePreview({ ruleId: 'no-inner-html', file: 'src/a.ts', edits: [{ startLine: 3, endLine: 3, replacement: 'safeRender($VALUE)' }] });
  assert.equal(preview.kind, 'nemesis-ast-grep-rewrite-preview');
  assert.equal(preview.applied, false);
  assert.ok(preview.edits[0].digest.startsWith('sha256:'));
});

test('capabilityReceipt records version and languages', () => {
  const receipt = capabilityReceipt({ executable: 'sg', version: '0.30.0', languages: ['ts', 'js', 'ts'] });
  assert.equal(receipt.version, '0.30.0');
  assert.deepEqual(receipt.languages, ['js', 'ts']);
});

test('rewrite preview is idempotent by digest', () => {
  const a = rewritePreview({ ruleId: 'r', file: 'f.ts', edits: [{ startLine: 1, endLine: 1, replacement: 'x' }] });
  const b = rewritePreview({ ruleId: 'r', file: 'f.ts', edits: [{ startLine: 1, endLine: 1, replacement: 'x' }] });
  assert.deepEqual(a, b);
});
