import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { PRE_COMMIT_HOOK, PRE_PUSH_HOOK, hookInstalled, installHook, uninstallHook } from '../../src/integrations/hooks/index.mjs';
import { actionSummary, sarifUploadCommand } from '../../src/integrations/github-action/index.mjs';
import { changedFiles, classifyFinding, prScopeResult, stableCommentId } from '../../src/lib/pr/scope.mjs';

test('pre-commit hook uses the fast profile with uncommitted scope', () => {
  assert.match(PRE_COMMIT_HOOK, /--profile fast/);
  assert.match(PRE_COMMIT_HOOK, /--type uncommitted/);
  assert.match(PRE_COMMIT_HOOK, /exec legion audit/);
  assert.doesNotMatch(PRE_COMMIT_HOOK, /\bnpx\b|\bnode\b|\bpython\b/);
});

test('pre-push hook uses the standard profile with local scope', () => {
  assert.match(PRE_PUSH_HOOK, /--profile standard/);
  assert.match(PRE_PUSH_HOOK, /--type local/);
});

test('hook install and uninstall are idempotent', () => {
  const dir = mkdtempSync(join(tmpdir(), 'legion-hooks-'));
  try {
    installHook({ root: dir, type: 'pre-commit' });
    assert.equal(hookInstalled({ root: dir, type: 'pre-commit' }), true);
    assert.equal(hookInstalled({ root: dir, type: 'pre-push' }), false);
    const removed = uninstallHook({ root: dir, type: 'pre-commit' });
    assert.equal(removed.removed, true);
    assert.equal(hookInstalled({ root: dir, type: 'pre-commit' }), false);
    // Uninstall again is a no-op, not an error.
    assert.equal(uninstallHook({ root: dir, type: 'pre-commit' }).removed, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('action.yml is composite and installs the package', () => {
  const action = readFileSync(new URL('../../action.yml', import.meta.url), 'utf8');
  assert.match(action, /using: composite/);
  // The action installs through pinned corepack pnpm and must never install
  // anything globally.
  assert.match(action, /corepack pnpm@[\d.]+ install/);
  assert.doesNotMatch(action, /install --global|npm install -g/);
  // The action runs the audit runner directly; there is no `legion audit`
  // shell invocation in the composite steps.
  assert.match(action, /tools\/audit\/audit-run\.mjs/);
});

test('changed-scope classifies introduced vs existing findings', () => {
  const changed = ['src/new.ts'];
  assert.equal(classifyFinding({ finding: { file: 'src/new.ts' }, changedPaths: changed }), 'introduced');
  assert.equal(classifyFinding({ finding: { file: 'src/old.ts' }, changedPaths: changed }), 'existing');
  // A file under a changed directory path is introduced.
  assert.equal(classifyFinding({ finding: { file: 'src/new.ts/helper.ts' }, changedPaths: ['src/new.ts/'] }), 'introduced');
  // The changed-files envelope is structured.
  const scope = changedFiles({ mergeBase: 'base', committed: ['a.ts'], uncommitted: ['b.ts'], untracked: ['c.ts'] });
  assert.deepEqual(scope.committed, ['a.ts']);
});

test('pr scope result preserves full-repository coverage truth', () => {
  const result = prScopeResult({
    findings: [
      { id: 'f1', file: 'src/new.ts', fingerprint: 'sha256:a' },
      { id: 'f2', file: 'src/old.ts', fingerprint: 'sha256:b' },
    ],
    changedPaths: ['src/new.ts'],
    fullCoverage: { incomplete: true, gaps: ['provider-incomplete'] },
  });
  assert.equal(result.introduced.length, 1);
  assert.equal(result.existing.length, 1);
  assert.equal(result.fullCoverage.incomplete, true);
});

test('stable comment ids are fingerprint-bound', () => {
  const a = stableCommentId({ fingerprint: 'sha256:f' });
  const b = stableCommentId({ fingerprint: 'sha256:f' });
  assert.equal(a, b);
  const c = stableCommentId({ fingerprint: 'sha256:g' });
  assert.notEqual(a, c);
});

test('action summary is deduped by fingerprint', () => {
  const summary = actionSummary({
    report: { audit_status: 'fail', quality_gate: 'blocked', coverage_gaps: [] },
    scoped: { introduced: [{ fingerprint: 'sha256:f' }], existing: [] },
    runDir: '/run',
  });
  assert.equal(summary.introducedCount, 1);
  assert.deepEqual(summary.commentIds, ['sha256:f']);
});

test('sarif upload uses the canonical CLI artifact', () => {
  const command = sarifUploadCommand({ sarifPath: '/run/report.sarif', githubToken: 'token' });
  assert.equal(command.executable, 'gh');
  assert.ok(command.args.some((arg) => arg.includes('report.sarif')));
});
