import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { completionIntegratedState, completionIntegratedStateForRepositories, latestScopedMaterialChange } from '../lib/completion-state.mjs';

function init(cwd) {
  execFileSync('git', ['init', '-q'], { cwd }); execFileSync('git', ['config', 'user.email', 't@example.test'], { cwd }); execFileSync('git', ['config', 'user.name', 't'], { cwd });
}

test('completion state binds scoped tracked and untracked source content', () => {
  const cwd = mkdtempSync(join(tmpdir(), 'arcane-completion-state-'));
  try {
    init(cwd);
    mkdirSync(join(cwd, 'src')); writeFileSync(join(cwd, 'src', 'tracked.mjs'), 'one\n'); execFileSync('git', ['add', '.'], { cwd }); execFileSync('git', ['commit', '-qm', 'seed'], { cwd });
    const baseline = completionIntegratedState(cwd, ['src/**']);
    writeFileSync(join(cwd, 'src', 'new.mjs'), 'untracked\n'); const untracked = completionIntegratedState(cwd, ['src/**']); assert.notEqual(untracked, baseline);
    writeFileSync(join(cwd, 'src', 'tracked.mjs'), 'two\n'); assert.notEqual(completionIntegratedState(cwd, ['src/**']), untracked);
  } finally { rmSync(cwd, { recursive: true, force: true }); }
});

test('completion state binds aggregate repositories, nested dirtiness, and scoped untracked bytes', () => {
  const root = mkdtempSync(join(tmpdir(), 'arcane-completion-aggregate-')); const second = mkdtempSync(join(tmpdir(), 'arcane-completion-second-'));
  try {
    init(root); init(second);
    mkdirSync(join(root, 'src')); writeFileSync(join(root, 'src', 'top.mjs'), 'top\n'); execFileSync('git', ['add', '.'], { cwd: root }); execFileSync('git', ['commit', '-qm', 'seed'], { cwd: root });
    writeFileSync(join(second, 'source.mjs'), 'one\n'); execFileSync('git', ['add', '.'], { cwd: second }); execFileSync('git', ['commit', '-qm', 'seed'], { cwd: second });
    writeFileSync(join(root, 'top-untracked.mjs'), 'one\n'); assert.notEqual(completionIntegratedState(root, ['**/*.mjs']), completionIntegratedState(root, ['src/**']));
    const aggregate = completionIntegratedStateForRepositories([{ cwd: root, scope: ['**/*.mjs'] }, { cwd: second, scope: ['**/*.mjs'] }]);
    assert.equal(aggregate, completionIntegratedStateForRepositories([{ cwd: second, scope: ['**/*.mjs'] }, { cwd: root, scope: ['**/*.mjs'] }]), 'aggregate ordering is stable');
    writeFileSync(join(second, 'source.mjs'), 'two\n'); assert.notEqual(completionIntegratedStateForRepositories([{ cwd: second, scope: ['**/*.mjs'] }, { cwd: root, scope: ['**/*.mjs'] }]), aggregate, 'second delivery repository changes aggregate state');
    writeFileSync(join(second, 'new.mjs'), 'new\n'); assert.notEqual(completionIntegratedStateForRepositories([{ cwd: second, scope: ['**/*.mjs'] }, { cwd: root, scope: ['**/*.mjs'] }]), aggregate, 'independent repository untracked bytes bind aggregate state');
  } finally { rmSync(root, { recursive: true, force: true }); rmSync(second, { recursive: true, force: true }); }
});

test('latest scoped material change canonicalizes absolute targets and denies escapes', () => {
  const cwd = mkdtempSync(join(tmpdir(), 'arcane-completion-receipts-'));
  try {
    init(cwd); mkdirSync(join(cwd, 'src')); writeFileSync(join(cwd, 'src', 'top.mjs'), 'one\n'); execFileSync('git', ['add', '.'], { cwd }); execFileSync('git', ['commit', '-qm', 'seed'], { cwd });
    const receiptStore = { list: () => [
      { kind: 'legion-effect-receipt', observedAt: '2026-01-01T00:00:00.000Z', observed: { target: join(cwd, 'src', 'top.mjs') } },
      { kind: 'legion-effect-receipt', observedAt: '2026-01-02T00:00:00.000Z', observed: { target: join(cwd, '..', 'escape.mjs') } },
    ] };
    assert.equal(latestScopedMaterialChange(receiptStore, 'run', ['**/*.mjs'], cwd), '2026-01-01T00:00:00.000Z');
  } finally { rmSync(cwd, { recursive: true, force: true }); }
});
