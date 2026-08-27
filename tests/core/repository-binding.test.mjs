import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { bindRepository } from '../../src/lib/core/repository-binding.mjs';

function git(root, args) {
  return execFileSync('git', args, { cwd: root, stdio: 'ignore', windowsHide: true });
}

test('Git repository binding tracks tracked & ordinary untracked source while honoring nested ignores', async () => {
  const root = mkdtempSync(join(tmpdir(), 'legion-repository-binding-git-'));
  try {
    git(root, ['init', '--quiet']);
    git(root, ['config', 'user.email', 'legion-tests@example.invalid']);
    git(root, ['config', 'user.name', 'Legion Tests']);
    mkdirSync(join(root, 'src'), { recursive: true });
    writeFileSync(join(root, '.gitignore'), '.agent/\n.audit/\n.legion/\nengine/target/\n');
    writeFileSync(join(root, 'src', 'tracked.mjs'), 'export const tracked = 1;\n');
    git(root, ['add', '.gitignore', 'src/tracked.mjs']);
    git(root, ['commit', '--quiet', '-m', 'baseline']);

    writeFileSync(join(root, 'src', 'untracked.mjs'), 'export const untracked = 1;\n');
    mkdirSync(join(root, 'src', '.audit'), { recursive: true });
    mkdirSync(join(root, 'src', '.agent'), { recursive: true });
    mkdirSync(join(root, 'engine', 'target'), { recursive: true });
    writeFileSync(join(root, 'src', '.audit', 'report.json'), 'audit output 1\n');
    writeFileSync(join(root, 'src', '.agent', 'state.sqlite'), 'runtime state 1\n');
    writeFileSync(join(root, 'engine', 'target', 'generated.bin'), 'generated output 1\n');

    const initial = await bindRepository(root);

    writeFileSync(join(root, 'src', '.audit', 'report.json'), 'audit output 2\n');
    writeFileSync(join(root, 'src', '.agent', 'state.sqlite'), 'runtime state 2\n');
    writeFileSync(join(root, 'engine', 'target', 'generated.bin'), 'generated output 2\n');
    const afterIgnoredMutation = await bindRepository(root);
    assert.equal(afterIgnoredMutation.dirtyOverlayDigest, initial.dirtyOverlayDigest);
    assert.equal(afterIgnoredMutation.digest, initial.digest);
    assert.equal(afterIgnoredMutation.fileCount, initial.fileCount);

    writeFileSync(join(root, 'src', 'tracked.mjs'), 'export const tracked = 2;\n');
    const afterTrackedMutation = await bindRepository(root);
    assert.notEqual(afterTrackedMutation.dirtyOverlayDigest, afterIgnoredMutation.dirtyOverlayDigest);
    assert.notEqual(afterTrackedMutation.digest, afterIgnoredMutation.digest);

    writeFileSync(join(root, 'src', 'untracked.mjs'), 'export const untracked = 2;\n');
    const afterUntrackedMutation = await bindRepository(root);
    assert.notEqual(afterUntrackedMutation.dirtyOverlayDigest, afterTrackedMutation.dirtyOverlayDigest);
    assert.notEqual(afterUntrackedMutation.digest, afterTrackedMutation.digest);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('non-Git repository binding excludes runtime state but tracks source mutations', async () => {
  const root = mkdtempSync(join(tmpdir(), 'legion-repository-binding-'));
  try {
    const source = join(root, 'src', 'feature.mjs');
    mkdirSync(join(root, 'src', '.audit'), { recursive: true });
    mkdirSync(join(root, 'src', '.agent'), { recursive: true });
    writeFileSync(source, 'export const value = 1;\n');
    writeFileSync(join(root, 'src', '.audit', 'fixture.txt'), 'source fixture\n');
    writeFileSync(join(root, 'src', '.agent', 'state.sqlite'), 'runtime state 1\n');

    const initial = await bindRepository(root);
    mkdirSync(join(root, '.agent'), { recursive: true });
    mkdirSync(join(root, '.audit'), { recursive: true });
    mkdirSync(join(root, '.legion'), { recursive: true });
    writeFileSync(join(root, '.agent', 'state.sqlite'), 'runtime state 1\n');
    writeFileSync(join(root, '.audit', 'report.json'), 'audit output 1\n');
    writeFileSync(join(root, '.legion', 'binding.json'), 'runtime state 1\n');
    writeFileSync(join(root, 'src', '.audit', 'fixture.txt'), 'source fixture 2\n');
    writeFileSync(join(root, 'src', '.agent', 'state.sqlite'), 'runtime state 2\n');
    const afterRuntimeMutation = await bindRepository(root);

    assert.equal(afterRuntimeMutation.dirtyOverlayDigest, initial.dirtyOverlayDigest);
    assert.equal(afterRuntimeMutation.digest, initial.digest);
    assert.equal(afterRuntimeMutation.fileCount, initial.fileCount);

    writeFileSync(source, 'export const value = 2;\n');
    const afterSourceMutation = await bindRepository(root);
    assert.notEqual(afterSourceMutation.dirtyOverlayDigest, afterRuntimeMutation.dirtyOverlayDigest);
    assert.notEqual(afterSourceMutation.digest, afterRuntimeMutation.digest);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
