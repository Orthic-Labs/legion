import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resolveSourceRevisionFs } from '../src/lib/host/arcane/source-revision.mjs';

const git = (cwd, ...args) => execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();

function repo() {
  const dir = mkdtempSync(join(tmpdir(), 'arcane-srcrev-'));
  git(dir, 'init', '-q');
  git(dir, 'config', 'user.email', 't@t.co');
  git(dir, 'config', 'user.name', 't');
  git(dir, 'commit', '-q', '--allow-empty', '-m', 'one');
  return dir;
}

test('fs resolver matches git rev-parse HEAD for a loose ref', () => {
  const dir = repo();
  try { assert.equal(resolveSourceRevisionFs(dir), git(dir, 'rev-parse', 'HEAD')); }
  finally { rmSync(dir, { recursive: true, force: true }); }
});

test('fs resolver matches git rev-parse HEAD after packing refs', () => {
  const dir = repo();
  try {
    git(dir, 'pack-refs', '--all');
    assert.equal(resolveSourceRevisionFs(dir), git(dir, 'rev-parse', 'HEAD'));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('fs resolver matches git rev-parse HEAD when detached', () => {
  const dir = repo();
  try {
    git(dir, 'checkout', '-q', '--detach', 'HEAD');
    assert.equal(resolveSourceRevisionFs(dir), git(dir, 'rev-parse', 'HEAD'));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('fs resolver matches git rev-parse HEAD in a linked worktree', () => {
  const dir = repo();
  const wt = `${dir}-wt`;
  try {
    git(dir, 'worktree', 'add', '-q', wt, 'HEAD');
    assert.equal(resolveSourceRevisionFs(wt), git(wt, 'rev-parse', 'HEAD'));
  } finally { rmSync(dir, { recursive: true, force: true }); rmSync(wt, { recursive: true, force: true }); }
});

test('fs resolver returns undefined (defer to fallback) outside a git repo', () => {
  const dir = mkdtempSync(join(tmpdir(), 'arcane-nogit-'));
  try { assert.equal(resolveSourceRevisionFs(dir), undefined); }
  finally { rmSync(dir, { recursive: true, force: true }); }
});

test('fs resolver never fabricates a revision for a malformed gitdir pointer', () => {
  const dir = mkdtempSync(join(tmpdir(), 'arcane-badgit-'));
  try {
    writeFileSync(join(dir, '.git'), 'gitdir: /nonexistent/path/xyz\n');
    assert.equal(resolveSourceRevisionFs(dir), undefined);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('fs resolver ignores an empty workspace argument', () => {
  assert.equal(resolveSourceRevisionFs(''), undefined);
  assert.equal(resolveSourceRevisionFs(null), undefined);
});
