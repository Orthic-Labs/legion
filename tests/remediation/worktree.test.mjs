import assert from 'node:assert/strict';
import test from 'node:test';
import { createRemediationWorktree, removeRemediationWorktree, worktreeReceipt } from '../../src/lib/remediation/worktree.mjs';
import { createCheckpoint, restorePlan, cleanupReceipt, checkpointDigest } from '../../src/lib/remediation/checkpoint.mjs';
import { changePassport, signPassport, verifyPassport } from '../../src/lib/provenance/passport.mjs';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

function fakeRunner(overrides = {}) {
  return {
    run: async (spec) => {
      if (overrides.fail) return { exitCode: 1, stderr: 'boom' };
      return { exitCode: 0 };
    },
  };
}

test('createRemediationWorktree uses an isolated detached path', async () => {
  const runner = fakeRunner();
  const result = await createRemediationWorktree({
    repo: { root: '/repo', gitCommonDir: '/repo/.git' },
    baseCommit: 'abc123', runId: 'run-1', processRunner: runner,
  });
  assert.equal(result.path, join('/repo/.git', 'legion-worktrees', 'run-1'));
  assert.equal(result.baseCommit, 'abc123');
  assert.deepEqual(result.cleanup, ['git', 'worktree', 'remove', '--force', result.path]);
});

test('worktree add failure throws', async () => {
  await assert.rejects(
    () => createRemediationWorktree({ repo: { root: '/r', gitCommonDir: '/r/.git' }, baseCommit: 'a', runId: 'r', processRunner: fakeRunner({ fail: true }) }),
    /git worktree add failed/,
  );
});

test('removeRemediationWorktree reports failure with recovery', async () => {
  const result = await removeRemediationWorktree({ path: '/w', processRunner: fakeRunner({ fail: true }) });
  assert.equal(result.removed, false);
  assert.equal(result.error, 'boom');
});

test('worktree receipt declares primary worktree untouched', () => {
  const receipt = worktreeReceipt({ path: '/w', baseCommit: 'a', runId: 'r', cleanup: ['git', 'worktree', 'remove', '--force', '/w'] });
  assert.equal(receipt.primaryWorktreeUntouched, true);
  assert.equal(receipt.kind, 'legion-remediation-worktree');
});

test('checkpoint digest is deterministic and restore plan is a reverse', () => {
  const checkpoint = createCheckpoint({ worktreePath: '/w', baseCommit: 'abc', files: ['a.ts', 'b.ts'] });
  const again = createCheckpoint({ worktreePath: '/w', baseCommit: 'abc', files: ['b.ts', 'a.ts'] });
  assert.equal(checkpoint.digest, again.digest);
  const restore = restorePlan(checkpoint);
  assert.equal(restore.kind, 'legion-checkpoint-restore');
  assert.equal(restore.steps.length, 2);
  assert.match(restore.recoveryCommand, /git -C \/w checkout/);
});

test('cleanup receipt keeps exact recovery commands on failure', () => {
  const receipt = cleanupReceipt({ path: '/w', removed: false, error: 'in-use', recoveryCommand: 'git worktree remove --force /w' });
  assert.equal(receipt.removed, false);
  assert.ok(receipt.recoveryCommand);
});

test('change passport signs content digests with HMAC', () => {
  const passport = changePassport({
    baseCommit: 'abc', patchDigest: 'sha256:patch', findingIds: ['f1'], producer: { kind: 'mechanical' },
    commands: ['git apply patch'], verificationArtifacts: ['verify.json'], createdAt: '2026-08-06T00:00:00Z',
    signingKey: 'local-key',
  });
  assert.equal(passport.kind, 'legion-change-passport');
  assert.equal(passport.signature.algorithm, 'HMAC-SHA256');
  assert.ok(passport.passportDigest.startsWith('sha256:'));
  assert.equal(verifyPassport(passport, 'local-key'), true);
  assert.equal(verifyPassport(passport, 'wrong-key'), false);
});

test('unsigned passport has a null signature and verifies false', () => {
  const passport = changePassport({
    baseCommit: 'abc', patchDigest: 'sha256:p', findingIds: [], producer: {}, commands: [], verificationArtifacts: [],
    createdAt: '2026-08-06T00:00:00Z', signingKey: null,
  });
  assert.equal(passport.signature.value, null);
  assert.equal(verifyPassport(passport, 'local-key'), false);
});

test('signPassport and verifyPassport round-trip', () => {
  const body = { schemaVersion: 1, kind: 'legion-change-passport', baseCommit: 'a', patchDigest: 'sha256:p', findingIds: [], producer: {}, commands: [], verificationArtifacts: [], createdAt: 't' };
  const signed = signPassport(body, 'key');
  assert.equal(verifyPassport(signed, 'key'), true);
  // Tampering breaks the signature.
  const tampered = { ...signed, patchDigest: 'sha256:evil' };
  assert.equal(verifyPassport(tampered, 'key'), false);
});

test('real git worktree lifecycle works end-to-end', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'legion-wt-'));
  try {
    spawnSync('git', ['init', '-q', dir], { stdio: 'ignore' });
    spawnSync('git', ['-C', dir, 'config', 'user.email', 't@t'], { stdio: 'ignore' });
    spawnSync('git', ['-C', dir, 'config', 'user.name', 't'], { stdio: 'ignore' });
    spawnSync('git', ['-C', dir, 'commit', '-q', '--allow-empty', '-m', 'base'], { stdio: 'ignore' });
    const base = spawnSync('git', ['-C', dir, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).stdout.trim();
    const gitDir = spawnSync('git', ['-C', dir, 'rev-parse', '--git-dir'], { encoding: 'utf8' }).stdout.trim();
    const { execFileSync } = await import('node:child_process');
    const runner = { run: async (spec) => {
      const r = spawnSync('git', spec.args, { cwd: spec.cwd, encoding: 'utf8' });
      return { exitCode: r.status, stderr: r.stderr };
    } };
    const wt = await createRemediationWorktree({ repo: { root: dir, gitCommonDir: join(dir, gitDir) }, baseCommit: base, runId: 'run-x', processRunner: runner });
    const removed = await removeRemediationWorktree({ path: wt.path, processRunner: runner });
    assert.equal(removed.removed, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
