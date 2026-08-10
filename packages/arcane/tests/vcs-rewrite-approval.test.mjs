// History rewrite is refused by default and appealable only against an exact
// target. Before this, force-push sat in the unconditional destructive list, so
// the operator could explicitly ask for a history purge and nothing could authorize
// it — the branch returned before any contract, policy, or approval was read.
//
// These cases cover the pure classification and key-binding, which is where the
// security property lives: an approval for one ref must never authorize another,
// and an unresolved target must never be bound to a guess.
import assert from 'node:assert/strict';
import test from 'node:test';

import { classifyVcsPush, isDestructiveCommand, vcsRewriteApprovalKey } from '../host/hook-adapter-core.mjs';

const FORCE = ['git', 'push', '--force', 'origin', 'main'].join(' ');
const LEASE = ['git', 'push', '--force-with-lease', 'origin', 'main'].join(' ');
const DELETE = ['git', 'push', '--delete', 'origin', 'old-branch'].join(' ');
const ORDINARY = ['git', 'push', 'origin', 'main'].join(' ');

test('an ordinary push is not a rewrite', () => {
  const info = classifyVcsPush(ORDINARY);
  assert.equal(info.rewrite, false);
  assert.equal(info.operation, 'git-push');
});

test('force, force-with-lease and delete are all rewrites, with their target extracted', () => {
  for (const [command, operation] of [[FORCE, 'git-push-force'], [LEASE, 'git-push-force'], [DELETE, 'git-push-delete']]) {
    const info = classifyVcsPush(command);
    assert.equal(info.rewrite, true, command);
    assert.equal(info.operation, operation, command);
    assert.equal(info.remote, 'origin', command);
  }
  assert.equal(classifyVcsPush(FORCE).ref, 'main');
  assert.equal(classifyVcsPush(DELETE).ref, 'old-branch');
});

test('a non-push command is not classified', () => {
  assert.equal(classifyVcsPush('git commit -m "x"'), null);
  assert.equal(classifyVcsPush(null), null);
});

test('the approval key binds session, class and exact target', () => {
  const key = vcsRewriteApprovalKey('sess-1', classifyVcsPush(FORCE));
  assert.equal(key, 'sess-1|VCS_PUSH|origin/main');
  // A different ref produces a different key, so one approval cannot ride another.
  assert.notEqual(key, vcsRewriteApprovalKey('sess-1', classifyVcsPush(DELETE)));
  // A different session cannot reuse it either.
  assert.notEqual(key, vcsRewriteApprovalKey('sess-2', classifyVcsPush(FORCE)));
});

test('an unresolved target yields no key — an approval is never bound to a guess', () => {
  assert.equal(vcsRewriteApprovalKey('sess-1', classifyVcsPush('git push --force')), null);
  assert.equal(vcsRewriteApprovalKey(null, classifyVcsPush(FORCE)), null);
});

test('an ordinary push needs no approval key', () => {
  assert.equal(vcsRewriteApprovalKey('sess-1', classifyVcsPush(ORDINARY)), null);
});

test('the unconditional destructive classes did not become appealable', () => {
  for (const command of ['rm -rf /tmp/x', 'terraform destroy -auto-approve', 'git clean -fdx', 'dropdb prod']) {
    assert.equal(isDestructiveCommand({ command }), true, command);
  }
  // Rewrite left that list — it is refused by the approval branch instead.
  assert.equal(isDestructiveCommand({ command: FORCE }), false);
});
