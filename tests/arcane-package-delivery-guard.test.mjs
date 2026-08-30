import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { finalizeClose as guardFinalizeClose, openDelivery as guardOpenDelivery, prepareClose as guardPrepareClose } from '../src/lib/cli/commands/governance/delivery/delivery-guard.mjs';

const deliveryOwners = new WeakMap();
function openDelivery(options) { const delivery = guardOpenDelivery(options); deliveryOwners.set(delivery, options.owner); return delivery; }
function prepareClose(delivery, disposition, options = {}) { return guardPrepareClose(delivery, disposition, { ...options, owner: options.owner ?? deliveryOwners.get(delivery) }); }
function finalizeClose(delivery, options = {}) { return guardFinalizeClose(delivery, { ...options, owner: options.owner ?? deliveryOwners.get(delivery) }); }

function repo() {
  // realpath: git reports canonical roots, and on macOS every /var/... tmpdir
  // is really /private/var/..., so a raw mkdtemp path never equals what the
  // guard returns.
  const dir = realpathSync(mkdtempSync(join(tmpdir(), 'arcane-delivery-')));
  const git = (args) => execFileSync('git', args, { cwd: dir, stdio: 'ignore' });
  git(['init', '--initial-branch=main']); git(['config', 'user.email', 'test@example.test']); git(['config', 'user.name', 'Test']); writeFileSync(join(dir, 'base.txt'), 'base\n'); writeFileSync(join(dir, '.gitignore'), '.audit/\n'); git(['add', '.']); git(['commit', '-m', 'base']);
  return { dir, git, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test('delivery guard serializes writers, preserves clean repository, & releases only matching lease', () => {
  const fixture = repo();
  try {
    const first = openDelivery({ repositories: [fixture.dir], readOnly: false, owner: { sessionId: 'one', runId: 'run-one', taskId: 'T-1' } });
    assert.throws(() => openDelivery({ repositories: [fixture.dir], readOnly: false, owner: { sessionId: 'two', runId: 'run-two', taskId: 'T-1' } }), { code: 'ARC_INTEGRATION_OWNER_CONFLICT' });
    assert.equal(prepareClose(first, 'complete')[0].state, 'clean');
    writeFileSync(join(fixture.dir, 'delivered.txt'), 'delivered\n'); fixture.git(['add', '.']); fixture.git(['commit', '-m', 'delivered']);
    const result = prepareClose(first, 'complete');
    assert.equal(result[0].state, 'integrated');
    finalizeClose(first);
    assert.doesNotThrow(() => openDelivery({ repositories: [fixture.dir], readOnly: false, owner: { sessionId: 'two', runId: 'run-two', taskId: 'T-1' } }));
  } finally { fixture.cleanup(); }
});

test('delivery guard archives tracked & untracked changes as a content-addressed binary patch', () => {
  const fixture = repo();
  try {
    const delivery = openDelivery({ repositories: [fixture.dir], readOnly: false, owner: { sessionId: 'one', runId: 'run-one', taskId: 'T-1' } });
    writeFileSync(join(fixture.dir, 'base.txt'), 'changed\n'); writeFileSync(join(fixture.dir, 'new.bin'), Buffer.from([0, 255, 2]));
    assert.throws(() => prepareClose(delivery, 'complete'), { code: 'ARC_DELIVERY_NOT_REACHABLE' });
    const archived = prepareClose(delivery, 'archive')[0];
    assert.equal(archived.state, 'archived'); assert.match(archived.patch.digest, /^[a-f0-9]{64}$/);
    finalizeClose(delivery);
  } finally { fixture.cleanup(); }
});

test('delivery guard archives patches larger than Node child-process default buffer', () => {
  const fixture = repo();
  try {
    const delivery = openDelivery({ repositories: [fixture.dir], readOnly: false, owner: { sessionId: 'one', runId: 'run-one', taskId: 'T-1' } });
    writeFileSync(join(fixture.dir, 'large.txt'), Array.from({ length: 90_000 }, (_, index) => `${index.toString(16).padStart(8, '0')}-${createHash('sha256').update(String(index)).digest('hex')}\n`).join(''));
    const archived = prepareClose(delivery, 'archive')[0];
    assert.equal(archived.state, 'archived');
    assert.ok(readFileSync(archived.patch.path).byteLength > 1024 * 1024);
    finalizeClose(delivery);
  } finally { fixture.cleanup(); }
});

test('archive persistence failures retain authority & never report an archive', () => {
  const writeFixture = repo(), renameFixture = repo(), hashFixture = repo();
  try {
    const owner = { sessionId: 'one', runId: 'run-one', taskId: 'T-1' };
    const writeDelivery = openDelivery({ repositories: [writeFixture.dir], readOnly: false, owner }); writeFileSync(join(writeFixture.dir, 'base.txt'), 'write failure\n');
    let tempPath = null;
    assert.throws(() => prepareClose(writeDelivery, 'archive', { io: { exists: existsSync, read: readFileSync, write(path) { tempPath = path; throw new Error('write failed'); }, rename() {}, hash: (bytes) => createHash('sha256').update(bytes).digest('hex') } }), /write failed/);
    assert.equal(existsSync(tempPath.slice(0, tempPath.lastIndexOf('.'))), false); assert.ok(existsSync(join(writeFixture.dir, '.audit', 'arcane', 'delivery', 'lease.json')));

    const renameDelivery = openDelivery({ repositories: [renameFixture.dir], readOnly: false, owner }); writeFileSync(join(renameFixture.dir, 'base.txt'), 'rename failure\n');
    let finalPath = null;
    assert.throws(() => prepareClose(renameDelivery, 'archive', { io: { exists: existsSync, read: readFileSync, write: writeFileSync, rename(_from, to) { finalPath = to; throw new Error('rename failed'); }, hash: (bytes) => createHash('sha256').update(bytes).digest('hex') } }), /rename failed/);
    assert.equal(existsSync(finalPath), false); assert.ok(existsSync(join(renameFixture.dir, '.audit', 'arcane', 'delivery', 'lease.json')));

    const hashDelivery = openDelivery({ repositories: [hashFixture.dir], readOnly: false, owner }); writeFileSync(join(hashFixture.dir, 'base.txt'), 'hash failure\n');
    const archived = prepareClose(hashDelivery, 'archive')[0]; writeFileSync(archived.patch.path, 'corrupt');
    assert.throws(() => prepareClose(hashDelivery, 'archive'), { code: 'ARC_DELIVERY_PATCH_HASH_INVALID' });
    assert.equal(readFileSync(archived.patch.path, 'utf8'), 'corrupt'); assert.ok(existsSync(join(hashFixture.dir, '.audit', 'arcane', 'delivery', 'lease.json')));
  } finally { writeFixture.cleanup(); renameFixture.cleanup(); hashFixture.cleanup(); }
});

test('read-only delivery closes clean but blocks snapshot change', () => {
  const fixture = repo();
  try {
    const delivery = openDelivery({ repositories: [fixture.dir], readOnly: true, owner: { sessionId: 'one', runId: 'run-one', taskId: 'T-1' } });
    assert.equal(prepareClose(delivery, 'complete')[0].state, 'clean');
    writeFileSync(join(fixture.dir, 'base.txt'), 'changed\n');
    assert.throws(() => prepareClose(delivery, 'complete'), { code: 'ARC_DELIVERY_READ_ONLY_MUTATED' });
  } finally { fixture.cleanup(); }
});

test('read-only retry reuses authoritative baseline while distinct owners coexist', () => {
  const fixture = repo();
  try {
    const owner = { sessionId: 'one', runId: 'run-one', taskId: 'T-1' };
    const first = openDelivery({ repositories: [fixture.dir], readOnly: true, owner }); writeFileSync(join(fixture.dir, 'after-open.txt'), 'changed\n');
    const retry = openDelivery({ repositories: [fixture.dir], readOnly: true, owner });
    const other = openDelivery({ repositories: [fixture.dir], readOnly: true, owner: { sessionId: 'two', runId: 'run-two', taskId: 'T-1' } });
    assert.equal(retry.repositories[0].snapshotTree, first.repositories[0].snapshotTree); assert.notEqual(other.repositories[0].leaseToken, first.repositories[0].leaseToken);
    assert.throws(() => prepareClose(retry, 'complete'), { code: 'ARC_DELIVERY_READ_ONLY_MUTATED' });
  } finally { fixture.cleanup(); }
});

test('same owner reopens stably, separate repositories coexist, & token mismatch preserves every lease', () => {
  const a = repo(), b = repo();
  try {
    const owner = { sessionId: 'one', runId: 'run-one', taskId: 'T-1' };
    const first = openDelivery({ repositories: [a.dir], readOnly: false, owner });
    writeFileSync(join(a.dir, 'after-open.txt'), 'must stay task output\n');
    const repeat = openDelivery({ repositories: [a.dir], readOnly: false, owner });
    assert.equal(first.repositories[0].leaseToken, repeat.repositories[0].leaseToken);
    assert.equal(first.repositories[0].snapshotTree, repeat.repositories[0].snapshotTree);
    assert.throws(() => prepareClose(repeat, 'complete'), { code: 'ARC_DELIVERY_NOT_REACHABLE' });
    const multi = openDelivery({ repositories: [b.dir], readOnly: false, owner: { sessionId: 'two', runId: 'run-two', taskId: 'T-1' } });
    first.repositories.push(multi.repositories[0]); first.repositories[1].leaseToken = 'wrong';
    assert.throws(() => finalizeClose(first), { code: 'ARC_DELIVERY_OWNER_MISMATCH' });
    assert.ok(existsSync(join(a.dir, '.audit', 'arcane', 'delivery', 'lease.json'))); assert.ok(existsSync(join(b.dir, '.audit', 'arcane', 'delivery', 'lease.json')));
  } finally { a.cleanup(); b.cleanup(); }
});

test('multi-repository conflict preserves reused same-owner authority', () => {
  const a = repo(), b = repo();
  try {
    const owner = { sessionId: 'one', runId: 'run-one', taskId: 'T-1' };
    const first = openDelivery({ repositories: [a.dir], readOnly: false, owner });
    openDelivery({ repositories: [b.dir], readOnly: false, owner: { sessionId: 'other', runId: 'run-other', taskId: 'T-1' } });
    assert.throws(() => openDelivery({ repositories: [a.dir, b.dir], readOnly: false, owner }), { code: 'ARC_INTEGRATION_OWNER_CONFLICT' });
    const lease = JSON.parse(readFileSync(join(a.dir, '.audit', 'arcane', 'delivery', 'lease.json'), 'utf8'));
    assert.equal(lease.token, first.repositories[0].leaseToken); assert.equal(JSON.parse(readFileSync(join(b.dir, '.audit', 'arcane', 'delivery', 'lease.json'), 'utf8')).sessionId, 'other');
  } finally { a.cleanup(); b.cleanup(); }
});

test('snapshot preserves real Git state, baseline dirt is clean, & detached primary fails closed', () => {
  const fixture = repo();
  try {
    writeFileSync(join(fixture.dir, 'base.txt'), 'staged\n'); fixture.git(['add', '.']); writeFileSync(join(fixture.dir, 'dirty.txt'), 'unstaged\n'); writeFileSync(join(fixture.dir, 'untracked.txt'), 'u\n');
    const before = { head: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: fixture.dir, encoding: 'utf8' }), ref: execFileSync('git', ['symbolic-ref', 'HEAD'], { cwd: fixture.dir, encoding: 'utf8' }), index: readFileSync(join(fixture.dir, '.git', 'index')), status: execFileSync('git', ['status', '--porcelain=v1'], { cwd: fixture.dir, encoding: 'utf8' }) };
    const delivery = openDelivery({ repositories: [fixture.dir], readOnly: false, owner: { sessionId: 'one', runId: 'run-one', taskId: 'T-1' } });
    assert.equal(prepareClose(delivery, 'complete')[0].state, 'clean');
    assert.deepEqual(readFileSync(join(fixture.dir, '.git', 'index')), before.index); assert.equal(execFileSync('git', ['rev-parse', 'HEAD'], { cwd: fixture.dir, encoding: 'utf8' }), before.head); assert.equal(execFileSync('git', ['symbolic-ref', 'HEAD'], { cwd: fixture.dir, encoding: 'utf8' }), before.ref); assert.equal(execFileSync('git', ['status', '--porcelain=v1'], { cwd: fixture.dir, encoding: 'utf8' }), before.status);
    finalizeClose(delivery); fixture.git(['checkout', '--detach']);
    assert.throws(() => openDelivery({ repositories: [fixture.dir], readOnly: false, owner: { sessionId: 'two', runId: 'run-two', taskId: 'T-1' } }), { code: 'ARC_DELIVERY_CANONICAL_REF_INVALID' });
  } finally { fixture.cleanup(); }
});

test('archive binary rename deletion is deterministic & complete failure retains lease', () => {
  const fixture = repo();
  try {
    writeFileSync(join(fixture.dir, 'gone.txt'), 'gone\n'); fixture.git(['add', '.']); fixture.git(['commit', '-m', 'extra']);
    const delivery = openDelivery({ repositories: [fixture.dir], readOnly: false, owner: { sessionId: 'one', runId: 'run-one', taskId: 'T-1' } });
    fixture.git(['mv', 'gone.txt', 'renamed.txt']); writeFileSync(join(fixture.dir, 'base.txt'), Buffer.from([0, 255, 1])); writeFileSync(join(fixture.dir, 'new.txt'), 'new\n');
    assert.throws(() => prepareClose(delivery, 'complete'), { code: 'ARC_DELIVERY_NOT_REACHABLE' }); assert.ok(existsSync(join(fixture.dir, '.audit', 'arcane', 'delivery', 'lease.json')));
    const one = prepareClose(delivery, 'archive')[0], two = prepareClose(delivery, 'archive')[0];
    assert.equal(one.state, 'archived'); assert.equal(one.patch.digest, two.patch.digest); assert.deepEqual(readFileSync(one.patch.path), readFileSync(two.patch.path)); assert.match(readFileSync(one.patch.path, 'utf8'), /GIT binary patch|rename from|new.txt/);
    finalizeClose(delivery);
  } finally { fixture.cleanup(); }
});

test('complete rejects nonancestor and missing canonical refs while retaining lease', () => {
  const fixture = repo();
  try {
    const delivery = openDelivery({ repositories: [fixture.dir], readOnly: false, owner: { sessionId: 'one', runId: 'run-one', taskId: 'T-1' } });
    fixture.git(['checkout', '-b', 'delivery']); writeFileSync(join(fixture.dir, 'base.txt'), 'branch\n'); fixture.git(['add', '.']); fixture.git(['commit', '-m', 'branch commit']);
    assert.throws(() => prepareClose(delivery, 'complete'), { code: 'ARC_DELIVERY_NOT_REACHABLE' });
    assert.ok(existsSync(join(fixture.dir, '.audit', 'arcane', 'delivery', 'lease.json')));
    fixture.git(['branch', '-D', 'main']);
    assert.throws(() => prepareClose(delivery, 'complete'), { code: 'ARC_DELIVERY_NOT_REACHABLE' });
    assert.ok(existsSync(join(fixture.dir, '.audit', 'arcane', 'delivery', 'lease.json')));
  } finally { fixture.cleanup(); }
});

test('terminal recovery accepts only already-released authority records', () => {
  const fixture = repo();
  try {
    const write = openDelivery({ repositories: [fixture.dir], readOnly: false, owner: { sessionId: 'write', runId: 'run-write', taskId: 'T-1' } });
    finalizeClose(write); assert.doesNotThrow(() => finalizeClose(write, { recovery: true }));
    const read = openDelivery({ repositories: [fixture.dir], readOnly: true, owner: { sessionId: 'read', runId: 'run-read', taskId: 'T-1' } });
    finalizeClose(read); assert.doesNotThrow(() => finalizeClose(read, { recovery: true }));
    const tampered = openDelivery({ repositories: [fixture.dir], readOnly: false, owner: { sessionId: 'tamper', runId: 'run-tamper', taskId: 'T-1' } });
    const lease = join(fixture.dir, '.audit', 'arcane', 'delivery', 'lease.json'); const record = JSON.parse(readFileSync(lease, 'utf8')); record.metadata.snapshotTree = 'forged'; writeFileSync(lease, JSON.stringify(record));
    assert.throws(() => finalizeClose(tampered, { recovery: true }), { code: 'ARC_DELIVERY_METADATA_MISMATCH' });
  } finally { fixture.cleanup(); }
});
