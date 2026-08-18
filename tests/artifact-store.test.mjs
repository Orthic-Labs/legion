import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { RunArtifactStore } from '../src/lib/artifacts/run-store.mjs';

function tempStore() {
  const dir = mkdtempSync(join(tmpdir(), 'legion-store-'));
  return { dir, store: new RunArtifactStore(dir) };
}

test('writeJson creates an atomic content-digested artifact', async () => {
  const { dir, store } = tempStore();
  try {
    await store.init();
    const record = await store.writeJson({
      path: 'plan.json', kind: 'audit-plan', producer: 'legion.core', schemaVersion: 1,
      binding: { planDigest: 'sha256:p' }, value: { kind: 'audit-provider-plan', sealed: true },
    });
    assert.equal(record.kind, 'audit-plan');
    assert.equal(record.producer, 'legion.core');
    assert.equal(record.schemaVersion, 1);
    assert.equal(record.mediaType, 'application/json');
    assert.ok(record.digest.startsWith('sha256:'));
    assert.ok(existsSync(join(dir, 'plan.json')));
    const bytes = readFileSync(join(dir, 'plan.json'));
    assert.equal(bytes.length, record.bytes);
    // No temp files remain.
    assert.ok(!readFileSync(join(dir, 'plan.json'), 'utf8').includes('.tmp'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('writeBytes records bytes, digest, and size', async () => {
  const { dir, store } = tempStore();
  try {
    await store.init();
    const record = await store.writeBytes({
      path: 'raw/out.txt', kind: 'raw-output', producer: 'provider.x', schemaVersion: 1,
      mediaType: 'text/plain', binding: null, bytes: Buffer.from('hello world'),
    });
    assert.equal(record.bytes, 11);
    assert.equal(record.digest, 'sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9');
    assert.equal(readFileSync(join(dir, 'raw/out.txt'), 'utf8'), 'hello world');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('nested paths create parent directories', async () => {
  const { dir, store } = tempStore();
  try {
    await store.init();
    await store.writeJson({
      path: 'provider-results/a/b/result.json', kind: 'provider-result', producer: 'p', schemaVersion: 1, binding: null,
      value: { provider: 'p', status: 'pass' },
    });
    assert.ok(existsSync(join(dir, 'provider-results/a/b/result.json')));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('paths escaping the run root are rejected', async () => {
  const { store } = tempStore();
  await store.init();
  await assert.rejects(
    () => store.writeJson({ path: '../escape.json', kind: 'x', producer: 'p', schemaVersion: 1, binding: null, value: {} }),
    /escapes run root/,
  );
  await assert.rejects(
    () => store.writeBytes({ path: '/abs/escape', kind: 'x', producer: 'p', schemaVersion: 1, mediaType: 'text/plain', bytes: Buffer.from('x') }),
    /escapes run root/,
  );
});

test('records are sorted and stable', async () => {
  const { store } = tempStore();
  await store.init();
  await store.writeJson({ path: 'b.json', kind: 'b', producer: 'p', schemaVersion: 1, binding: null, value: { n: 1 } });
  await store.writeJson({ path: 'a.json', kind: 'a', producer: 'p', schemaVersion: 1, binding: null, value: { n: 2 } });
  const records = store.records();
  assert.deepEqual(records.map((record) => record.path), ['a.json', 'b.json']);
});

test('overwriting an artifact updates the record digest', async () => {
  const { store } = tempStore();
  await store.init();
  const first = await store.writeJson({ path: 'x.json', kind: 'x', producer: 'p', schemaVersion: 1, binding: null, value: { v: 1 } });
  const second = await store.writeJson({ path: 'x.json', kind: 'x', producer: 'p', schemaVersion: 1, binding: null, value: { v: 2 } });
  assert.notEqual(first.digest, second.digest);
  assert.equal(store.records().length, 1);
});
