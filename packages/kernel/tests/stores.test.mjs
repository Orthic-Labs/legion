import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { ArtifactStore, digestContent } from '../lib/stores.mjs';
import { mintId } from '../lib/ids.mjs';

function artifactRecord(content) {
  return {
    schemaVersion: 1,
    kind: 'legion-artifact',
    artifactId: mintId('artifact'),
    artifactKind: 'evidence',
    digest: digestContent(content),
    bytes: content.length,
    immutable: true,
    producerAuthority: 'kernel',
    sourceRevision: '1234567',
    sensitivity: 'internal',
    retention: { policy: 'task' },
    redaction: { applied: false, metadata: [] },
    createdAt: '2026-08-09T00:00:00.000Z',
  };
}

test('concurrent duplicate artifact writes preserve one typed immutable record', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'kernel-artifact-race-'));
  const store = await ArtifactStore.open(root);
  const content = Buffer.from('same immutable content');
  const record = artifactRecord(content);

  const outcomes = await Promise.allSettled([
    store.put(record, content),
    store.put(record, content),
  ]);
  assert.equal(outcomes.filter(({ status }) => status === 'fulfilled').length, 1);
  const rejected = outcomes.find(({ status }) => status === 'rejected');
  assert.equal(rejected.reason.code, 'SCOPE_CONFLICT');

  const reopened = await ArtifactStore.open(root);
  assert.deepEqual(await reopened.getContent(record.artifactId), content);
});

test('artifact retrieval detects blob corruption against bound digest', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'kernel-artifact-integrity-'));
  const store = await ArtifactStore.open(root);
  const content = Buffer.from('bound content');
  const record = artifactRecord(content);
  await store.put(record, content);

  await writeFile(path.join(root, 'blobs', record.digest.slice('sha256:'.length)), 'tampered');
  await assert.rejects(() => store.getContent(record.artifactId), (error) => {
    assert.equal(error.code, 'ARTIFACT_DIGEST_MISMATCH');
    assert.equal(error.category, 'integrity');
    return true;
  });
});
