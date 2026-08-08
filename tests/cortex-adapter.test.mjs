import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { CortexAdapter } from '../lib/adapters/cortex/index.mjs';

test('external mode requires a configured command', async () => {
  const adapter = new CortexAdapter({ mode: 'external', externalCommand: null });
  const compatible = await adapter.ensureCompatible();
  assert.equal(compatible.ok, false);
  assert.match(compatible.error, /not configured/);
});

test('bundled mode reports compatibility when bundled provider is present', async () => {
  const adapter = new CortexAdapter({ mode: 'bundled', bundled: '@orthic-labs/cortex' });
  const compatible = await adapter.ensureCompatible();
  assert.equal(compatible.ok, true);
  assert.equal(compatible.provider, '@orthic-labs/cortex');
});

test('precomputed mode verifies binding and reads the projection', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'nemesis-cortex-'));
  try {
    const path = join(dir, 'projection.json');
    writeFileSync(path, JSON.stringify({
      schemaVersion:1,state: 'ready', generationId: 'gen-p', manifestDigest: 'sha256:m',
      files: ['a.ts'], fileSetDigest: 'sha256:f', parsedExtensions: ['ts'],
    }));
    const adapter = new CortexAdapter({ mode: 'precomputed', precomputedPath: path });
    assert.equal((await adapter.ensureCompatible()).ok, true);
    const projection = await adapter.generateOrLoadProjection({ repositoryRoot: dir });
    assert.equal(projection.state, 'ready');
    assert.equal(projection.generationId, 'gen-p');
    assert.equal(projection.mode, 'precomputed');
    const freshness = await adapter.verifyFreshness({ repositoryRoot: dir, projection });
    assert.equal(freshness.fresh, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('precomputed mode fails cleanly when the path is missing', async () => {
  const adapter = new CortexAdapter({ mode: 'precomputed', precomputedPath: '/nonexistent/projection.json' });
  const compatible = await adapter.ensureCompatible();
  assert.equal(compatible.ok, false);
});

test('verifyFreshness reports stale for non-ready projections', async () => {
  const adapter = new CortexAdapter({ mode: 'external', externalCommand: 'cortex' });
  const freshness = await adapter.verifyFreshness({ repositoryRoot: '/tmp', projection: { state: 'unproven', reason: 'missing' } });
  assert.equal(freshness.fresh, false);
});

test('adapter never adds a parallel repository walker', () => {
  const adapter = new CortexAdapter({ mode: 'external', externalCommand: 'cortex' });
  // The adapter's contract is projection generation/loading only.
  assert.equal(typeof adapter.generateOrLoadProjection, 'function');
  assert.equal(typeof adapter.verifyFreshness, 'function');
  assert.equal(typeof adapter.readManifestBinding, 'function');
  assert.equal(typeof adapter.readProjection, 'function');
  assert.ok(!Object.keys(adapter).some((key) => /walk|discover/i.test(key)));
});
