import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { MembraneAdapter } from '../src/lib/adapters/membrane/index.mjs';

const packet = Object.freeze({ schema: 'membrane.context-packet.v1', status: 'ready', packetDigest: 'sha256:packet' });

test('Membrane adapter exposes bounded one-shot mode without resident transport', async () => {
  const adapter = new MembraneAdapter({ blueprintBin: '/missing/blueprint' });
  assert.deepEqual(await adapter.ensureCompatible(), { ok: true, mode: 'bounded-one-shot', provider: 'membrane' });
  assert.equal((await adapter.generateOrLoadProjection()).status, 'unavailable');
});

test('Membrane adapter transports Blueprint packet unchanged', async () => {
  const adapter = new MembraneAdapter({ transport: async () => packet });
  const result = await adapter.generateOrLoadProjection({ request: { root: '/repo' } });
  assert.strictEqual(result, packet);
  assert.deepEqual(await adapter.verifyFreshness({ packet: result }), { fresh: true, packetDigest: 'sha256:packet' });
});

test('Membrane adapter uses bounded one-shot when resident reports enrollment absence', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'legion-membrane-one-shot-'));
  const bin = join(dir, 'blueprint');
  const payload = {
    schema: 'membrane.blueprint-packet.v1',
    status: 'ready',
    state: 'ready',
    generationId: 'one-shot-generation',
    manifestDigest: `sha256:${'d'.repeat(64)}`,
    files: ['src/main.rs'],
  };
  writeFileSync(bin, `#!/usr/bin/env node\nconsole.log(${JSON.stringify(JSON.stringify(payload))});\n`);
  chmodSync(bin, 0o755);
  try {
    const adapter = new MembraneAdapter({
      transport: async () => ({ schema: 'legion.context-result.v1', status: 'unavailable', reason: 'root_not_enrolled' }),
      blueprintBin: bin,
      outDir: '.audit/blueprint',
      timeoutMs: 1000,
    });
    const result = await adapter.generateOrLoadProjection({ request: { root: process.cwd() } });
    assert.equal(result.status, 'ready');
    assert.equal(result.generationId, 'one-shot-generation');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
