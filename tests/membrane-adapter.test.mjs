import assert from 'node:assert/strict';
import test from 'node:test';
import { MembraneAdapter } from '../src/lib/adapters/membrane/index.mjs';

const packet = Object.freeze({ schema: 'membrane.context-packet.v1', status: 'ready', packetDigest: 'sha256:packet' });

test('Membrane adapter reports typed absence without semantic fallback', async () => {
  const adapter = new MembraneAdapter();
  assert.equal((await adapter.ensureCompatible()).ok, false);
  assert.equal((await adapter.generateOrLoadProjection()).status, 'unavailable');
});

test('Membrane adapter transports Blueprint packet unchanged', async () => {
  const adapter = new MembraneAdapter({ transport: async () => packet });
  const result = await adapter.generateOrLoadProjection({ request: { root: '/repo' } });
  assert.strictEqual(result, packet);
  assert.deepEqual(await adapter.verifyFreshness({ packet: result }), { fresh: true, packetDigest: 'sha256:packet' });
});
