import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  assembleContextPacket,
  assessPacketFreshness,
  bindCortexProjection,
  createCapabilityReport,
  createUnavailableContextAdapter,
  createContextReceipt,
  validateContextPacket,
  validateContextReceipt,
} from '../lib/context.mjs';

const fixtureUrl = new URL('../fixtures/cortex-projection.json', import.meta.url);
const DIGEST_A = `sha256:${'a'.repeat(64)}`;
const SOURCE = {
  id: 'src-1',
  origin: 'cortex',
  digest: DIGEST_A,
  generation: 'cortex:gen-1',
  revision: 'abcdef0',
  observedAt: '2026-08-08T00:00:00.000Z',
  trustClass: 'repository-fact',
  content: { path: 'src/example.mjs', lines: [1, 2] },
};

function packet() {
  return assembleContextPacket({
    runId: 'run_01ARZ3NDEKTSV4RRFFQ69G5FAV',
    consumer: 'sage',
    purpose: 'compile bug-fix contract',
    repositoryBinding: { repository: 'D:/Claude', revision: 'abcdef0' },
    sources: [SOURCE],
  });
}

test('assembles a structurally valid, digest-bound context packet', () => {
  const value = packet();
  assert.equal(validateContextPacket(value), true);
  assert.match(value.packetDigest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(value.sources[0].trustClass, 'repository-fact');
  assert.equal(packet().packetDigest, value.packetDigest);
  const slashPacket = assembleContextPacket({ ...value, sources: [{ ...SOURCE, content: 'src/example.mjs' }] });
  const backslashPacket = assembleContextPacket({ ...value, sources: [{ ...SOURCE, content: 'src\\example.mjs' }] });
  assert.notEqual(slashPacket.packetDigest, backslashPacket.packetDigest);
  assert.throws(() => validateContextPacket({ ...value, packetDigest: DIGEST_A }), /packetDigest mismatch/);
  assert.throws(() => assembleContextPacket({ ...value, consumer: 'alchemist' }), /consumer/);
  assert.throws(
    () => assembleContextPacket({ ...value, sources: [{ ...SOURCE, trustClass: 'trusted' }] }),
    /trustClass/,
  );
});

test('binds only a matching precomputed Cortex projection', async () => {
  const projection = JSON.parse(await readFile(fixtureUrl, 'utf8'));
  const available = bindCortexProjection(projection, projection.binding);
  assert.equal(available.status, 'available');
  assert.equal(available.generation, 'cortex:gen-1');

  assert.deepEqual(bindCortexProjection(null, projection.binding), {
    capability: 'cortex',
    status: 'absent',
    reason: 'projection-absent',
    stale: false,
    generation: null,
    projection: null,
  });

  const stale = bindCortexProjection(projection, { ...projection.binding, revision: 'fedcba9' });
  assert.equal(stale.status, 'degraded');
  assert.equal(stale.reason, 'repository-binding-mismatch');
  assert.equal(stale.stale, true);
  assert.equal(stale.projection, null);

  const emptyGenFallback = {
    schemaVersion: 1, binding: { repository: 'D:/Claude', revision: 'abcdef0' },
    generation: '', manifestDigest: DIGEST_A,
  };
  const bound = bindCortexProjection(emptyGenFallback, emptyGenFallback.binding);
  assert.equal(bound.status, 'available');
  assert.equal(bound.generation, DIGEST_A);
});

test('revision change invalidates packet and evidence-capability receipt', () => {
  const value = packet();
  const fresh = assessPacketFreshness(value, {
    revision: 'abcdef0',
    generations: { cortex: 'cortex:gen-1' },
  });
  assert.equal(fresh.stale, false);

  const changed = assessPacketFreshness(value, {
    revision: 'fedcba9',
    generations: { cortex: 'cortex:gen-1' },
  });
  assert.equal(changed.stale, true);
  assert.equal(changed.packet.stale, true);
  assert.equal(changed.mismatches[0].field, 'revision');

  const { receipt, receiptDigest } = createContextReceipt({
    packet: value,
    evidenceId: 'ev_01ARZ3NDEKTSV4RRFFQ69G5FAV',
    producerAuthority: 'legion',
    currentState: { revision: 'fedcba9', generations: { cortex: 'cortex:gen-1' } },
    observedAt: '2026-08-08T00:01:00.000Z',
  });
  assert.equal(receipt.kind, 'legion-evidence-capability-receipt');
  assert.equal(receipt.capability, 'context-assembly');
  assert.equal(receipt.stale, true);
  assert.equal(receipt.observation.consumer, 'sage');
  assert.equal(receipt.observation.packetDigest, value.packetDigest);
  assert.match(receiptDigest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(validateContextReceipt(receipt), true);
  assert.throws(() => validateContextReceipt({ ...receipt, producerAuthority: 'worker' }), /producerAuthority/);
});

test('reports capability degradation without silent upgrades', () => {
  const report = createCapabilityReport({
    cortex: { status: 'available', reason: null },
    memory: { status: 'absent', reason: 'adapter-not-wired' },
    externalEvidence: { status: 'degraded', reason: 'offline' },
  });
  assert.deepEqual(report, {
    cortex: { capability: 'cortex', status: 'available', reason: null },
    memory: { capability: 'memory', status: 'absent', reason: 'adapter-not-wired' },
    externalEvidence: { capability: 'external-evidence', status: 'degraded', reason: 'offline' },
  });
  assert.throws(
    () => createCapabilityReport({ cortex: { status: 'available' } }),
    /memory capability status is required/,
  );
});

test('Crypt interface remains a typed absence without live access', async () => {
  const adapter = createUnavailableContextAdapter('memory', 'crypt-not-wired');
  assert.deepEqual(adapter.capability, {
    capability: 'memory', status: 'absent', reason: 'crypt-not-wired',
  });
  assert.deepEqual(await adapter.read(), {
    status: 'absent', reason: 'crypt-not-wired', items: [],
  });
});