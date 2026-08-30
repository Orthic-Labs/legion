import test from 'node:test';
import assert from 'node:assert/strict';
import { AcceptanceEvidenceRegistry, compareEvidenceCandidates } from '../src/lib/verification/arcane/evidence-registry.mjs';
import { ProviderCapabilityRegistry } from '../src/lib/verification/arcane/provider-capability.mjs';

test('evidence candidates fail mechanically-defined hard gates before scoring', () => {
  const result = compareEvidenceCandidates({
    candidates: [{ id: 'high-but-wrong-region', region: 'us', score: 99 }, { id: 'eligible', region: 'eu', score: 1 }],
    hardGates: [{ id: 'residency', field: 'region', equals: 'eu' }],
  });
  assert.equal(result.eliminated[0].candidate.id, 'high-but-wrong-region');
  assert.equal(result.eliminated[0].phase, 'HARD_GATE');
  assert.equal(result.ranked[0].candidate.id, 'eligible');
});

test('expired or drifted waivers stay visible & require refresh', () => {
  const registry = new AcceptanceEvidenceRegistry();
  assert.equal(registry.registerWaiver({ waiverId: 'W-1', acceptanceId: 'AC-1', reason: 'bounded exception', carrierState: { tree: 'before' }, issuedAt: '2026-08-01T00:00:00.000Z', validUntil: '2026-08-02T00:00:00.000Z' }).allowed, true);
  const waiver = registry.getWaiver('W-1', { now: new Date('2026-08-03T00:00:00.000Z'), carrierState: { tree: 'after' } });
  assert.equal(waiver.lifecycle, 'REFRESH_REQUIRED');
  assert.equal(waiver.visible, true);
  assert.equal(registry.evaluateWaiver('W-1', { now: new Date('2026-08-03T00:00:00.000Z') }).code, 'ARC_EVIDENCE_STALE');
});

test('provider gateability is derived from adapter-backed durable state', () => {
  const records = new Map();
  const registry = new ProviderCapabilityRegistry({ adapter: records });
  const capability = { adapterId: 'provider-cli-v1', machineReadable: true, gateable: true, downloadable: true, trustedRetrieval: true, trajectoryBindable: true };
  const stored = registry.record({ providerId: 'provider', adapter: capability, observedAt: '2026-08-01T00:00:00.000Z', retention: '7d', deletionOwner: 'privacy' });
  assert.equal(stored.allowed, true, stored.message);
  assert.equal(registry.verify('provider', { now: new Date('2026-08-01T01:00:00.000Z') }).allowed, true);
  assert.equal(new ProviderCapabilityRegistry({ adapter: new Map() }).verify('dashboard').detail.admission, 'INFORMATIONAL_ONLY');
});
