import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { runWebScenario } from '../../../providers/runtime/web/scenario/index.mjs';
import { verifyApiExercise } from '../../../providers/runtime/web/api/index.mjs';
import { verifyOperationsExercise } from '../../../providers/runtime/web/operations/index.mjs';
import { buildActorFixtures } from '../../../providers/runtime/web/actors/index.mjs';
import { qualifyWebPlatform } from '../../../qualification/platforms/web/qualification.mjs';

const binding = Object.freeze({ targetId: 'web', environment: 'test', actorId: 'editor', tenantId: 'tenant-a', browser: 'chromium', browserVersion: '128', viewport: '1440x900', locale: 'en-GB', sourceRevision: 'abc', artifactDigest: 'sha256:artifact' });
const completeRest = (item) => { const request = '{"request":"absent"}', response = '{"response":"absent"}', requestSchema = { id: 'absent:request', version: '1', digest: `sha256:${'a'.repeat(64)}` }, responseSchema = { id: 'absent:response', version: '1', digest: `sha256:${'b'.repeat(64)}` }, correlationId = 'corr-absent', rawBinding = { caseId: item.id, protocol: item.protocol, method: 'DELETE', path: '/items/absent', operation: null, correlationId }; return { ...item, method: 'DELETE', path: '/items/absent', requestSchema, responseSchema, compatibility: { status: 'compatible', requestDigest: requestSchema.digest, responseDigest: responseSchema.digest }, expectedError: null, observedError: null, correlationId, dependencyBehavior: { status: 'pass', terminal: true, dependencies: [], binding }, rawArtifacts: [{ kind: 'request', ...rawBinding, redacted: true, content: request, digest: `sha256:${createHash('sha256').update(request).digest('hex')}`, binding }, { kind: 'response', ...rawBinding, redacted: true, content: response, digest: `sha256:${createHash('sha256').update(response).digest('hex')}`, binding }] }; };

test('scenario requires canonical deep equality including exact object keys', async () => {
  const receipt = await runWebScenario({ binding, controls: ['forms'], expectedState: { saved: true }, adapter: { invoke: async () => ({ observedState: { saved: true, extra: true }, durableState: { saved: true } }) } });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.includes('control:forms:observed-state-mismatch'));
});

test('API present contract requires exists=true plus present equal values', () => {
  const receipt = verifyApiExercise({ binding, cases: [{ id: 'present', protocol: 'rest', lifecycle: 'read', actorId: 'editor', tenantId: 'tenant-a', dataScope: 'own', expected: { exists: true, value: 0 }, observed: { exists: false, value: 0 }, durableEffect: { exists: false, value: 0 }, boundaries: true, idempotency: true, pagination: true, retry: true, rateLimit: true, malformed: true, partialFailure: true }] });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.includes('present:observed-exists-not-true'));
  assert.ok(receipt.coverageGaps.includes('present:durable-exists-not-true'));
});

test('API absent contract requires exists=false plus absent value properties', () => {
  const receipt = verifyApiExercise({ binding, cases: [completeRest({ id: 'absent', protocol: 'rest', lifecycle: 'delete', actorId: 'editor', tenantId: 'tenant-a', dataScope: 'own', expected: { exists: false }, observed: { exists: false }, durableEffect: { exists: false }, boundaries: true, idempotency: true, pagination: true, retry: true, rateLimit: true, malformed: true, partialFailure: true })] });
  assert.equal(receipt.status, 'pass');
});

test('operations rejects invalid/future/unordered UTC lifecycle evidence', () => {
  const receipt = verifyOperationsExercise({ binding, now: '2026-08-08T00:00:00.000Z', maxAgeMs: 60_000, exercises: [{ id: 'restore', binding, issuedAt: '2026-08-08T00:02:00.000Z', checkedAt: 'not-utc', expiresAt: '2026-08-07T00:00:00.000Z', exercised: true, workload: 'w', dataset: 'd', region: 'r', providerLimits: {}, cost: {}, assumptions: [], alert: true, action: true, recovery: true, residualDamage: [] }] });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.some((gap) => gap.includes('checkedAt-timestamp-invalid')));
});

test('qualification recomputes artifact digest from content & rejects foreign binding', () => {
  const artifact = { path: 'raw/fake.json', family: 'web', digest: `sha256:${'0'.repeat(64)}`, binding: { ...binding, targetId: 'foreign' }, content: '{"claimed":true}' };
  const receipt = qualifyWebPlatform({ binding, fixtures: [{ id: 'foreign', family: 'web', applicableControls: ['x'], receipts: [{ controlId: 'x', targetId: 'web', status: 'pass', terminal: true, binding, artifacts: [artifact] }] }] });
  assert.deepEqual(receipt.rawArtifacts, []);
  assert.ok(receipt.coverageGaps.includes('foreign:produced-artifact-invalid'));
});

test('actor expiry/revocation timestamps are finite UTC & causally ordered', () => {
  const receipt = buildActorFixtures({ binding, now: '2026-08-08T00:00:00.000Z', required: [{ role: 'editor', tier: 'pro', tenantId: 'tenant-a', accountState: 'revoked' }], actors: [{ id: 'editor', role: 'editor', tier: 'pro', tenantId: 'tenant-a', accountState: 'revoked', secretRef: 'vault://actors/editor', issuedAt: '2026-08-09T00:00:00.000Z', expiresAt: 'not-a-date', revokedAt: '2026-08-10T00:00:00.000Z', serverAuthorizations: [], uiVisibility: [] }] });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.includes('credential-expiresAt-timestamp-invalid:editor'));
  assert.ok(receipt.coverageGaps.includes('credential-revoked-in-future:editor'));
});
