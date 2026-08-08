import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import test from 'node:test';
import { compileWebMatrix } from '../../../providers/runtime/web/matrix/index.mjs';
import { runWebScenario } from '../../../providers/runtime/web/scenario/index.mjs';
import { inspectWebBackend } from '../../../providers/runtime/web/backend/index.mjs';
import { executeWebProtocol } from '../../../providers/runtime/web/protocols/index.mjs';
import { captureWebEvidence } from '../../../providers/runtime/web/capture/index.mjs';
import { verifyApiExercise } from '../../../providers/runtime/web/api/index.mjs';
import { buildActorFixtures } from '../../../providers/runtime/web/actors/index.mjs';
import { verifyWebPerformance } from '../../../providers/runtime/web/performance/index.mjs';
import { verifyWebAccessibility } from '../../../providers/runtime/web/accessibility/index.mjs';
import { importExternalEvidence } from '../../../providers/runtime/external-evidence/index.mjs';
import { verifyOperationsExercise } from '../../../providers/runtime/web/operations/index.mjs';
import { verifyThirdPartyExercise } from '../../../providers/runtime/web/third-party/index.mjs';
import { integrateWebEvidence } from '../../../providers/runtime/web/integration/index.mjs';
import { qualifyWebPlatform } from '../../../qualification/platforms/web/qualification.mjs';
import { exactBinding } from '../../../providers/runtime/web/shared.mjs';
import { validateExternalEvidence } from '../../../lib/platform/external/validate.mjs';

const binding = Object.freeze({ targetId: 'web', environment: 'test', actorId: 'editor', tenantId: 'tenant-a', browser: 'chromium', browserVersion: '128', viewport: '1440x900', locale: 'en-GB', sourceRevision: 'abc', artifactDigest: 'sha256:artifact' });
const tool = { name: 'playwright', version: '1', accessibilityEngine: 'ax', accessibilityEngineVersion: '1' };
const perf = { lcp: 100, longTasks: [], layoutShifts: [], paints: [], memory: 10, userTimings: [] };
const capture = (repeat, suffix = repeat) => ({ repeat, screenshot: `s${suffix}`, dom: `d${suffix}`, accessibilityTree: `a${suffix}`, style: `c${suffix}`, geometry: `g${suffix}`, trace: `t${suffix}`, performance: perf });
const apiCase = (id, extra = {}) => ({ id, protocol: 'rest', lifecycle: 'read', actorId: 'editor', tenantId: 'tenant-a', dataScope: 'own', expected: { exists: true, value: 0 }, observed: { exists: true, value: 0 }, durableEffect: { exists: true, value: 0 }, boundaries: true, idempotency: true, pagination: true, retry: true, rateLimit: true, malformed: true, partialFailure: true, ...extra });
const artifact = (content, artifactBinding = binding, family = 'web') => ({ path: `raw/${createHash('sha256').update(content).digest('hex').slice(0, 8)}.json`, family, content, digest: `sha256:${createHash('sha256').update(content).digest('hex')}`, binding: artifactBinding });
const fixture = (id, content) => ({ id, family: 'web', applicableControls: ['x'], receipts: [{ controlId: 'x', targetId: 'web', status: 'pass', terminal: true, binding, artifacts: [artifact(content)] }] });

test('empty matrix/scenario/backend denominators cannot pass', async () => {
  const matrix = compileWebMatrix({ binding, policy: { combinations: [], maxCombinations: 1 } });
  assert.equal(matrix.complete, false); assert.ok(matrix.coverageGaps.includes('matrix-denominator-empty'));
  const scenario = await runWebScenario({ binding, controls: [], protocols: [] });
  assert.notEqual(scenario.status, 'pass'); assert.ok(scenario.coverageGaps.includes('scenario-denominator-empty'));
  const backend = inspectWebBackend({ binding, endpoints: [] });
  assert.notEqual(backend.status, 'pass'); assert.ok(backend.coverageGaps.includes('backend-denominator-empty'));
});

test('protocol null state or pending status cannot pass', async () => {
  const nullState = await executeWebProtocol({ binding, protocol: 'http', adapter: { execute: async () => ({ status: 'pass', observedState: null, durableState: null }) } });
  assert.notEqual(nullState.status, 'pass');
  const pending = await executeWebProtocol({ binding, protocol: 'http', adapter: { execute: async () => ({ status: 'pending', observedState: {}, durableState: {} }) } });
  assert.notEqual(pending.status, 'pass'); assert.ok(pending.coverageGaps.includes('protocol-status-pending'));
});

test('capture rejects false/zero/empty artifacts & repeated produced evidence identities', () => {
  const thin = { repeat: 1, screenshot: false, dom: '', accessibilityTree: 0, style: false, geometry: '', trace: 0, performance: { lcp: false, longTasks: false, layoutShifts: false, paints: false, memory: false, userTimings: false } };
  assert.notEqual(captureWebEvidence({ binding, surface: { id: 'x', route: '/', componentIds: ['x'] }, tool, captures: [thin, { ...thin, repeat: 2 }] }).status, 'pass');
  const duplicateEvidence = captureWebEvidence({ binding, surface: { id: 'x', route: '/', componentIds: ['x'] }, tool, captures: [capture(1, 'same'), capture(2, 'same')] });
  assert.notEqual(duplicateEvidence.status, 'pass'); assert.ok(duplicateEvidence.coverageGaps.includes('capture-evidence-identities-not-unique'));
});

test('duplicate/missing IDs & binding mismatches fail API, actors, matrix, backend & scenario', async () => {
  const api = verifyApiExercise({ binding, cases: [apiCase('dup', { actorId: 'other', tenantId: 'other' }), apiCase('dup'), apiCase(undefined)] });
  for (const gap of ['api-case-id-missing', 'api-case-id-duplicate:dup', 'dup:actor-binding-mismatch', 'dup:tenant-binding-mismatch']) assert.ok(api.coverageGaps.includes(gap));
  const actors = buildActorFixtures({ binding, now: '2026-08-08T00:00:00.000Z', required: [{ role: 0, tier: false, tenantId: 'tenant-a', accountState: 'active' }], actors: [{ id: 0, role: 0, tier: false, tenantId: 'tenant-a', accountState: 'active', secretRef: 'vault://actors/x', expiresAt: '2026-08-09T00:00:00.000Z' }, { id: 0, role: 0, tier: false, tenantId: 'tenant-a', accountState: 'active', secretRef: 'vault://actors/y', expiresAt: '2026-08-09T00:00:00.000Z' }] });
  assert.notEqual(actors.status, 'pass'); assert.ok(actors.coverageGaps.includes('actor-id-duplicate:0'));
  const combo = { id: 'dup', browser: 'chromium', status: 'pass' };
  assert.ok(compileWebMatrix({ binding, capabilities: [{ id: 'chromium', status: 'available', binding }], policy: { combinations: [combo, combo], maxCombinations: 3 } }).coverageGaps.includes('matrix-id-duplicate:dup'));
  assert.ok(inspectWebBackend({ binding, endpoints: [{ id: 'dup', method: 'GET', path: '/a' }, { id: 'dup', method: 'GET', path: '/b' }] }).coverageGaps.includes('backend-id-duplicate:dup'));
  assert.ok((await runWebScenario({ binding, controls: ['save', 'save'], expectedState: {}, adapter: { invoke: async () => ({ observedState: {}, durableState: {} }) } })).coverageGaps.includes('scenario-id-duplicate:control:save'));
});

test('exact binding rejects false/zero required values & actor clock omission cannot pass expired fixture', () => {
  assert.ok(exactBinding({ ...binding, targetId: false, environment: 0 }).gaps.includes('targetId'));
  const expired = buildActorFixtures({ binding, required: [{ role: 'editor', tier: 'pro', tenantId: 'tenant-a', accountState: 'active' }], actors: [{ id: 'editor', role: 'editor', tier: 'pro', tenantId: 'tenant-a', accountState: 'active', secretRef: 'vault://actors/editor', expiresAt: '2020-01-01T00:00:00.000Z' }] });
  assert.notEqual(expired.status, 'pass'); assert.ok(expired.coverageGaps.includes('actor-clock-unbound'));
});

test('performance boolean budgets & accessibility false/wrong-bound/pending evidence cannot pass', () => {
  const input = { binding, surface: { id: 'x', route: '/', componentIds: ['x'] }, tool, captures: [capture(1), capture(2)] };
  const performance = verifyWebPerformance({ ...input, budgets: { longTasks: false } });
  assert.notEqual(performance.status, 'pass'); assert.ok(performance.coverageGaps.includes('budget-invalid:longTasks'));
  const accessibility = verifyWebAccessibility({ ...input, inspections: [{ repeat: 1, status: 'pending', binding: { ...binding, targetId: 'other' }, screenshot: false, violations: [] }, { repeat: 2, status: 'pass', binding, screenshot: true, violations: [] }] });
  assert.notEqual(accessibility.status, 'pass');
  assert.ok(accessibility.coverageGaps.includes('accessibility-binding-mismatch:1'));
  assert.ok(accessibility.coverageGaps.includes('accessibility-status-pending:1'));
  assert.ok(accessibility.coverageGaps.includes('accessibility-screenshot-invalid:1'));
});

test('generic external import rejects empty & unsigned forged evidence', () => {
  assert.notEqual(importExternalEvidence({ evidence: [], expected: binding }).status, 'pass');
  const forged = { producer: 'ci', scope: 'deploy', environment: 'test', binding, targetId: 'web', artifactDigest: 'sha256:artifact' };
  assert.notEqual(importExternalEvidence({ evidence: [forged], expected: binding }).status, 'pass');
});

test('operations rejects unsigned/duplicate IDs & digest is order-stable', () => {
  const row = (workload) => ({ id: 'dup', binding, issuedAt: '2026-08-07T23:59:00.000Z', checkedAt: '2026-08-08T00:00:00.000Z', expiresAt: '2026-08-09T00:00:00.000Z', exercised: true, workload, dataset: 'd', region: 'r', providerLimits: {}, cost: {}, assumptions: [], alert: true, action: true, recovery: true, residualDamage: [] });
  const a = verifyOperationsExercise({ binding, now: '2026-08-08T00:00:00.000Z', maxAgeMs: 60_000, exercises: [row('a'), row('b')] });
  const b = verifyOperationsExercise({ binding, now: '2026-08-08T00:00:00.000Z', maxAgeMs: 60_000, exercises: [row('b'), row('a')] });
  assert.notEqual(a.status, 'pass'); assert.ok(a.coverageGaps.includes('operation-id-duplicate:dup')); assert.ok(a.coverageGaps.includes('operation-signature-unproven:dup')); assert.equal(a.digest, b.digest);
});

test('integration rejects empty binding & non-applicable receipt artifacts', () => {
  const empty = integrateWebEvidence({ binding: {}, applicableControls: ['x'], receipts: [{ controlId: 'x', targetId: undefined, status: 'pass', terminal: true, binding: {} }] });
  assert.notEqual(empty.status, 'pass');
  const integrated = integrateWebEvidence({ binding, applicableControls: ['x'], receipts: [{ controlId: 'x', targetId: 'web', status: 'pass', terminal: true, binding, artifacts: ['raw/x.json'] }, { controlId: 'y', targetId: 'web', status: 'pass', terminal: true, binding, artifacts: ['raw/y.json'] }] });
  assert.ok(integrated.coverageGaps.includes('non-applicable-receipt:y')); assert.ok(integrated.coverageGaps.includes('artifact-invalid:x')); assert.deepEqual(integrated.rawArtifacts, []);
});

test('qualification rejects empty/duplicate/malformed fixtures & invalid artifact forms deterministically', () => {
  assert.notEqual(qualifyWebPlatform({ binding, fixtures: [] }).status, 'pass');
  const left = qualifyWebPlatform({ binding, fixtures: [fixture('dup', 'a'), fixture('dup', 'b')] });
  const right = qualifyWebPlatform({ binding, fixtures: [fixture('dup', 'b'), fixture('dup', 'a')] });
  assert.ok(left.coverageGaps.includes('fixture-id-duplicate:dup')); assert.equal(left.digest, right.digest);
  assert.doesNotThrow(() => qualifyWebPlatform({ binding, fixtures: [{ id: 'missing', family: 'web', applicableControls: ['x'] }] }));
  const conflict = artifact('x'); conflict.bytesBase64 = Buffer.from('different').toString('base64');
  const invalid = qualifyWebPlatform({ binding, fixtures: [{ id: 'invalid', family: 'other', applicableControls: ['x'], receipts: [{ controlId: 'y', targetId: 'web', status: 'pass', terminal: true, binding, artifacts: [artifact('', binding, 'other'), conflict] }] }] });
  assert.deepEqual(invalid.rawArtifacts, []); assert.notEqual(invalid.status, 'pass');
});

test('duplicate configured provider keys or adapter IDs are rejected', () => {
  const base = { adapterKey: 'stripe', provider: 'stripe', environment: 'sandbox', binding, signed: true, issuedAt: '2026-08-07T23:59:00.000Z', checkedAt: '2026-08-08T00:00:00.000Z', expiresAt: '2026-08-09T00:00:00.000Z', client: 'ok', backend: 'ok', providerState: 'ok', userState: 'ok', consent: true, webhook: true, idempotency: true, quota: {}, cost: {} };
  const receipt = verifyThirdPartyExercise({ binding, now: '2026-08-08T00:00:00.000Z', maxAgeMs: 60_000, configuredProviders: [{ key: 'stripe', adapterId: 'same' }, { key: 'stripe', adapterId: 'other' }, { key: 'mail', adapterId: 'same' }], applicableProviders: ['stripe'], exercises: [base] });
  assert.notEqual(receipt.status, 'pass'); assert.ok(receipt.coverageGaps.includes('provider-config-key-duplicate:stripe')); assert.ok(receipt.coverageGaps.includes('provider-config-adapter-duplicate:same'));
});

test('qualification propagates non-pass applicable control status despite valid artifact bytes', () => {
  const receipt = qualifyWebPlatform({ binding, fixtures: [{ ...fixture('failed-control', 'valid-bytes'), receipts: [{ controlId: 'x', targetId: 'web', status: 'fail', terminal: true, binding, artifacts: [artifact('valid-bytes')] }] }] });
  assert.notEqual(receipt.status, 'pass');
  assert.equal(receipt.receipts[0].status, 'partial');
  assert.ok(receipt.coverageGaps.includes('failed-control:integrated-status:partial'));
});

test('signed external evidence still rejects expired or cross-bound envelope semantics', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const producer = 'ci';
  const content = 'deployed bytes';
  const produced = { path: 'raw/external/deploy.json', content, digest: `sha256:${createHash('sha256').update(content).digest('hex')}`, binding };
  const payload = { producer, scope: 'deploy', targetId: 'web', environment: 'test', artifactDigest: binding.artifactDigest, controlId: 'deploy', binding, issuedAt: '2020-01-01T00:00:00.000Z', checkedAt: '2020-01-02T00:00:00.000Z', expiresAt: '2020-01-03T00:00:00.000Z', artifacts: [produced], exerciseReceipt: { controlId: 'deploy', status: 'pass', terminal: true, binding } };
  const signedContent = JSON.stringify(payload);
  const signature = sign(null, Buffer.from(signedContent), privateKey).toString('base64');
  const expected = { targetId: 'web', environment: 'test', artifactDigest: binding.artifactDigest, controlId: 'deploy', binding, requiresExercise: true, now: '2026-08-08T00:00:00.000Z', maxAgeMs: 60_000, trustedProducers: [{ id: producer, publicKey: publicKey.export({ type: 'spki', format: 'pem' }) }] };
  const envelope = { ...payload, artifacts: undefined, exerciseReceipt: undefined, signedContent, signature };
  const expired = validateExternalEvidence(envelope, expected);
  assert.notEqual(expired.status, 'pass'); assert.ok(expired.gaps.includes('evidence-expired'));
  const crossBound = validateExternalEvidence({ ...envelope, environment: 'production', binding: { ...binding, tenantId: 'other' } }, { ...expected, now: '2020-01-02T00:00:00.000Z', maxAgeMs: 86_400_000 });
  assert.notEqual(crossBound.status, 'pass'); assert.ok(crossBound.gaps.includes('envelope-environment-mismatch')); assert.ok(crossBound.gaps.includes('envelope-binding-mismatch'));
});
