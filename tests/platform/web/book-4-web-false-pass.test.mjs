import assert from 'node:assert/strict';
import test from 'node:test';
import { runWebScenario } from '../../../providers/runtime/web/scenario/index.mjs';
import { verifyApiExercise } from '../../../providers/runtime/web/api/index.mjs';
import { verifyOperationsExercise } from '../../../providers/runtime/web/operations/index.mjs';
import { verifyThirdPartyExercise } from '../../../providers/runtime/web/third-party/index.mjs';
import { captureWebEvidence } from '../../../providers/runtime/web/capture/index.mjs';
import { compileWebMatrix } from '../../../providers/runtime/web/matrix/index.mjs';
import { buildActorFixtures } from '../../../providers/runtime/web/actors/index.mjs';
import { qualifyWebPlatform } from '../../../qualification/platforms/web/qualification.mjs';

const binding = Object.freeze({ targetId: 'web', environment: 'test', actorId: 'editor', tenantId: 'tenant-a', browser: 'chromium', browserVersion: '128', viewport: '1440x900', locale: 'en-GB', sourceRevision: 'abc', artifactDigest: 'sha256:artifact' });
const performance = { lcp: 1, longTasks: [], layoutShifts: [], paints: [], memory: 10, userTimings: [] };

test('scenario fails canonically contradictory expected, observed & durable state', async () => {
  const receipt = await runWebScenario({ binding, controls: ['forms'], expectedState: { value: 0, nested: { b: 2, a: 1 } }, adapter: { invoke: async () => ({ observedState: { nested: { a: 1, b: 2 }, value: false }, durableState: { value: 0, nested: { a: 1, b: 2 } } }) } });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.includes('control:forms:observed-state-mismatch'));
});

test('API expected exists=false rejects any observed or durable value property', () => {
  const receipt = verifyApiExercise({ binding, cases: [{ id: 'absent', protocol: 'rest', lifecycle: 'delete', actorId: 'editor', tenantId: 'tenant-a', dataScope: 'own', expected: { exists: false }, observed: { value: false }, durableEffect: { value: 0 }, boundaries: true, idempotency: true, pagination: true, retry: true, rateLimit: true, malformed: true, partialFailure: true }] });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.includes('absent:observed-value-present'));
  assert.ok(receipt.coverageGaps.includes('absent:durable-effect-present'));
});

test('operations explicit false alert, action & recovery outcomes cannot pass', () => {
  const receipt = verifyOperationsExercise({ binding, now: '2026-08-08T00:00:00.000Z', maxAgeMs: 60_000, exercises: [{ id: 'restore', binding, exercised: true, checkedAt: '2026-08-08T00:00:00.000Z', workload: 'w', dataset: 'd', region: 'r', providerLimits: {}, cost: {}, assumptions: [], alert: false, action: false, recovery: false, residualDamage: [] }] });
  assert.notEqual(receipt.status, 'pass');
  for (const gap of ['alert-not-observed', 'action-not-observed', 'recovery-not-observed']) assert.ok(receipt.coverageGaps.includes(`restore:${gap}`));
});

test('third-party invalid or future timestamps fail bounded freshness', () => {
  const receipt = verifyThirdPartyExercise({ binding, now: '2026-08-08T00:00:00.000Z', maxAgeMs: 60_000, applicableProviders: ['stripe'], exercises: [{ provider: 'stripe', environment: 'sandbox', binding, signed: true, issuedAt: 'not-a-date', checkedAt: '2026-08-08T00:01:00.000Z', expiresAt: '2026-08-07T00:00:00.000Z', client: 'ok', backend: 'ok', providerState: 'ok', userState: 'ok', consent: true, webhook: true, idempotency: true, quota: {}, cost: {} }] });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.some((gap) => gap.includes('timestamp-invalid')));
  assert.ok(receipt.coverageGaps.some((gap) => gap.includes('checked-in-future')));
});

test('capture duplicate repeat identities do not satisfy repeat denominator', () => {
  const base = { repeat: 1, screenshot: 's', dom: 'd', accessibilityTree: 'a', style: 'c', geometry: 'g', trace: 't', performance };
  const receipt = captureWebEvidence({ binding, surface: { id: 'home', route: '/', componentIds: ['hero'] }, tool: { name: 'playwright', version: '1', accessibilityEngine: 'ax', accessibilityEngineVersion: '1' }, captures: [base, { ...base, screenshot: 's2' }] });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.includes('capture-repeat-identities-not-unique'));
});

test('matrix passing combination cannot use unsupported browser capability', () => {
  const receipt = compileWebMatrix({ binding, capabilities: [{ id: 'chromium', status: 'unsupported', binding }], policy: { mandatoryDimensions: { browser: ['chromium'], browserVersion: ['128'], binary: ['stable'], device: ['desktop'], dpr: [1], input: ['mouse'], colorScheme: ['light'], contrast: ['normal'], motion: ['reduce'], locale: ['en-GB'], network: ['online'] }, pairwise: [['browser', 'device']], combinations: [{ id: 'bad', browser: 'chromium', browserVersion: '128', binary: 'stable', device: 'desktop', dpr: 1, input: 'mouse', colorScheme: 'light', contrast: 'normal', motion: 'reduce', locale: 'en-GB', network: 'online', status: 'pass' }], maxCombinations: 2 } });
  assert.equal(receipt.complete, false);
  assert.ok(receipt.coverageGaps.includes('browser-capability-unsupported-but-pass:chromium:bad'));
});

test('actors reject literal secret material & only emit typed reference identifiers', () => {
  const receipt = buildActorFixtures({ binding, required: [{ role: 'editor', tier: 'pro', tenantId: 'tenant-a', accountState: 'active' }], actors: [{ id: 'editor', role: 'editor', tier: 'pro', tenantId: 'tenant-a', accountState: 'active', secretRef: 'sk-live-literal-secret', serverAuthorizations: [], uiVisibility: [] }] });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.includes('credential-reference-invalid:editor'));
  assert.equal(JSON.stringify(receipt).includes('sk-live-literal-secret'), false);
});

test('qualification ignores fixture-declared raw path strings without produced digest+binding artifacts', () => {
  const receipt = qualifyWebPlatform({ binding, fixtures: [{ id: 'declared-only', applicableControls: ['x'], receipts: [{ controlId: 'x', targetId: 'web', status: 'pass', terminal: true, binding, artifacts: [] }], rawArtifacts: ['raw/fake.json'] }] });
  assert.deepEqual(receipt.rawArtifacts, []);
  assert.ok(receipt.coverageGaps.includes('declared-only:produced-artifact-missing'));
});
