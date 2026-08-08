import assert from 'node:assert/strict';
import test from 'node:test';
import { buildActorFixtures } from '../../../providers/runtime/web/actors/index.mjs';
import { compileWebMatrix } from '../../../providers/runtime/web/matrix/index.mjs';
import { runWebScenario } from '../../../providers/runtime/web/scenario/index.mjs';
import { captureWebEvidence } from '../../../providers/runtime/web/capture/index.mjs';
import { verifyApiExercise } from '../../../providers/runtime/web/api/index.mjs';
import { verifyThirdPartyExercise } from '../../../providers/runtime/web/third-party/index.mjs';
import { verifyOperationsExercise } from '../../../providers/runtime/web/operations/index.mjs';
import { executeWebProtocol } from '../../../providers/runtime/web/protocols/index.mjs';
import { runWebControl } from '../../../providers/runtime/web/runner/index.mjs';
import { inspectWebBackend } from '../../../providers/runtime/web/backend/index.mjs';
import { verifyServiceApi } from '../../../providers/runtime/service/api/index.mjs';
import * as webProvider from '../../../providers/runtime/web/index.mjs';
import { createWebQualificationFixtures } from '../../../qualification/platforms/web/fixtures.mjs';
import { qualifyWebPlatform } from '../../../qualification/platforms/web/qualification.mjs';
import { qualifyWebPlatformFile } from '../../../scripts/qualify-web-platform.mjs';

const binding = Object.freeze({ targetId: 'web', environment: 'test', actorId: 'editor', tenantId: 'tenant-a', browser: 'chromium', browserVersion: '128', viewport: '1440x900', locale: 'en-GB', sourceRevision: 'abc', artifactDigest: 'sha256:artifact' });

test('scenario cannot pass absent observed/durable state or unexercised applicable protocol', async () => {
  const receipt = await runWebScenario({ binding, controls: ['forms'], protocols: [{ name: 'http', applicable: true }], adapter: { invoke: async () => ({}) }, expectedState: { saved: true } });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.some((gap) => gap.includes('observed-state-missing')));
  assert.ok(receipt.coverageGaps.some((gap) => gap.includes('durable-state-missing')));
  assert.ok(receipt.coverageGaps.some((gap) => gap.includes('protocol-unexercised')));
});

test('matrix rejects wrong values, absent pairwise coverage & mismatched capability binding', () => {
  const receipt = compileWebMatrix({ binding, capabilities: [{ id: 'chromium', status: 'available', binding: { ...binding, targetId: 'other' } }], policy: { mandatoryDimensions: { browser: ['chromium', 'firefox'], browserVersion: ['128'], binary: ['stable'], device: ['desktop'], dpr: [1], input: ['mouse'], colorScheme: ['light'], contrast: ['normal'], motion: ['reduce'], locale: ['en-GB'], network: ['online'] }, pairwise: [['browser', 'device']], combinations: [{ id: 'bad', browser: 'webkit', browserVersion: '127', binary: 'beta', device: 'phone', dpr: 2, input: 'touch', colorScheme: 'dark', contrast: 'high', motion: 'full', locale: 'fr', network: 'offline', status: 'pass' }], maxCombinations: 4 } });
  assert.equal(receipt.complete, false);
  assert.ok(receipt.coverageGaps.some((gap) => gap.startsWith('dimension-value-outside-policy:')));
  assert.ok(receipt.coverageGaps.includes('pairwise-uncovered:browser=chromium:device=desktop'));
  assert.ok(receipt.coverageGaps.includes('capability-binding-mismatch:chromium'));
});

test('actors reject empty requirements & block unavailable identity/environment exactly', () => {
  assert.notEqual(buildActorFixtures({ binding, actors: [], required: [] }).status, 'pass');
  const blocked = buildActorFixtures({ binding, required: [{ role: 'editor', tier: 'pro', tenantId: 'tenant-a', accountState: 'active' }], identityCapability: { status: 'unavailable' }, environmentCapability: { status: 'permission-denied' } });
  assert.equal(blocked.status, 'blocked');
  assert.equal(blocked.terminal, true);
  assert.deepEqual(blocked.coverageGaps, ['environment-capability-permission-denied', 'identity-capability-unavailable']);
});

test('capture rejects thin runtime and absent versioned accessibility engine/performance families', () => {
  const receipt = captureWebEvidence({ binding, surface: { id: 'x', route: '/', componentIds: ['x'] }, tool: { name: 'browser', version: '1' }, captures: [{ repeat: 1, screenshot: 'x', dom: 'x', accessibilityTree: 'x', style: 'x', geometry: 'x', trace: 'x', performance: { lcp: 1 } }, { repeat: 2, screenshot: 'y', dom: 'y', accessibilityTree: 'y', style: 'y', geometry: 'y', trace: 'y', performance: { lcp: 2 } }] });
  assert.notEqual(receipt.status, 'pass');
  for (const key of ['accessibility-engine-unversioned', 'longTasks', 'layoutShifts', 'paints', 'memory', 'userTimings']) assert.ok(receipt.coverageGaps.some((gap) => gap.includes(key)));
});

test('API mismatch, missing resilience & absent values cannot pass', () => {
  const receipt = verifyApiExercise({ binding, cases: [{ id: 'x', protocol: 'rest', lifecycle: 'create', actorId: 'editor', tenantId: 'tenant-a', dataScope: 'own', expected: { exists: true, value: 1 }, observed: { value: 2 }, durableEffect: {}, boundaries: true, idempotency: false }] });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.some((gap) => gap.includes('observed-value-mismatch')));
  assert.ok(receipt.coverageGaps.some((gap) => gap.includes('durable-effect-missing')));
  assert.ok(receipt.coverageGaps.some((gap) => gap.includes('retry-unproven')));
});

test('third-party rejects stale/unsigned/cross-bound & divergent state or false controls', () => {
  const receipt = verifyThirdPartyExercise({ binding, now: '2026-08-08T00:02:00.000Z', maxAgeMs: 60_000, applicableProviders: ['stripe'], exercises: [{ provider: 'stripe', environment: 'sandbox', binding: { ...binding, targetId: 'other' }, signed: false, checkedAt: '2026-08-08T00:00:00.000Z', client: 'ok', backend: 'ok', providerState: 'failed', userState: 'ok', consent: false, webhook: false, idempotency: false, quota: {}, cost: {} }] });
  assert.notEqual(receipt.status, 'pass');
  for (const gap of ['binding-mismatch', 'signature-unproven', 'evidence-stale', 'state-divergence', 'consent-unproven', 'webhook-unproven', 'idempotency-unproven']) assert.ok(receipt.coverageGaps.some((item) => item.includes(gap)));
});

test('operations rejects absent freshness & cross-release/environment evidence', () => {
  const receipt = verifyOperationsExercise({ binding, exercises: [{ id: 'restore', binding: { ...binding, environment: 'prod', artifactDigest: 'sha256:other' }, exercised: true, workload: 'w', dataset: 'd', region: 'r', providerLimits: {}, cost: {}, assumptions: [], alert: true, action: true, recovery: true, residualDamage: [] }] });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.some((gap) => gap.includes('freshness-unbound')));
  assert.ok(receipt.coverageGaps.some((gap) => gap.includes('binding-mismatch')));
});

test('owned web runner/protocol/backend/service paths delegate to real evidence contracts', async () => {
  assert.equal(typeof webProvider.runWebControl, 'function');
  assert.equal(typeof qualifyWebPlatformFile, 'function');
  const protocol = await executeWebProtocol({ binding, protocol: 'http', adapter: { execute: async () => ({ observedState: { ok: true }, durableState: { ok: true } }) } });
  assert.equal(protocol.status, 'pass');
  const run = await runWebControl({ binding, family: 'protocol', input: { protocol: 'http', adapter: { execute: async () => ({ observedState: { ok: true }, durableState: { ok: true } }) } } });
  assert.equal(run.status, 'pass');
  assert.equal(inspectWebBackend({ binding, endpoints: [{ id: 'health', method: 'GET', path: '/health' }] }).denominator.accounted, 1);
  assert.equal(verifyServiceApi({ binding, cases: [] }).provider, 'runtime.service.api');
});

test('fixture qualification covers planted/clean/mitigated/missing/stale/multi-target with exact provisional ceiling', () => {
  const fixtures = createWebQualificationFixtures({ binding });
  assert.deepEqual(fixtures.map((item) => item.id), ['clean', 'mitigated', 'missing', 'multi-target', 'planted', 'stale']);
  const receipt = qualifyWebPlatform({ binding, fixtures });
  assert.equal(receipt.denominator.total, 6);
  assert.equal(receipt.denominator.accounted, 6);
  assert.equal(receipt.claimLevel, 'source');
  assert.equal(receipt.provisional, true);
  assert.equal(receipt.rawArtifacts.length, 3);
  assert.equal(receipt.rejectedArtifacts.length, 2);
  assert.equal(receipt.receipts.find((item) => item.id === 'multi-target').status, 'error');
});
