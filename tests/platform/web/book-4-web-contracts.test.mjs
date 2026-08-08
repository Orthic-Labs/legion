import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { buildActorFixtures, switchActor } from '../../../providers/runtime/web/actors/index.mjs';
import { compileWebMatrix } from '../../../providers/runtime/web/matrix/index.mjs';
import { runWebScenario } from '../../../providers/runtime/web/scenario/index.mjs';
import { captureWebEvidence } from '../../../providers/runtime/web/capture/index.mjs';
import { verifyApiExercise } from '../../../providers/runtime/web/api/index.mjs';
import { verifyDataExercise } from '../../../providers/runtime/web/data/index.mjs';
import { verifyInfrastructureExercise } from '../../../providers/runtime/web/infrastructure/index.mjs';
import { verifyThirdPartyExercise } from '../../../providers/runtime/web/third-party/index.mjs';
import { verifyOperationsExercise } from '../../../providers/runtime/web/operations/index.mjs';
import { integrateWebEvidence } from '../../../providers/runtime/web/integration/index.mjs';
import { digest, redact } from '../../../providers/runtime/web/shared.mjs';
import { executeWebProtocol } from '../../../providers/runtime/web/protocols/index.mjs';
import { verifyWebAccessibility } from '../../../providers/runtime/web/accessibility/index.mjs';

const binding = Object.freeze({ targetId: 'web', environment: 'test', actorId: 'editor', tenantId: 'tenant-a', browser: 'chromium', browserVersion: '128', viewport: '1440x900', locale: 'en-GB', sourceRevision: 'abc', artifactDigest: 'sha256:artifact' });
const scenarioControls = ['direct-link', 'deep-link', 'history', 'refresh', 'tabs', 'forms', 'uploads', 'concurrency', 'cancel', 'connectivity', 'auth-expiry', 'error'];
const canonicalCaptureSurface = Object.freeze({ id: 'control:direct-link', journeyId: 'control:direct-link', controlId: 'direct-link', routeId: 'route:home', route: '/', stateId: 'loaded', actionId: 'action:navigate-direct', protocolId: 'http', directApplicable: true, deepApplicable: false, matrixCombinationId: 'desktop-chromium', binding, componentIds: ['hero'] });
const captureSample = (repeat) => ({ repeat, screenshot: `s${repeat}`, dom: `d${repeat}`, accessibilityTree: `a${repeat}`, style: `c${repeat}`, geometry: `g${repeat}`, trace: `t${repeat}`, performance: { lcp: 1000 + repeat, longTasks: [0], layoutShifts: [0], paints: [0], memory: 10, userTimings: [0] } });
const matrixObservations = (plan, vitalIds) => plan.combinations.map((definition) => ({ ...definition, binding, status: 'pass', terminal: true, ...(vitalIds.has(definition.id) ? { vitals: { cls: 0.01, inp: 100, lcp: 1000, binding } } : {}) }));
const dataDefinition = ({ id = 'query', dataset = 'seed', schemaVersion = '1' } = {}) => ({ id, operationType: 'query', dataset: { id: dataset, digest: `sha256:${'a'.repeat(64)}` }, schema: { version: schemaVersion, digest: `sha256:${'b'.repeat(64)}` }, engine: { name: 'sqlite', version: '3', digest: `sha256:${'c'.repeat(64)}` }, isolation: { id: `tx-${id}`, environment: binding.environment, binding }, cleanupBinding: { datasetId: dataset, schemaVersion, environment: binding.environment, binding }, statementDigest: `sha256:${'d'.repeat(64)}` });
const apiContract = (item) => {
  const requestContent = JSON.stringify({ caseId: item.id, direction: 'request' });
  const responseContent = JSON.stringify({ caseId: item.id, direction: 'response' });
  const requestSchema = { id: `${item.id}:request`, version: '1', digest: `sha256:${'a'.repeat(64)}` };
  const responseSchema = { id: `${item.id}:response`, version: '1', digest: `sha256:${'b'.repeat(64)}` };
  const protocolContract = item.protocol === 'graphql' ? { method: 'POST', operation: { type: 'query', name: 'Read' } } : item.protocol === 'websocket' ? { method: 'CONNECT', path: '/ws', operation: { type: 'message', name: 'Update' } } : item.protocol === 'webhook' ? { method: 'POST', path: '/hooks', operation: { type: 'event', name: 'Changed' } } : { method: 'GET', path: '/items' };
  const correlationId = `corr-${item.id}`;
  const protocolPack = item.protocol === 'graphql' ? { kind: 'graphql', binding, depth: { limit: 10, observed: 2, passed: true }, cost: { limit: 100, observed: 5, passed: true }, schemaCompatibility: { status: 'compatible', requestDigest: requestSchema.digest, responseDigest: responseSchema.digest } } : item.protocol === 'websocket' ? { kind: 'websocket', binding, auth: true, backpressure: true, reconnect: true } : item.protocol === 'webhook' ? { kind: 'webhook', binding, signature: true, replay: true, idempotency: true, delivery: true } : null;
  const artifactBinding = { caseId: item.id, protocol: item.protocol, method: protocolContract.method, path: protocolContract.path ?? null, operation: protocolContract.operation ?? null, correlationId };
  return { ...item, ...protocolContract, protocolPack, requestSchema, responseSchema, compatibility: { status: 'compatible', requestDigest: requestSchema.digest, responseDigest: responseSchema.digest }, expectedError: null, observedError: null, correlationId, dependencyBehavior: { status: 'pass', terminal: true, dependencies: [], binding }, rawArtifacts: [{ kind: 'request', ...artifactBinding, redacted: true, content: requestContent, digest: `sha256:${createHash('sha256').update(requestContent).digest('hex')}`, binding }, { kind: 'response', ...artifactBinding, redacted: true, content: responseContent, digest: `sha256:${createHash('sha256').update(responseContent).digest('hex')}`, binding }] };
};

test('B4-007 actors use isolated secret references & keep server authorization distinct', () => {
  const receipt = buildActorFixtures({ binding, now: '2026-08-08T00:00:00.000Z', actors: [
    { id: 'editor', identityId: 'identity-editor', credentialPolicyId: 'vault-v1', sessionPolicyId: 'isolated-v1', role: 'editor', tier: 'pro', tenantId: 'tenant-a', accountState: 'active', secretRef: 'vault://actors/editor', expiresAt: '2026-08-09T00:00:00.000Z', serverAuthorizations: ['write'], uiVisibility: ['save'], transitionCapabilities: [] },
    { id: 'viewer', identityId: 'identity-viewer', credentialPolicyId: 'vault-v1', sessionPolicyId: 'isolated-v1', role: 'viewer', tier: 'free', tenantId: 'tenant-b', accountState: 'revoked', secretRef: 'vault://actors/viewer', revokedAt: '2026-08-07T00:00:00.000Z', serverAuthorizations: ['read'], uiVisibility: [], transitionCapabilities: [] },
  ], required: [{ role: 'editor', tier: 'pro', tenantId: 'tenant-a', accountState: 'active' }, { role: 'viewer', tier: 'free', tenantId: 'tenant-b', accountState: 'revoked' }] });
  assert.equal(receipt.status, 'pass');
  assert.equal(receipt.denominator.total, 2);
  assert.equal(JSON.stringify(receipt).includes('password'), false);
  assert.notDeepEqual(receipt.actors[0].serverAuthorizations, receipt.actors[0].uiVisibility);
  assert.equal(switchActor({ receipt, from: 'editor', to: 'viewer', concurrentActorIds: ['editor'] }).status, 'blocked');
});

test('B4-008 matrix requires bounded dimensions, treats pending/omitted as incomplete & separates physical/mobile vitals', () => {
  const registry = JSON.parse(readFileSync(new URL('../../../registry/platform-matrices/web.json', import.meta.url), 'utf8'));
  const capabilities = registry.browserPolicy.map(({ id, versions, binaryPolicy }) => ({ id, status: 'available', browserVersion: versions[0], binary: binaryPolicy, binding }));
  const planned = compileWebMatrix({ binding, capabilities, policy: { maxCombinations: registry.pairwisePolicy.maxCombinations } });
  const vitalIds = new Set([...registry.vitalsDenominators.desktop.combinationIds, ...registry.vitalsDenominators.mobile.combinationIds]);
  const observations = matrixObservations(planned, vitalIds);
  const receipt = compileWebMatrix({ binding, capabilities, policy: { combinations: observations, maxCombinations: registry.pairwisePolicy.maxCombinations } });
  assert.equal(receipt.complete, true);
  assert.equal(receipt.denominator.total, planned.combinations.length);
  assert.ok(receipt.denominator.total > registry.mandatoryCombinations.length);
  assert.deepEqual(Object.keys(receipt.vitalsByDeviceClass), ['desktop', 'mobile']);
  assert.equal(receipt.combinations.find((item) => item.id === 'mobile-webkit-emulated').physicality, 'emulated');
  const incomplete = compileWebMatrix({ binding, policy: { combinations: [{ id: 'x', status: 'pending' }], omitted: [{ id: 'y', reason: 'budget' }], maxCombinations: 2 } });
  assert.equal(incomplete.complete, false);
  assert.equal(incomplete.denominator.omitted, 1);
});

test('B4-009 runtime records expected, observed & durable state across protocol applicability', async () => {
  const adapter = { invoke: async ({ control, journey }) => ({ observedState: { ok: true }, durableState: { ok: true }, routeEvidence: journey ? { kind: 'web-route-navigation', journeyId: journey.id, routeId: journey.routeId, control, actionId: journey.actionId, route: journey.route, stateId: journey.stateId, matrixCombinationId: journey.matrixCombinationId, binding } : null, artifacts: [{ kind: 'trace', value: 'authorization: Bearer secret user@example.com' }] }) };
  const receipt = await runWebScenario({ binding, adapter, controls: ['direct-link', 'deep-link', 'history', 'refresh', 'tabs', 'forms', 'uploads', 'concurrency', 'cancel', 'connectivity', 'auth-expiry', 'error'], protocols: [{ name: 'http', applicable: true }, { name: 'websocket', applicable: false, reason: 'not-used' }], expectedState: { ok: true } });
  assert.equal(receipt.terminal, true);
  assert.equal(receipt.denominator.total, 14);
  assert.equal(receipt.denominator.accounted, 14);
  assert.equal(receipt.receipts.length, 14);
  assert.equal(JSON.stringify(receipt).includes('secret'), false);
});

test('B4-009 production effects are blocked before adapter invocation', async () => {
  let calls = 0;
  const receipt = await runWebScenario({ binding: { ...binding, environment: 'production' }, adapter: { invoke: async () => { calls += 1; } }, controls: ['forms'], expectedState: {} });
  assert.equal(calls, 0);
  assert.equal(receipt.status, 'blocked');
});

test('B4-010 capture binds full surface, tool, repeats, variance & p75 inputs without verdict elevation', () => {
  const receipt = captureWebEvidence({ binding, surface: canonicalCaptureSurface, tool: { name: 'playwright', version: '1.55', accessibilityEngine: 'chromium-ax', accessibilityEngineVersion: '128' }, captures: [{ repeat: 1, screenshot: 'sha256:s1', dom: 'sha256:d1', accessibilityTree: 'sha256:a1', style: 'sha256:c1', geometry: 'sha256:g1', trace: 'sha256:t1', performance: { lcp: 1000, longTasks: [0], layoutShifts: [0], paints: [0], memory: 10, userTimings: [0] } }, { repeat: 2, screenshot: 'sha256:s2', dom: 'sha256:d2', accessibilityTree: 'sha256:a2', style: 'sha256:c2', geometry: 'sha256:g2', trace: 'sha256:t2', performance: { lcp: 2000, longTasks: [0], layoutShifts: [0], paints: [0], memory: 11, userTimings: [0] } }] });
  assert.equal(receipt.status, 'pass');
  assert.equal(receipt.verdict, 'unproven');
  assert.deepEqual(receipt.performance.p75Inputs, [1000, 2000]);
  assert.equal(receipt.performance.p75, 2000);
});

test('B4-011 API accepts present false/zero/empty & requires durable effects', () => {
  const receipt = verifyApiExercise({ binding, cases: [
    apiContract({ id: 'rest', protocol: 'rest', lifecycle: 'create', actorId: 'editor', tenantId: 'tenant-a', dataScope: 'own', expected: { exists: true }, observed: { exists: true, value: 0 }, durableEffect: { exists: true, value: 0 }, boundaries: true, idempotency: true, pagination: true, retry: true, rateLimit: true, malformed: true, partialFailure: true }),
    apiContract({ id: 'graphql', protocol: 'graphql', lifecycle: 'read', actorId: 'editor', tenantId: 'tenant-a', dataScope: 'own', expected: { exists: true, value: false }, observed: { exists: true, value: false }, durableEffect: { exists: true, value: false }, boundaries: true, idempotency: true, pagination: true, retry: true, rateLimit: true, malformed: true, partialFailure: true }),
    apiContract({ id: 'ws', protocol: 'websocket', lifecycle: 'update', actorId: 'editor', tenantId: 'tenant-a', dataScope: 'own', expected: { exists: true, value: '' }, observed: { exists: true, value: '' }, durableEffect: { exists: true, value: '' }, boundaries: true, idempotency: true, pagination: true, retry: true, rateLimit: true, malformed: true, partialFailure: true }),
    apiContract({ id: 'hook', protocol: 'webhook', lifecycle: 'delete', actorId: 'editor', tenantId: 'tenant-a', dataScope: 'own', expected: { exists: true, value: [] }, observed: { exists: true, value: [] }, durableEffect: { exists: true, value: [] }, boundaries: true, idempotency: true, pagination: true, retry: true, rateLimit: true, malformed: true, partialFailure: true }),
  ] });
  assert.equal(receipt.status, 'pass');
  assert.equal(receipt.denominator.accounted, 4);
});

test('B4-012 data exercise binds lifecycle & cleanup after failure', async () => {
  let cleanup = 0;
  const receipt = await verifyDataExercise({ binding, dataset: 'seed-a', schemaVersion: '7', adapter: { exercise: async () => { throw new Error('interrupted'); }, cleanup: async () => { cleanup += 1; return { residualDamage: ['queue-lag'] }; } }, cases: [dataDefinition({ id: 'interrupted', dataset: 'seed-a', schemaVersion: '7' })] });
  assert.equal(cleanup, 1);
  assert.equal(receipt.status, 'error');
  assert.deepEqual(receipt.cleanup.residualDamage, ['queue-lag']);
});

test('B4-013 infrastructure rejects repo/config intent as deployed or rollback proof', () => {
  const receipt = verifyInfrastructureExercise({ binding, evidence: { kind: 'repository-config', targetId: 'web', environment: 'test', artifactDigest: 'sha256:artifact', producer: 'iac', scope: 'repo', binding, signed: false, fresh: true, exercisedRollback: false } });
  assert.equal(receipt.status, 'unproven');
  assert.ok(receipt.coverageGaps.includes('deployed-proof-required'));
  assert.ok(receipt.coverageGaps.includes('rollback-not-exercised'));
});

test('B4-014 third party stays sandboxed & reconciles client/backend/provider/user', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const content = 'stripe sandbox receipt';
  const evidenceArtifact = { path: 'raw/external/stripe.json', content, digest: `sha256:${createHash('sha256').update(content).digest('hex')}`, binding };
  const exerciseReceipt = { controlId: 'stripe', status: 'pass', terminal: true, binding };
  const payload = { adapterKey: 'stripe', provider: 'stripe', producer: 'stripe-ci', scope: 'third-party', targetId: 'web', environment: 'sandbox', artifactDigest: binding.artifactDigest, controlId: 'stripe', binding, issuedAt: '2026-08-07T23:59:00.000Z', checkedAt: '2026-08-08T00:00:00.000Z', expiresAt: '2026-08-09T00:00:00.000Z', artifacts: [evidenceArtifact], exerciseReceipt, client: 'ok', backend: 'ok', providerState: 'ok', userState: 'ok', consent: true, webhook: true, idempotency: true, quota: { limit: 10 }, cost: { amount: 0, currency: 'USD' } };
  const signedContent = JSON.stringify(payload);
  const receipt = verifyThirdPartyExercise({ binding, now: '2026-08-08T00:00:00.000Z', maxAgeMs: 60_000, trustedProducers: [{ id: 'stripe-ci', publicKey: publicKey.export({ type: 'spki', format: 'pem' }) }], configuredProviders: [{ key: 'stripe', adapterId: 'stripe-sandbox-v1', producerId: 'stripe-ci', environment: 'sandbox' }], applicableProviders: ['stripe'], exercises: [{ ...payload, artifacts: undefined, signedContent, signature: sign(null, Buffer.from(signedContent), privateKey).toString('base64') }] });
  assert.equal(receipt.status, 'pass');
  const gap = verifyThirdPartyExercise({ binding, applicableProviders: ['stripe', 'sendgrid'], exercises: [{ provider: 'stripe', environment: 'sandbox' }] });
  assert.equal(gap.status, 'unproven');
  assert.ok(gap.coverageGaps.includes('provider-missing:sendgrid'));
});

test('B4-015 operations requires exercised recovery & fresh bound workload evidence', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const operationIds = ['alerts', 'backlog', 'backup', 'capacity', 'containment', 'cost', 'dashboards', 'health', 'incidents', 'load', 'provider', 'quota', 'region', 'restore', 'rollback', 'rpo', 'rto', 'slo', 'support'];
  const exercises = operationIds.map((id) => { const signedContent = JSON.stringify({ id, producer: 'ops', binding, exercised: true, status: 'pass', terminal: true, outcome: { executed: true }, issuedAt: '2026-08-07T23:59:00.000Z', checkedAt: '2026-08-08T00:00:00.000Z', expiresAt: '2026-08-09T00:00:00.000Z', workload: 'w1', dataset: 'seed-a', region: 'eu', providerLimits: { rps: 2 }, cost: { amount: 0 }, assumptions: [], alert: true, action: true, recovery: true, residualDamage: [] }); return { id, producer: 'ops', signedContent, signature: sign(null, Buffer.from(signedContent), privateKey).toString('base64') }; });
  const receipt = verifyOperationsExercise({ binding, now: '2026-08-08T00:00:00.000Z', maxAgeMs: 60_000, trustedProducers: [{ id: 'ops', publicKey: publicKey.export({ type: 'spki', format: 'pem' }) }], exercises });
  assert.equal(receipt.status, 'pass');
  const configured = verifyOperationsExercise({ binding, exercises: [{ id: 'restore', configured: true }] });
  assert.equal(configured.status, 'error');
  assert.ok(configured.coverageGaps.includes('restore:operation-status-invalid:missing'));
});

test('B4-016 integration emits one terminal receipt per applicable control, rejects cross-target evidence & stays source-only', () => {
  const artifact = (controlId) => { const content = controlId; return { family: 'web', id: controlId, path: `raw/web/${controlId}.json`, targetId: binding.targetId, environment: binding.environment, sourceRevision: binding.sourceRevision, controlId, content, digest: `sha256:${createHash('sha256').update(content).digest('hex')}`, binding }; };
  const receipts = [
    { controlId: 'clean', targetId: 'web', status: 'pass', terminal: true, binding, artifacts: [artifact('clean')] },
    { controlId: 'planted', targetId: 'web', status: 'fail', terminal: true, binding, artifacts: [artifact('planted')] },
    { controlId: 'mitigated', targetId: 'web', status: 'partial', terminal: true, binding, artifacts: [artifact('mitigated')] },
    { controlId: 'stale', targetId: 'web', status: 'stale', terminal: true, binding: { ...binding, sourceRevision: 'old' }, artifacts: ['raw/stale.json'] },
  ];
  const integrated = integrateWebEvidence({ binding, applicableControls: ['clean', 'planted', 'mitigated', 'missing', 'stale'], receipts });
  assert.equal(integrated.terminal, true);
  assert.equal(integrated.claimLevel, 'source');
  assert.equal(integrated.status, 'partial');
  assert.equal(integrated.denominator.total, 5);
  assert.equal(integrated.denominator.accounted, 5);
  assert.ok(integrated.coverageGaps.includes('missing-terminal-receipt:missing'));
  assert.ok(integrated.coverageGaps.includes('binding-mismatch:stale'));
  assert.equal(integrated.rawArtifacts.length, 3);
  assert.throws(() => integrateWebEvidence({ binding, applicableControls: ['x'], receipts: [{ controlId: 'x', targetId: 'other', status: 'pass', terminal: true, binding }] }), /cross-target/);
});

test('web evidence bundle is deterministic under input reordering', () => {
  const a = integrateWebEvidence({ binding, applicableControls: ['b', 'a'], receipts: [{ controlId: 'b', targetId: 'web', status: 'pass', terminal: true, binding }, { controlId: 'a', targetId: 'web', status: 'pass', terminal: true, binding }] });
  const b = integrateWebEvidence({ binding, applicableControls: ['a', 'b'], receipts: [{ controlId: 'a', targetId: 'web', status: 'pass', terminal: true, binding }, { controlId: 'b', targetId: 'web', status: 'pass', terminal: true, binding }] });
  assert.equal(a.digest, b.digest);
});

test('matrix rejects every non-success or nonterminal observation explicitly', () => {
  const registry = JSON.parse(readFileSync(new URL('../../../registry/platform-matrices/web.json', import.meta.url), 'utf8'));
  const capabilities = registry.browserPolicy.map(({ id, versions, binaryPolicy }) => ({ id, status: 'available', browserVersion: versions[0], binary: binaryPolicy, binding }));
  const plan = compileWebMatrix({ binding, capabilities, policy: { maxCombinations: registry.pairwisePolicy.maxCombinations } });
  const vitalIds = new Set([...registry.vitalsDenominators.desktop.combinationIds, ...registry.vitalsDenominators.mobile.combinationIds]);
  const valid = matrixObservations(plan, vitalIds);
  for (const status of ['fail', 'partial', 'unproven', 'blocked', 'error', 'pending']) {
    const receipt = compileWebMatrix({ binding, capabilities, policy: { combinations: [{ ...valid[0], status }, ...valid.slice(1)], maxCombinations: registry.pairwisePolicy.maxCombinations } });
    assert.notEqual(receipt.status, 'pass'); assert.ok(receipt.coverageGaps.includes(`combination-status-${status}:${valid[0].id}`));
  }
  const nonterminal = compileWebMatrix({ binding, capabilities, policy: { combinations: [{ ...valid[0], terminal: false }, ...valid.slice(1)], maxCombinations: registry.pairwisePolicy.maxCombinations } });
  assert.notEqual(nonterminal.status, 'pass'); assert.ok(nonterminal.coverageGaps.includes(`combination-nonterminal:${valid[0].id}`));
});

test('scenario enforces frozen web controls and direct/deep-link route evidence', async () => {
  const adapter = { invoke: async () => ({ observedState: { ok: true }, durableState: { ok: true } }) };
  const arbitrary = await runWebScenario({ binding, controls: ['caller-control'], expectedState: { ok: true }, adapter });
  assert.notEqual(arbitrary.status, 'pass'); assert.ok(arbitrary.coverageGaps.includes('control-unrecognized:caller-control')); assert.ok(arbitrary.coverageGaps.includes('control-missing:direct-link'));
  const routesMissing = await runWebScenario({ binding, controls: scenarioControls, expectedState: { ok: true }, adapter });
  assert.notEqual(routesMissing.status, 'pass'); assert.ok(routesMissing.coverageGaps.includes('control:direct-link:route-evidence-missing')); assert.ok(routesMissing.coverageGaps.includes('control:deep-link:route-evidence-missing'));
});

test('capture requires route, state and matrix-combination identity', () => {
  const receipt = captureWebEvidence({ binding, surface: { id: 'home', route: '/', componentIds: ['hero'] }, tool: { name: 'playwright', version: '1', accessibilityEngine: 'ax', accessibilityEngineVersion: '1' }, captures: [captureSample(1), captureSample(2)] });
  assert.notEqual(receipt.status, 'pass'); assert.ok(receipt.coverageGaps.includes('capture-state-binding-missing')); assert.ok(receipt.coverageGaps.includes('capture-matrix-combination-binding-missing'));
});

test('data cleanup failure returns terminal receipt with primary and cleanup damage', async () => {
  const cleanupError = Object.assign(new Error('cleanup failed'), { residualDamage: ['orphan-row'] });
  const receipt = await verifyDataExercise({ binding, dataset: 'seed', schemaVersion: '1', cases: [dataDefinition()], adapter: { exercise: async () => { throw new Error('primary failed'); }, cleanup: async () => { throw cleanupError; } } });
  assert.equal(receipt.terminal, true); assert.equal(receipt.status, 'error'); assert.equal(receipt.receipts[0].error, 'primary failed'); assert.equal(receipt.cleanup.error, 'cleanup failed'); assert.deepEqual(receipt.cleanup.residualDamage, ['orphan-row']);
});

test('matrix aggregate preserves worst terminal status and row gaps', () => {
  const registry = JSON.parse(readFileSync(new URL('../../../registry/platform-matrices/web.json', import.meta.url), 'utf8'));
  const capabilities = registry.browserPolicy.map(({ id, versions, binaryPolicy }) => ({ id, status: 'available', browserVersion: versions[0], binary: binaryPolicy, binding }));
  const plan = compileWebMatrix({ binding, capabilities, policy: { maxCombinations: registry.pairwisePolicy.maxCombinations } });
  const vitalIds = new Set([...registry.vitalsDenominators.desktop.combinationIds, ...registry.vitalsDenominators.mobile.combinationIds]);
  const valid = matrixObservations(plan, vitalIds);
  const mixed = valid.map((item, index) => ({ ...item, ...([0, 1, 2].includes(index) ? { status: ['blocked', 'fail', 'error'][index] } : {}) }));
  const errored = compileWebMatrix({ binding, capabilities, policy: { combinations: mixed, maxCombinations: registry.pairwisePolicy.maxCombinations } });
  assert.equal(errored.status, 'error');
  assert.ok(errored.coverageGaps.includes(`combination-status-error:${mixed[2].id}`));
  const failed = compileWebMatrix({ binding, capabilities, policy: { combinations: mixed.map((item) => item.status === 'error' ? { ...item, status: 'pass' } : item), maxCombinations: registry.pairwisePolicy.maxCombinations } });
  assert.equal(failed.status, 'fail');
  const blocked = compileWebMatrix({ binding, capabilities, policy: { combinations: mixed.map((item) => ['error', 'fail'].includes(item.status) ? { ...item, status: 'pass' } : item), maxCombinations: registry.pairwisePolicy.maxCombinations } });
  assert.equal(blocked.status, 'blocked');
});

test('scenario denominator derives from frozen canonical journey plan and exposes omissions', async () => {
  let plan;
  try { plan = JSON.parse(readFileSync(new URL('../../../registry/platform-scenarios/web.json', import.meta.url), 'utf8')); } catch { plan = null; }
  assert.ok(plan?.journeys?.length > 0);
  assert.ok(plan?.protocols?.length > 0);
  const receipt = await runWebScenario({ binding, controls: [], protocols: [], expectedState: { ok: true }, adapter: {} });
  assert.equal(receipt.denominator.total, plan.journeys.length + plan.protocols.length);
  for (const row of plan.journeys) assert.ok(receipt.coverageGaps.includes(`journey-omitted:${row.id}`));
  for (const row of plan.protocols) assert.ok(receipt.coverageGaps.includes(`protocol-omitted:${row.id}`));
});

test('direct and deep evidence must match canonical journey and matrix identity', async () => {
  const adapter = { invoke: async ({ control }) => ({ observedState: { ok: true }, durableState: { ok: true }, routeEvidence: { kind: 'web-route-navigation', journeyId: `caller:${control}`, routeId: 'route:forged', control, actionId: 'action:forged', route: '/forged', stateId: 'state:forged', matrixCombinationId: 'caller-matrix', binding } }) };
  const receipt = await runWebScenario({ binding, controls: scenarioControls, protocols: [{ name: 'http', applicable: true }, { name: 'websocket', applicable: false, reason: 'not-used' }], expectedState: { ok: true }, adapter });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.includes('control:direct-link:route-evidence-plan-mismatch'));
  assert.ok(receipt.coverageGaps.includes('control:deep-link:route-evidence-plan-mismatch'));
});

test('capture rejects nonempty route state or matrix identities outside authoritative plans', () => {
  const receipt = captureWebEvidence({ binding, surface: { id: 'forged', route: '/forged', stateId: 'state:forged', matrixCombinationId: 'caller-matrix', componentIds: ['hero'] }, tool: { name: 'playwright', version: '1', accessibilityEngine: 'ax', accessibilityEngineVersion: '1' }, captures: [captureSample(1), captureSample(2)] });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.includes('capture-journey-binding-unplanned'));
  assert.ok(receipt.coverageGaps.includes('capture-matrix-combination-unplanned'));
});

test('capture surface requires exact canonical journey identity and full binding', () => {
  const cases = [
    ['id', 'caller-id', 'capture-surface-id-mismatch'],
    ['controlId', 'caller-control', 'capture-control-binding-mismatch'],
    ['routeId', 'route:caller', 'capture-route-id-binding-mismatch'],
    ['actionId', 'action:caller', 'capture-action-binding-mismatch'],
    ['protocolId', 'websocket', 'capture-protocol-binding-mismatch'],
    ['directApplicable', false, 'capture-direct-applicability-mismatch'],
    ['deepApplicable', true, 'capture-deep-applicability-mismatch'],
    ['binding', { ...binding, actorId: 'other' }, 'capture-surface-binding-mismatch'],
  ];
  for (const [field, value, gap] of cases) {
    const receipt = captureWebEvidence({ binding, surface: { ...canonicalCaptureSurface, [field]: value }, tool: { name: 'playwright', version: '1', accessibilityEngine: 'ax', accessibilityEngineVersion: '1' }, captures: [captureSample(1), captureSample(2)] });
    assert.notEqual(receipt.status, 'pass', field);
    assert.ok(receipt.coverageGaps.includes(gap), field);
  }
  const omitted = captureWebEvidence({ binding, surface: { ...canonicalCaptureSurface, journeyId: undefined }, tool: { name: 'playwright', version: '1', accessibilityEngine: 'ax', accessibilityEngineVersion: '1' }, captures: [captureSample(1), captureSample(2)] });
  assert.ok(omitted.coverageGaps.includes('capture-journey-id-missing'));
});

test('scenario journey receipt requires browser diagnostics and distinct server authorization evidence', async () => {
  const receipt = await runWebScenario({ binding, controls: ['forms'], expectedState: { saved: true }, adapter: { invoke: async () => ({ observedState: { saved: true }, durableState: { saved: true } }) } });
  const forms = receipt.receipts.find((item) => item.id === 'control:forms');
  assert.notEqual(forms.status, 'pass');
  assert.ok(forms.coverageGaps.includes('browser-diagnostics-missing'));
  assert.ok(forms.coverageGaps.includes('server-authorization-evidence-missing'));
});

test('API receipt requires protocol-specific contract and bound redacted raw evidence', () => {
  const receipt = verifyApiExercise({ binding, cases: [{ id: 'rest-thin', protocol: 'rest', lifecycle: 'read', actorId: 'editor', tenantId: 'tenant-a', dataScope: 'own', expected: { exists: true, value: 1 }, observed: { exists: true, value: 1 }, durableEffect: { exists: true, value: 1 }, boundaries: true, idempotency: true, pagination: true, retry: true, rateLimit: true, malformed: true, partialFailure: true }] });
  assert.notEqual(receipt.status, 'pass');
  for (const gap of ['missing-method', 'rest-path-invalid', 'request-schema-unproven', 'response-schema-unproven', 'error-contract-unproven', 'correlation-id-missing', 'dependency-behavior-unproven', 'raw-request-evidence-invalid', 'raw-response-evidence-invalid']) assert.ok(receipt.coverageGaps.includes(`rest-thin:${gap}`));
});

test('data case rejects null durable observation and absent produced evidence after valid preflight', async () => {
  const receipt = await verifyDataExercise({ binding, dataset: 'seed', schemaVersion: '1', cases: [dataDefinition()], adapter: { exercise: async () => ({ status: 'pass', terminal: true, cases: [{ id: 'query', operationType: 'query', status: 'pass', terminal: true, binding, observed: null, durableResult: null, artifacts: [] }] }), cleanup: async () => ({ datasetId: 'seed', schemaVersion: '1', environment: binding.environment, binding, residualDamage: [] }) } });
  assert.notEqual(receipt.status, 'pass');
  for (const gap of ['data-case-observed-invalid:query', 'data-case-durable-result-invalid:query', 'data-case-artifacts-invalid:query']) assert.ok(receipt.coverageGaps.includes(gap));
});

test('infrastructure generic signed envelope cannot replace typed exercised control facts', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const content = 'generic deploy receipt';
  const artifact = { content, digest: `sha256:${createHash('sha256').update(content).digest('hex')}`, binding };
  const payload = { producer: 'ci', targetId: binding.targetId, environment: binding.environment, artifactDigest: binding.artifactDigest, binding, issuedAt: '2026-08-07T23:59:00.000Z', checkedAt: '2026-08-08T00:00:00.000Z', expiresAt: '2026-08-09T00:00:00.000Z', exerciseReceipt: { status: 'pass', terminal: true, artifacts: [artifact] } };
  const signedContent = JSON.stringify(payload);
  const receipt = verifyInfrastructureExercise({ binding, evidence: { producer: 'ci', signedContent, signature: sign(null, Buffer.from(signedContent), privateKey).toString('base64') }, trustedProducers: [{ id: 'ci', publicKey: publicKey.export({ type: 'spki', format: 'pem' }) }], now: payload.checkedAt, maxAgeMs: 60_000 });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.includes('infrastructure-control-missing:infra'));
  assert.ok(receipt.coverageGaps.includes('infrastructure-control-missing:rollback'));
});

test('redaction preserves typed server authorization while redacting secret leaves', async () => {
  const diagnosticIds = ['cache', 'console', 'cookies', 'cors', 'csp', 'error', 'headers', 'hydration', 'network'];
  const browserDiagnostics = { denominator: diagnosticIds, facts: diagnosticIds.map((id) => ({ id, status: 'pass', terminal: true, binding })) };
  const adapter = { invoke: async () => ({ observedState: { ok: true }, durableState: { ok: true }, browserDiagnostics, serverAuthorization: { kind: 'server-authorization-evidence', source: 'server', uiDerived: false, actorId: binding.actorId, tenantId: binding.tenantId, controlId: 'forms', status: 'pass', terminal: true, authorizationIds: ['write'], token: 'secret-value', cookie: 'session=secret', binding } }) };
  const receipt = await runWebScenario({ binding, controls: ['forms'], expectedState: { ok: true }, adapter });
  const authorization = receipt.receipts.find((item) => item.id === 'control:forms').serverAuthorization;
  assert.equal(authorization.kind, 'server-authorization-evidence');
  assert.deepEqual(authorization.authorizationIds, ['write']);
  assert.equal(authorization.token, '[REDACTED]');
  assert.equal(authorization.cookie, '[REDACTED]');
});

test('API GraphQL websocket and webhook require exact protocol packs', () => {
  for (const item of [apiContract({ id: 'gql-pack', protocol: 'graphql', lifecycle: 'read', actorId: 'editor', tenantId: 'tenant-a', dataScope: 'own', expected: { exists: true, value: 1 }, observed: { exists: true, value: 1 }, durableEffect: { exists: true, value: 1 }, boundaries: true, idempotency: true, pagination: true, retry: true, rateLimit: true, malformed: true, partialFailure: true }), apiContract({ id: 'ws-pack', protocol: 'websocket', lifecycle: 'read', actorId: 'editor', tenantId: 'tenant-a', dataScope: 'own', expected: { exists: true, value: 1 }, observed: { exists: true, value: 1 }, durableEffect: { exists: true, value: 1 }, boundaries: true, idempotency: true, pagination: true, retry: true, rateLimit: true, malformed: true, partialFailure: true }), apiContract({ id: 'hook-pack', protocol: 'webhook', lifecycle: 'read', actorId: 'editor', tenantId: 'tenant-a', dataScope: 'own', expected: { exists: true, value: 1 }, observed: { exists: true, value: 1 }, durableEffect: { exists: true, value: 1 }, boundaries: true, idempotency: true, pagination: true, retry: true, rateLimit: true, malformed: true, partialFailure: true })]) {
    const receipt = verifyApiExercise({ binding, cases: [{ ...item, protocolPack: undefined }] });
    assert.notEqual(receipt.status, 'pass', item.protocol);
    assert.ok(receipt.coverageGaps.includes(`${item.id}:${item.protocol}-pack-unproven`));
  }
});

test('API raw request and response artifacts bind exact case and protocol surface', () => {
  const item = apiContract({ id: 'raw-bound', protocol: 'rest', lifecycle: 'read', actorId: 'editor', tenantId: 'tenant-a', dataScope: 'own', expected: { exists: true, value: 1 }, observed: { exists: true, value: 1 }, durableEffect: { exists: true, value: 1 }, boundaries: true, idempotency: true, pagination: true, retry: true, rateLimit: true, malformed: true, partialFailure: true });
  const receipt = verifyApiExercise({ binding, cases: [{ ...item, rawArtifacts: item.rawArtifacts.map(({ kind, redacted, content, digest, binding: artifactBinding }) => ({ kind, redacted, content, digest, binding: artifactBinding })) }] });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.includes('raw-bound:raw-request-evidence-invalid'));
  assert.ok(receipt.coverageGaps.includes('raw-bound:raw-response-evidence-invalid'));
});

test('data invalid adapter or row status becomes explicit terminal error', async () => {
  const content = '{"rows":1}';
  const definition = { id: 'query', operationType: 'query', dataset: { id: 'seed', digest: `sha256:${'a'.repeat(64)}` }, schema: { version: '1', digest: `sha256:${'b'.repeat(64)}` }, engine: { name: 'sqlite', version: '3', digest: `sha256:${'c'.repeat(64)}` }, isolation: { id: 'tx', environment: binding.environment, binding }, cleanupBinding: { datasetId: 'seed', schemaVersion: '1', environment: binding.environment, binding }, statementDigest: `sha256:${'d'.repeat(64)}` };
  const artifact = { kind: 'data-result', caseId: 'query', datasetId: 'seed', schemaVersion: '1', engineVersion: '3', content, digest: `sha256:${createHash('sha256').update(content).digest('hex')}`, binding };
  const receipt = await verifyDataExercise({ binding, dataset: 'seed', schemaVersion: '1', cases: [definition], adapter: { exercise: async () => ({ status: 'mystery', terminal: true, cases: [{ id: 'query', operationType: 'query', status: 'mystery', terminal: true, binding, observed: { rows: 1 }, durableResult: { rows: 1 }, artifacts: [artifact] }] }), cleanup: async () => ({ datasetId: 'seed', schemaVersion: '1', environment: binding.environment, binding, residualDamage: [] }) } });
  assert.equal(receipt.status, 'error');
  assert.ok(receipt.coverageGaps.includes('adapter-status-invalid:mystery'));
  assert.ok(receipt.coverageGaps.includes('data-case-status-invalid:query'));
});

test('operations denominator comes from frozen canonical controls and exposes every omission', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const payload = { id: 'restore', producer: 'ops', binding, exercised: true, issuedAt: '2026-08-07T23:59:00.000Z', checkedAt: '2026-08-08T00:00:00.000Z', expiresAt: '2026-08-09T00:00:00.000Z', workload: 'w', dataset: 'd', region: 'r', providerLimits: {}, cost: {}, assumptions: [], alert: true, action: true, recovery: true, residualDamage: [] };
  const signedContent = JSON.stringify(payload);
  const receipt = verifyOperationsExercise({ binding, now: payload.checkedAt, maxAgeMs: 60_000, trustedProducers: [{ id: 'ops', publicKey: publicKey.export({ type: 'spki', format: 'pem' }) }], exercises: [{ id: 'restore', producer: 'ops', signedContent, signature: sign(null, Buffer.from(signedContent), privateKey).toString('base64') }] });
  assert.equal(receipt.denominator.total, 19);
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.includes('operation-omitted:load'));
  assert.ok(receipt.coverageGaps.includes('operation-omitted:rpo'));
});

test('third-party denominator never passes vacuously without applicability evidence', () => {
  const receipt = verifyThirdPartyExercise({ binding });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.denominator.total > 0);
  assert.ok(receipt.coverageGaps.includes('conditional-provider-applicability-source-missing'));
});

test('redaction catches composite case-insensitive secret keys at any depth', () => {
  const output = redact({ outer: { clientSecret: 'one', APIToken: 'two', private_key: 'three', accessToken: 'four', RefreshToken: 'five', sessionCookie: 'six' } });
  for (const value of Object.values(output.outer)) assert.equal(value, '[REDACTED]');
});

test('API raw evidence verifies sanitized PII bytes instead of caller redacted claim', () => {
  const item = apiContract({ id: 'pii', protocol: 'rest', lifecycle: 'read', actorId: 'editor', tenantId: 'tenant-a', dataScope: 'own', expected: { exists: true, value: 1 }, observed: { exists: true, value: 1 }, durableEffect: { exists: true, value: 1 }, boundaries: true, idempotency: true, pagination: true, retry: true, rateLimit: true, malformed: true, partialFailure: true });
  const leaked = '{"contact":{"phone":"+1-202-555-0198"}}';
  const rawArtifacts = item.rawArtifacts.map((artifact) => artifact.kind === 'request' ? { ...artifact, redacted: true, content: leaked, digest: `sha256:${createHash('sha256').update(leaked).digest('hex')}` } : artifact);
  const receipt = verifyApiExercise({ binding, cases: [{ ...item, sensitiveFields: [{ path: '$.contact.phone', type: 'phone' }], rawArtifacts }] });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.includes('pii:raw-request-pii-leak'));
});

test('signed not-applicable receipt cannot override explicitly applicable provider', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const payload = { producer: 'policy', provider: 'stripe', status: 'not-applicable', reason: 'claimed absent', binding };
  const signedContent = JSON.stringify(payload);
  const receipt = verifyThirdPartyExercise({ binding, configuredProviders: [{ key: 'stripe', adapterId: 'stripe-v1' }], applicableProviders: ['stripe'], trustedProducers: [{ id: 'policy', publicKey: publicKey.export({ type: 'spki', format: 'pem' }) }], notApplicableReceipts: [{ producer: 'policy', provider: 'stripe', signedContent, signature: sign(null, Buffer.from(signedContent), privateKey).toString('base64') }] });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.includes('provider-applicability-contradiction:stripe'));
  assert.ok(receipt.coverageGaps.includes('provider-missing:stripe'));
});

test('operations invalid or nonterminal outcome becomes terminal error and worst aggregate', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const ids = ['alerts', 'backlog', 'backup', 'capacity', 'containment', 'cost', 'dashboards', 'health', 'incidents', 'load', 'provider', 'quota', 'region', 'restore', 'rollback', 'rpo', 'rto', 'slo', 'support'];
  const exercises = ids.map((id) => { const payload = { id, producer: 'ops', binding, exercised: true, status: id === 'restore' ? 'mystery' : 'pass', terminal: id !== 'restore', outcome: { executed: true }, issuedAt: '2026-08-07T23:59:00.000Z', checkedAt: '2026-08-08T00:00:00.000Z', expiresAt: '2026-08-09T00:00:00.000Z', workload: 'w', dataset: 'd', region: 'r', providerLimits: {}, cost: {}, assumptions: [], alert: true, action: true, recovery: true, residualDamage: [] }, signedContent = JSON.stringify(payload); return { id, producer: 'ops', signedContent, signature: sign(null, Buffer.from(signedContent), privateKey).toString('base64') }; });
  const receipt = verifyOperationsExercise({ binding, exercises, trustedProducers: [{ id: 'ops', publicKey: publicKey.export({ type: 'spki', format: 'pem' }) }], now: '2026-08-08T00:00:00.000Z', maxAgeMs: 60_000 });
  assert.equal(receipt.status, 'error');
  assert.equal(receipt.receipts.find((item) => item.id === 'restore').status, 'error');
  assert.ok(receipt.coverageGaps.includes('restore:operation-status-invalid:mystery'));
  assert.ok(receipt.coverageGaps.includes('restore:operation-nonterminal'));
});

test('actor switch permits frozen bounded tenant transition with server authorization', () => {
  const receipt = buildActorFixtures({ binding, now: '2026-08-08T00:00:00.000Z', required: [{ role: 'editor', tier: 'pro', tenantId: 'tenant-a', accountState: 'active' }, { role: 'editor', tier: 'pro', tenantId: 'tenant-b', accountState: 'active' }], actors: [{ id: 'editor', identityId: 'identity-1', credentialPolicyId: 'sso-1', sessionPolicyId: 'bounded-1', role: 'editor', tier: 'pro', tenantId: 'tenant-a', accountState: 'active', secretRef: 'vault://actors/editor', expiresAt: '2026-08-09T00:00:00.000Z', serverAuthorizations: ['tenant.switch'], uiVisibility: [], transitionCapabilities: [{ id: 'tenant-account-switch', toActorId: 'editor-b', fromTenantId: 'tenant-a', toTenantId: 'tenant-b', authorizationId: 'tenant.switch' }] }, { id: 'editor-b', identityId: 'identity-1', credentialPolicyId: 'sso-1', sessionPolicyId: 'bounded-1', role: 'editor', tier: 'pro', tenantId: 'tenant-b', accountState: 'active', secretRef: 'vault://actors/editor-b', expiresAt: '2026-08-09T00:00:00.000Z', serverAuthorizations: ['tenant.switch'], uiVisibility: [], transitionCapabilities: [] }] });
  const serverAuthorization = { kind: 'server-authorization-evidence', transitionId: 'tenant-account-switch', controlId: 'tenant-account-switch', authorizationId: 'tenant.switch', fromActorId: 'editor', toActorId: 'editor-b', actorId: 'editor', fromTenantId: 'tenant-a', toTenantId: 'tenant-b', tenantId: 'tenant-a', fromAccountState: 'active', toAccountState: 'active', sessionPolicyId: 'bounded-1', sessionBinding: binding, status: 'pass', terminal: true, binding };
  const switched = switchActor({ receipt, from: 'editor', to: 'editor-b', currentActorId: 'editor', sessionBinding: binding, transitionCapabilityId: 'tenant-account-switch', serverAuthorization });
  assert.equal(switched.status, 'pass');
  assert.equal(switched.tenantId, 'tenant-b');
});

test('redaction normalizes separators and catches sensitive composite suffixes', () => {
  const output = redact({ nested: { dbPassword: 'one', 'X-API-Key': 'two', client_secret: 'three', authorizationToken: 'four' } });
  for (const value of Object.values(output.nested)) assert.equal(value, '[REDACTED]');
});

test('API configured PII paths resolve nested array indices before sanitation', () => {
  const item = apiContract({ id: 'nested-pii', protocol: 'rest', lifecycle: 'read', actorId: 'editor', tenantId: 'tenant-a', dataScope: 'own', expected: { exists: true, value: 1 }, observed: { exists: true, value: 1 }, durableEffect: { exists: true, value: 1 }, boundaries: true, idempotency: true, pagination: true, retry: true, rateLimit: true, malformed: true, partialFailure: true });
  const contents = { request: '{"contacts":[{"taxId":"raw-tax-123"}]}', response: '{"contacts":[{"taxId":"[REDACTED]"}]}' };
  const rawArtifacts = item.rawArtifacts.map((artifact) => ({ ...artifact, content: contents[artifact.kind], digest: `sha256:${createHash('sha256').update(contents[artifact.kind]).digest('hex')}` }));
  const receipt = verifyApiExercise({ binding, cases: [{ ...item, sensitiveFields: [{ path: '$.contacts[0].taxId', type: 'string' }], rawArtifacts }] });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.includes('nested-pii:raw-request-pii-leak'));
});

test('configured provider cannot be excluded by later signed not-applicable receipt', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const payload = { producer: 'policy', provider: 'stripe', status: 'not-applicable', reason: 'claimed absent', binding };
  const signedContent = JSON.stringify(payload);
  const receipt = verifyThirdPartyExercise({ binding, configuredProviders: [{ key: 'stripe', adapterId: 'stripe-v1' }], trustedProducers: [{ id: 'policy', publicKey: publicKey.export({ type: 'spki', format: 'pem' }) }], notApplicableReceipts: [{ producer: 'policy', provider: 'stripe', signedContent, signature: sign(null, Buffer.from(signedContent), privateKey).toString('base64') }] });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.includes('provider-applicability-contradiction:stripe'));
  assert.ok(receipt.coverageGaps.includes('provider-missing:stripe'));
});

test('actor transition IDs are unique and authorization binds one exact destination', () => {
  const actor = (id, tenantId, transitionCapabilities = []) => ({ id, identityId: 'identity-1', credentialPolicyId: 'sso-1', sessionPolicyId: 'bounded-1', role: 'editor', tier: 'pro', tenantId, accountState: 'active', secretRef: `vault://actors/${id}`, expiresAt: '2026-08-09T00:00:00.000Z', serverAuthorizations: ['tenant.switch'], uiVisibility: [], transitionCapabilities });
  const required = ['tenant-a', 'tenant-b', 'tenant-c'].map((tenantId) => ({ role: 'editor', tier: 'pro', tenantId, accountState: 'active' }));
  const duplicate = buildActorFixtures({ binding, now: '2026-08-08T00:00:00.000Z', required, actors: [actor('editor', 'tenant-a', [{ id: 'tenant-switch', toActorId: 'editor-b', fromTenantId: 'tenant-a', toTenantId: 'tenant-b', authorizationId: 'tenant.switch' }, { id: 'tenant-switch', toActorId: 'editor-c', fromTenantId: 'tenant-a', toTenantId: 'tenant-c', authorizationId: 'tenant.switch' }]), actor('editor-b', 'tenant-b'), actor('editor-c', 'tenant-c')] });
  assert.notEqual(duplicate.status, 'pass');
  assert.ok(duplicate.coverageGaps.includes('actor-transition-id-duplicate:tenant-switch'));
  const receipt = buildActorFixtures({ binding, now: '2026-08-08T00:00:00.000Z', required: required.slice(0, 2), actors: [actor('editor', 'tenant-a', [{ id: 'tenant-switch', toActorId: 'editor-b', fromTenantId: 'tenant-a', toTenantId: 'tenant-b', authorizationId: 'tenant.switch' }]), actor('editor-b', 'tenant-b')] });
  const reusable = { kind: 'server-authorization-evidence', actorId: 'editor', tenantId: 'tenant-a', controlId: 'tenant-switch', authorizationId: 'tenant.switch', status: 'pass', terminal: true, binding };
  const switched = switchActor({ receipt, from: 'editor', to: 'editor-b', currentActorId: 'editor', sessionBinding: binding, transitionCapabilityId: 'tenant-switch', serverAuthorization: reusable });
  assert.equal(switched.status, 'blocked');
  assert.equal(switched.reason, 'cross-tenant-server-authorization-unproven');
});

test('redaction catches normalized generic secret-key variants without erasing authorization shape', () => {
  const output = redact({ secret_key: 'one', 'Secret-Key': 'two', secretKey: 'three', serverAuthorization: { kind: 'server-authorization-evidence', secretKey: 'four', status: 'pass' } });
  assert.equal(output.secret_key, '[REDACTED]');
  assert.equal(output['Secret-Key'], '[REDACTED]');
  assert.equal(output.secretKey, '[REDACTED]');
  assert.equal(output.serverAuthorization.kind, 'server-authorization-evidence');
  assert.equal(output.serverAuthorization.secretKey, '[REDACTED]');
});

test('API indexed PII path verifies every array sibling and wildcard path deterministically', () => {
  const item = apiContract({ id: 'sibling-pii', protocol: 'rest', lifecycle: 'read', actorId: 'editor', tenantId: 'tenant-a', dataScope: 'own', expected: { exists: true, value: 1 }, observed: { exists: true, value: 1 }, durableEffect: { exists: true, value: 1 }, boundaries: true, idempotency: true, pagination: true, retry: true, rateLimit: true, malformed: true, partialFailure: true });
  const leaked = '{"contacts":[{"taxId":"[REDACTED]"},{"taxId":"raw-tax-456"}]}';
  const safe = '{"contacts":[{"taxId":"[REDACTED]"},{"taxId":"[REDACTED]"}]}';
  const artifacts = (requestContent) => item.rawArtifacts.map((artifact) => { const content = artifact.kind === 'request' ? requestContent : safe; return { ...artifact, content, digest: `sha256:${createHash('sha256').update(content).digest('hex')}` }; });
  for (const path of ['$.contacts[0].taxId', '$.contacts[*].taxId']) {
    const receipt = verifyApiExercise({ binding, cases: [{ ...item, id: `sibling-${path.includes('*') ? 'wildcard' : 'indexed'}`, correlationId: `corr-${path.includes('*') ? 'wildcard' : 'indexed'}`, sensitiveFields: [{ path, type: 'string' }], rawArtifacts: artifacts(leaked).map((artifact) => ({ ...artifact, caseId: `sibling-${path.includes('*') ? 'wildcard' : 'indexed'}`, correlationId: `corr-${path.includes('*') ? 'wildcard' : 'indexed'}` })) }] });
    assert.notEqual(receipt.status, 'pass', path);
    assert.ok(receipt.coverageGaps.some((gap) => gap.endsWith(':raw-request-pii-leak')), path);
  }
});

test('API raw PII detection permits strict ISO timestamp but still rejects phone text', () => {
  const item = apiContract({ id: 'timestamp-raw', protocol: 'rest', lifecycle: 'read', actorId: 'editor', tenantId: 'tenant-a', dataScope: 'own', expected: { exists: true, value: 1 }, observed: { exists: true, value: 1 }, durableEffect: { exists: true, value: 1 }, boundaries: true, idempotency: true, pagination: true, retry: true, rateLimit: true, malformed: true, partialFailure: true });
  const withContent = (content) => ({ ...item, rawArtifacts: item.rawArtifacts.map((artifact) => ({ ...artifact, content, digest: `sha256:${createHash('sha256').update(content).digest('hex')}` })) });
  const timestamp = verifyApiExercise({ binding, cases: [withContent('observed 2026-08-08T00:00:00.000Z')] });
  assert.equal(timestamp.status, 'pass');
  const phone = verifyApiExercise({ binding, cases: [withContent('call 212-555-0123')] });
  assert.notEqual(phone.status, 'pass');
  assert.ok(phone.coverageGaps.some((gap) => gap.endsWith(':raw-request-pii-leak')));
});

test('data API scenario and protocol artifacts use shared bound sanitation with recomputed digests', async () => {
  const leaked = 'Bearer lane-token user@example.com 123-45-6789 212-555-0123';
  const digestOf = (content) => `sha256:${createHash('sha256').update(content).digest('hex')}`;
  const dataArtifact = { kind: 'data-result', caseId: 'query', datasetId: 'seed', schemaVersion: '1', engineVersion: '3', content: leaked, digest: digestOf(leaked), binding };
  const data = await verifyDataExercise({ binding, dataset: 'seed', schemaVersion: '1', cases: [dataDefinition()], adapter: { exercise: async () => ({ status: 'pass', terminal: true, cases: [{ id: 'query', operationType: 'query', status: 'pass', terminal: true, binding, observed: { rows: 1 }, durableResult: { rows: 1 }, artifacts: [dataArtifact] }] }), cleanup: async () => ({ datasetId: 'seed', schemaVersion: '1', environment: binding.environment, binding, residualDamage: [] }) } });
  const item = apiContract({ id: 'shared-sanitize', protocol: 'rest', lifecycle: 'read', actorId: 'editor', tenantId: 'tenant-a', dataScope: 'own', expected: { exists: true, value: 1 }, observed: { exists: true, value: 1 }, durableEffect: { exists: true, value: 1 }, boundaries: true, idempotency: true, pagination: true, retry: true, rateLimit: true, malformed: true, partialFailure: true });
  item.rawArtifacts = item.rawArtifacts.map((artifact) => ({ ...artifact, content: leaked, digest: digestOf(leaked) }));
  const api = verifyApiExercise({ binding, cases: [item] });
  const genericArtifact = { path: 'raw/web/lane.txt', content: leaked, digest: digestOf(leaked), binding };
  const scenario = await runWebScenario({ binding, controls: ['forms'], expectedState: {}, adapter: { invoke: async () => ({ observedState: {}, durableState: {}, artifacts: [genericArtifact] }) } });
  const protocol = await executeWebProtocol({ binding, protocol: 'http', adapter: { execute: async () => ({ observedState: {}, durableState: {}, artifacts: [genericArtifact] }) } });
  for (const [receipt, artifact] of [[data, data.receipts[0].artifacts[0]], [api, api.receipts[0].rawArtifacts[0]], [scenario, scenario.receipts.find((row) => row.control === 'forms').artifacts[0]], [protocol, protocol.artifacts[0]]]) {
    assert.notEqual(receipt.status, 'pass');
    assert.equal(JSON.stringify(receipt).includes('lane-token'), false);
    assert.equal(JSON.stringify(receipt).includes('user@example.com'), false);
    assert.deepEqual(artifact.binding, binding);
    assert.equal(artifact.digest, digestOf(artifact.content));
  }
});

test('accessibility reconciles exact planned repeats and rejects malformed duplicate unplanned or nonterminal inspections', () => {
  const captures = [captureSample(1), captureSample(2)];
  const base = { binding, surface: canonicalCaptureSurface, tool: { name: 'playwright', version: '1', accessibilityEngine: 'ax', accessibilityEngineVersion: '1' }, captures };
  const malformed = verifyWebAccessibility({ ...base, inspections: {} });
  assert.notEqual(malformed.status, 'pass');
  const receipt = verifyWebAccessibility({ ...base, inspections: [{ repeat: 1, violations: [], screenshot: 's1', status: 'pass', terminal: true, binding }, { repeat: 1, violations: [], screenshot: 's1b', status: 'pass', terminal: true, binding }, { repeat: 3, violations: [], screenshot: 's3', status: 'pass', terminal: false, binding }] });
  assert.equal(receipt.denominator.total, 2);
  for (const gap of ['accessibility-inspection-duplicate:1', 'accessibility-inspection-unplanned:3', 'accessibility-inspection-missing:2', 'accessibility-nonterminal:3']) assert.ok(receipt.coverageGaps.includes(gap));
});

test('frozen not-applicable policy cannot downgrade a configured provider', () => {
  const providers = ['analytics', 'commerce', 'email', 'payments'].map((id) => ({ applicable: false, id, reason: 'policy says absent' }));
  const applicabilitySource = { kind: 'frozen-conditional-provider-applicability', id: 'web:conditional-providers', binding, providers, digest: `sha256:${createHash('sha256').update(JSON.stringify(providers)).digest('hex')}` };
  const receipt = verifyThirdPartyExercise({ binding, configuredProviders: [{ key: 'analytics', adapterId: 'analytics-test-v1' }], applicabilitySource });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.includes('provider-applicability-contradiction:analytics'));
  assert.ok(receipt.coverageGaps.includes('provider-missing:analytics'));
});

test('switchActor rejects incomplete or non-pass fixture proof including duplicate transitions', () => {
  const actor = (id, tenantId, transitionCapabilities = []) => ({ id, identityId: 'identity-1', credentialPolicyId: 'sso-1', sessionPolicyId: 'bounded-1', role: 'editor', tier: 'pro', tenantId, accountState: 'active', secretRef: `vault://actors/${id}`, expiresAt: '2026-08-09T00:00:00.000Z', serverAuthorizations: ['tenant.switch'], uiVisibility: [], transitionCapabilities });
  const capability = { id: 'tenant-switch', toActorId: 'editor-b', fromTenantId: 'tenant-a', toTenantId: 'tenant-b', authorizationId: 'tenant.switch' };
  const required = ['tenant-a', 'tenant-b'].map((tenantId) => ({ role: 'editor', tier: 'pro', tenantId, accountState: 'active' }));
  const receipt = buildActorFixtures({ binding, now: '2026-08-08T00:00:00.000Z', required, actors: [actor('editor', 'tenant-a', [capability]), actor('editor-b', 'tenant-b')] });
  const authorization = { kind: 'server-authorization-evidence', transitionId: 'tenant-switch', controlId: 'tenant-switch', authorizationId: 'tenant.switch', fromActorId: 'editor', toActorId: 'editor-b', actorId: 'editor', fromTenantId: 'tenant-a', toTenantId: 'tenant-b', tenantId: 'tenant-a', fromAccountState: 'active', toAccountState: 'active', sessionPolicyId: 'bounded-1', sessionBinding: binding, status: 'pass', terminal: true, binding };
  const { digest: ignored, ...body } = receipt;
  const incompleteBody = { ...body, complete: false, proof: false };
  const incomplete = { ...incompleteBody, digest: digest(incompleteBody) };
  assert.equal(switchActor({ receipt: incomplete, from: 'editor', to: 'editor-b', currentActorId: 'editor', sessionBinding: binding, transitionCapabilityId: 'tenant-switch', serverAuthorization: authorization }).status, 'blocked');
  const duplicate = buildActorFixtures({ binding, now: '2026-08-08T00:00:00.000Z', required, actors: [actor('editor', 'tenant-a', [capability, capability]), actor('editor-b', 'tenant-b')] });
  assert.equal(switchActor({ receipt: duplicate, from: 'editor', to: 'editor-b', currentActorId: 'editor', sessionBinding: binding, transitionCapabilityId: 'tenant-switch', serverAuthorization: authorization }).status, 'blocked');
});
