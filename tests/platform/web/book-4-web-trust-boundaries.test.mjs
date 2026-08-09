import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import test from 'node:test';
import { verifyThirdPartyExercise } from '../../../providers/runtime/web/third-party/index.mjs';
import { verifyDataExercise } from '../../../providers/runtime/web/data/index.mjs';
import { verifyApiExercise } from '../../../providers/runtime/web/api/index.mjs';
import { runWebScenario } from '../../../providers/runtime/web/scenario/index.mjs';
import { buildActorFixtures, switchActor } from '../../../providers/runtime/web/actors/index.mjs';
import { verifyInfrastructureExercise } from '../../../providers/runtime/web/infrastructure/index.mjs';
import { integrateWebEvidence } from '../../../providers/runtime/web/integration/index.mjs';
import { validateExternalEvidence } from '../../../lib/platform/external/validate.mjs';
import { verifyOperationsExercise } from '../../../providers/runtime/web/operations/index.mjs';
import { compileWebMatrix } from '../../../providers/runtime/web/matrix/index.mjs';
import { captureWebEvidence } from '../../../providers/runtime/web/capture/index.mjs';
import { inspectWebBackend } from '../../../providers/runtime/web/backend/index.mjs';
import { qualifyWebPlatform } from '../../../qualification/platforms/web/qualification.mjs';
import { sanitizeProducedArtifact } from '../../../lib/platform/artifact-sanitize.mjs';
import { verifyWebPerformance } from '../../../providers/runtime/web/performance/index.mjs';
import { BINDING_KEYS, canonicalize, exactBinding, finalize } from '../../../providers/runtime/web/shared.mjs';
import { redact } from '../../../providers/runtime/web/shared.mjs';
import { runWebControl } from '../../../providers/runtime/web/runner/index.mjs';

const binding = Object.freeze({ targetId: 'web', environment: 'test', actorId: 'editor', tenantId: 'tenant-a', browser: 'chromium', browserVersion: '128', viewport: '1440x900', locale: 'en-GB', sourceRevision: 'abc', artifactDigest: 'sha256:artifact' });
const thirdPartyBase = { environment: 'sandbox', binding, signed: true, issuedAt: '2026-08-07T23:59:00.000Z', checkedAt: '2026-08-08T00:00:00.000Z', expiresAt: '2026-08-09T00:00:00.000Z', client: 'ok', backend: 'ok', providerState: 'ok', userState: 'ok', consent: true, webhook: true, idempotency: true, quota: {}, cost: {} };
const dataDefinition = (bound = binding, extra = {}) => ({ id: 'query', operationType: 'query', dataset: { id: 'seed', digest: `sha256:${'a'.repeat(64)}` }, schema: { version: '1', digest: `sha256:${'b'.repeat(64)}` }, engine: { name: 'sqlite', version: '3', digest: `sha256:${'c'.repeat(64)}` }, isolation: { id: 'tx', environment: bound.environment, binding: bound }, cleanupBinding: { datasetId: 'seed', schemaVersion: '1', environment: bound.environment, binding: bound }, statementDigest: `sha256:${'d'.repeat(64)}`, ...extra });
const aliasBase64 = (canonical) => { const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', position = canonical.length - 3; return `${canonical.slice(0, position)}${alphabet[alphabet.indexOf(canonical[position]) + 1]}==`; };

test('third-party identity comes from configured adapter key; duplicate/spoof IDs are rejected exactly', () => {
  const receipt = verifyThirdPartyExercise({ binding, now: '2026-08-08T00:00:00.000Z', maxAgeMs: 60_000, configuredProviders: [{ key: 'stripe', adapterId: 'payments-v1' }], applicableProviders: ['stripe'], exercises: [{ ...thirdPartyBase, adapterKey: 'stripe', provider: 'sendgrid' }, { ...thirdPartyBase, adapterKey: 'stripe', provider: 'stripe' }] });
  assert.notEqual(receipt.status, 'pass');
  assert.equal(receipt.denominator.total, 1);
  assert.equal(receipt.receipts.length, 1);
  assert.ok(receipt.coverageGaps.includes('provider-duplicate:stripe'));
  assert.ok(receipt.coverageGaps.includes('provider-identity-spoof:stripe'));
});

test('data propagates adapter failure/nonterminal state & rejects empty exact case denominator', async () => {
  const failed = await verifyDataExercise({ binding, dataset: 'seed', schemaVersion: '1', cases: [dataDefinition()], adapter: { exercise: async () => ({ status: 'fail', terminal: true, cases: [{ id: 'query', operationType: 'query', status: 'fail', terminal: true, binding }] }), cleanup: async () => ({ datasetId: 'seed', schemaVersion: '1', environment: binding.environment, binding, residualDamage: [] }) } });
  assert.equal(failed.status, 'fail');
  const nonterminal = await verifyDataExercise({ binding, dataset: 'seed', schemaVersion: '1', cases: [dataDefinition()], adapter: { exercise: async () => ({ status: 'pass', terminal: false, cases: [{ id: 'query', operationType: 'query', status: 'pass', terminal: false, binding }] }), cleanup: async () => ({ datasetId: 'seed', schemaVersion: '1', environment: binding.environment, binding, residualDamage: [] }) } });
  assert.notEqual(nonterminal.status, 'pass');
  assert.ok(nonterminal.coverageGaps.includes('adapter-result-nonterminal'));
  const empty = await verifyDataExercise({ binding, dataset: 'seed', schemaVersion: '1', cases: [], adapter: { exercise: async () => ({ status: 'pass', terminal: true, cases: [] }), cleanup: async () => ({ residualDamage: [] }) } });
  assert.notEqual(empty.status, 'pass');
  assert.ok(empty.coverageGaps.includes('data-case-denominator-empty'));
});

test('API empty denominator needs exact configured not-applicable source', () => {
  assert.notEqual(verifyApiExercise({ binding, cases: [] }).status, 'pass');
  const applicability = { status: 'not-applicable', reason: 'no-api-surface', source: { kind: 'configured', id: 'portfolio:web:no-api', digest: `sha256:${'a'.repeat(64)}`, binding } };
  const receipt = verifyApiExercise({ binding, cases: [], applicability });
  assert.equal(receipt.status, 'pass');
  assert.equal(receipt.applicable, false);
});

test('protocol exclusion requires typed evidence, remains visible & prevents whole-scenario pass', async () => {
  const missing = await runWebScenario({ binding, controls: [], protocols: [{ name: 'websocket', applicable: false, reason: 'not-used' }] });
  assert.notEqual(missing.status, 'pass');
  assert.ok(missing.coverageGaps.includes('protocol:websocket:protocol-exclusion-evidence-missing'));
  const evidence = { kind: 'configured-protocol-applicability', reason: 'not-in-product-contract', source: 'portfolio:web', digest: `sha256:${'b'.repeat(64)}`, binding };
  const excluded = await runWebScenario({ binding, controls: [], protocols: [{ name: 'websocket', applicable: false, reason: 'not-in-product-contract', evidence }] });
  assert.notEqual(excluded.status, 'pass');
  assert.ok(excluded.coverageGaps.includes('protocol:websocket:protocol-excluded'));
});

test('actor switch validates frozen fixture, source/current/session/tenant/account binding', () => {
  const receipt = buildActorFixtures({ binding, now: '2026-08-08T00:00:00.000Z', required: [{ role: 'editor', tier: 'pro', tenantId: 'tenant-a', accountState: 'active' }, { role: 'reviewer', tier: 'pro', tenantId: 'tenant-a', accountState: 'active' }], actors: [{ id: 'editor', identityId: 'identity-editor', credentialPolicyId: 'vault-v1', sessionPolicyId: 'isolated-v1', role: 'editor', tier: 'pro', tenantId: 'tenant-a', accountState: 'active', secretRef: 'vault://actors/editor', expiresAt: '2026-08-09T00:00:00.000Z', serverAuthorizations: [], uiVisibility: [], transitionCapabilities: [] }, { id: 'reviewer', identityId: 'identity-reviewer', credentialPolicyId: 'vault-v1', sessionPolicyId: 'isolated-v1', role: 'reviewer', tier: 'pro', tenantId: 'tenant-a', accountState: 'active', secretRef: 'vault://actors/reviewer', expiresAt: '2026-08-09T00:00:00.000Z', serverAuthorizations: [], uiVisibility: [], transitionCapabilities: [] }] });
  assert.equal(switchActor({ receipt, from: 'missing', to: 'reviewer', currentActorId: 'missing', sessionBinding: { ...binding, actorId: 'missing' } }).status, 'blocked');
  assert.equal(switchActor({ receipt, from: 'editor', to: 'reviewer', currentActorId: 'editor', sessionBinding: binding }).status, 'blocked');
  assert.equal(switchActor({ receipt, from: 'editor', to: 'reviewer', currentActorId: 'other', sessionBinding: binding }).status, 'blocked');
});

test('infrastructure ignores trusted-looking booleans & verifies signed bound exercised bytes', () => {
  const booleanOnly = verifyInfrastructureExercise({ binding, evidence: { kind: 'deployed-exercise', targetId: 'web', environment: 'test', artifactDigest: 'sha256:artifact', producer: 'ci', scope: 'deploy', binding, signed: true, fresh: true, exercisedRollback: true } });
  assert.notEqual(booleanOnly.status, 'pass');
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const artifactContent = '{"rollback":"pass"}';
  const artifact = { path: 'raw/cloud/rollback.json', family: 'cloud', content: artifactContent, digest: `sha256:${createHash('sha256').update(artifactContent).digest('hex')}`, binding };
  const applicableControls = ['cdn', 'deployment', 'dns', 'drift', 'health', 'iam', 'infra', 'network', 'region', 'rollback', 'runtime', 'scaling', 'secrets', 'storage', 'tls'];
  const controlFacts = applicableControls.map((id) => { const content = JSON.stringify({ control: id, exercised: true }); return { id, kind: 'infrastructure-control-fact', applicable: true, configured: true, deployed: true, exercised: true, status: 'pass', terminal: true, binding, artifacts: [{ path: `raw/cloud/${id}.json`, content, digest: `sha256:${createHash('sha256').update(content).digest('hex')}`, binding }] }; });
  const payload = JSON.stringify({ producer: 'ci', targetId: 'web', environment: 'test', artifactDigest: 'sha256:artifact', binding, issuedAt: '2026-08-07T23:59:00.000Z', checkedAt: '2026-08-08T00:00:00.000Z', expiresAt: '2026-08-09T00:00:00.000Z', applicableControls, controlFacts, exerciseReceipt: { status: 'pass', terminal: true, artifacts: [artifact] } });
  const evidence = { producer: 'ci', signedContent: payload, signature: sign(null, Buffer.from(payload), privateKey).toString('base64') };
  const verified = verifyInfrastructureExercise({ binding, evidence, trustedProducers: [{ id: 'ci', publicKey: publicKey.export({ type: 'spki', format: 'pem' }) }], now: '2026-08-08T00:00:00.000Z', maxAgeMs: 60_000 });
  assert.equal(verified.status, 'pass');
  assert.equal(verified.suppliedOnly, true);
  assert.equal(verified.networkAttempted, false);
});

test('data rejects malformed production destructive isolation binding and operation inputs before adapters', async () => {
  const inputs = [
    { bound: binding, definition: { id: 'bad', operationType: 'unknown' } },
    { bound: { ...binding, environment: 'production' }, definition: dataDefinition({ ...binding, environment: 'production' }) },
    { bound: binding, definition: dataDefinition(binding, { destructive: true }) },
    { bound: binding, definition: dataDefinition(binding, { isolation: { id: 'tx', environment: 'other', binding } }) },
    { bound: { ...binding, locale: '' }, definition: dataDefinition({ ...binding, locale: '' }) },
    { bound: binding, definition: dataDefinition(binding, { statementDigest: 'invalid' }) },
  ];
  for (const { bound, definition } of inputs) {
    let calls = 0;
    const receipt = await verifyDataExercise({ binding: bound, dataset: 'seed', schemaVersion: '1', cases: [definition], adapter: { exercise: async () => { calls += 1; return { status: 'pass', terminal: true, cases: [] }; }, cleanup: async () => { calls += 1; return { datasetId: 'seed', schemaVersion: '1', environment: bound.environment, binding: bound, residualDamage: [] }; } } });
    assert.equal(calls, 0);
    assert.notEqual(receipt.status, 'pass');
    assert.ok(receipt.coverageGaps.includes('data-preflight-invalid'));
  }
});

test('scenario duplicate planned controls or protocols fail preflight before all adapters', async () => {
  let calls = 0;
  const invoke = async () => { calls += 1; return { observedState: {}, durableState: {} }; };
  const receipt = await runWebScenario({ binding, controls: ['forms', 'forms'], protocols: [{ name: 'http', applicable: true }, { name: 'http', applicable: true }], expectedState: {}, adapter: { invoke, invokeProtocol: invoke } });
  assert.equal(calls, 0);
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.includes('scenario-preflight-invalid'));
  assert.ok(receipt.coverageGaps.includes('scenario-id-duplicate:control:forms'));
  assert.ok(receipt.coverageGaps.includes('scenario-id-duplicate:protocol:http'));
});

test('API REST accepts only normalized single-slash relative routes', () => {
  const paths = ['//authority/path', '/https://evil.test/x', '/a/../b', '/%2e%2e/admin', '/ok\\bad', "/x\u0000y"];
  const cases = paths.map((path, index) => ({ id: `unsafe-${index}`, protocol: 'rest', method: 'GET', path }));
  const receipt = verifyApiExercise({ binding, cases });
  for (const item of cases) assert.ok(receipt.coverageGaps.includes(`${item.id}:rest-path-invalid`), item.path);
});

test('API REST rejects query fragment and any encoded noncanonical route', () => {
  const paths = ['/%252e%252e/admin', '/ok?x=1', '/ok#x', '/%41'];
  const cases = paths.map((path, index) => ({ id: `noncanonical-${index}`, protocol: 'rest', method: 'GET', path }));
  const receipt = verifyApiExercise({ binding, cases });
  for (const item of cases) assert.ok(receipt.coverageGaps.includes(`${item.id}:rest-path-invalid`), item.path);
});

test('API REST accepts exact root as canonical route', () => {
  const receipt = verifyApiExercise({ binding, cases: [{ id: 'root-route', protocol: 'rest', method: 'GET', path: '/' }] });
  assert.equal(receipt.coverageGaps.includes('root-route:rest-path-invalid'), false);
});

test('external validator never passes or returns raw secret and PII artifact bytes', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const content = 'Authorization: Bearer token-value customer@example.com';
  const artifact = { path: 'raw/external/leak.txt', content, digest: `sha256:${createHash('sha256').update(content).digest('hex')}`, binding };
  const payload = { producer: 'ci', scope: 'deploy', targetId: binding.targetId, environment: binding.environment, artifactDigest: binding.artifactDigest, controlId: 'deploy', binding, issuedAt: '2026-08-07T23:59:00.000Z', checkedAt: '2026-08-08T00:00:00.000Z', expiresAt: '2026-08-09T00:00:00.000Z', artifacts: [artifact] };
  const signedContent = JSON.stringify(payload);
  const receipt = validateExternalEvidence({ ...payload, artifacts: undefined, signedContent, signature: sign(null, Buffer.from(signedContent), privateKey).toString('base64') }, { trustedProducers: [{ id: 'ci', publicKey: publicKey.export({ type: 'spki', format: 'pem' }) }], scope: 'deploy', targetId: binding.targetId, environment: binding.environment, artifactDigest: binding.artifactDigest, controlId: 'deploy', binding, now: payload.checkedAt, maxAgeMs: 60_000 });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.gaps.includes('produced-artifact-sensitive-data'));
  assert.equal(JSON.stringify(receipt).includes('token-value'), false);
  assert.equal(JSON.stringify(receipt).includes('customer@example.com'), false);
});

test('integration excludes secret or PII artifacts independently', () => {
  const content = '{"email":"customer@example.com","authorization":"Bearer token-value"}';
  const artifact = { family: 'web', targetId: binding.targetId, environment: binding.environment, sourceRevision: binding.sourceRevision, controlId: 'x', path: 'raw/web/leak.json', content, digest: `sha256:${createHash('sha256').update(content).digest('hex')}`, binding };
  const receipt = integrateWebEvidence({ binding, applicableControls: ['x'], receipts: [{ controlId: 'x', targetId: binding.targetId, status: 'pass', terminal: true, binding, artifacts: [artifact] }] });
  assert.notEqual(receipt.status, 'pass');
  assert.deepEqual(receipt.rawArtifacts, []);
  assert.equal(JSON.stringify(receipt).includes('customer@example.com'), false);
  assert.equal(JSON.stringify(receipt).includes('token-value'), false);
});

test('third-party duplicate config identity rejection is permutation deterministic', () => {
  const configs = [{ key: 'stripe', adapterId: 'stripe-adapter', environment: 'sandbox' }, { key: 'stripe', adapterId: 'duplicate-adapter', environment: 'test' }, { key: 'email', adapterId: 'duplicate-adapter', environment: 'sandbox' }];
  const input = { binding, configuredProviders: configs, applicableProviders: ['stripe'], exercises: [{ ...thirdPartyBase, adapterKey: 'stripe', provider: 'stripe' }], now: '2026-08-08T00:00:00.000Z', maxAgeMs: 60_000 };
  const left = verifyThirdPartyExercise(input);
  const right = verifyThirdPartyExercise({ ...input, configuredProviders: [...configs].reverse() });
  assert.notEqual(left.status, 'pass');
  assert.deepEqual(left.coverageGaps, right.coverageGaps);
  assert.deepEqual(left.receipts, right.receipts);
  assert.equal(left.digest, right.digest);
  assert.ok(left.coverageGaps.includes('provider-config-key-duplicate:stripe'));
  assert.ok(left.coverageGaps.includes('provider-config-adapter-duplicate:duplicate-adapter'));
});

test('infrastructure rejects unsafe paths and sanitizes secret or PII artifacts before return', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const ids = ['cdn', 'deployment', 'dns', 'drift', 'health', 'iam', 'infra', 'network', 'region', 'rollback', 'runtime', 'scaling', 'secrets', 'storage', 'tls'];
  const content = 'Bearer infrastructure-token owner@example.com';
  const artifact = { path: '../raw/infra.txt', content, digest: `sha256:${createHash('sha256').update(content).digest('hex')}`, binding };
  const payload = { producer: 'ci', targetId: binding.targetId, environment: binding.environment, artifactDigest: binding.artifactDigest, binding, issuedAt: '2026-08-07T23:59:00.000Z', checkedAt: '2026-08-08T00:00:00.000Z', expiresAt: '2026-08-09T00:00:00.000Z', applicableControls: ids, controlFacts: ids.map((id) => ({ id, kind: 'infrastructure-control-fact', applicable: true, configured: true, deployed: true, exercised: true, status: 'pass', terminal: true, binding, artifacts: [artifact] })), exerciseReceipt: { status: 'pass', terminal: true, artifacts: [artifact] } };
  const signedContent = JSON.stringify(payload);
  const receipt = verifyInfrastructureExercise({ binding, evidence: { producer: 'ci', signedContent, signature: sign(null, Buffer.from(signedContent), privateKey).toString('base64') }, trustedProducers: [{ id: 'ci', publicKey: publicKey.export({ type: 'spki', format: 'pem' }) }], now: payload.checkedAt, maxAgeMs: 60_000 });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.includes('produced-evidence-invalid'));
  assert.ok(receipt.coverageGaps.includes('infrastructure-sensitive-data'));
  assert.equal(JSON.stringify(receipt).includes('infrastructure-token'), false);
  assert.equal(JSON.stringify(receipt).includes('owner@example.com'), false);
});

test('operations rejects and sanitizes secret or PII signed record artifacts', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const content = 'Bearer operations-token operator@example.com';
  const artifact = { path: 'raw/operations/alerts.txt', content, digest: `sha256:${createHash('sha256').update(content).digest('hex')}`, binding };
  const record = { id: 'alerts', producer: 'ops', binding, exercised: true, status: 'pass', terminal: true, outcome: { executed: true }, issuedAt: '2026-08-07T23:59:00.000Z', checkedAt: '2026-08-08T00:00:00.000Z', expiresAt: '2026-08-09T00:00:00.000Z', workload: 'w1', dataset: 'seed', region: 'eu', providerLimits: {}, cost: {}, assumptions: [], alert: true, action: true, recovery: true, residualDamage: [], artifacts: [artifact] };
  const signedContent = JSON.stringify(record);
  const receipt = verifyOperationsExercise({ binding, exercises: [{ id: 'alerts', producer: 'ops', signedContent, signature: sign(null, Buffer.from(signedContent), privateKey).toString('base64') }], trustedProducers: [{ id: 'ops', publicKey: publicKey.export({ type: 'spki', format: 'pem' }) }], now: record.checkedAt, maxAgeMs: 60_000 });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.includes('alerts:operation-sensitive-data'));
  assert.equal(JSON.stringify(receipt).includes('operations-token'), false);
  assert.equal(JSON.stringify(receipt).includes('operator@example.com'), false);
  const safeArtifact = receipt.receipts.find((item) => item.id === 'alerts').record.artifacts[0];
  assert.equal(safeArtifact.digest, `sha256:${createHash('sha256').update(safeArtifact.content).digest('hex')}`);
});

test('WebSocket and webhook require the same canonical paths as REST', () => {
  const paths = ['//authority/path', '/ok?x=1', '/ok#x', '/%252e%252e/admin', '/a/../b', '/ok\\bad', "/x\u0000y"];
  const cases = paths.flatMap((path, index) => [{ id: `ws-${index}`, protocol: 'websocket', method: 'CONNECT', path, operation: { type: 'message', name: 'Update' } }, { id: `hook-${index}`, protocol: 'webhook', method: 'POST', path, operation: { type: 'event', name: 'Changed' } }]);
  const receipt = verifyApiExercise({ binding, cases });
  for (const item of cases) assert.ok(receipt.coverageGaps.includes(`${item.id}:${item.protocol}-contract-invalid`), `${item.protocol}:${item.path}`);
});

test('matrix duplicate capability IDs reject before Map and remain permutation deterministic', () => {
  const capabilities = [{ id: 'chromium', status: 'available', browserVersion: '128', binary: 'bundled-pinned', binding }, { id: 'chromium', status: 'blocked', browserVersion: '128', binary: 'bundled-pinned', binding }];
  const policy = { combinations: [{ id: 'desktop-chromium', status: 'pass', terminal: true }] };
  const left = compileWebMatrix({ binding, policy, capabilities });
  const right = compileWebMatrix({ binding, policy, capabilities: [...capabilities].reverse() });
  assert.notEqual(left.status, 'pass');
  assert.ok(left.coverageGaps.includes('capability-id-duplicate:chromium'));
  assert.deepEqual(left, right);
});

test('API matrix and third-party malformed collections return terminal receipts without throwing', () => {
  const calls = [() => verifyApiExercise({ binding, cases: {} }), () => compileWebMatrix({ binding, capabilities: {}, policy: { combinations: {} } }), () => verifyThirdPartyExercise({ binding, configuredProviders: {}, exercises: {} })];
  for (const invoke of calls) {
    let receipt;
    assert.doesNotThrow(() => { receipt = invoke(); });
    assert.equal(receipt.terminal, true);
    assert.notEqual(receipt.status, 'pass');
  }
});

test('shared external sanitizer removes common phone forms without treating ISO dates as phones', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const content = 'observed 2026-08-08T00:00:00.000Z; call 212-555-0123 or +1 (415) 555-0199';
  const artifact = { path: 'raw/external/phones.txt', content, digest: `sha256:${createHash('sha256').update(content).digest('hex')}`, binding };
  const payload = { producer: 'ci', scope: 'deploy', targetId: binding.targetId, environment: binding.environment, artifactDigest: binding.artifactDigest, controlId: 'deploy', binding, issuedAt: '2026-08-07T23:59:00.000Z', checkedAt: '2026-08-08T00:00:00.000Z', expiresAt: '2026-08-09T00:00:00.000Z', artifacts: [artifact] };
  const signedContent = JSON.stringify(payload);
  const receipt = validateExternalEvidence({ ...payload, artifacts: undefined, signedContent, signature: sign(null, Buffer.from(signedContent), privateKey).toString('base64') }, { trustedProducers: [{ id: 'ci', publicKey: publicKey.export({ type: 'spki', format: 'pem' }) }], scope: 'deploy', targetId: binding.targetId, environment: binding.environment, artifactDigest: binding.artifactDigest, controlId: 'deploy', binding, now: payload.checkedAt, maxAgeMs: 60_000 });
  assert.notEqual(receipt.status, 'pass');
  assert.equal(JSON.stringify(receipt).includes('212-555-0123'), false);
  assert.equal(JSON.stringify(receipt).includes('+1 (415) 555-0199'), false);
  assert.equal(receipt.payload.artifacts[0].content.includes('2026-08-08T00:00:00.000Z'), true);
});

test('matrix observations and vitals require full binding plus every planned dimension', () => {
  const receipt = compileWebMatrix({ binding, capabilities: [{ id: 'chromium', status: 'available', browserVersion: '128', binary: 'bundled-pinned', binding }], policy: { combinations: [{ id: 'desktop-chromium', status: 'pass', terminal: true, vitals: { cls: 0, inp: 1, lcp: 2 } }] } });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.includes('observation-binding-mismatch:desktop-chromium'));
  assert.ok(receipt.coverageGaps.includes('observation-dimension-missing:desktop-chromium:browser'));
  assert.ok(receipt.coverageGaps.includes('vitals-binding-mismatch:desktop-chromium'));
});

test('listed web collection boundaries return terminal errors instead of throwing', async () => {
  const invocations = [() => captureWebEvidence({ binding, captures: {} }), () => buildActorFixtures({ binding, actors: {}, required: {} }), () => verifyOperationsExercise({ binding, exercises: {} }), () => runWebScenario({ binding, controls: {}, protocols: {} }), () => inspectWebBackend({ binding, endpoints: {} }), () => integrateWebEvidence({ binding, applicableControls: {}, receipts: {} }), () => qualifyWebPlatform({ binding, fixtures: {} })];
  for (const invoke of invocations) {
    let receipt;
    await assert.doesNotReject(async () => { receipt = await invoke(); });
    assert.equal(receipt.terminal, true);
    assert.notEqual(receipt.status, 'pass');
  }
});

test('data cleanup runs zero times without exercise and exactly once after exercise starts', async () => {
  let missingCalls = 0;
  const missing = await verifyDataExercise({ binding, dataset: 'seed', schemaVersion: '1', cases: [dataDefinition()], adapter: { cleanup: async () => { missingCalls += 1; } } });
  assert.equal(missingCalls, 0);
  assert.notEqual(missing.status, 'pass');
  assert.ok(missing.coverageGaps.includes('adapter-exercise-missing'));
  let startedCalls = 0;
  await verifyDataExercise({ binding, dataset: 'seed', schemaVersion: '1', cases: [dataDefinition()], adapter: { exercise: async () => { startedCalls += 1; throw new Error('started'); }, cleanup: async () => { startedCalls += 1; throw new Error('cleanup'); } } });
  assert.equal(startedCalls, 2);
});

test('capture performance and matrix vitals reject negative or nonfinite metrics', () => {
  const surface = { id: 'control:direct-link', journeyId: 'control:direct-link', controlId: 'direct-link', routeId: 'route:home', route: '/', stateId: 'loaded', actionId: 'action:navigate-direct', protocolId: 'http', directApplicable: true, deepApplicable: false, matrixCombinationId: 'desktop-chromium', binding, componentIds: ['hero'] };
  const sample = (repeat, performance) => ({ repeat, screenshot: `s${repeat}`, dom: `d${repeat}`, accessibilityTree: `a${repeat}`, style: `c${repeat}`, geometry: `g${repeat}`, trace: `t${repeat}`, performance });
  const capture = captureWebEvidence({ binding, surface, tool: { name: 'playwright', version: '1', accessibilityEngine: 'ax', accessibilityEngineVersion: '1' }, captures: [sample(1, { lcp: -1, memory: Number.NaN, longTasks: [-1], layoutShifts: [Number.POSITIVE_INFINITY], paints: [Number.NaN], userTimings: [-1] }), sample(2, { lcp: 1, memory: 1, longTasks: [], layoutShifts: [], paints: [], userTimings: [] })] });
  for (const gap of ['capture-performance-lcp-invalid:1', 'capture-performance-memory-invalid:1', 'capture-performance-longTasks-invalid:1', 'capture-performance-layoutShifts-invalid:1', 'capture-performance-paints-invalid:1', 'capture-performance-userTimings-invalid:1']) assert.ok(capture.coverageGaps.includes(gap), gap);
  const capability = { id: 'chromium', status: 'available', browserVersion: '128', binary: 'bundled-pinned', binding };
  const plan = compileWebMatrix({ binding, capabilities: [capability], policy: { maxCombinations: 24 } });
  const definition = plan.combinations.find((item) => item.id === 'desktop-chromium');
  const matrix = compileWebMatrix({ binding, capabilities: [capability], policy: { maxCombinations: 24, combinations: [{ ...definition, binding, status: 'pass', terminal: true, vitals: { cls: -1, inp: -1, lcp: -1, binding } }] } });
  for (const metric of ['cls', 'inp', 'lcp']) assert.ok(matrix.coverageGaps.includes(`vitals-metric-invalid:desktop-chromium:${metric}`), metric);
});

test('canonical Base64 admission rejects unused-bit aliases across shared external infrastructure and integration paths', () => {
  const alias = 'AB==';
  const digest = `sha256:${createHash('sha256').update(Buffer.from(alias, 'base64')).digest('hex')}`;
  assert.equal(sanitizeProducedArtifact({ bytesBase64: alias, digest }).valid, false);
  const webArtifact = { family: 'web', targetId: binding.targetId, environment: binding.environment, sourceRevision: binding.sourceRevision, controlId: 'x', path: 'raw/web/alias.bin', bytesBase64: alias, digest, binding };
  const integrated = integrateWebEvidence({ binding, applicableControls: ['x'], receipts: [{ controlId: 'x', targetId: binding.targetId, status: 'pass', terminal: true, binding, artifacts: [webArtifact] }] });
  assert.notEqual(integrated.status, 'pass'); assert.deepEqual(integrated.rawArtifacts, []);
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const artifact = { path: 'raw/external/alias.bin', bytesBase64: alias, digest, binding };
  const base = { producer: 'ci', targetId: binding.targetId, environment: binding.environment, artifactDigest: binding.artifactDigest, binding, issuedAt: '2026-08-07T23:59:00.000Z', checkedAt: '2026-08-08T00:00:00.000Z', expiresAt: '2026-08-09T00:00:00.000Z' };
  const signPayload = (payload) => { const signedContent = JSON.stringify(payload); return { producer: 'ci', signedContent, signature: sign(null, Buffer.from(signedContent), privateKey).toString('base64') }; };
  const trustedProducers = [{ id: 'ci', publicKey: publicKey.export({ type: 'spki', format: 'pem' }) }];
  const externalPayload = { ...base, scope: 'deploy', controlId: 'deploy', artifacts: [artifact] };
  const external = validateExternalEvidence(signPayload(externalPayload), { trustedProducers, scope: 'deploy', targetId: binding.targetId, environment: binding.environment, artifactDigest: binding.artifactDigest, controlId: 'deploy', binding, now: base.checkedAt, maxAgeMs: 60_000 });
  assert.notEqual(external.status, 'pass'); assert.ok(external.gaps.includes('produced-artifact-invalid'));
  const ids = ['cdn', 'deployment', 'dns', 'drift', 'health', 'iam', 'infra', 'network', 'region', 'rollback', 'runtime', 'scaling', 'secrets', 'storage', 'tls'];
  const infrastructurePayload = { ...base, applicableControls: ids, controlFacts: ids.map((id) => ({ id, kind: 'infrastructure-control-fact', applicable: true, configured: true, deployed: true, exercised: true, status: 'pass', terminal: true, binding, artifacts: [artifact] })), exerciseReceipt: { status: 'pass', terminal: true, artifacts: [artifact] } };
  const infrastructure = verifyInfrastructureExercise({ binding, evidence: signPayload(infrastructurePayload), trustedProducers, now: base.checkedAt, maxAgeMs: 60_000 });
  assert.notEqual(infrastructure.status, 'pass'); assert.ok(infrastructure.coverageGaps.includes('produced-evidence-invalid'));
  for (const extraAlias of ['AC==', 'AD==']) assert.equal(sanitizeProducedArtifact({ bytesBase64: extraAlias, digest }).valid, false);
});

test('capture distinguishes absent performance metrics from invalid metric values', () => {
  const surface = { id: 'control:direct-link', journeyId: 'control:direct-link', controlId: 'direct-link', routeId: 'route:home', route: '/', stateId: 'loaded', actionId: 'action:navigate-direct', protocolId: 'http', directApplicable: true, deepApplicable: false, matrixCombinationId: 'desktop-chromium', binding, componentIds: ['hero'] };
  const evidence = (repeat, performance) => ({ repeat, screenshot: `s${repeat}`, dom: `d${repeat}`, accessibilityTree: `a${repeat}`, style: `c${repeat}`, geometry: `g${repeat}`, trace: `t${repeat}`, performance });
  const receipt = captureWebEvidence({ binding, surface, tool: { name: 'playwright', version: '1', accessibilityEngine: 'ax', accessibilityEngineVersion: '1' }, captures: [evidence(1, { lcp: null, memory: null, longTasks: null }), evidence(2, { lcp: 1, memory: 1, longTasks: [], layoutShifts: [], paints: [], userTimings: [] })] });
  for (const metric of ['lcp', 'memory', 'longTasks', 'layoutShifts', 'paints', 'userTimings']) assert.ok(receipt.coverageGaps.includes(`capture-performance-${metric}-missing:1`), metric);
});

test('web qualification rejects noncanonical Base64 before raw artifact admission', () => {
  const bytesBase64 = 'AB==';
  const artifact = { family: 'web', targetId: binding.targetId, environment: binding.environment, sourceRevision: binding.sourceRevision, controlId: 'x', path: 'raw/web/alias.bin', bytesBase64, digest: `sha256:${createHash('sha256').update(Buffer.from(bytesBase64, 'base64')).digest('hex')}`, binding };
  const receipt = qualifyWebPlatform({ binding, fixtures: [{ id: 'alias', family: 'web', applicableControls: ['x'], receipts: [{ controlId: 'x', targetId: binding.targetId, status: 'pass', terminal: true, binding, artifacts: [artifact] }] }] });
  assert.notEqual(receipt.status, 'pass'); assert.deepEqual(receipt.rawArtifacts, []); assert.equal(receipt.rejectedArtifacts.length, 1);
});

test('operations rejects noncanonical Base64 and never returns null admitted artifacts', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const bytesBase64 = 'AB==';
  const artifact = { path: 'raw/operations/alias.bin', bytesBase64, digest: `sha256:${createHash('sha256').update(Buffer.from(bytesBase64, 'base64')).digest('hex')}`, binding };
  const record = { id: 'alerts', producer: 'ops', binding, exercised: true, status: 'pass', terminal: true, outcome: { executed: true }, issuedAt: '2026-08-07T23:59:00.000Z', checkedAt: '2026-08-08T00:00:00.000Z', expiresAt: '2026-08-09T00:00:00.000Z', workload: 'w1', dataset: 'seed', region: 'eu', providerLimits: {}, cost: {}, assumptions: [], alert: true, action: true, recovery: true, residualDamage: [], artifacts: [artifact] };
  const signedContent = JSON.stringify(record);
  const receipt = verifyOperationsExercise({ binding, exercises: [{ id: 'alerts', producer: 'ops', signedContent, signature: sign(null, Buffer.from(signedContent), privateKey).toString('base64') }], trustedProducers: [{ id: 'ops', publicKey: publicKey.export({ type: 'spki', format: 'pem' }) }], now: record.checkedAt, maxAgeMs: 60_000 });
  const alerts = receipt.receipts.find((item) => item.id === 'alerts');
  assert.ok(alerts.coverageGaps.includes('operation-artifact-invalid')); assert.notEqual(alerts.status, 'pass'); assert.deepEqual(alerts.record.artifacts, []);
});

test('external validator rejects noncanonical Base64 signature aliases before verification', () => {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const content = 'safe';
  const artifact = { path: 'raw/external/safe.txt', content, digest: `sha256:${createHash('sha256').update(content).digest('hex')}`, binding };
  const payload = { producer: 'ci', scope: 'deploy', targetId: binding.targetId, environment: binding.environment, artifactDigest: binding.artifactDigest, controlId: 'deploy', binding, issuedAt: '2026-08-07T23:59:00.000Z', checkedAt: '2026-08-08T00:00:00.000Z', expiresAt: '2026-08-09T00:00:00.000Z', artifacts: [artifact] };
  const signedContent = JSON.stringify(payload), canonical = sign(null, Buffer.from(signedContent), privateKey).toString('base64');
  const position = canonical.length - 3, aliased = `${canonical.slice(0, position)}${alphabet[alphabet.indexOf(canonical[position]) + 1]}==`;
  assert.deepEqual(Buffer.from(aliased, 'base64'), Buffer.from(canonical, 'base64'));
  const receipt = validateExternalEvidence({ ...payload, signedContent, signature: aliased }, { trustedProducers: [{ id: 'ci', publicKey: publicKey.export({ type: 'spki', format: 'pem' }) }], scope: 'deploy', targetId: binding.targetId, environment: binding.environment, artifactDigest: binding.artifactDigest, controlId: 'deploy', binding, now: payload.checkedAt, maxAgeMs: 60_000 });
  assert.notEqual(receipt.status, 'pass'); assert.ok(receipt.gaps.includes('signature-noncanonical'));
});

test('capture accepts only finite scalar or nonempty numeric-array performance metrics', () => {
  const surface = { id: 'control:direct-link', journeyId: 'control:direct-link', controlId: 'direct-link', routeId: 'route:home', route: '/', stateId: 'loaded', actionId: 'action:navigate-direct', protocolId: 'http', directApplicable: true, deepApplicable: false, matrixCombinationId: 'desktop-chromium', binding, componentIds: ['hero'] };
  const evidence = (repeat, performance) => ({ repeat, screenshot: `s${repeat}`, dom: `d${repeat}`, accessibilityTree: `a${repeat}`, style: `c${repeat}`, geometry: `g${repeat}`, trace: `t${repeat}`, performance });
  const tool = { name: 'playwright', version: '1', accessibilityEngine: 'ax', accessibilityEngineVersion: '1' };
  const invalid = captureWebEvidence({ binding, surface, tool, captures: [evidence(1, { lcp: 1, memory: 1, longTasks: [], layoutShifts: [{}], paints: [0], userTimings: [0] }), evidence(2, { lcp: 2, memory: 2, longTasks: [0], layoutShifts: [0], paints: [0], userTimings: [0] })] });
  assert.ok(invalid.coverageGaps.includes('capture-performance-longTasks-invalid:1'));
  assert.ok(invalid.coverageGaps.includes('capture-performance-layoutShifts-invalid:1'));
  const valid = captureWebEvidence({ binding, surface, tool, captures: [evidence(1, { lcp: 1, memory: 1, longTasks: [0], layoutShifts: [0], paints: [0], userTimings: [0] }), evidence(2, { lcp: 2, memory: 2, longTasks: [1], layoutShifts: [0.1], paints: [1], userTimings: [1] })] });
  assert.equal(valid.status, 'pass'); assert.equal(Number.isFinite(valid.performance.p75), true);
});

test('operations rejects noncanonical Base64 signature aliases before verification', () => {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const record = { id: 'alerts', producer: 'ops', binding, exercised: true, status: 'pass', terminal: true, outcome: { executed: true }, issuedAt: '2026-08-07T23:59:00.000Z', checkedAt: '2026-08-08T00:00:00.000Z', expiresAt: '2026-08-09T00:00:00.000Z', workload: 'w1', dataset: 'seed', region: 'eu', providerLimits: {}, cost: {}, assumptions: [], alert: true, action: true, recovery: true, residualDamage: [] };
  const signedContent = JSON.stringify(record), canonical = sign(null, Buffer.from(signedContent), privateKey).toString('base64');
  const position = canonical.length - 3, signature = `${canonical.slice(0, position)}${alphabet[alphabet.indexOf(canonical[position]) + 1]}==`;
  assert.deepEqual(Buffer.from(signature, 'base64'), Buffer.from(canonical, 'base64'));
  const receipt = verifyOperationsExercise({ binding, exercises: [{ id: 'alerts', producer: 'ops', signedContent, signature }], trustedProducers: [{ id: 'ops', publicKey: publicKey.export({ type: 'spki', format: 'pem' }) }], now: record.checkedAt, maxAgeMs: 60_000 });
  const alerts = receipt.receipts.find((item) => item.id === 'alerts');
  assert.ok(alerts.coverageGaps.includes('signature-noncanonical')); assert.notEqual(alerts.status, 'pass');
});

test('infrastructure rejects noncanonical Base64 signatures before verification', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const payload = { producer: 'ci', targetId: binding.targetId, environment: binding.environment, artifactDigest: binding.artifactDigest, binding };
  const signedContent = JSON.stringify(payload), canonical = sign(null, Buffer.from(signedContent), privateKey).toString('base64'), signature = aliasBase64(canonical);
  assert.deepEqual(Buffer.from(signature, 'base64'), Buffer.from(canonical, 'base64'));
  const receipt = verifyInfrastructureExercise({ binding, evidence: { producer: 'ci', signedContent, signature }, trustedProducers: [{ id: 'ci', publicKey: publicKey.export({ type: 'spki', format: 'pem' }) }] });
  assert.notEqual(receipt.status, 'pass'); assert.ok(receipt.coverageGaps.includes('signature-noncanonical'));
});

test('infrastructure malformed control facts return terminal gaps without throwing', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const payload = { producer: 'ci', targetId: binding.targetId, environment: binding.environment, artifactDigest: binding.artifactDigest, binding, issuedAt: '2026-08-07T23:59:00.000Z', checkedAt: '2026-08-08T00:00:00.000Z', expiresAt: '2026-08-09T00:00:00.000Z', applicableControls: [], controlFacts: [null], exerciseReceipt: { status: 'pass', terminal: true, artifacts: [] } };
  const signedContent = JSON.stringify(payload), evidence = { producer: 'ci', signedContent, signature: sign(null, Buffer.from(signedContent), privateKey).toString('base64') };
  let receipt;
  assert.doesNotThrow(() => { receipt = verifyInfrastructureExercise({ binding, evidence, trustedProducers: [{ id: 'ci', publicKey: publicKey.export({ type: 'spki', format: 'pem' }) }], now: payload.checkedAt, maxAgeMs: 60_000 }); });
  assert.equal(receipt.terminal, true); assert.ok(receipt.coverageGaps.includes('infrastructure-control-facts-invalid'));
});

test('third-party malformed applicability providers return terminal invalid source', () => {
  let receipt;
  assert.doesNotThrow(() => { receipt = verifyThirdPartyExercise({ binding, applicabilitySource: { kind: 'frozen-conditional-provider-applicability', id: 'web:conditional-providers', binding, providers: [null], digest: `sha256:${'a'.repeat(64)}` } }); });
  assert.equal(receipt.terminal, true); assert.notEqual(receipt.status, 'pass'); assert.ok(receipt.coverageGaps.includes('conditional-provider-applicability-source-invalid'));
});

test('third-party not-applicable receipt rejects noncanonical Base64 signature', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const payload = { producer: 'policy', provider: 'payments', status: 'not-applicable', reason: 'absent', binding };
  const signedContent = JSON.stringify(payload), canonical = sign(null, Buffer.from(signedContent), privateKey).toString('base64'), signature = aliasBase64(canonical);
  const receipt = verifyThirdPartyExercise({ binding, notApplicableReceipts: [{ producer: 'policy', provider: 'payments', signedContent, signature }], trustedProducers: [{ id: 'policy', publicKey: publicKey.export({ type: 'spki', format: 'pem' }) }] });
  assert.notEqual(receipt.status, 'pass'); assert.ok(receipt.coverageGaps.includes('provider-not-applicable-signature-noncanonical:payments'));
});

test('API raw artifact identities require exactly one request and response deterministically', () => {
  const artifact = (kind, suffix = '') => { const content = `${kind}${suffix}`; return { kind, redacted: true, caseId: 'raw-denominator', protocol: 'rest', method: 'GET', path: '/items', operation: null, correlationId: 'corr-raw', content, digest: `sha256:${createHash('sha256').update(content).digest('hex')}`, binding }; };
  const item = { id: 'raw-denominator', protocol: 'rest', method: 'GET', path: '/items', correlationId: 'corr-raw', sensitiveFields: [], rawArtifacts: [artifact('request'), artifact('request', '-duplicate'), artifact('response'), artifact('trace')] };
  const left = verifyApiExercise({ binding, cases: [item] }), right = verifyApiExercise({ binding, cases: [{ ...item, rawArtifacts: [...item.rawArtifacts].reverse() }] });
  assert.notEqual(left.status, 'pass'); assert.ok(left.coverageGaps.includes('raw-denominator:raw-request-evidence-duplicate')); assert.ok(left.coverageGaps.includes('raw-denominator:raw-artifact-unplanned:trace')); assert.equal(left.digest, right.digest);
});

test('API malformed sensitive field descriptors return terminal error without throwing', () => {
  let receipt;
  assert.doesNotThrow(() => { receipt = verifyApiExercise({ binding, cases: [{ id: 'bad-sensitive', protocol: 'rest', method: 'GET', path: '/', sensitiveFields: {} }] }); });
  assert.equal(receipt.terminal, true); assert.equal(receipt.status, 'error'); assert.ok(receipt.coverageGaps.includes('bad-sensitive:sensitive-fields-invalid'));
});

test('infrastructure malformed trusted producer collection returns terminal gap', () => {
  let receipt;
  assert.doesNotThrow(() => { receipt = verifyInfrastructureExercise({ binding, trustedProducers: { id: 'ci' } }); });
  assert.equal(receipt.terminal, true); assert.notEqual(receipt.status, 'pass'); assert.ok(receipt.coverageGaps.includes('trusted-producers-invalid'));
});

test('performance rejects malformed capture collection and layout shift shapes before reduction', () => {
  let malformed;
  assert.doesNotThrow(() => { malformed = verifyWebPerformance({ binding, captures: {}, budgets: { lcp: 1 } }); });
  assert.equal(malformed.terminal, true); assert.equal(malformed.status, 'error');
  const receipt = verifyWebPerformance({ binding, captures: [{ performance: { lcp: 1, longTasks: [0], layoutShifts: [{}], paints: [0], memory: 1, userTimings: [0] } }], budgets: { layoutShifts: 1 } });
  assert.notEqual(receipt.status, 'pass'); assert.ok(receipt.coverageGaps.includes('performance-layoutShifts-invalid:missing'));
});

test('same-tenant role escalation requires exact transition and server authorization', () => {
  const actorBinding = { ...binding, actorId: 'viewer' };
  const capability = { id: 'role-escalation', toActorId: 'admin', fromTenantId: 'tenant-a', toTenantId: 'tenant-a', authorizationId: 'role.elevate' };
  const actor = (id, role, transitions = []) => ({ id, identityId: 'identity-1', credentialPolicyId: 'vault-v1', sessionPolicyId: 'isolated-v1', role, tier: 'pro', tenantId: 'tenant-a', accountState: 'active', secretRef: `vault://actors/${id}`, expiresAt: '2026-08-09T00:00:00.000Z', serverAuthorizations: ['role.elevate'], uiVisibility: [], transitionCapabilities: transitions });
  const receipt = buildActorFixtures({ binding: actorBinding, now: '2026-08-08T00:00:00.000Z', required: [{ role: 'viewer', tier: 'pro', tenantId: 'tenant-a', accountState: 'active' }, { role: 'admin', tier: 'pro', tenantId: 'tenant-a', accountState: 'active' }], actors: [actor('viewer', 'viewer', [capability]), actor('admin', 'admin')] });
  assert.equal(switchActor({ receipt, from: 'viewer', to: 'admin', currentActorId: 'viewer', sessionBinding: actorBinding }).status, 'blocked');
  const serverAuthorization = { kind: 'server-authorization-evidence', transitionId: 'role-escalation', controlId: 'role-escalation', authorizationId: 'role.elevate', fromActorId: 'viewer', toActorId: 'admin', actorId: 'viewer', fromTenantId: 'tenant-a', toTenantId: 'tenant-a', tenantId: 'tenant-a', fromAccountState: 'active', toAccountState: 'active', sessionPolicyId: 'isolated-v1', sessionBinding: actorBinding, status: 'pass', terminal: true, binding: actorBinding };
  assert.equal(switchActor({ receipt, from: 'viewer', to: 'admin', currentActorId: 'viewer', sessionBinding: actorBinding, transitionCapabilityId: 'role-escalation', serverAuthorization }).status, 'pass');
});

test('infrastructure malformed exercise artifacts return terminal typed gap', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const payload = { producer: 'ci', targetId: binding.targetId, environment: binding.environment, artifactDigest: binding.artifactDigest, binding, issuedAt: '2026-08-07T23:59:00.000Z', checkedAt: '2026-08-08T00:00:00.000Z', expiresAt: '2026-08-09T00:00:00.000Z', applicableControls: [], controlFacts: [], exerciseReceipt: { status: 'pass', terminal: true, artifacts: {} } };
  const signedContent = JSON.stringify(payload), evidence = { producer: 'ci', signedContent, signature: sign(null, Buffer.from(signedContent), privateKey).toString('base64') };
  let receipt;
  assert.doesNotThrow(() => { receipt = verifyInfrastructureExercise({ binding, evidence, trustedProducers: [{ id: 'ci', publicKey: publicKey.export({ type: 'spki', format: 'pem' }) }], now: payload.checkedAt, maxAgeMs: 60_000 }); });
  assert.equal(receipt.terminal, true); assert.ok(receipt.coverageGaps.includes('exercise-receipt-artifacts-invalid'));
});

test('matrix malformed dimension and pairwise policy returns terminal error', () => {
  for (const policy of [{ mandatoryDimensions: { browser: {} } }, { pairwise: [null] }]) {
    let receipt;
    assert.doesNotThrow(() => { receipt = compileWebMatrix({ binding, capabilities: [], policy }); });
    assert.equal(receipt.terminal, true); assert.equal(receipt.status, 'error'); assert.ok(receipt.coverageGaps.includes('matrix-policy-invalid'));
  }
});

test('actor malformed transition elements return terminal error and no proof', () => {
  let receipt;
  assert.doesNotThrow(() => { receipt = buildActorFixtures({ binding, actors: [{ id: 'editor', role: 'editor', tier: 'pro', tenantId: 'tenant-a', accountState: 'active', transitionCapabilities: [null] }], required: [] }); });
  assert.equal(receipt.terminal, true); assert.equal(receipt.status, 'error'); assert.equal(receipt.proof, false); assert.ok(receipt.coverageGaps.includes('actor-collections-invalid'));
});

test('capture null surface returns terminal error before property access', () => {
  let receipt;
  assert.doesNotThrow(() => { receipt = captureWebEvidence({ binding, surface: null, captures: [] }); });
  assert.equal(receipt.terminal, true); assert.equal(receipt.status, 'error'); assert.ok(receipt.coverageGaps.includes('capture-surface-invalid'));
});

test('matrix malformed combination and omission elements return terminal error', () => {
  for (const policy of [{ combinations: [null] }, { combinations: ['bad'] }, { combinations: [{ id: 0 }] }, { omitted: [null] }, { omitted: [0] }, { omitted: [{ id: '' }] }]) {
    let receipt;
    assert.doesNotThrow(() => { receipt = compileWebMatrix({ binding, capabilities: [], policy }); });
    assert.equal(receipt.terminal, true); assert.equal(receipt.status, 'error'); assert.ok(receipt.coverageGaps.includes('matrix-collections-invalid'));
  }
});

test('qualification rejects malformed nested receipts and artifacts deterministically', () => {
  const malformed = [[null], [{ controlId: 'x', artifacts: {} }], [{ controlId: 'x', artifacts: [null] }]];
  for (const nested of malformed) {
    let left;
    assert.doesNotThrow(() => { left = qualifyWebPlatform({ binding, fixtures: [{ id: 'bad', family: 'web', applicableControls: ['x'], receipts: nested }] }); });
    const right = qualifyWebPlatform({ binding, fixtures: [{ id: 'bad', family: 'web', applicableControls: ['x'], receipts: nested }] });
    assert.equal(left.status, 'error'); assert.equal(left.terminal, true); assert.equal(left.receipts[0].status, 'error'); assert.ok(left.receipts[0].coverageGaps.includes('fixture-rejected')); assert.equal(left.digest, right.digest);
  }
});

test('qualification never returns original sensitive produced or rejected artifact payloads', () => {
  const artifact = (path, content) => ({ family: 'web', targetId: binding.targetId, environment: binding.environment, sourceRevision: binding.sourceRevision, controlId: 'x', path, content, digest: `sha256:${createHash('sha256').update(content).digest('hex')}`, binding });
  const receipt = qualifyWebPlatform({ binding, fixtures: [{ id: 'sensitive', family: 'web', applicableControls: ['x'], receipts: [{ controlId: 'x', targetId: binding.targetId, status: 'pass', terminal: true, binding, artifacts: [artifact('raw/web/safe.txt', 'Bearer qualification-token owner@example.com'), artifact('../unsafe.txt', 'Bearer rejected-token rejected@example.com')] }] }] });
  const serialized = JSON.stringify(receipt);
  for (const leaked of ['qualification-token', 'owner@example.com', 'rejected-token', 'rejected@example.com']) assert.equal(serialized.includes(leaked), false);
  assert.match(receipt.rawArtifacts[0].content, /\[REDACTED\]/); assert.equal(receipt.rawArtifacts[0].digest, `sha256:${createHash('sha256').update(receipt.rawArtifacts[0].content).digest('hex')}`);
  assert.equal(Object.hasOwn(receipt.rejectedArtifacts[0], 'content'), false); assert.equal(Object.hasOwn(receipt.rejectedArtifacts[0], 'bytesBase64'), false);
});

test('operations records artifact sanitation as explicit non-pass evidence gap', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const content = 'Bearer ops-sanitized-token ops@example.com', artifact = { path: 'raw/operations/alerts.txt', content, digest: `sha256:${createHash('sha256').update(content).digest('hex')}`, binding };
  const record = { id: 'alerts', producer: 'ops', binding, exercised: true, status: 'pass', terminal: true, outcome: { executed: true }, issuedAt: '2026-08-07T23:59:00.000Z', checkedAt: '2026-08-08T00:00:00.000Z', expiresAt: '2026-08-09T00:00:00.000Z', workload: 'w1', dataset: 'seed', region: 'eu', providerLimits: {}, cost: {}, assumptions: [], alert: true, action: true, recovery: true, residualDamage: [], artifacts: [artifact] };
  const signedContent = JSON.stringify(record), receipt = verifyOperationsExercise({ binding, exercises: [{ id: 'alerts', producer: 'ops', signedContent, signature: sign(null, Buffer.from(signedContent), privateKey).toString('base64') }], trustedProducers: [{ id: 'ops', publicKey: publicKey.export({ type: 'spki', format: 'pem' }) }], now: record.checkedAt, maxAgeMs: 60_000 });
  assert.notEqual(receipt.status, 'pass'); assert.ok(receipt.coverageGaps.includes('alerts:operation-artifact-sanitized'));
});

test('capture recursively sanitizes returned evidence and records explicit non-pass gap', () => {
  const surface = { id: 'control:direct-link', journeyId: 'control:direct-link', controlId: 'direct-link', routeId: 'route:home', route: '/', stateId: 'loaded', actionId: 'action:navigate-direct', protocolId: 'http', directApplicable: true, deepApplicable: false, matrixCombinationId: 'desktop-chromium', binding, componentIds: ['hero'] };
  const sample = (repeat, screenshot, dom) => ({ repeat, screenshot, dom, accessibilityTree: `tree-${repeat}`, style: `style-${repeat}`, geometry: `geometry-${repeat}`, trace: `trace-${repeat}`, performance: { lcp: repeat, memory: repeat, longTasks: [0], layoutShifts: [0], paints: [0], userTimings: [0] } });
  const receipt = captureWebEvidence({ binding, surface, tool: { name: 'playwright', version: '1', accessibilityEngine: 'ax', accessibilityEngineVersion: '1' }, captures: [sample(1, 'Bearer capture-token', 'owner@example.com'), sample(2, 'safe-shot', 'safe-dom')] });
  assert.notEqual(receipt.status, 'pass'); assert.ok(receipt.coverageGaps.includes('capture-sensitive-data-sanitized')); assert.equal(JSON.stringify(receipt).includes('capture-token'), false); assert.equal(JSON.stringify(receipt).includes('owner@example.com'), false);
});

test('capture malformed tool returns terminal error before property access', () => {
  for (const tool of [null, [], 'playwright']) { let receipt; assert.doesNotThrow(() => { receipt = captureWebEvidence({ binding, surface: {}, tool, captures: [] }); }); assert.equal(receipt.status, 'error'); assert.equal(receipt.terminal, true); assert.ok(receipt.coverageGaps.includes('capture-tool-invalid')); }
});

test('qualification catch never echoes attacker-controlled exception text', () => {
  const controlId = 'Bearer exception-token attacker@example.com';
  const receipt = qualifyWebPlatform({ binding, fixtures: [{ id: 'caught', family: 'web', applicableControls: [controlId], receipts: [{ controlId, targetId: 'foreign', status: 'pass', terminal: true, binding, artifacts: [] }] }] });
  assert.equal(receipt.status, 'error'); assert.deepEqual(receipt.receipts[0].error, { code: 'qualification-integration-error', type: 'integration-rejected', message: 'fixture integration rejected' });
  assert.equal(JSON.stringify(receipt).includes('exception-token'), false); assert.equal(JSON.stringify(receipt).includes('attacker@example.com'), false);
});

test('qualification maps unsafe fixture control and receipt IDs to stable opaque identities', () => {
  const fixtureId = 'Bearer fixture-token fixture@example.com', controlId = 'Bearer control-token control@example.com', receiptId = 'Bearer receipt-token receipt@example.com';
  const input = { binding, fixtures: [{ id: fixtureId, family: 'web', applicableControls: [controlId], receipts: [{ id: receiptId, controlId, targetId: binding.targetId, status: 'pass', terminal: true, binding, artifacts: [] }] }] };
  const left = qualifyWebPlatform(input), right = qualifyWebPlatform(input), serialized = JSON.stringify(left);
  for (const leaked of [fixtureId, controlId, receiptId, 'fixture-token', 'control-token', 'receipt-token', 'fixture@example.com', 'control@example.com', 'receipt@example.com']) assert.equal(serialized.includes(leaked), false);
  assert.match(left.receipts[0].id, /^opaque-[a-f0-9]{24}$/); assert.equal(left.digest, right.digest); assert.deepEqual(left.denominator, right.denominator); assert.deepEqual(left.coverageGaps, right.coverageGaps);
});

test('qualification recursively maps nested BigInt and cyclic identifier values without throwing', () => {
  const cyclicId = {}; cyclicId.self = cyclicId;
  const controlId = 'Bearer hostile-control hostile@example.com', content = 'safe evidence';
  const artifact = { id: 19n, sourceReceiptId: 'Bearer nested-token nested@example.com', metadata: { aliasIds: ['Bearer alias-token alias@example.com', 23n, cyclicId], safeOwnerId: 'owner-1' }, family: 'web', targetId: binding.targetId, environment: binding.environment, sourceRevision: binding.sourceRevision, controlId, path: 'raw/web/nested.json', content, digest: `sha256:${createHash('sha256').update(content).digest('hex')}`, binding };
  const input = { binding, fixtures: [{ id: cyclicId, family: 'web', applicableControls: [controlId], receipts: [{ id: 17n, controlId, targetId: binding.targetId, status: 'pass', terminal: true, binding, artifacts: [artifact] }] }] };
  let left;
  assert.doesNotThrow(() => { left = qualifyWebPlatform(input); });
  const right = qualifyWebPlatform(input), serialized = JSON.stringify(left), returned = left.rawArtifacts[0];
  for (const leaked of ['hostile-control', 'hostile@example.com', 'nested-token', 'nested@example.com', 'alias-token', 'alias@example.com']) assert.equal(serialized.includes(leaked), false);
  assert.match(left.receipts[0].id, /^opaque-[a-f0-9]{24}$/); assert.match(returned.id, /^opaque-[a-f0-9]{24}$/); assert.match(returned.sourceReceiptId, /^opaque-[a-f0-9]{24}$/); for (const id of returned.metadata.aliasIds) assert.match(id, /^opaque-[a-f0-9]{24}$/); assert.equal(returned.metadata.safeOwnerId, 'owner-1'); assert.equal(left.digest, right.digest);
});

test('qualification normalizes hostile top-level binding identifiers before empty-fixture output', () => {
  const cycle = {}; cycle.self = cycle;
  const values = [29n, Symbol.for('binding-secret'), function bindingSecret() {}, [], { secret: 'owner@example.com' }, cycle];
  for (const value of values) {
    const hostileBinding = { ...binding, actorId: value, metadata: { sourceReceiptId: value, safeOwnerId: 'owner-1' } };
    let left;
    assert.doesNotThrow(() => { left = qualifyWebPlatform({ binding: hostileBinding, fixtures: [] }); });
    const right = qualifyWebPlatform({ binding: hostileBinding, fixtures: [] });
    assert.match(left.binding.actorId, /^opaque-[a-f0-9]{24}$/); assert.equal(Object.hasOwn(left.binding, 'metadata'), false); assert.ok(left.coverageGaps.includes('binding-extra-undeclared')); assert.equal(left.digest, right.digest);
  }
});

test('shared canonicalization and finalize are cycle-safe and reject hostile bindings opaquely', () => {
  const cycle = {}; cycle.self = cycle; const hostile = [31n, Symbol.for('shared-secret'), function sharedSecret() {}, cycle];
  for (const actorId of hostile) {
    const value = { payload: actorId, cycle }; let receipt;
    assert.doesNotThrow(() => { JSON.stringify(canonicalize(value)); receipt = finalize('hostile-binding-probe', { status: 'pass', terminal: false, binding: { ...binding, actorId, apiToken: 'Bearer binding-token', email: 'binding@example.com' } }); });
    assert.equal(receipt.status, 'error'); assert.equal(receipt.terminal, true); assert.match(receipt.binding.actorId, /^opaque-[a-f0-9]{24}$/); assert.equal(Object.hasOwn(receipt.binding, 'apiToken'), false); assert.equal(Object.hasOwn(receipt.binding, 'email'), false); assert.equal(JSON.stringify(receipt).includes('binding-token'), false); assert.equal(JSON.stringify(receipt).includes('binding@example.com'), false);
  }
  const exact = exactBinding({ ...binding, apiToken: 'Bearer extra-token', email: 'extra@example.com', undeclared: 'x' });
  assert.deepEqual(Object.keys(exact.binding), [...BINDING_KEYS].sort()); assert.ok(exact.gaps.includes('binding-extra-sensitive')); assert.ok(exact.gaps.includes('binding-extra-undeclared')); assert.equal(JSON.stringify(exact).includes('extra-token'), false); assert.equal(JSON.stringify(exact).includes('extra@example.com'), false);
});

test('API rejects hostile case IDs before sorting or interpolation', () => {
  const cycle = {}; cycle.self = cycle;
  for (const id of [Symbol.for('case-secret'), 41n, {}, cycle]) { let receipt; assert.doesNotThrow(() => { receipt = verifyApiExercise({ binding, cases: [{ id }] }); }); assert.equal(receipt.status, 'error'); assert.equal(receipt.terminal, true); assert.ok(receipt.coverageGaps.includes('api-case-id-invalid')); }
});

test('scenario rejects hostile control and protocol IDs before adapter invocation', async () => {
  let calls = 0;
  for (const input of [{ controls: [Symbol.for('control-secret')], protocols: [] }, { controls: [], protocols: [{ name: 43n, applicable: true }] }]) {
    let receipt;
    await assert.doesNotReject(async () => { receipt = await runWebScenario({ binding, ...input, adapter: { invoke: async () => { calls += 1; return {}; } } }); });
    assert.equal(receipt.status, 'error'); assert.equal(receipt.terminal, true); assert.ok(receipt.coverageGaps.includes('scenario-identifiers-invalid'));
  }
  assert.equal(calls, 0);
});

test('scenario propagates explicit terminal adapter failure status', async () => {
  const diagnostics = ['cache', 'console', 'cookies', 'cors', 'csp', 'error', 'headers', 'hydration', 'network'];
  const receipt = await runWebScenario({ binding, controls: ['forms'], protocols: [], expectedState: { ok: true }, adapter: { invoke: async ({ control }) => ({ status: 'fail', terminal: true, observedState: { ok: true }, durableState: { ok: true }, browserDiagnostics: { denominator: diagnostics, facts: diagnostics.map((id) => ({ id, status: 'pass', terminal: true, binding })) }, serverAuthorization: { kind: 'server-authorization-evidence', source: 'server', uiDerived: false, actorId: binding.actorId, tenantId: binding.tenantId, controlId: control, status: 'pass', terminal: true, authorizationIds: ['write'], binding } }) } });
  assert.equal(receipt.receipts.find((item) => item.id === 'control:forms').status, 'fail'); assert.notEqual(receipt.status, 'pass');
});

test('different actor identities require exact transition and server authorization even without role or tenant change', () => {
  const actor = (id, identityId) => ({ id, identityId, credentialPolicyId: 'vault-v1', sessionPolicyId: 'isolated-v1', role: 'editor', tier: 'pro', tenantId: 'tenant-a', accountState: 'active', secretRef: `vault://actors/${id}`, expiresAt: '2026-08-09T00:00:00.000Z', serverAuthorizations: [], uiVisibility: [], transitionCapabilities: [] });
  const receipt = buildActorFixtures({ binding, now: '2026-08-08T00:00:00.000Z', required: [{ role: 'editor', tier: 'pro', tenantId: 'tenant-a', accountState: 'active' }], actors: [actor('editor', 'identity-a'), actor('editor-copy', 'identity-b')] });
  assert.equal(receipt.status, 'pass'); assert.equal(switchActor({ receipt, from: 'editor', to: 'editor-copy', currentActorId: 'editor', sessionBinding: binding }).status, 'blocked');
});

test('cycle-safe redaction prevents API RangeError and raw recursive leaks', () => {
  const cycle = { email: 'cycle@example.com', token: 'cycle-token' }; cycle.self = cycle;
  let safe, receipt;
  assert.doesNotThrow(() => { safe = redact(cycle); receipt = verifyApiExercise({ binding, cases: [{ id: 'cycle', observed: cycle, durableEffect: cycle }] }); JSON.stringify(receipt); });
  assert.equal(JSON.stringify(safe).includes('cycle@example.com'), false); assert.equal(JSON.stringify(safe).includes('cycle-token'), false); assert.equal(receipt.terminal, true);
});

test('web API runner preserves runtime web provider identity across service delegation', async () => {
  const receipt = await runWebControl({ binding, family: 'api', input: { cases: [] } });
  assert.equal(receipt.provider, 'runtime.web'); assert.equal(receipt.delegatedProvider, 'runtime.service.api'); assert.notEqual(receipt.kind, 'legion-service-api-provider');
});

test('third-party operations and actors reject hostile identifiers before sorting or interpolation', () => {
  for (const invoke of [() => verifyThirdPartyExercise({ binding, applicableProviders: [Symbol.for('provider-secret')] }), () => verifyOperationsExercise({ binding, exercises: [{ id: Symbol.for('operation-secret') }] }), () => buildActorFixtures({ binding, actors: [{ id: Symbol.for('actor-secret') }], required: [] })]) {
    let receipt; assert.doesNotThrow(() => { receipt = invoke(); }); assert.equal(receipt.status, 'error'); assert.equal(receipt.terminal, true); assert.ok(receipt.coverageGaps.some((gap) => gap.includes('identifiers-invalid')));
  }
});
