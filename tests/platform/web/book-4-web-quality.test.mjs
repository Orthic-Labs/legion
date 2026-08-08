import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import test from 'node:test';
import { validateExternalEvidence } from '../../../lib/platform/external/validate.mjs';
import { qualifyWebPlatform } from '../../../qualification/platforms/web/qualification.mjs';
import { verifyInfrastructureExercise } from '../../../providers/runtime/web/infrastructure/index.mjs';
import { integrateWebEvidence } from '../../../providers/runtime/web/integration/index.mjs';
import { executeWebProtocol } from '../../../providers/runtime/web/protocols/index.mjs';
import { runWebScenario } from '../../../providers/runtime/web/scenario/index.mjs';

const binding = Object.freeze({ targetId: 'web', environment: 'test', actorId: 'editor', tenantId: 'tenant-a', browser: 'chromium', browserVersion: '128', viewport: '1440x900', locale: 'en-GB', sourceRevision: 'abc', artifactDigest: 'sha256:artifact' });
const times = Object.freeze({ issuedAt: '2026-08-07T23:59:00.000Z', checkedAt: '2026-08-08T00:00:00.000Z', expiresAt: '2026-08-09T00:00:00.000Z' });
const sha = (content) => `sha256:${createHash('sha256').update(content).digest('hex')}`;

test('infrastructure rejects zero-byte artifacts despite matching digest', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const ids = ['cdn', 'deployment', 'dns', 'drift', 'health', 'iam', 'infra', 'network', 'region', 'rollback', 'runtime', 'scaling', 'secrets', 'storage', 'tls'];
  const artifact = { content: '', digest: sha(''), binding };
  const payload = { producer: 'ci', targetId: binding.targetId, environment: binding.environment, artifactDigest: binding.artifactDigest, binding, ...times, applicableControls: ids, controlFacts: ids.map((id) => ({ id, kind: 'infrastructure-control-fact', applicable: true, configured: true, deployed: true, exercised: true, status: 'pass', terminal: true, binding, artifacts: [artifact] })), exerciseReceipt: { status: 'pass', terminal: true, artifacts: [artifact] } };
  const signedContent = JSON.stringify(payload);
  const receipt = verifyInfrastructureExercise({ binding, evidence: { producer: 'ci', signedContent, signature: sign(null, Buffer.from(signedContent), privateKey).toString('base64') }, trustedProducers: [{ id: 'ci', publicKey: publicKey.export({ type: 'spki', format: 'pem' }) }], now: times.checkedAt, maxAgeMs: 60_000 });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.includes('produced-evidence-invalid'));
  assert.ok(receipt.coverageGaps.includes('infrastructure-control-artifact-invalid:infra'));
});

test('external validator returns terminal unproven for malformed artifact collection', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const payload = { producer: 'ci', scope: 'deploy', targetId: binding.targetId, environment: binding.environment, artifactDigest: binding.artifactDigest, controlId: 'deploy', binding, ...times, artifacts: { 0: { content: 'x', digest: sha('x') }, length: 1 } };
  const signedContent = JSON.stringify(payload);
  const evidence = { ...payload, artifacts: undefined, signedContent, signature: sign(null, Buffer.from(signedContent), privateKey).toString('base64') };
  const expected = { trustedProducers: [{ id: 'ci', publicKey: publicKey.export({ type: 'spki', format: 'pem' }) }], scope: 'deploy', targetId: binding.targetId, environment: binding.environment, artifactDigest: binding.artifactDigest, controlId: 'deploy', binding, now: times.checkedAt, maxAgeMs: 60_000 };
  let receipt;
  assert.doesNotThrow(() => { receipt = validateExternalEvidence(evidence, expected); });
  assert.equal(receipt.status, 'unproven');
  assert.ok(receipt.gaps.includes('produced-artifact-invalid'));
});

test('qualification rejects unsafe absolute traversal empty and ambiguous artifact paths', () => {
  for (const path of ['/tmp/raw.json', 'C:\\raw\\web\\x.json', '../raw/web/x.json', '', 'raw//web/x.json', 'raw\\web/x.json']) {
    const content = 'produced';
    const artifact = { path, family: 'web', content, digest: sha(content), binding };
    const receipt = qualifyWebPlatform({ binding, fixtures: [{ id: `unsafe-${Buffer.from(path).toString('hex') || 'empty'}`, family: 'web', applicableControls: ['x'], receipts: [{ controlId: 'x', targetId: binding.targetId, status: 'pass', terminal: true, binding, artifacts: [artifact] }] }] });
    assert.deepEqual(receipt.rawArtifacts, [], path);
    assert.ok(receipt.coverageGaps.some((gap) => gap.endsWith(':produced-artifact-invalid')), path);
  }
});

test('integration canonicalizes artifact order and rejects duplicate artifact identity', () => {
  const artifact = (id, path, controlId) => ({ family: 'web', id, path, targetId: binding.targetId, environment: binding.environment, sourceRevision: binding.sourceRevision, controlId, content: id, digest: sha(id), binding });
  const duplicate = artifact('a', 'raw/web/a.json', 'x');
  const z = artifact('z', 'raw/web/z.json', 'y');
  const left = integrateWebEvidence({ binding, applicableControls: ['x', 'y'], receipts: [{ controlId: 'x', targetId: 'web', status: 'pass', terminal: true, binding, artifacts: [duplicate, { ...duplicate }] }, { controlId: 'y', targetId: 'web', status: 'pass', terminal: true, binding, artifacts: [z] }] });
  const right = integrateWebEvidence({ binding, applicableControls: ['y', 'x'], receipts: [{ controlId: 'y', targetId: 'web', status: 'pass', terminal: true, binding, artifacts: [z] }, { controlId: 'x', targetId: 'web', status: 'pass', terminal: true, binding, artifacts: [{ ...duplicate }, duplicate] }] });
  assert.equal(left.digest, right.digest);
  assert.equal(left.rawArtifacts.length, 2);
  assert.notEqual(left.status, 'pass');
  assert.ok(left.coverageGaps.some((gap) => gap.startsWith('artifact-identity-duplicate:')));
});

test('integration admits only produced fully bound applicable safe web artifacts', () => {
  const content = 'captured';
  const base = { family: 'web', targetId: binding.targetId, environment: binding.environment, sourceRevision: binding.sourceRevision, controlId: 'x', path: 'raw/web/x.json', content, digest: sha(content), binding };
  for (const artifact of [null, { ...base, path: '../raw/web/x.json' }, { ...base, targetId: 'other' }, { ...base, binding: { ...binding, tenantId: 'other' } }, { ...base, digest: `sha256:${'0'.repeat(64)}` }]) {
    const receipt = integrateWebEvidence({ binding, applicableControls: ['x'], receipts: [{ controlId: 'x', targetId: binding.targetId, status: 'pass', terminal: true, binding, artifacts: [artifact] }] });
    assert.notEqual(receipt.status, 'pass');
    assert.deepEqual(receipt.rawArtifacts, []);
    assert.ok(receipt.coverageGaps.includes('artifact-invalid:x'));
  }
});

test('external validator rejects null and unsafe-path artifacts without throwing', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const expected = { trustedProducers: [{ id: 'ci', publicKey: publicKey.export({ type: 'spki', format: 'pem' }) }], scope: 'deploy', targetId: binding.targetId, environment: binding.environment, artifactDigest: binding.artifactDigest, controlId: 'deploy', binding, now: times.checkedAt, maxAgeMs: 60_000 };
  for (const artifact of [null, { path: '../raw/deploy.json', content: 'x', digest: sha('x') }, { path: '/tmp/deploy.json', content: 'x', digest: sha('x') }]) {
    const payload = { producer: 'ci', scope: 'deploy', targetId: binding.targetId, environment: binding.environment, artifactDigest: binding.artifactDigest, controlId: 'deploy', binding, ...times, artifacts: [artifact] };
    const signedContent = JSON.stringify(payload);
    const evidence = { ...payload, artifacts: undefined, signedContent, signature: sign(null, Buffer.from(signedContent), privateKey).toString('base64') };
    let receipt;
    assert.doesNotThrow(() => { receipt = validateExternalEvidence(evidence, expected); });
    assert.notEqual(receipt.status, 'pass');
    assert.ok(receipt.gaps.includes('produced-artifact-invalid'));
  }
});

test('external validator requires safe path and exact binding on every produced artifact', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const expected = { trustedProducers: [{ id: 'ci', publicKey: publicKey.export({ type: 'spki', format: 'pem' }) }], scope: 'deploy', targetId: binding.targetId, environment: binding.environment, artifactDigest: binding.artifactDigest, controlId: 'deploy', binding, now: times.checkedAt, maxAgeMs: 60_000 };
  const base = { content: 'deployed', digest: sha('deployed') };
  for (const artifact of [{ ...base, binding }, { ...base, path: 'raw/external/deploy.json' }, { ...base, path: 'raw/external/deploy.json', binding: { ...binding, tenantId: 'foreign' } }]) {
    const payload = { producer: 'ci', scope: 'deploy', targetId: binding.targetId, environment: binding.environment, artifactDigest: binding.artifactDigest, controlId: 'deploy', binding, ...times, artifacts: [artifact] };
    const signedContent = JSON.stringify(payload);
    const receipt = validateExternalEvidence({ ...payload, artifacts: undefined, signedContent, signature: sign(null, Buffer.from(signedContent), privateKey).toString('base64') }, expected);
    assert.equal(receipt.status, 'unproven');
    assert.ok(receipt.gaps.includes('produced-artifact-invalid'));
  }
});

test('scenario rejects unplanned control or incomplete binding before adapter invocation', async () => {
  let calls = 0;
  const adapter = { invoke: async () => { calls += 1; return { observedState: {}, durableState: {} }; } };
  const unknown = await runWebScenario({ binding, controls: ['invented-control'], expectedState: {}, adapter });
  const incomplete = await runWebScenario({ binding: { ...binding, locale: '' }, controls: ['forms'], expectedState: {}, adapter });
  assert.notEqual(unknown.status, 'pass');
  assert.notEqual(incomplete.status, 'pass');
  assert.equal(calls, 0);
});

test('scenario preflights mixed planned and unplanned controls and protocols before any invocation', async () => {
  let calls = 0;
  const invoke = async () => { calls += 1; return { observedState: {}, durableState: {} }; };
  const receipt = await runWebScenario({ binding, controls: ['forms', 'invented-control'], protocols: [{ name: 'http', applicable: true }, { name: 'invented-protocol', applicable: true }], expectedState: {}, adapter: { invoke, invokeProtocol: invoke } });
  assert.equal(calls, 0);
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.includes('scenario-preflight-invalid'));
  assert.ok(receipt.coverageGaps.includes('control-unrecognized:invented-control'));
  assert.ok(receipt.coverageGaps.includes('protocol-unrecognized:invented-protocol'));
});

test('scenario preflights planned protocol applicability mismatch before any invocation', async () => {
  let calls = 0;
  const invoke = async () => { calls += 1; return { observedState: {}, durableState: {} }; };
  const receipt = await runWebScenario({ binding, controls: ['forms'], protocols: [{ name: 'http', applicable: false }], expectedState: {}, adapter: { invoke, invokeProtocol: invoke } });
  assert.equal(calls, 0);
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.includes('scenario-preflight-invalid'));
  assert.ok(receipt.coverageGaps.some((gap) => gap.endsWith(':protocol-applicability-mismatch')));
});

test('protocol rejects unplanned non-applicable or incompletely bound protocol before invocation', async () => {
  let calls = 0;
  const adapter = { execute: async () => { calls += 1; return { observedState: {}, durableState: {} }; } };
  for (const input of [{ binding, protocol: 'invented' }, { binding, protocol: 'websocket' }, { binding: { ...binding, locale: '' }, protocol: 'http' }]) {
    const receipt = await executeWebProtocol({ ...input, adapter });
    assert.notEqual(receipt.status, 'pass');
  }
  assert.equal(calls, 0);
});
