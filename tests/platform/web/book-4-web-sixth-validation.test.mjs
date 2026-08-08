import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { validateExternalEvidence } from '../../../lib/platform/external/validate.mjs';
import { verifyInfrastructureExercise } from '../../../providers/runtime/web/infrastructure/index.mjs';
import { verifyThirdPartyExercise } from '../../../providers/runtime/web/third-party/index.mjs';

const binding = Object.freeze({ targetId: 'web', environment: 'test', actorId: 'editor', tenantId: 'tenant-a', browser: 'chromium', browserVersion: '128', viewport: '1440x900', locale: 'en-GB', sourceRevision: 'abc', artifactDigest: 'sha256:artifact' });
const times = { issuedAt: '2026-08-07T23:59:00.000Z', checkedAt: '2026-08-08T00:00:00.000Z', expiresAt: '2026-08-09T00:00:00.000Z' };
const signed = (payload, privateKey, envelope = {}) => { const signedContent = JSON.stringify(payload); return { ...payload, artifacts: undefined, ...envelope, signedContent, signature: sign(null, Buffer.from(signedContent), privateKey).toString('base64') }; };

test('external validator requires expected scope parity with signed payload and envelope', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const content = 'external receipt';
  const exerciseReceipt = { controlId: 'deploy', status: 'pass', terminal: true, binding };
  const payload = { producer: 'ci', scope: 'wrong-scope', targetId: 'web', environment: 'test', artifactDigest: binding.artifactDigest, controlId: 'deploy', binding, ...times, artifacts: [{ path: 'raw/external/deploy.json', content, digest: `sha256:${createHash('sha256').update(content).digest('hex')}`, binding }], exerciseReceipt };
  const receipt = validateExternalEvidence(signed(payload, privateKey, { exerciseReceipt }), { trustedProducers: [{ id: 'ci', publicKey: publicKey.export({ type: 'spki', format: 'pem' }) }], scope: 'deploy', targetId: 'web', environment: 'test', artifactDigest: binding.artifactDigest, controlId: 'deploy', binding, requiresExercise: true, now: times.checkedAt, maxAgeMs: 60_000 });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.gaps.includes('mismatched-scope'));
});

test('infrastructure rejects signed payload with foreign actor or tenant binding', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const content = 'rollback evidence';
  const foreign = { ...binding, actorId: 'attacker', tenantId: 'tenant-b' };
  const payload = { producer: 'ci', targetId: binding.targetId, environment: binding.environment, artifactDigest: binding.artifactDigest, binding: foreign, ...times, exerciseReceipt: { status: 'pass', terminal: true, artifacts: [{ content, digest: `sha256:${createHash('sha256').update(content).digest('hex')}`, binding }] } };
  const signedContent = JSON.stringify(payload);
  const receipt = verifyInfrastructureExercise({ binding, evidence: { producer: 'ci', binding, signedContent, signature: sign(null, Buffer.from(signedContent), privateKey).toString('base64') }, trustedProducers: [{ id: 'ci', publicKey: publicKey.export({ type: 'spki', format: 'pem' }) }], now: times.checkedAt, maxAgeMs: 60_000 });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.includes('binding-mismatch'));
});

test('third-party boolean signed flag cannot establish provider trust', () => {
  const exercise = { adapterKey: 'stripe', provider: 'stripe', environment: 'sandbox', binding, signed: true, ...times, client: 'ok', backend: 'ok', providerState: 'ok', userState: 'ok', consent: true, webhook: true, idempotency: true, quota: {}, cost: {} };
  const receipt = verifyThirdPartyExercise({ binding, configuredProviders: [{ key: 'stripe', adapterId: 'stripe-sandbox-v1' }], applicableProviders: ['stripe'], exercises: [exercise], now: times.checkedAt, maxAgeMs: 60_000 });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.some((gap) => gap.includes('signature-unproven')));
});

test('web platform matrix declares bounded B4-008 values, physicality and disjoint vitals denominators', () => {
  const matrix = JSON.parse(readFileSync(new URL('../../../registry/platform-matrices/web.json', import.meta.url), 'utf8'));
  assert.deepEqual(matrix.dimensions, ['browser', 'browserVersion', 'binary', 'viewport', 'device', 'physicality', 'dpr', 'input', 'colorScheme', 'contrast', 'motion', 'locale', 'network', 'offline']);
  assert.ok(matrix.browserPolicy.every(({ id, versions, binaryPolicy }) => id && versions.length && binaryPolicy));
  assert.ok(matrix.mandatoryCombinations.length >= 2);
  assert.ok(matrix.pairwisePolicy.maxCombinations > 0 && matrix.pairwisePolicy.pairs.length > 0);
  assert.equal(matrix.physicality.mobileEmulationEqualsPhysical, false);
  assert.notDeepEqual(matrix.vitalsDenominators.desktop, matrix.vitalsDenominators.mobile);
  assert.ok(matrix.dimensionValues.offline.includes(true) && matrix.dimensionValues.offline.includes(false));
});

test('web platform matrix requires keyboard input without weakening mouse or touch coverage', () => {
  const matrix = JSON.parse(readFileSync(new URL('../../../registry/platform-matrices/web.json', import.meta.url), 'utf8'));
  assert.deepEqual(matrix.dimensionValues.input, ['keyboard', 'mouse', 'touch']);
  const keyboard = matrix.mandatoryCombinations.find((item) => item.input === 'keyboard');
  assert.equal(keyboard?.device, 'desktop');
  assert.equal(keyboard?.physicality, 'physical');
  assert.ok(matrix.pairwisePolicy.pairs.some(([left, right]) => left === 'device' && right === 'input'));
  assert.ok(matrix.vitalsDenominators.desktop.combinationIds.includes(keyboard.id));
});
