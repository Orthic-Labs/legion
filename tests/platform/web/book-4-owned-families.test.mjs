import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { validateSchema } from '../../../lib/qualification/schema-validator.mjs';
import { buildActorFixtures } from '../../../providers/runtime/web/actors/index.mjs';
import { verifyWebPerformance } from '../../../providers/runtime/web/performance/index.mjs';
import { verifyWebAccessibility } from '../../../providers/runtime/web/accessibility/index.mjs';
import { verifyServiceData } from '../../../providers/runtime/service/data/index.mjs';
import { verifyCloudEvidence } from '../../../providers/runtime/external/cloud/index.mjs';
import { verifyDnsEvidence } from '../../../providers/runtime/external/dns/index.mjs';
import { verifyEmailEvidence } from '../../../providers/runtime/external/email/index.mjs';
import { verifyCommerceEvidence } from '../../../providers/runtime/external/commerce/index.mjs';
import { verifyAnalyticsEvidence } from '../../../providers/runtime/external/analytics/index.mjs';
import { verifyThirdPartyEvidence } from '../../../providers/runtime/external/third-party/index.mjs';
import { verifyBackupEvidence } from '../../../providers/runtime/external/backup/index.mjs';
import { verifyIncidentEvidence } from '../../../providers/runtime/external/incidents/index.mjs';

const binding = Object.freeze({ targetId: 'web', environment: 'test', actorId: 'editor', tenantId: 'tenant-a', browser: 'chromium', browserVersion: '128', viewport: '1440x900', locale: 'en-GB', sourceRevision: 'abc', artifactDigest: 'sha256:artifact' });
const tool = { name: 'playwright', version: '1.55', accessibilityEngine: 'chromium-ax', accessibilityEngineVersion: '128' };
const capture = (repeat, lcp) => ({ repeat, screenshot: `s${repeat}`, dom: `d${repeat}`, accessibilityTree: `a${repeat}`, style: `c${repeat}`, geometry: `g${repeat}`, trace: `t${repeat}`, performance: { lcp, longTasks: [0], layoutShifts: [0], paints: [0], memory: 10, userTimings: [0] } });

test('actor schema validates complete runtime proof and rejects forged sparse pass bundle', () => {
  const schema = JSON.parse(readFileSync(new URL('../../../schemas/platform/web-actor-fixture-v1.schema.json', import.meta.url), 'utf8'));
  const receipt = buildActorFixtures({ binding, now: '2026-08-08T00:00:00.000Z', required: [{ role: 'editor', tier: 'pro', tenantId: 'tenant-a', accountState: 'active' }], actors: [{ id: 'editor', identityId: 'identity-1', credentialPolicyId: 'sso-1', sessionPolicyId: 'bounded-1', role: 'editor', tier: 'pro', tenantId: 'tenant-a', accountState: 'active', secretRef: 'vault://actors/editor', expiresAt: '2026-08-09T00:00:00.000Z', serverAuthorizations: ['write'], uiVisibility: ['save'], transitionCapabilities: [] }] });
  assert.deepEqual(validateSchema(schema, receipt), []);
  const forged = { schemaVersion: 1, kind: 'nemesis-web-actor-fixtures', status: 'pass', terminal: true, binding: {}, actors: [], denominator: { total: 0, accounted: 0, missing: [] }, coverageGaps: [], digest: `sha256:${'a'.repeat(64)}` };
  assert.ok(validateSchema(schema, forged).length > 0);
});

test('actor schema requires runtime identity policy transition and typed authorization fields', () => {
  const schema = JSON.parse(readFileSync(new URL('../../../schemas/platform/web-actor-fixture-v1.schema.json', import.meta.url), 'utf8'));
  for (const field of ['identityId', 'credentialPolicyId', 'sessionPolicyId', 'transitionCapabilities', 'serverAuthorizations', 'uiVisibility']) assert.ok(schema.$defs.actor.required.includes(field), field);
  assert.equal(schema.$defs.actor.properties.serverAuthorizations.type, 'array');
  assert.equal(schema.$defs.actor.properties.uiVisibility.type, 'array');
  assert.equal(schema.$defs.actor.properties.transitionCapabilities.items.$ref, '#/$defs/transitionCapability');
  assert.deepEqual(schema.$defs.credentialReference.properties.type.enum, ['env', 'keychain', 'secret-manager', 'vault']);
  assert.equal(JSON.stringify(schema).includes('password'), false);
});

test('actor runtime rejects scalar authorization and visibility collections', () => {
  const receipt = buildActorFixtures({ binding, now: '2026-08-08T00:00:00.000Z', required: [{ role: 'editor', tier: 'pro', tenantId: 'tenant-a', accountState: 'active' }], actors: [{ id: 'editor', identityId: 'identity-1', credentialPolicyId: 'sso-1', sessionPolicyId: 'bounded-1', role: 'editor', tier: 'pro', tenantId: 'tenant-a', accountState: 'active', secretRef: 'vault://actors/editor', expiresAt: '2026-08-09T00:00:00.000Z', serverAuthorizations: 'write', uiVisibility: 'save', transitionCapabilities: [] }] });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.includes('actor-serverAuthorizations-invalid:editor'));
  assert.ok(receipt.coverageGaps.includes('actor-uiVisibility-invalid:editor'));
});

test('actor runtime enforces account state and identity policy field types before proof', () => {
  const receipt = buildActorFixtures({ binding, now: '2026-08-08T00:00:00.000Z', required: [{ role: 'editor', tier: 'pro', tenantId: 'tenant-a', accountState: 'active' }], actors: [{ id: 'editor', identityId: 0, credentialPolicyId: false, sessionPolicyId: [], role: {}, tier: 0, tenantId: '', accountState: 'invented', secretRef: 'vault://actors/editor', expiresAt: '2026-08-09T00:00:00.000Z', serverAuthorizations: [], uiVisibility: [], transitionCapabilities: [] }] });
  assert.notEqual(receipt.status, 'pass');
  assert.equal(receipt.complete, false);
  assert.equal(receipt.proof, false);
  for (const gap of ['actor-role-invalid:editor', 'actor-tier-invalid:editor', 'actor-tenantId-invalid:editor', 'actor-accountState-invalid:editor', 'actor-identityId-invalid:editor', 'actor-credentialPolicyId-invalid:editor', 'actor-sessionPolicyId-invalid:editor']) assert.ok(receipt.coverageGaps.includes(gap), gap);
});

test('performance & accessibility families delegate to strict bound capture evidence', () => {
  const input = { binding, surface: { id: 'control:direct-link', journeyId: 'control:direct-link', controlId: 'direct-link', routeId: 'route:home', route: '/', stateId: 'loaded', actionId: 'action:navigate-direct', protocolId: 'http', directApplicable: true, deepApplicable: false, matrixCombinationId: 'desktop-chromium', binding, componentIds: ['hero'] }, tool, captures: [capture(1, 1000), capture(2, 1200)] };
  const performance = verifyWebPerformance({ ...input, budgets: { lcp: 1500, longTasks: 1, layoutShifts: 0 } });
  assert.equal(performance.status, 'pass');
  assert.equal(performance.evidenceClass, 'measured');
  const accessibility = verifyWebAccessibility({ ...input, inspections: [
    { repeat: 1, status: 'pass', terminal: true, binding, screenshot: 'sha256:a11y-1', violations: [] },
    { repeat: 2, status: 'pass', terminal: true, binding, screenshot: 'sha256:a11y-2', violations: [] },
  ] });
  assert.equal(accessibility.status, 'pass');
  assert.equal(accessibility.engine.name, 'chromium-ax');
});

test('service data delegates lifecycle execution & cleanup', async () => {
  let cleanup = 0;
  const content = '{"rows":1}';
  const caseDefinition = { id: 'database', operationType: 'query', dataset: { id: 'seed', digest: `sha256:${'a'.repeat(64)}` }, schema: { version: '1', digest: `sha256:${'b'.repeat(64)}` }, engine: { name: 'sqlite', version: '3', digest: `sha256:${'c'.repeat(64)}` }, isolation: { id: 'transaction-1', environment: 'test', binding }, cleanupBinding: { datasetId: 'seed', schemaVersion: '1', environment: 'test', binding }, statementDigest: `sha256:${'d'.repeat(64)}` };
  const artifact = { kind: 'data-result', caseId: 'database', datasetId: 'seed', schemaVersion: '1', engineVersion: '3', content, digest: `sha256:${createHash('sha256').update(content).digest('hex')}`, binding };
  const receipt = await verifyServiceData({ binding, dataset: 'seed', schemaVersion: '1', cases: [caseDefinition], adapter: { exercise: async () => ({ status: 'pass', terminal: true, cases: [{ id: 'database', operationType: 'query', status: 'pass', terminal: true, binding, observed: { rows: 1 }, durableResult: { rows: 1 }, artifacts: [artifact] }] }), cleanup: async () => { cleanup += 1; return { datasetId: 'seed', schemaVersion: '1', environment: 'test', binding, residualDamage: [] }; } } });
  assert.equal(receipt.provider, 'runtime.service.data');
  assert.equal(receipt.status, 'pass');
  assert.equal(cleanup, 1);
});

test('cloud & DNS families remain supplied-only external validators', () => {
  for (const receipt of [verifyCloudEvidence({ binding }), verifyDnsEvidence({ binding })]) {
    assert.equal(receipt.claimLevel, 'external');
    assert.equal(receipt.suppliedOnly, true);
    assert.equal(receipt.networkAttempted, false);
    assert.notEqual(receipt.status, 'pass');
  }
});

test('email, commerce, analytics & third-party families reconcile only supplied provider exercises', () => {
  for (const verify of [verifyEmailEvidence, verifyCommerceEvidence, verifyAnalyticsEvidence, verifyThirdPartyEvidence]) {
    const receipt = verify({ binding, applicableProviders: ['provider'], exercises: [] });
    assert.equal(receipt.claimLevel, 'external');
    assert.equal(receipt.suppliedOnly, true);
    assert.equal(receipt.networkAttempted, false);
    assert.ok(receipt.coverageGaps.includes('provider-missing:provider'));
  }
});

test('backup & incidents families require supplied exercised operations evidence', () => {
  for (const receipt of [verifyBackupEvidence({ binding, exercises: [] }), verifyIncidentEvidence({ binding, exercises: [] })]) {
    assert.equal(receipt.claimLevel, 'external');
    assert.equal(receipt.suppliedOnly, true);
    assert.equal(receipt.networkAttempted, false);
    assert.notEqual(receipt.status, 'pass');
    assert.ok(receipt.coverageGaps.includes('operations-denominator-empty'));
  }
});
