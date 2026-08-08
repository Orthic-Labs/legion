import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { canonicalJson, createSeer, seer as publicSeer, translateLegacyReport } from '../index.mjs';

const RUN = 'run_01J8Z3K9QG7X6M2N4P5R8S0T1V';
const REQUEST = 'req_01J8Z3K9QG7X6M2N4P5R8S0T1V';
const REVISION = '4e82122e713341f9a27545207a00ba45645d8e8f';
const NOW = '2026-08-08T00:00:00.000Z';

function request(operation, options = {}, input = {}) {
  return {
    schemaVersion: 1,
    kind: 'legion-operation-envelope',
    envelopeKind: 'request',
    operationId: `seer.${operation}`,
    operationVersion: '1.0.0',
    requestId: REQUEST,
    runId: RUN,
    callerAuthority: 'legion',
    authorityAssertion: {
      assertedBy: 'test-kernel',
      perMessage: true,
      verificationMethod: 'capability-signature',
    },
    input: {
      options,
      runIdentity: {
        schemaVersion: 1,
        kind: 'legion-run-identity',
        runId: RUN,
        workspace: 'D:/Claude',
        repository: 'tools/skills/nemesis',
        revision: REVISION,
        dirtyDigest: null,
        capturedAt: NOW,
      },
      workingContext: { marker: 'seer-isolated-01' },
      ...input,
    },
    idempotencyKey: null,
    sourceRevision: REVISION,
    requestedAt: NOW,
  };
}

const clock = { now: () => new Date(NOW) };

test('all five operations delegate to named canonical core APIs', async () => {
  const calls = [];
  const core = Object.fromEntries([
    ['inspectProduct', 'inspect'],
    ['buildPlan', 'plan'],
    ['audit', 'audit'],
    ['verifyRun', 'verify'],
    ['explain', 'explain'],
  ].map(([api, operation]) => [api, async (options, host) => {
    calls.push({ api, options, host });
    return { kind: `nemesis-${operation}`, claimBoundary: 'PARTIALLY_PROVEN' };
  }]));
  const seer = createSeer({ core, clock });
  const host = { identity: 'fixed-host' };

  for (const operation of ['inspect', 'plan', 'audit', 'verify', 'explain']) {
    const pair = await seer[operation](request(operation, { token: operation }), { host });
    assert.equal(pair.request.operationId, `seer.${operation}`);
    assert.equal(pair.result.invocationState, 'COMPLETED');
    assert.equal(pair.result.domainOutcome, 'COMPLETE');
    assert.equal(pair.result.claimBoundary, 'PARTIALLY_PROVEN');
    assert.equal(pair.result.error, null);
    assert.equal(pair.artifacts.length, 1);
    assert.match(pair.artifacts[0].record.digest, /^sha256:[0-9a-f]{64}$/);
    assert.deepEqual(pair.artifacts[0].value, { kind: `nemesis-${operation}`, claimBoundary: 'PARTIALLY_PROVEN' });
  }
  assert.deepEqual(calls.map(({ api }) => api), ['inspectProduct', 'buildPlan', 'audit', 'verifyRun', 'explain']);
  assert.deepEqual(calls.map(({ options }) => options.token), ['inspect', 'plan', 'audit', 'verify', 'explain']);
  assert.ok(calls.every((entry) => entry.host === host));
});

test('audit findings are successful invocation plus domain output, never an error', async () => {
  const finding = { id: 'F-31', severity: 'high', claim: 'FINDING_CONFIRMED' };
  const seer = createSeer({ core: { audit: async () => ({ report: { findings: [finding], claimBoundary: 'PARTIALLY_PROVEN' } }) }, clock });
  const pair = await seer.audit(request('audit'));
  assert.equal(pair.result.invocationState, 'COMPLETED');
  assert.equal(pair.result.domainOutcome, 'COMPLETE');
  assert.equal(pair.result.error, null);
  assert.deepEqual(pair.artifacts[0].value.report.findings, [finding]);
});

test('claim boundary and denominator digest pass through verbatim', async () => {
  const denominatorDigest = `sha256:${'d'.repeat(64)}`;
  const coreOutput = {
    claimBoundary: 'EVIDENCE_INSUFFICIENT',
    plan: { denominator: { fileSetDigest: denominatorDigest } },
    claims: [{ name: 'EVIDENCE_INSUFFICIENT', status: 'VALIDATED' }],
  };
  const seer = createSeer({ core: { verifyRun: async () => coreOutput }, clock });
  const pair = await seer.verify(request('verify'));
  assert.equal(pair.result.claimBoundary, coreOutput.claimBoundary);
  assert.equal(pair.artifacts[0].record.denominatorDigest, denominatorDigest);
  assert.deepEqual(pair.artifacts[0].value.claims, coreOutput.claims);
});

test('legacy fixture translates with exact findings, denominators, and claims parity', async () => {
  const fixture = JSON.parse(await readFile(new URL('../fixtures/legacy-parity.json', import.meta.url), 'utf8'));
  const legacy = JSON.parse(await readFile(new URL(fixture.source, new URL('../fixtures/', import.meta.url)), 'utf8'));
  const pair = translateLegacyReport(request('audit'), legacy, { clock });
  const expected = fixture.expected;
  assert.equal(canonicalJson(pair.artifacts[0].value), canonicalJson(legacy));
  assert.deepEqual(pair.artifacts[0].value.checks.map(({ check, findings }) => ({ check, findings })), expected.findings.checks);
  assert.deepEqual(pair.artifacts[0].value.provider_reconciliation.providerResults.map(({ provider, findings, candidates, coverageGaps }) => ({ provider, findings, candidates, coverageGaps })), expected.findings.providerResults);
  assert.deepEqual(pair.artifacts[0].value.plan.denominator, expected.denominators.plan);
  assert.deepEqual(pair.artifacts[0].value.provider_reconciliation.providerResults.map(({ provider, coverage }) => ({ provider, denominatorDigest: coverage.denominatorDigest })), expected.denominators.providers);
  assert.deepEqual(pair.artifacts[0].value.checks.map(({ check, status, verdict }) => ({ check, status, verdict })), expected.claims.checkVerdicts);
  assert.deepEqual(pair.artifacts[0].value.provider_reconciliation.providerResults.map(({ provider, status }) => ({ provider, status })), expected.claims.providerStatuses);
  assert.deepEqual(pair.artifacts[0].value.provider_reconciliation.coverageFamilies, expected.claims.coverageFamilies);
  assert.deepEqual(pair.artifacts[0].value.provider_reconciliation.unresolvedCoverage, expected.claims.unresolvedCoverage);
  assert.deepEqual(pair.artifacts[0].value.provider_reconciliation.missingRuntimeProviders, expected.claims.missingRuntimeProviders);
  assert.deepEqual(pair.artifacts[0].value.provider_reconciliation.denominatorMismatches, expected.claims.denominatorMismatches);
});

test('remediation proposals remain immutable artifacts and are never applied as effects', async () => {
  let applied = false;
  const remediation = { kind: 'remediation-proposal', action: 'rotate-secret', applied: false };
  const seer = createSeer({
    core: {
      audit: async () => ({
        domainOutcome: 'BLOCKED_DECISION',
        claimBoundary: 'EVIDENCE_INSUFFICIENT',
        remediation,
      }),
      applyRemediation: async () => { applied = true; },
    },
    clock,
  });
  const pair = await seer.audit(request('audit'));
  assert.equal(applied, false);
  assert.deepEqual(pair.artifacts[0].value.remediation, remediation);
  assert.equal(pair.artifacts[0].record.immutable, true);
  assert.equal(pair.result.domainOutcome, 'BLOCKED_DECISION');
  assert.equal(pair.result.claimBoundary, 'EVIDENCE_INSUFFICIENT');
});

test('mutation-capable requests fail before core invocation', async () => {
  let invoked = false;
  const seer = createSeer({ core: { audit: async () => { invoked = true; } }, clock });
  const pair = await seer.audit(request('audit', {}, { capabilities: ['source.read', 'source.mutate'] }));
  assert.equal(invoked, false);
  assert.equal(pair.result.invocationState, 'FAILED_INVOCATION');
  assert.equal(pair.result.domainOutcome, 'FAILED_CONTRACT');
  assert.equal(pair.result.error.code, 'SEER_MUTATION_CAPABILITY_REJECTED');
  assert.equal(pair.artifacts.length, 0);

  const effectPair = await seer.audit(request('audit', { applyEffect: true }));
  assert.equal(effectPair.result.error.code, 'SEER_MUTATION_CAPABILITY_REJECTED');
  assert.equal(effectPair.artifacts.length, 0);
  assert.equal(invoked, false);
});

test('missing public core APIs produce typed blockers', async () => {
  const seer = createSeer({ core: {}, clock });
  for (const operation of ['inspect', 'plan', 'audit', 'verify', 'explain']) {
    const pair = await seer[operation](request(operation));
    assert.equal(pair.result.invocationState, 'FAILED_INVOCATION');
    assert.equal(pair.result.domainOutcome, 'FAILED_CONTRACT');
    assert.equal(pair.result.claimBoundary, 'UNPROVEN');
    assert.equal(pair.result.error.code, 'SEER_CORE_API_UNAVAILABLE');
    assert.equal(pair.result.error.retriable, false);
    assert.equal(pair.result.error.remediation, `Coordinator must expose ${({ inspect: 'inspectProduct', plan: 'buildPlan', audit: 'audit', verify: 'verifyRun', explain: 'explain' })[operation]}; facade core changes are forbidden`);
    assert.match(pair.result.error.message, /canonical core API/);
  }
});

test('default public core exposes inspect while explain stays typed-blocked', async () => {
  assert.notEqual((await publicSeer.inspect(request('inspect'))).result.error?.code, 'SEER_CORE_API_UNAVAILABLE');
  assert.equal((await publicSeer.explain(request('explain'))).result.error?.code, 'SEER_CORE_API_UNAVAILABLE');
});

test('run identity and isolated working context are forwarded without mutation', async () => {
  const envelope = request('plan');
  let forwarded; const seer = createSeer({ core: { buildPlan: async (input) => (forwarded = input, { claimBoundary: 'UNPROVEN' }) }, clock });
  const pair = await seer.plan(envelope);
  assert.deepEqual(forwarded.runIdentity, envelope.input.runIdentity);
  assert.deepEqual(forwarded.workingContext, envelope.input.workingContext);
  assert.notEqual(pair.runIdentity, envelope.input.runIdentity);
  assert.ok(Object.isFrozen(pair.runIdentity));
  assert.ok(Object.isFrozen(pair.workingContext));
});

test('result envelopes and artifact records contain every frozen-contract required field', async () => {
  assert.throws(() => canonicalJson(Array(1)), /array hole/);
  const operationSchema = JSON.parse(await readFile(new URL('../../contracts/schemas/operation-envelope-v1.schema.json', import.meta.url), 'utf8'));
  const artifactSchema = JSON.parse(await readFile(new URL('../../contracts/schemas/artifact-v1.schema.json', import.meta.url), 'utf8'));
  const seer = createSeer({ core: { buildPlan: async () => ({ claimBoundary: 'UNPROVEN' }) }, clock });
  const pair = await seer.plan(request('plan'));
  for (const field of operationSchema.$defs.OperationResult.required) assert.ok(Object.hasOwn(pair.result, field), `result missing ${field}`);
  for (const field of artifactSchema.required) assert.ok(Object.hasOwn(pair.artifacts[0].record, field), `artifact missing ${field}`);
});
