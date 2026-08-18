import assert from 'node:assert/strict';
import test from 'node:test';
import { gitlabCiAdapter, bitbucketAdapter, azureDevopsAdapter } from '../../src/integrations/forges.mjs';
import { organizationPolicy, applyPolicy } from '../../src/lib/policy/org/index.mjs';
import { loadControls, mapEvidenceToControls } from '../../src/lib/policy/compliance.mjs';
import { economicsReceipt, runSummary } from '../../src/lib/metrics/economics.mjs';
import { privacyDataDictionary, privacyReceipt } from '../../src/lib/privacy/index.mjs';

test('gitlab adapter calls the canonical CLI with identical output contracts', () => {
  const adapter = gitlabCiAdapter({ profile: 'standard' });
  assert.equal(adapter.canonicalCli, true);
  assert.ok(adapter.script.some((line) => line.includes('legion audit .')));
  assert.ok(adapter.artifacts.reports.sarif.includes('report.sarif'));
});

test('bitbucket and azure adapters use the same CLI', () => {
  const bitbucket = bitbucketAdapter();
  assert.equal(bitbucket.canonicalCli, true);
  const azure = azureDevopsAdapter();
  assert.equal(azure.canonicalCli, true);
  assert.ok(JSON.stringify(azure.steps).includes('legion audit'));
});

test('organization policy is signed and versioned with rollout modes', () => {
  const policy = organizationPolicy({
    id: 'org.example.security', version: '1.0.0', digest: 'sha256:d', signature: { alg: 'ed25519', value: 'sig' },
    rollout: 'blocking', requiredProviders: ['security.credentials'], thresholds: {}, suppressionPolicy: {}, complianceMappings: [],
  });
  assert.equal(policy.kind, 'legion-organization-policy');
  assert.equal(policy.rollout, 'blocking');
  assert.ok(policy.signature.value);
});

test('repository policy cannot override host-bounded providers', () => {
  const policy = organizationPolicy({ id: 'p', version: '1', digest: 'sha256:d', signature: {}, rollout: 'blocking', requiredProviders: ['runtime.app'], thresholds: {}, suppressionPolicy: {}, complianceMappings: [] });
  const result = applyPolicy({ policy, plan: { denominator: { providerIds: [] } }, hostPolicy: { disabledProviders: ['runtime.app'] } });
  assert.ok(result.violations.some((item) => item.kind === 'host-bounded-provider'));
});

test('blocking policy fails when a required provider is missing', () => {
  const policy = organizationPolicy({ id: 'p', version: '1', digest: 'sha256:d', signature: {}, rollout: 'blocking', requiredProviders: ['security.credentials'], thresholds: {}, suppressionPolicy: {}, complianceMappings: [] });
  const result = applyPolicy({ policy, plan: { denominator: { providerIds: ['core.repo'] } }, hostPolicy: {} });
  assert.equal(result.blocked, true);
});

test('absence of a finding is never compliance evidence', () => {
  const controls = loadControls();
  const mapped = mapEvidenceToControls({ report: { findings: [], coverage_gaps: [] }, controls });
  for (const entry of mapped) {
    assert.equal(entry.absenceIsEvidence, false);
    assert.notEqual(entry.status, 'supported');
  }
});

test('compliance mapping distinguishes supported, unproven, not-applicable', () => {
  const controls = loadControls();
  const mapped = mapEvidenceToControls({
    report: {
      findings: [{ id: 'f1', ruleId: 'credentials.format' }],
      coverage_gaps: [{ kind: 'osv-incomplete' }],
    },
    controls,
  });
  const secret = mapped.find((entry) => entry.controlId === 'control.secret-management');
  assert.equal(secret.status, 'supported');
  const dep = mapped.find((entry) => entry.controlId === 'control.dependency-vulnerability');
  assert.equal(dep.status, 'unproven');
});

test('economics are content-free aggregates', () => {
  const records = [
    economicsReceipt({ provider: 'a', durationMs: 100, cpuMs: 50, memoryMb: 10, toolCost: 0, modelTokens: 0, modelCost: 0 }),
    economicsReceipt({ provider: 'b', durationMs: 200, cpuMs: 100, memoryMb: 20, toolCost: 0, modelTokens: 500, modelCost: 0.01 }),
  ];
  const summary = runSummary(records);
  assert.equal(summary.totalDurationMs, 300);
  assert.equal(summary.totalModelTokens, 500);
  assert.ok(!JSON.stringify(summary).includes('source'));
});

test('privacy defaults telemetry off and documents egress', () => {
  const receipt = privacyReceipt({ telemetry: 'off', integrations: ['github-action'], egress: [{ integration: 'github-action', leavesMachine: ['SARIF report'] }] });
  assert.equal(receipt.telemetry, 'off');
  assert.equal(receipt.egress[0].leavesMachine[0], 'SARIF report');
  assert.ok(receipt.exportCommand);
  const dictionary = privacyDataDictionary();
  assert.equal(dictionary.telemetry.default, 'off');
});
