import assert from 'node:assert/strict';
import test from 'node:test';
import { normalizeScanResult, normalizeVulnerability, osvCommand } from '../../../providers/osv/index.mjs';
import { sbomReceipt, syftCommand } from '../../../providers/sbom/index.mjs';
import { denominatorReceipt, gitleaksCommand, normalizeFinding as normalizeSecret, redact } from '../../../providers/secrets/index.mjs';
import { normalizeLicense, policyResult } from '../../../providers/licenses/index.mjs';
import { normalizeIaCFinding, offlineState, trivyCommand } from '../../../providers/container-iac/index.mjs';

test('osv command uses v2 scan flags and offline DB env', () => {
  const contract = osvCommand({ resolvedOsvScanner: '/opt/osv', outputPath: '/out/v.json', repositoryRoot: '/repo', policy: {}, offlineDb: '/db' });
  assert.deepEqual(contract.args.slice(0, 5), ['scan', '--format', 'json', '--output', '/out/v.json']);
  assert.ok(contract.environmentKeys.includes('OSV_SCANNER_OFFLINE_DB'));
});

test('osv normalize marks reachability unknown, never inferred', () => {
  const result = normalizeScanResult({
    results: [{
      packages: [{
        package: { name: 'lodash', ecosystem: 'npm', purl: 'pkg:npm/lodash@4.17.20' },
        vulnerabilities: [{ id: 'GHSA-xxxx', summary: 'prototype pollution', severity: 'HIGH' }],
      }],
    }],
  });
  assert.equal(result.packageCount, 1);
  assert.equal(result.vulnerabilities[0].reachability, 'unknown');
  assert.equal(result.vulnerabilities[0].id, 'GHSA-xxxx');
});

test('osv offline mode is recorded', () => {
  const result = normalizeScanResult({ results: [] }, { offlineDb: '/db', dbDigest: 'sha256:db' });
  assert.equal(result.offline, true);
  assert.equal(result.databaseDigest, 'sha256:db');
});

test('syft command emits both CycloneDX and SPDX artifacts', () => {
  const contract = syftCommand({ resolvedSyft: '/opt/syft', cycloneDxPath: '/out/c.json', spdxPath: '/out/s.json', repositoryRoot: '/repo', policy: {} });
  assert.ok(contract.args.includes('cyclonedx-json=/out/c.json'));
  assert.ok(contract.args.includes('spdx-json=/out/s.json'));
});

test('sbom receipt records package count and artifact digests', () => {
  const receipt = sbomReceipt({
    providerVersion: '1.0.0', packageCount: 42, sourceScope: 'repository',
    syftVersion: '1.5.0', cycloneDxDigest: 'sha256:c', spdxDigest: 'sha256:s',
    cycloneDxPath: 'raw/c.json', spdxPath: 'raw/s.json',
  });
  assert.equal(receipt.kind, 'nemesis-sbom-receipt');
  assert.equal(receipt.packageCount, 42);
  assert.equal(receipt.artifacts.length, 2);
});

test('gitleaks current-tree command uses detect with a report path', () => {
  const contract = gitleaksCommand({ resolvedGitleaks: '/opt/gitleaks', repositoryRoot: '/repo', policy: {}, reportPath: '/out/g.json' });
  assert.equal(contract.args[0], 'detect');
  assert.ok(contract.args.includes('--report-path'));
});

test('gitleaks history mode scans full git history', () => {
  const contract = gitleaksCommand({ resolvedGitleaks: '/opt/gitleaks', repositoryRoot: '/repo', mode: 'history', policy: {} });
  assert.deepEqual(contract.args.slice(0, 2), ['git', 'log']);
});

test('secret values are redacted; digests retained', () => {
  const finding = normalizeSecret({ RuleID: 'aws-access-key', File: 'env.ts', StartLine: 3, Match: 'AKIAIOSFODNN7EXAMPLE-SUPERSECRET-123456', SecretDigest: 'sha256:secret' });
  assert.ok(!finding.match.includes('SUPERSECRET'), 'raw secret must not persist');
  assert.ok(finding.match.includes('[REDACTED]'));
  assert.equal(finding.secretDigest, 'sha256:secret');
});

test('redact masks long token-like strings', () => {
  assert.equal(redact('ghp_123456789012345678901234567890123456'), '[REDACTED]');
  assert.equal(redact('short'), 'short');
});

test('secret denominator receipt records tracked/untracked/history', () => {
  const receipt = denominatorReceipt({ mode: 'current', trackedFiles: 10, untrackedFiles: 2 });
  assert.equal(receipt.trackedFiles, 10);
  assert.equal(receipt.untrackedFiles, 2);
});

test('license normalization distinguishes known and unknown', () => {
  const known = normalizeLicense({ name: 'lodash', version: '4.17.20', declared: 'MIT', path: 'package-lock.json' });
  assert.equal(known.status, 'known');
  const unknown = normalizeLicense({ name: 'x', version: '1.0.0' });
  assert.equal(unknown.status, 'unknown');
});

test('license policy flags unknown and blocked licenses', () => {
  const result = policyResult({
    records: [
      normalizeLicense({ name: 'a', version: '1', declared: 'MIT' }),
      normalizeLicense({ name: 'b', version: '1' }),
      normalizeLicense({ name: 'c', version: '1', declared: 'GPL-3.0' }),
    ],
    policy: { allow: ['MIT'] },
  });
  assert.equal(result.complete, false);
  assert.equal(result.unknown.length, 1);
  // Under an allowlist, the unknown license and the GPL license both fail.
  assert.equal(result.blocked.length, 2);
});

test('trivy fs command records offline DB env', () => {
  const contract = trivyCommand({ resolvedTrivy: '/opt/trivy', repositoryRoot: '/repo', policy: {}, outputPath: '/out/t.json' });
  assert.equal(contract.args[0], 'fs');
  assert.ok(contract.environmentKeys.includes('TRIVY_OFFLINE_DB'));
});

test('IaC findings normalize with tool database identity', () => {
  const finding = normalizeIaCFinding({ rule_id: 'AVD-AWS-001', severity: 'HIGH', target: 'main.tf', message: 'open ingress' });
  assert.equal(finding.ruleId, 'AVD-AWS-001');
  assert.equal(finding.severity, 'HIGH');
});

test('IaC offline state is explicit', () => {
  const state = offlineState({ offline: true, databaseDigest: 'sha256:db', databaseVersion: '2.1' });
  assert.equal(state.offline, true);
  assert.equal(state.databaseVersion, '2.1');
});

test('no advisory DB update is requested during offline audit', () => {
  // All command contracts must be runnable offline without fetching advisories.
  const osv = osvCommand({ resolvedOsvScanner: '/opt/osv', outputPath: '/o.json', repositoryRoot: '/r', policy: {}, offlineDb: '/db' });
  const trivy = trivyCommand({ resolvedTrivy: '/opt/trivy', repositoryRoot: '/r', policy: {}, outputPath: '/o.json' });
  assert.ok(!JSON.stringify([osv, trivy]).includes('update'));
  assert.ok(!JSON.stringify([osv, trivy]).includes('download'));
});
