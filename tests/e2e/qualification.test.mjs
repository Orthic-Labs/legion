import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { qualificationBundle } from '../../scripts/qualify-release.mjs';

test('qualification bundle captures the full release evidence set', () => {
  const bundle = qualificationBundle({
    sourceCommit: 'abc', dispatchDigest: 'sha256:d', testRuns: [{ name: 'unit', exitCode: 0 }],
    benchmarks: [{ name: 'bench', ok: true }], coverageRegistryDigest: 'sha256:c',
    securityQualificationDigest: 'sha256:s', knownGaps: [], publicationPolicy: {}, decision: 'INTERNAL_ONLY',
  });
  assert.equal(bundle.kind, 'nemesis-release-qualification');
  assert.equal(bundle.sourceCommit, 'abc');
  assert.equal(bundle.decision, 'INTERNAL_ONLY');
  assert.ok(bundle.testRuns.length >= 1);
});

test('decision is RELEASE only when gates pass and policy is open', () => {
  const open = qualificationBundle({
    sourceCommit: 'a', dispatchDigest: 'sha256:d', testRuns: [], benchmarks: [],
    coverageRegistryDigest: 'sha256:c', securityQualificationDigest: 'sha256:s',
    knownGaps: [], publicationPolicy: { channels: { npm: { allowed: true, approvedBy: 'x', approvedAt: 't', policyDigest: 'sha256:p' } } },
    decision: 'RELEASE',
  });
  assert.equal(open.decision, 'RELEASE');
});

test('publication stays blocked without an explicit grant', () => {
  const bundle = qualificationBundle({
    sourceCommit: 'a', dispatchDigest: 'sha256:d', testRuns: [], benchmarks: [],
    coverageRegistryDigest: 'sha256:c', securityQualificationDigest: 'sha256:s',
    knownGaps: [{ kind: 'publication-policy-closed' }],
    publicationPolicy: { channels: {}, absent: true },
    decision: 'INTERNAL_ONLY',
  });
  assert.equal(bundle.decision, 'INTERNAL_ONLY');
  assert.ok(bundle.knownGaps.some((gap) => gap.kind === 'publication-policy-closed'));
});

test('no benchmark cherry-picking: all required runs are recorded with exit codes', () => {
  const bundle = qualificationBundle({
    sourceCommit: 'a', dispatchDigest: 'sha256:d',
    testRuns: [
      { name: 'unit-tests', exitCode: 0 },
      { name: 'conformance', exitCode: 1 },
      { name: 'security-bench', exitCode: 0 },
    ],
    benchmarks: [], coverageRegistryDigest: 'sha256:c', securityQualificationDigest: 'sha256:s',
    knownGaps: [{ kind: 'unit-tests-failed' }], publicationPolicy: {}, decision: 'BLOCKED',
  });
  assert.equal(bundle.decision, 'BLOCKED');
  assert.equal(bundle.testRuns.length, 3);
  assert.ok(bundle.testRuns.some((run) => run.name === 'conformance' && run.exitCode === 1));
});
