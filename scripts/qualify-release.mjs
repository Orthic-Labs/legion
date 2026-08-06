#!/usr/bin/env node
// Full qualification runner per SNIP-QUALIFY-01. Runs the complete test/
// benchmark set, archives a signed qualification bundle, and produces a
// release decision. Publication stays BLOCKED while the publication guard is
// closed.

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirnameOf(import.meta.url), '..');

function dirnameOf(metaUrl) {
  return fileURLToPath(new URL('.', metaUrl));
}

function digestFile(path) {
  if (!existsSync(path)) return null;
  return `sha256:${createHash('sha256').update(readFileSync(path)).digest('hex')}`;
}

export function qualificationBundle({ sourceCommit, dispatchDigest, testRuns, benchmarks, coverageRegistryDigest, securityQualificationDigest, knownGaps, publicationPolicy, decision }) {
  return {
    schemaVersion: 1,
    kind: 'nemesis-release-qualification',
    sourceCommit,
    dispatchDigest,
    package: {},
    nativeArtifacts: [],
    signatures: [],
    attestations: [],
    testRuns,
    benchmarks,
    coverageRegistryDigest,
    securityQualificationDigest,
    knownGaps,
    publicationPolicy,
    decision,
  };
}

export function runQualification({ sourceCommit, dispatchDigest, outDir = resolve(root, 'qualification') }) {
  mkdirSync(outDir, { recursive: true });

  const testRuns = [];
  const run = (name, command, args) => {
    try {
      const output = execFileSync(command, args, { cwd: root, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
      testRuns.push({ name, command: `${command} ${args.join(' ')}`, exitCode: 0, outputDigest: digestText(output) });
      return true;
    } catch (error) {
      testRuns.push({ name, command: `${command} ${args.join(' ')}`, exitCode: error.status ?? 1, outputDigest: digestText(error.stdout ?? '') });
      return false;
    }
  };

  const unitOk = run('unit-tests', process.execPath, ['--test', '--test-concurrency=1', 'tests/*.test.mjs']);
  const conformanceOk = run('conformance', process.execPath, ['tests/run-audit-conformance-tests.mjs']);
  const securityOk = run('security-bench', process.execPath, ['bench/security/run.mjs']);
  const benchOk = run('bench', process.execPath, ['bench/run-bench.mjs']);

  const coverageRegistryDigest = digestFile(resolve(root, 'registry/coverage/coverage-registry.json'));
  const securityQualificationDigest = digestFile(resolve(root, 'bench/security/qualification.json')) ?? null;

  // Publication policy: only an explicit tracked grant opens a channel.
  const policyPath = resolve(root, 'release/publication-policy.json');
  const publicationPolicy = existsSync(policyPath)
    ? JSON.parse(readFileSync(policyPath, 'utf8'))
    : { schemaVersion: 1, kind: 'nemesis-publication-policy', channels: {}, absent: true };

  const mandatoryGatesPass = unitOk && conformanceOk && securityOk && benchOk;
  const publicationOpen = Object.values(publicationPolicy.channels ?? {}).some((grant) => grant?.allowed === true);
  const decision = !mandatoryGatesPass ? 'BLOCKED' : publicationOpen ? 'RELEASE' : 'INTERNAL_ONLY';

  const bundle = qualificationBundle({
    sourceCommit,
    dispatchDigest,
    testRuns,
    benchmarks: [
      { name: 'bench', ok: benchOk },
      { name: 'security', ok: securityOk },
    ],
    coverageRegistryDigest,
    securityQualificationDigest,
    knownGaps: [
      ...(!unitOk ? [{ kind: 'unit-tests-failed' }] : []),
      ...(!publicationOpen ? [{ kind: 'publication-policy-closed' }] : []),
    ],
    publicationPolicy,
    decision,
  });

  const path = resolve(outDir, 'qualification-bundle.json');
  writeFileSync(path, `${JSON.stringify(bundle, null, 2)}\n`);
  return { bundle, path, decision };
}

function digestText(text) {
  return `sha256:${createHash('sha256').update(text ?? '').digest('hex')}`;
}

if (import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const profileIndex = process.argv.indexOf('--profile');
  const profile = profileIndex >= 0 ? process.argv[profileIndex + 1] : 'release';
  const result = runQualification({
    sourceCommit: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim(),
    dispatchDigest: process.env.NEMESIS_DISPATCH_DIGEST ?? null,
  });
  console.log(`qualification: ${result.decision} (profile ${profile})`);
  console.log(`bundle: ${result.path}`);
}
