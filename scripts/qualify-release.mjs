#!/usr/bin/env node
// Final release qualification is evidence accounting, never a publication
// command. Missing credentials, hosts, builds, or evidence remain BLOCKED.

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fileDigest } from '../lib/distribution/release-manifest.mjs';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));

export function qualificationBundle({
  sourceCommit,
  dispatchDigest,
  evidence = [],
  testRuns = [],
  benchmarks = [],
  coverageRegistryDigest = null,
  securityQualificationDigest = null,
  publicationPolicy = {},
  knownGaps = [],
  decision,
}) {
  const publicationOpen = Object.values(publicationPolicy.channels ?? {}).some((channel) =>
    channel?.allowed === true && channel?.approvedBy && channel?.approvedAt && channel?.policyDigest);
  const qualifiedDecision = decision === 'RELEASE' && (!publicationOpen || knownGaps.length)
    ? 'BLOCKED'
    : decision;
  return {
    schemaVersion: 1,
    kind: 'legion-release-qualification',
    sourceCommit,
    dispatchDigest,
    evidence,
    testRuns,
    benchmarks,
    coverageRegistryDigest,
    securityQualificationDigest,
    publicationPolicy,
    knownGaps,
    decision: qualifiedDecision,
  };
}

const REQUIRED_EVIDENCE = [
  ['release-manifest', 'release-manifest.json'],
  ['recursive-suite-inventory', 'qualification/suites.json'],
  ['package-smoke', 'qualification/package-smoke.json'],
  ['native-equivalence', 'qualification/native-equivalence.json'],
  ['source-provenance', 'qualification/source-provenance.json'],
  ['claims', 'references/generated/claims.json'],
  ['support-matrix', 'references/generated/support-matrix.json'],
];

function sourceRevision() {
  try { return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim(); }
  catch { return null; }
}

export function collectReleaseEvidence({ base = root } = {}) {
  return REQUIRED_EVIDENCE.map(([id, path]) => {
    const absolute = resolve(base, path);
    const present = existsSync(absolute);
    return { id, path, present, digest: present ? fileDigest(absolute) : null };
  });
}

export function runQualification({ base = root, sourceCommit = sourceRevision(), dispatchDigest = null, outDir = resolve(root, 'qualification') } = {}) {
  mkdirSync(outDir, { recursive: true });
  const evidence = collectReleaseEvidence({ base });
  const knownGaps = evidence.filter((item) => !item.present).map((item) => ({
    kind: 'required-release-evidence-absent', evidence: item.id, path: item.path,
    state: 'BLOCKED',
  }));
  if (!sourceCommit) knownGaps.push({ kind: 'source-revision-unavailable', state: 'BLOCKED' });
  // A release decision also needs signing & platform receipts. Their absence
  // is explicit, rather than being inferred from current host properties.
  knownGaps.push({ kind: 'platform-signing-and-clean-host-qualification-required', state: 'UNPROVEN' });
  const decision = knownGaps.length ? 'BLOCKED' : 'INTERNAL_ONLY';
  const bundle = qualificationBundle({ sourceCommit, dispatchDigest, evidence, knownGaps, decision });
  const path = resolve(outDir, 'qualification-bundle.json');
  writeFileSync(path, `${JSON.stringify(bundle, null, 2)}\n`);
  return { bundle, path, decision };
}

if (import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const result = runQualification({ dispatchDigest: process.env.LEGION_DISPATCH_DIGEST ?? null });
  console.log(`qualification: ${result.decision}`);
  console.log(`bundle: ${result.path}`);
  process.exit(result.decision === 'BLOCKED' ? 1 : 0);
}
