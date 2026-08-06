// Mechanical fix producers per SNIP-FIX-01. Deterministic ast-grep/config/
// dependency transforms that are idempotent and parse-clean.

import { fixProposal } from './fix-contract.mjs';

export function mechanicalAstGrepProposal({ finding, edits }) {
  return fixProposal({
    findingId: finding.id,
    rootCauseDigest: finding.rootCauseDigest ?? null,
    producer: { kind: 'mechanical', engine: 'ast-grep', version: '1' },
    targetPaths: [...new Set((edits ?? []).map((edit) => edit.file))].sort(),
    preconditions: ['rewrite preview is parse-clean', 'patch is idempotent'],
    patch: { path: 'patches/fix.patch', digest: null },
    expectedBehavior: ['rewritten sites no longer match the finding rule'],
    risks: ['behavioral change to covered call sites'],
    validationCommands: ['parse-check', 'affected-provider-rerun'],
    tier: 'MECHANICAL',
  });
}

export function mechanicalConfigProposal({ finding, configPath, change }) {
  return fixProposal({
    findingId: finding.id,
    rootCauseDigest: finding.rootCauseDigest ?? null,
    producer: { kind: 'mechanical', engine: 'config-transform', version: '1' },
    targetPaths: [configPath],
    preconditions: ['configuration value is validated by schema'],
    patch: { path: 'patches/config.patch', digest: null },
    expectedBehavior: ['configuration no longer matches the finding rule'],
    risks: ['deployment behavior change'],
    validationCommands: ['config-schema-check', 'affected-provider-rerun'],
    tier: 'MECHANICAL',
  });
}

export function mechanicalDependencyProposal({ finding, manifestPath, dependencyChange }) {
  return fixProposal({
    findingId: finding.id,
    rootCauseDigest: finding.rootCauseDigest ?? null,
    producer: { kind: 'mechanical', engine: 'dependency-policy', version: '1' },
    targetPaths: [manifestPath],
    preconditions: ['lockfile update is offline-safe'],
    patch: { path: 'patches/dependency.patch', digest: null },
    expectedBehavior: ['dependency satisfies the policy'],
    risks: ['transitive breakage'],
    validationCommands: ['lockfile-reconcile', 'affected-provider-rerun'],
    tier: 'MECHANICAL',
  });
}
