// Mechanical fix producers per SNIP-FIX-01 and SNIP-16 (B7-031).
//
// Only qualified, rule-specific, low-risk transforms live here. A producer
// proposes and previews; it never applies, and it never verifies its own
// result. Anything unsupported or ambiguous becomes a MANUAL proposal rather
// than a guess.

import { createHash } from 'node:crypto';
import { fixProposal } from './fix-contract.mjs';
import { CONFIG_PRODUCERS, renderConfigPreview } from './producers/config.mjs';
import { STRUCTURAL_PRODUCERS, renderStructuralPreview } from './producers/structural.mjs';

const ALL_PRODUCERS = Object.freeze([...STRUCTURAL_PRODUCERS, ...CONFIG_PRODUCERS]);

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}

function digestOf(namespace, value) {
  return `sha256:${createHash('sha256').update(`${namespace}\0${JSON.stringify(canonical(value))}`).digest('hex')}`;
}

// The committed producer catalogue. Qualification is version-bound in both
// directions: a producer whose version drifts from its qualified version is
// refused, as is a rule the producer was never qualified for.
export const MECHANICAL_REGISTRY = Object.freeze({
  schemaVersion: 1,
  kind: 'legion-mechanical-remediation-registry',
  source: 'src/lib/remediation/producers/',
  generator: 'src/lib/remediation/mechanical.mjs',
  producers: ALL_PRODUCERS.map((producer) => ({
    id: producer.id,
    producerVersion: producer.version,
    kind: producer.kind,
    risk: producer.risk,
    ruleIds: [...producer.ruleIds],
    description: producer.description,
    qualificationDigest: digestOf('mechanical-producer-qualification', {
      id: producer.id,
      version: producer.version,
      kind: producer.kind,
      ruleIds: [...producer.ruleIds],
      preconditions: [...producer.preconditions],
      validationPlan: [...producer.validationPlan],
    }),
  })).sort((a, b) => a.id.localeCompare(b.id)),
});

export function producerFor(ruleId) {
  return ALL_PRODUCERS.find((producer) => producer.ruleIds.includes(ruleId)) ?? null;
}

export function assertProducerQualified(producer, ruleId) {
  const entry = MECHANICAL_REGISTRY.producers.find((item) => item.id === producer?.id);
  if (!entry) throw new Error(`producer ${producer?.id} is not in the mechanical registry`);
  if (entry.producerVersion !== producer.version) {
    throw new Error(`producer ${producer.id} version ${producer.version} is not the qualified version ${entry.producerVersion}`);
  }
  if (!entry.ruleIds.includes(ruleId)) {
    throw new Error(`producer ${producer.id} is not qualified for rule ${ruleId}`);
  }
  return true;
}

function assertSandbox(sandbox) {
  if (sandbox?.kind !== 'legion-remediation-sandbox') {
    throw new Error('mechanical producers run only inside a remediation sandbox');
  }
  if (sandbox.primaryRepositoryMutated !== false) {
    throw new Error('refusing to produce against a sandbox that reports the primary repository mutated');
  }
  return true;
}

export function manualProposal({ finding, reason, binding, targetPaths = [] }) {
  const body = {
    schemaVersion: 1,
    kind: 'legion-remediation-proposal',
    findingIds: [finding.id],
    owner: 'manual',
    producer: {},
    targetPaths: [...targetPaths].sort(),
    preconditions: [],
    patch: null,
    expectedBehavior: [],
    publicSurfaceChanges: [],
    affectedFamilies: [],
    validationPlan: [],
    rollback: {},
    tier: 'MANUAL',
    reason,
    binding,
  };
  return { ...body, id: digestOf('remediation-proposal', body) };
}

export function createMechanicalProposal({ finding, producer, preview, targetPath, binding }) {
  const rendered = producer.kind === 'config'
    ? { render: 'config', edits: preview.edits }
    : { render: 'structural', edits: preview.edits };
  const patchBody = { producer: producer.id, path: targetPath, ...rendered };
  const body = {
    schemaVersion: 1,
    kind: 'legion-remediation-proposal',
    findingIds: [finding.id],
    owner: 'code',
    producer: { id: producer.id, kind: producer.kind, version: producer.version, self: 'producer-only' },
    targetPaths: [targetPath],
    preconditions: [...producer.preconditions],
    patch: {
      path: `patches/${producer.id}.patch`,
      digest: digestOf('remediation-patch', patchBody),
      format: 'legion-preview-edits',
      edits: preview.edits,
    },
    expectedBehavior: [...producer.expectedBehavior],
    publicSurfaceChanges: [...(preview.publicSurfaceChanges ?? [])],
    affectedFamilies: [...producer.affectedFamilies],
    validationPlan: [...producer.validationPlan],
    rollback: {
      reversePatch: { strategy: 'restore-checkpoint-then-reverse-edits', edits: preview.edits },
      checkpointRequired: true,
    },
    tier: 'MECHANICAL',
    binding,
  };
  return { ...body, id: digestOf('remediation-proposal', body) };
}

/**
 * Plan one mechanical remediation. Returns a SNIP-16 proposal, or a MANUAL
 * proposal when no qualified producer applies or the target is ambiguous.
 */
export function planMechanicalRemediation({ finding, sandbox, readFile, binding }) {
  assertSandbox(sandbox);
  const producer = producerFor(finding.ruleId);
  if (!producer) {
    return manualProposal({ finding, reason: `no qualified mechanical producer for rule ${finding.ruleId}`, binding });
  }
  assertProducerQualified(producer, finding.ruleId);

  const targetPath = finding.location?.path ?? null;
  const text = readFile(targetPath);
  const preview = producer.preview({ path: targetPath, text, finding });

  if (preview.unsupported) {
    return manualProposal({ finding, reason: `unsupported target: ${preview.unsupported}`, binding, targetPaths: targetPath ? [targetPath] : [] });
  }
  if (preview.edits.length === 0) {
    return manualProposal({ finding, reason: 'no mechanical edit applies to the finding target', binding, targetPaths: targetPath ? [targetPath] : [] });
  }
  if (!finding.location && preview.edits.length > 1) {
    return manualProposal({ finding, reason: `ambiguous target: ${preview.edits.length} candidate sites and no unique finding location`, binding });
  }
  return createMechanicalProposal({ finding, producer, preview, targetPath, binding });
}

export function renderPreview(producer, text, edits) {
  return producer.kind === 'config'
    ? renderConfigPreview(text, edits)
    : renderStructuralPreview(text, edits);
}

// ---------------------------------------------------------------------------
// Pre-existing producer helpers retained for their existing callers.
// ---------------------------------------------------------------------------

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
