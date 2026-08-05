import { createHmac } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  canonicalJson,
  evaluateCoverageFamilies,
  registryDigest,
  selectProviders,
  sha256,
} from './registry/provider-registry.mjs';

function normalizedScope(scope = {}) {
  return {
    mode: scope.mode ?? 'whole-repo',
    type: scope.type ?? 'all',
    base: scope.base ?? null,
    baseCommit: scope.baseCommit ?? scope.base_commit ?? null,
    dir: scope.dir ?? null,
  };
}

function providerPlanRecord(provider) {
  return {
    id: provider.id,
    role: provider.role,
    phase: provider.phase,
    runner: provider.runner,
    selectionReason: provider.selectionReason,
    denominator: provider.denominator,
    benchmark: provider.benchmark ?? { status: 'unproven', requiredForCleanClaim: true },
    freshContextRequired: Boolean(provider.freshContextRequired),
    mayCloseOwnCandidates: provider.role === 'candidate-generator'
      ? false
      : provider.mayCloseOwnCandidates !== false,
    producesSecurityCandidates: Boolean(provider.producesSecurityCandidates),
    conditionalActivation: provider.conditionalActivation ?? null,
  };
}

function planSignature(unsigned, signingKey) {
  return `hmac-sha256:${createHmac('sha256', signingKey).update(canonicalJson(unsigned)).digest('hex')}`;
}

function signingKeyId(signingKey) {
  return sha256(`audit-plan-key\0${signingKey}`).slice('sha256:'.length, 'sha256:'.length + 16);
}

export function sealPlan(plan, signingKey = process.env.AUDIT_PLAN_SIGNING_KEY ?? null) {
  const unsigned = { ...plan };
  delete unsigned.seal;
  return {
    ...unsigned,
    seal: {
      algorithm: 'sha256',
      digest: sha256(unsigned),
      authenticity: signingKey ? 'hmac-sha256' : 'unsigned',
      signature: signingKey ? planSignature(unsigned, signingKey) : null,
      keyId: signingKey ? signingKeyId(signingKey) : null,
      semantics: signingKey
        ? 'integrity digest plus key-backed HMAC signature bound to revision, dirty digest, Cortex generation, registry digest, provider set, and denominators'
        : 'integrity digest only; authenticity is unproven until AUDIT_PLAN_SIGNING_KEY is supplied',
    },
  };
}

export function verifyPlanSeal(plan) {
  if (plan?.seal?.algorithm !== 'sha256' || !plan?.seal?.digest) return false;
  const unsigned = { ...plan };
  delete unsigned.seal;
  return sha256(unsigned) === plan.seal.digest;
}

export function verifyPlanSignature(plan, signingKey = process.env.AUDIT_PLAN_SIGNING_KEY ?? null) {
  if (!verifyPlanSeal(plan) || !signingKey) return false;
  if (plan?.seal?.authenticity !== 'hmac-sha256' || !plan?.seal?.signature) return false;
  const unsigned = { ...plan };
  delete unsigned.seal;
  return plan.seal.keyId === signingKeyId(signingKey)
    && plan.seal.signature === planSignature(unsigned, signingKey);
}

export function buildAuditPlan({
  root,
  registry,
  projection,
  repositoryBinding,
  scope = {},
  only = [],
  skip = [],
  generatedAt = new Date().toISOString(),
  signingKey = process.env.AUDIT_PLAN_SIGNING_KEY ?? null,
}) {
  const selection = selectProviders(registry, projection, { only, skip });
  const providers = selection.selected.map(providerPlanRecord);
  const coverage = evaluateCoverageFamilies(registry, projection, selection.selected);
  const expectedChecks = providers
    .filter((provider) => provider.runner.kind === 'legacy-check')
    .map((provider) => provider.runner.check)
    .sort();
  const runtimeProviders = providers
    .filter((provider) => provider.phase === 'runtime')
    .map((provider) => provider.id)
    .sort();
  const reasoningProviders = providers
    .filter((provider) => provider.phase === 'reasoning')
    .map((provider) => provider.id)
    .sort();
  const benchmarkGaps = providers
    .filter((provider) => provider.benchmark?.requiredForCleanClaim && provider.benchmark?.status !== 'measured')
    .map((provider) => ({
      kind: 'unmeasured-rule-pack',
      provider: provider.id,
      benchmarkStatus: provider.benchmark?.status ?? 'unproven',
    }));
  const skippedByRequest = selection.excluded
    .filter((entry) => entry.reason === 'skipped-by-request')
    .map((entry) => ({ kind: 'skipped-provider', provider: entry.id, check: entry.check ?? null }));
  const discoveryGaps = projection.state === 'ready'
    ? (projection.unsupportedExtensions ?? []).map((extension) => ({ kind: 'unsupported-cortex-extension', extension }))
    : [{ kind: 'cortex-discovery', state: projection.state, reason: projection.reason ?? 'unknown' }];
  const signingGaps = signingKey ? [] : [{ kind: 'unsigned-plan', requiredEnvironment: 'AUDIT_PLAN_SIGNING_KEY' }];
  const coverageGaps = [...discoveryGaps, ...coverage.gaps, ...benchmarkGaps, ...skippedByRequest, ...signingGaps];

  const plan = {
    schemaVersion: 1,
    kind: 'audit-provider-plan',
    generatedAt,
    root: resolve(root),
    scope: normalizedScope(scope),
    filters: { only: [...only].sort(), skip: [...skip].sort() },
    binding: {
      repositoryRevision: repositoryBinding.repositoryRevision,
      dirty: repositoryBinding.dirty,
      dirtyPatchDigest: repositoryBinding.dirtyPatchDigest,
      cortex: {
        state: projection.state,
        generationId: projection.generationId ?? null,
        manifestDigest: projection.manifestDigest ?? null,
        sourceStatusDigest: projection.sourceObservation?.statusDigest ?? null,
        sourceHead: projection.sourceObservation?.head ?? null,
      },
      registryDigest: registryDigest(registry),
    },
    denominator: {
      discoveryOwner: 'cortex',
      firstPartyFileCount: projection.fileCount ?? 0,
      sourceFileCount: projection.sourceFileCount ?? 0,
      fileSetDigest: projection.fileSetDigest,
      parsedExtensions: projection.parsedExtensions ?? [],
      unsupportedExtensions: projection.unsupportedExtensions ?? [],
      providerIds: providers.map((provider) => provider.id).sort(),
      expectedChecks,
      runtimeProviders,
      reasoningProviders,
    },
    providers,
    excludedProviders: selection.excluded,
    coverageFamilies: coverage.families,
    coverageGaps,
    qualification: {
      state: coverageGaps.length ? 'unproven' : 'ready',
      discovery: projection.state,
      providerCoverageComplete: coverage.gaps.length === 0,
      precisionMeasured: benchmarkGaps.length === 0,
      planSigned: Boolean(signingKey),
    },
  };
  return sealPlan(plan, signingKey);
}

export function verifyPlanBinding(plan, currentRepositoryBinding, currentCortexBinding, signingKey = process.env.AUDIT_PLAN_SIGNING_KEY ?? null) {
  const drift = [];
  if (!verifyPlanSeal(plan)) drift.push({ field: 'seal', expected: plan?.seal?.digest ?? null, observed: 'invalid' });
  if (!verifyPlanSignature(plan, signingKey)) {
    drift.push({ field: 'signature', expected: 'valid hmac-sha256', observed: plan?.seal?.authenticity ?? 'missing' });
  }
  if (plan.binding.repositoryRevision !== currentRepositoryBinding.repositoryRevision) {
    drift.push({ field: 'repositoryRevision', expected: plan.binding.repositoryRevision, observed: currentRepositoryBinding.repositoryRevision });
  }
  if (plan.binding.dirty !== currentRepositoryBinding.dirty) {
    drift.push({ field: 'dirty', expected: plan.binding.dirty, observed: currentRepositoryBinding.dirty });
  }
  if (plan.binding.dirtyPatchDigest !== currentRepositoryBinding.dirtyPatchDigest) {
    drift.push({ field: 'dirtyPatchDigest', expected: plan.binding.dirtyPatchDigest, observed: currentRepositoryBinding.dirtyPatchDigest });
  }
  if (currentCortexBinding?.state !== 'ready') {
    drift.push({ field: 'cortex', expected: 'ready', observed: currentCortexBinding?.state ?? 'unproven' });
  } else {
    if (plan.binding.cortex.generationId !== currentCortexBinding.generationId) {
      drift.push({ field: 'cortex.generationId', expected: plan.binding.cortex.generationId, observed: currentCortexBinding.generationId });
    }
    if (plan.binding.cortex.manifestDigest && currentCortexBinding.manifestDigest
      && plan.binding.cortex.manifestDigest !== currentCortexBinding.manifestDigest) {
      drift.push({ field: 'cortex.manifestDigest', expected: plan.binding.cortex.manifestDigest, observed: currentCortexBinding.manifestDigest });
    }
    const currentStatusDigest = currentCortexBinding.sourceObservation?.statusDigest ?? null;
    if (plan.binding.cortex.sourceStatusDigest !== currentStatusDigest) {
      drift.push({ field: 'cortex.sourceStatusDigest', expected: plan.binding.cortex.sourceStatusDigest, observed: currentStatusDigest });
    }
    const currentSourceHead = currentCortexBinding.sourceObservation?.head ?? null;
    if (plan.binding.cortex.sourceHead !== currentSourceHead) {
      drift.push({ field: 'cortex.sourceHead', expected: plan.binding.cortex.sourceHead, observed: currentSourceHead });
    }
  }
  return { valid: drift.length === 0, drift };
}

export function reconcilePlanWithFacts(plan, facts) {
  const expected = new Set(plan.denominator.expectedChecks ?? []);
  const observed = new Map((facts.checks ?? []).map((check) => [check.check, check]));
  const missing = [...expected].filter((check) => !observed.has(check)).sort();
  const supplemental = new Set((facts.checks ?? []).filter((check) => check.tier === 'supplemental').map((check) => check.check));
  const unplanned = [...observed.keys()].filter((check) => !expected.has(check) && !supplemental.has(check)).sort();
  const providerResults = plan.providers.map((provider) => {
    if (provider.runner.kind === 'legacy-check') {
      const result = observed.get(provider.runner.check);
      return {
        provider: provider.id,
        phase: provider.phase,
        check: provider.runner.check,
        status: result?.status ?? 'missing',
        complete: Boolean(result) && result.status === 'ran',
        findingsCount: result?.findings_count ?? null,
        benchmark: provider.benchmark,
      };
    }
    return {
      provider: provider.id,
      phase: provider.phase,
      status: 'pending',
      complete: false,
      benchmark: provider.benchmark,
    };
  });
  return {
    valid: missing.length === 0 && unplanned.length === 0,
    expectedChecks: [...expected].sort(),
    observedChecks: [...observed.keys()].sort(),
    missingChecks: missing,
    unplannedChecks: unplanned,
    providerResults,
  };
}

export function writeAuditPlan(path, plan) {
  if (!verifyPlanSeal(plan)) throw new Error('refusing to write an invalid audit plan seal');
  writeFileSync(path, `${JSON.stringify(plan, null, 2)}\n`, 'utf8');
}

export function stablePlanDigest(plan) {
  return sha256(canonicalJson(plan));
}
