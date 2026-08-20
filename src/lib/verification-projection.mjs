// Stable semantic projection of an audit run for out-of-band verification.
// Compares the canonical digest of this projection instead of the complete
// facts.json byte stream so that output directory, log path, timestamp, and
// temporary-path changes do not create semantic drift.

import { canonicalJson, sha256 } from '../registry/provider-registry.mjs';

function stableFinding(finding) {
  return {
    id: finding.id ?? null,
    ruleId: finding.ruleId ?? finding.category ?? null,
    severity: finding.severity ?? null,
    verdict: finding.verdict ?? finding.status ?? null,
    file: finding.file ? String(finding.file).replaceAll('\\', '/') : null,
    line: Number.isInteger(finding.line) ? finding.line : null,
    evidenceDigest:
      finding.evidenceDigest
      ?? finding.proof?.digest
      ?? finding.verdictDigest
      ?? null,
  };
}

function stableCheck(check) {
  return {
    check: check.check,
    provider: check.provider ?? null,
    executionStatus: check.execution_status ?? check.executionStatus ?? check.status,
    verdict: check.verdict ?? null,
    exitCode: check.exit_code ?? check.exitCode ?? null,
    tool: check.tool ?? null,
    toolVersion: check.version ?? check.toolVersion ?? null,
    findings: (check.findings ?? []).map(stableFinding)
      .sort((a, b) => canonicalJson(a).localeCompare(canonicalJson(b))),
    findingsCount: check.findings_count ?? check.findingsCount ?? null,
  };
}

function stableProvider(result) {
  return {
    provider: result.provider,
    providerVersion: result.providerVersion ?? null,
    status: result.status,
    complete: result.complete,
    applicable: result.applicable ?? true,
    required: result.required ?? false,
    denominatorDigest:
      result.coverage?.denominatorDigest
      ?? result.coverage?.examinedPathsDigest
      ?? null,
    toolVersion: result.toolVersion ?? null,
    findings: (result.findings ?? []).map(stableFinding)
      .sort((a, b) => canonicalJson(a).localeCompare(canonicalJson(b))),
    candidates: (result.candidates ?? []).map((candidate) => ({
      id: candidate.id,
      ruleId: candidate.ruleId ?? null,
      provider: candidate.provider ?? result.provider,
      verdict: candidate.verdict ?? null,
      evidenceRefs: [...(candidate.evidenceRefs ?? [])].sort(),
    })).sort((a, b) => canonicalJson(a).localeCompare(canonicalJson(b))),
    coverageGaps: (result.coverageGaps ?? []).map((gap) => ({
      kind: gap.kind ?? null,
      provider: gap.provider ?? result.provider,
      path: gap.path ?? null,
      reason: gap.reason ?? null,
    })).sort((a, b) => canonicalJson(a).localeCompare(canonicalJson(b))),
  };
}

export function verificationProjection(facts) {
  return {
    schemaVersion: 1,
    kind: 'legion-verification-projection',
    workspaceIdentity: facts.workspace_identity ?? facts.workspaceIdentity ?? facts.workspace ?? null,
    commit: facts.commit ?? facts.repository?.revision
      ?? facts.plan?.binding?.repositoryRevision
      ?? facts.plan_binding?.repositoryRevision
      ?? null,
    dirtyPatchDigest:
      facts.repository?.dirtyPatchDigest
      ?? facts.repository_binding?.dirtyPatchDigest
      ?? facts.plan?.binding?.dirtyPatchDigest
      ?? null,
    plan: {
      digest: facts.plan?.seal?.digest ?? facts.plan?.digest ?? null,
      signature: facts.plan?.seal?.signature ?? null,
      registryDigest: facts.plan?.binding?.registryDigest
        ?? facts.plan?.binding?.registryDigest ?? null,
      providerIds: [...(facts.plan?.denominator?.providerIds ?? [])].sort(),
      expectedChecks: [...(facts.plan?.denominator?.expectedChecks ?? [])].sort(),
    },
    blueprint: {
      generationId: facts.blueprint?.generationId
        ?? facts.plan?.binding?.blueprint?.generationId ?? null,
      manifestDigest: facts.blueprint?.manifestDigest
        ?? facts.plan?.binding?.blueprint?.manifestDigest ?? null,
      providerVersion: facts.blueprint?.providerVersion ?? null,
    },
    networkPolicy: {
      mode: facts.network_policy?.mode ?? null,
      sandboxActive: facts.network_policy?.sandboxActive === true,
    },
    checks: (facts.checks ?? []).map(stableCheck)
      .sort((a, b) => a.check.localeCompare(b.check)),
    providers: (facts.provider_reconciliation?.providerResults ?? [])
      .map(stableProvider)
      .sort((a, b) => a.provider.localeCompare(b.provider)),
  };
}

export function verificationDigest(facts) {
  return sha256(canonicalJson(verificationProjection(facts)));
}
