import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { finalizeAudit } from '../tools/audit/audit-finalize.mjs';
import {
  aggregateSecurityCandidates, assertRunOwnedOutScope, executeUnexecutedProviders,
  isMainEntrypoint, loadMeasurementEvidence, sameExecutableHref,
} from '../tools/audit/audit-run.mjs';
import { reconcileCompleteRun } from '../tools/audit/audit-complete.mjs';

function facts(overrides = {}) {
  return {
    workspace: '/repo', out_dir: '/repo/.audit/run',
    plan: { binding: { repositoryRevision: 'abc' }, coverageGaps: [], selectedProviderIds: [], reasoningProviders: [] },
    blueprint: { state: 'ready', generationId: 'gen-1' },
    checks: [{ check: 'repo', status: 'ran' }],
    network_policy: { mode: 'deny', skippedChecks: [] },
    lenses_ran: [],
    plan_binding_verification: { valid: true, drift: [] },
    provider_reconciliation: { valid: true, missingChecks: [], unplannedChecks: [], unresolvedCoverage: [], missingRuntimeProviders: [], denominatorMismatches: [], providerResults: [] },
    ...overrides,
  };
}

const emptyCandidates = { candidates: [] };
const completeAdjudication = { complete: true, verdicts: [] };
const repoRoot = fileURLToPath(new URL('../', import.meta.url));
function sealedRunner(relativeModule) {
  const bytes = readFileSync(fileURLToPath(new URL('../' + relativeModule, import.meta.url)));
  return { kind: 'runtime-script', module: relativeModule, moduleDigest: 'sha256:' + createHash('sha256').update(bytes).digest('hex') };
}

test('missing selected lens coverage is rejected', () => {
  const report = finalizeAudit({
    facts: facts({ plan: { binding: { repositoryRevision: 'abc' }, coverageGaps: [], reasoningProviders: ['security.adjudication'] }, lenses_ran: [] }),
    candidates: emptyCandidates,
    adjudication: completeAdjudication,
  });
  assert.equal(report.audit_status, 'incomplete');
  assert.ok(report.coverage_gaps.some((gap) => gap.kind === 'missing-reasoning-lens' && gap.lens === 'security.adjudication'));
});

test('recorded lens coverage passes and is published on the canonical report', () => {
  const factsInput = facts({
    plan: { binding: { repositoryRevision: 'abc' }, coverageGaps: [], selectedProviderIds: ['security.adjudication'], reasoningProviders: ['security.adjudication'] },
    lenses_ran: ['security.adjudication'],
  });
  const report = finalizeAudit({ facts: factsInput, candidates: emptyCandidates, adjudication: completeAdjudication });
  assert.equal(report.audit_status, 'pass');
  assert.deepEqual(report.lenses_ran, ['security.adjudication']);
  assert.deepEqual(report.lenses.required, ['security.adjudication']);
  assert.equal(report.summary.lenses_required, 1);
  assert.equal(report.summary.lenses_ran, 1);
});

test('selected runtime-script providers execute through the sealed runner contract', async () => {
  const result = {
    plan: {
      root: repoRoot,
      binding: {},
      denominator: {},
      providers: [{
        id: 'accessibility.internal-suite', role: 'deterministic', phase: 'runtime',
        runner: sealedRunner('src/providers/accessibility-suite.mjs'),
        denominator: {},
        hostCapabilities: [],
      }],
    },
    providerResults: [], projection: { files: [] }, securityResult: null, outDir: '/tmp',
  };
  const { appended, invokedIds } = await executeUnexecutedProviders({ result, host: {} });
  assert.ok(invokedIds.has('accessibility.internal-suite'));
  assert.equal(appended.length, 1);
  assert.equal(appended[0].provider, 'accessibility.internal-suite');
  // The sealed module body actually executed (its own zero-denominator gap proves dispatch).
  assert.ok(appended[0].coverageGaps.some((gap) => gap.kind === 'accessibility-denominator-zero'));
});

test('reasoning lenses enter lenses_ran only when they actually ran to completion', async () => {
  const reviewerCalls = [];
  const provider = {
    id: 'security.adjudication', role: 'adjudicator', phase: 'reasoning', freshContextRequired: true,
    runner: { kind: 'reasoning-contract', contract: 'security-adjudication-v1' },
    benchmark: { status: 'unproven', requiredForCleanClaim: true }, hostCapabilities: [],
  };
  const result = {
    plan: { root: '/repo', binding: {}, denominator: {}, providers: [provider] },
    providerResults: [], projection: {}, securityResult: null, outDir: '/tmp',
  };
  const completed = await executeUnexecutedProviders({ result, host: { reviewer: { review: async (packet) => {
    reviewerCalls.push(packet);
    return { complete: true, status: 'pass', findings: [], candidates: [] };
  } } } });
  assert.equal(reviewerCalls.length, 1); // actually executed through the contract
  assert.deepEqual(completed.ranReasoning, ['security.adjudication']);

  const unrun = await executeUnexecutedProviders({
    result,
    host: { reviewer: { review: async () => { throw new Error('no reviewer available'); } } },
  });
  // A failed/unavailable lens execution is NEVER recorded as ran.
  assert.deepEqual(unrun.ranReasoning, []);
  assert.ok(unrun.invokedIds.has('security.adjudication'));
  assert.ok(unrun.appended[0].coverageGaps.some((gap) => gap.kind === 'provider-execution-error'));
});

test('independent reasoning contracts fan out concurrently through native reviewer seam', async () => {
  const providers = ['reasoning.correctness', 'reasoning.architecture'].map((id) => ({
    id, role: 'adjudicator', phase: 'reasoning', freshContextRequired: true,
    runner: { kind: 'reasoning-contract', contract: `${id}-v1` },
    benchmark: { status: 'unproven', requiredForCleanClaim: true }, hostCapabilities: [],
  }));
  const result = {
    plan: { root: '/repo', binding: {}, denominator: {}, providers },
    providerResults: [], projection: {}, securityResult: null, outDir: '/tmp',
  };
  let active = 0;
  let maxActive = 0;
  const completed = await executeUnexecutedProviders({
    result,
    host: { reviewer: { review: async () => {
      active += 1;
      maxActive = Math.max(maxActive, active);
      await new Promise((resolve) => setTimeout(resolve, 20));
      active -= 1;
      return { complete: true, status: 'pass', findings: [], candidates: [] };
    } } },
  });
  assert.equal(maxActive, 2);
  assert.deepEqual(completed.ranReasoning, providers.map(({ id }) => id));
});

test('runtime-script modules without a sealed digest are rejected loudly by the runner contract', async () => {
  const result = {
    plan: {
      root: repoRoot, binding: {}, denominator: {},
      providers: [{ id: 'x.suite', role: 'deterministic', phase: 'runtime', runner: { kind: 'runtime-script', module: 'src/providers/accessibility-suite.mjs' }, hostCapabilities: [] }],
    },
    providerResults: [], projection: { files: [] }, securityResult: null, outDir: '/tmp',
  };
  const { appended } = await executeUnexecutedProviders({ result, host: {} });
  const outcome = appended.find((entry) => entry.provider === 'x.suite');
  assert.ok(outcome);
  assert.equal(outcome.complete, false);
  assert.ok(outcome.coverageGaps.some((gap) => gap.kind === 'provider-execution-error'));
});

test('measurement evidence integrates when the optional benchmarks module exists', async () => {
  const measurementEvidence = await loadMeasurementEvidence();
  assert.equal(typeof measurementEvidence, 'function');
  const evidence = measurementEvidence({ root: repoRoot, providers: [{ id: 'generic.source', runner: { module: 'src/providers/generic-source-suite.mjs' } }] });
  assert.equal(evidence.state, 'unproven');
  assert.deepEqual(evidence.unmeasuredProviders, ['generic.source']);
  assert.equal(evidence.precisionMeasured, false);
});

test('redacted secret candidate values survive adjudication verbatim', () => {
  const digest = 'sha256:' + 'a'.repeat(64);
  const candidates = {
    candidates: [{
      id: 's1', provider: 'secrets.gitleaks', ruleId: 'secret.aws-key',
      claim: 'A tracked secret fallback value.', match: '[REDACTED]', secretDigest: digest,
      mode: 'current', classification: 'unproven',
      evidence: [{ file: 'src/k.ts', line: 12 }],
    }],
  };
  const adjudication = {
    complete: true,
    verdicts: [{ candidateId: 's1', candidateProvider: 'secrets.gitleaks', verdict: 'TRUE_POSITIVE', severity: 'high', evidenceStrength: 'verified', rationale: 'Reproduced.' }],
  };
  const report = finalizeAudit({ facts: facts(), candidates, adjudication });
  const finding = report.findings.find((entry) => entry.id === 's1');
  assert.ok(finding);
  assert.equal(finding.redacted_secret.match, '[REDACTED]');
  assert.equal(finding.redacted_secret.secretDigest, digest);
  assert.equal(finding.file, 'src/k.ts');
  assert.equal(report.summary.findings_total, report.findings.length);
  assert.equal(report.summary.security_findings_surviving, 1);
});

test('verdicts referencing unknown candidates are orphan gaps, never silent drops', () => {
  const adjudication = {
    complete: true,
    verdicts: [{ candidateId: 'ghost', candidateProvider: 'secrets.gitleaks', verdict: 'TRUE_POSITIVE', severity: 'high', evidenceStrength: 'verified' }],
  };
  const report = finalizeAudit({ facts: facts(), candidates: emptyCandidates, adjudication });
  assert.equal(report.audit_status, 'incomplete');
  assert.ok(report.coverage_gaps.some((gap) => gap.kind === 'orphan-security-verdict' && gap.candidateId === 'ghost'));
});

test('canonical summary reconciles provider and finding counts across surfaces', () => {
  const factsInput = facts({
    plan: { binding: { repositoryRevision: 'abc' }, coverageGaps: [], selectedProviderIds: ['a.one', 'b.two'], reasoningProviders: [] },
    provider_reconciliation: {
      valid: true, missingChecks: [], unplannedChecks: [], unresolvedCoverage: [], denominatorMismatches: [],
      missingRuntimeProviders: ['b.two'],
      providerResults: [
        { provider: 'a.one', status: 'pass', complete: true, findings: [{ id: 'f1', ruleId: 'a.rule', message: 'x', severity: 'medium' }] },
      ],
    },
  });
  const report = finalizeAudit({ facts: factsInput, candidates: emptyCandidates, adjudication: completeAdjudication });
  assert.equal(report.summary.providers_selected, 2);
  assert.equal(report.summary.providers_ran, 1);
  assert.equal(report.summary.providers_missing, 1);
  assert.equal(report.summary.findings_total, report.findings.length);
  assert.equal(report.summary.findings_by_severity.medium, 1);
  assert.ok(report.coverage_gaps.some((gap) => gap.kind === 'missing-runtime-provider' && gap.provider === 'b.two'));
});

test('aggregateSecurityCandidates keeps redacted secret fields on candidates', () => {
  const plan = { providers: [{ id: 'secrets.gitleaks', producesSecurityCandidates: true }] };
  const providerResults = [{
    provider: 'secrets.gitleaks', findings: [],
    candidates: [{ id: 'c-secret', ruleId: 'secret.aws-key', claim: 'tracked secret', evidence: [{ file: 'a.ts', line: 3 }], match: '[REDACTED]' }],
  }];
  const aggregated = aggregateSecurityCandidates(plan, null, providerResults);
  assert.equal(aggregated.candidates.length, 1);
  assert.equal(aggregated.candidates[0].match, '[REDACTED]');
  assert.equal(aggregated.candidates[0].verdict, 'UNADJUDICATED');
  assert.deepEqual(aggregated.coverage.candidateProviders, ['secrets.gitleaks']);
});

test('--out must stay strictly inside the run-owned .audit scope', () => {
  assert.equal(assertRunOwnedOutScope({ root: '/repo', outDir: '/repo/.audit/run-2024' }), resolve('/repo/.audit/run-2024'));
  assert.throws(() => assertRunOwnedOutScope({ root: '/repo', outDir: '/repo/build/x' }));
  assert.throws(() => assertRunOwnedOutScope({ root: '/repo', outDir: '/repo/.audit/../evil' }));
  assert.throws(() => assertRunOwnedOutScope({ root: '/repo', outDir: '/other/.audit/run' }));
});

test('executable href comparison is normalized for Windows drive-letter case', () => {
  assert.equal(sameExecutableHref('file:///C:/repo/tools/audit/audit-run.mjs', 'file:///c:/repo/tools/audit/audit-run.mjs', 'win32'), true);
  assert.equal(sameExecutableHref('file:///C:/repo/a.mjs', 'file:///C:/repo/b.mjs', 'win32'), false);
  assert.equal(sameExecutableHref('file:///repo/a.mjs', 'file:///repo/a.MJS', 'darwin'), false);
  const selfPath = fileURLToPath(new URL('../tools/audit/audit-run.mjs', import.meta.url));
  assert.equal(isMainEntrypoint(pathToFileURL(selfPath).href, selfPath), true);
  assert.equal(isMainEntrypoint(pathToFileURL(selfPath).href, new URL('../tools/audit/audit-complete.mjs', import.meta.url).pathname), false);
  assert.equal(isMainEntrypoint(pathToFileURL(selfPath).href, null), false);
});

test('reconciled facts expose selected reasoning providers for lens coverage validation', () => {
  const plan = {
    schemaVersion: 1, kind: 'audit-provider-plan', root: '/repo', scope: {}, filters: { only: [], skip: [] }, generatedAt: 'now',
    binding: { repositoryRevision: 'abc', dirty: false, dirtyPatchDigest: null, blueprint: {} },
    denominator: { discoveryOwner: 'blueprint', firstPartyFileCount: 0, sourceFileCount: 0, fileSetDigest: 'x', parsedExtensions: [], unsupportedExtensions: [], providerIds: ['security.adjudication'], expectedChecks: [], runtimeProviders: [], reasoningProviders: ['security.adjudication'] },
    providers: [], excludedProviders: [], coverageFamilies: [], coverageGaps: [],
    qualification: { state: 'ready', discovery: 'ready', providerCoverageComplete: true, precisionMeasured: true, planSigned: true },
  };
  const reconciled = reconcileCompleteRun({
    plan,
    facts: { incomplete: false, checks: [] },
    providerResults: [],
    securityResult: { candidates: [] },
    projection: { state: 'ready' },
    bindingVerification: { valid: true, drift: [] },
  });
  assert.deepEqual(reconciled.plan.reasoningProviders, ['security.adjudication']);
});
