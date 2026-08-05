import assert from 'node:assert/strict';
import test from 'node:test';
import { finalizeAudit } from '../audit-finalize.mjs';

function facts(overrides = {}) {
  return {
    workspace: '/repo', out_dir: '/repo/.audit/run',
    plan: { binding: { repositoryRevision: 'abc' }, coverageGaps: [] },
    cortex: { state: 'ready', generationId: 'gen-1' },
    checks: [{ check: 'repo', status: 'ran' }],
    network_policy: { mode: 'deny', skippedChecks: [] },
    plan_binding_verification: { valid: true, drift: [] },
    provider_reconciliation: { valid: true, missingChecks: [], unplannedChecks: [], unresolvedCoverage: [], missingRuntimeProviders: [], denominatorMismatches: [], providerResults: [] },
    ...overrides,
  };
}

const emptyCandidates = { candidates: [] };
const completeAdjudication = { complete: true, verdicts: [] };

test('complete clean audit passes', () => {
  const report = finalizeAudit({ facts: facts(), candidates: emptyCandidates, adjudication: completeAdjudication });
  assert.equal(report.audit_status, 'pass');
  assert.equal(report.quality_gate, 'pass');
  assert.equal(report.incomplete, false);
});

test('plan coverage gaps remain incomplete', () => {
  const report = finalizeAudit({
    facts: facts({ plan: { binding: { repositoryRevision: 'abc' }, coverageGaps: [{ kind: 'unmeasured-rule-pack', provider: 'security.credentials' }] } }),
    candidates: emptyCandidates,
    adjudication: completeAdjudication,
  });
  assert.equal(report.audit_status, 'incomplete');
  assert.ok(report.coverage_gaps.some((gap) => gap.kind === 'plan-coverage'));
});

test('provider degradation remains incomplete', () => {
  const report = finalizeAudit({
    facts: facts({ provider_reconciliation: { valid: true, missingChecks: [], unplannedChecks: [], unresolvedCoverage: [], missingRuntimeProviders: [], denominatorMismatches: [], providerResults: [{ provider: 'runtime.app', status: 'unproven', complete: false }] } }),
    candidates: emptyCandidates,
    adjudication: completeAdjudication,
  });
  assert.equal(report.audit_status, 'incomplete');
  assert.ok(report.coverage_gaps.some((gap) => gap.kind === 'provider-incomplete'));
});

test('provider denominator mismatch remains incomplete', () => {
  const report = finalizeAudit({
    facts: facts({ provider_reconciliation: { valid: true, missingChecks: [], unplannedChecks: [], unresolvedCoverage: [], missingRuntimeProviders: [], providerResults: [], denominatorMismatches: [{ provider: 'security.credentials', expectedPathCount: 10, observedPathCount: 9 }] } }),
    candidates: emptyCandidates,
    adjudication: completeAdjudication,
  });
  assert.equal(report.audit_status, 'incomplete');
  assert.ok(report.coverage_gaps.some((gap) => gap.kind === 'provider-denominator-mismatch'));
});

test('raw facts incomplete flag cannot be overridden by an otherwise clean report', () => {
  const report = finalizeAudit({ facts: facts({ incomplete: true }), candidates: emptyCandidates, adjudication: completeAdjudication });
  assert.equal(report.audit_status, 'incomplete');
  assert.equal(report.quality_gate, 'unproven');
  assert.ok(report.coverage_gaps.some((gap) => gap.kind === 'facts-incomplete'));
});

test('verified security finding blocks quality gate and maps evidence', () => {
  const candidates = { candidates: [{ id: 'c1', provider: 'security.misuse-resistance', ruleId: 'security.command-injection', claim: 'Input reaches shell.', evidence: [{ file: 'src/run.ts', line: 8 }] }] };
  const adjudication = { complete: true, verdicts: [{ candidateId: 'c1', candidateProvider: 'security.misuse-resistance', verdict: 'TRUE_POSITIVE', severity: 'critical', evidenceStrength: 'verified', impact: 'command execution', rationale: 'Reproduced.' }] };
  const report = finalizeAudit({ facts: facts(), candidates, adjudication });
  assert.equal(report.audit_status, 'fail');
  assert.equal(report.quality_gate, 'blocked');
  assert.equal(report.findings[0].file, 'src/run.ts');
  assert.equal(report.findings[0].line, 8);
});

test('unclosed adjudication is never clean', () => {
  const report = finalizeAudit({ facts: facts(), candidates: { candidates: [{ id: 'c1' }] }, adjudication: { complete: false, verdicts: [] } });
  assert.equal(report.audit_status, 'incomplete');
  assert.equal(report.gates.security_adjudication, 'unproven');
});
