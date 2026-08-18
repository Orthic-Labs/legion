import assert from 'node:assert/strict';
import test from 'node:test';
import { executePlan, reconcileRun, finalizeRun } from '../src/lib/core/index.mjs';
import { executionReceipt, blocked } from '../src/lib/core/execution-receipt.mjs';
import { skippedReceipt } from '../src/lib/core/execute-plan.mjs';
import { fixedHost } from '../src/lib/host/fixed-host.mjs';
import { exitCodeForReport } from '../src/lib/cli/exit-code.mjs';
import { EXIT } from '../src/lib/errors.mjs';

function planWithProviders(providers) {
  return { kind: 'audit-provider-plan', root: '/tmp/repo', providers, denominator: { providerIds: providers.map((p) => p.id) } };
}

test('spawnStatus completed does not imply provider verdict pass', () => {
  const receipt = executionReceipt({
    provider: 'types', command: { executable: 'tsc', args: [], cwd: '/repo' },
    startedAt: new Date('2026-08-06T00:00:00Z'), completedAt: new Date('2026-08-06T00:00:01Z'),
    spawnStatus: 'completed', exitCode: 2,
    providerResult: { provider: 'types', status: 'error', complete: false },
  });
  assert.equal(receipt.spawnStatus, 'completed');
  assert.equal(receipt.providerResult.status, 'error');
  assert.notEqual(receipt.spawnStatus, receipt.providerResult.status);
});

test('missing tool produces a blocked execution receipt', () => {
  const receipt = blocked({ provider: 'sast', executable: 'opengrep', args: [], cwd: '/repo' }, 'executable-not-allowlisted');
  assert.equal(receipt.spawnStatus, 'blocked');
  assert.equal(receipt.providerResult.status, 'blocked');
  assert.equal(receipt.providerResult.complete, false);
});

test('unsealed legacy host result stays unproven', async () => {
  const host = fixedHost({
    processRunner: { run: async () => ({ exitCode: 1, status: 'completed', stdout: '', stderr: '' }) },
  });
  const plan = planWithProviders([{ id: 'lint', phase: 'facts', runner: { kind: 'legacy-check', check: 'eslint' }, benchmark: { status: 'unproven', requiredForCleanClaim: true } }]);
  const { receipts } = await executePlan(plan, host);
  const receipt = receipts[0];
  assert.equal(receipt.spawnStatus, 'completed');
  assert.equal(receipt.providerResult.status, 'unproven');
  assert.equal(receipt.providerResult.complete, false);
});

test('unsealed timeout-shaped host result cannot claim timeout receipt authority', async () => {
  const host = fixedHost({
    processRunner: { run: async () => ({ status: 'timeout', timedOut: true, exitCode: null, stdout: '', stderr: '' }) },
  });
  const plan = planWithProviders([{ id: 'build', phase: 'facts', runner: { kind: 'legacy-check', check: 'build' }, benchmark: {} }]);
  const { receipts } = await executePlan(plan, host);
  assert.equal(receipts[0].spawnStatus, 'completed');
  assert.equal(receipts[0].timedOut, false);
  assert.equal(receipts[0].providerResult.status, 'unproven');
});

test('malformed output (runner throws) produces an error receipt', async () => {
  const host = fixedHost({
    processRunner: { run: async () => { throw new Error('malformed output'); } },
  });
  const plan = planWithProviders([{ id: 'sast', phase: 'facts', runner: { kind: 'legacy-check', check: 'semgrep' }, benchmark: {} }]);
  const { receipts } = await executePlan(plan, host);
  assert.equal(receipts[0].spawnStatus, 'blocked');
  assert.equal(receipts[0].providerResult.complete, false);
});

test('selected provider with unsealed runtime module remains blocked', async () => {
  const host = fixedHost({ processRunner: { run: async () => ({ exitCode: 0, status: 'completed', stdout: '', stderr: '' }) } });
  const plan = planWithProviders([
    { id: 'runtime.app', phase: 'runtime', runner: { kind: 'runtime-script', script: 'x' }, activation: { kind: 'url-supplied' }, benchmark: {} },
  ]);
  const { receipts } = await executePlan(plan, host);
  assert.equal(receipts.length, 1);
  assert.equal(receipts[0].providerResult.status, 'blocked');
  assert.equal(receipts[0].providerResult.complete, false);
  assert.ok(receipts[0].providerResult.coverageGaps.length);
});

test('reconcileRun marks incomplete when a terminal receipt is missing', () => {
  const host = fixedHost();
  const plan = planWithProviders([{ id: 'a', phase: 'facts', runner: { kind: 'legacy-check', check: 'a' }, benchmark: {} }]);
  const facts = reconcileRun({ plan, receipts: [], artifacts: null }, host);
  assert.equal(facts.incomplete, true);
  assert.equal(facts.provider_reconciliation.providerResults[0].status, 'missing');
});

test('reconcileRun keeps blocked execution status visible', () => {
  const host = fixedHost();
  const plan = planWithProviders([{ id: 'a', phase: 'facts', runner: { kind: 'legacy-check', check: 'a' }, benchmark: {} }]);
  const receipt = skippedReceipt({ id: 'a', activation: { kind: 'always' } }, 'not-activated');
  const facts = reconcileRun({ plan, receipts: [receipt], artifacts: null }, host);
  assert.equal(facts.incomplete, true);
  assert.equal(facts.provider_reconciliation.providerResults[0].status, 'blocked');
});

test('exit taxonomy: incomplete is never pass, policy fail is 1', async () => {
  assert.equal(exitCodeForReport({ audit_status: 'pass' }), EXIT.PASS);
  assert.equal(exitCodeForReport({ audit_status: 'fail' }), EXIT.POLICY_FAIL);
  assert.equal(exitCodeForReport({ audit_status: 'incomplete' }), EXIT.INCOMPLETE);
  assert.equal(exitCodeForReport({ integrity: { valid: false } }), EXIT.INTEGRITY);
  // A zero-finding run with a required gap is exit 2, never 0.
  assert.equal(exitCodeForReport({ audit_status: 'incomplete', findings: [], incomplete: true }), EXIT.INCOMPLETE);
});

test('finalizeRun attaches the canonical exit code', async () => {
  const host = fixedHost();
  const plan = { kind: 'audit-provider-plan', binding: { repositoryRevision: 'abc' }, coverageGaps: [], providers: [] };
  const facts = {
    workspace: '/tmp/repo', out_dir: '/tmp/out',
    checks: [{ check: 'repo', status: 'ran', execution_status: 'ran', verdict: 'pass' }],
    network_policy: { mode: 'deny' },
    plan_binding_verification: { valid: true },
    provider_reconciliation: { providerResults: [], missingChecks: [], unplannedChecks: [], unresolvedCoverage: [], missingRuntimeProviders: [], denominatorMismatches: [] },
    plan,
  };
  const report = await finalizeRun({ plan, facts, results: { securityCandidates: [], adjudication: { complete: true, verdicts: [] } } }, host);
  assert.equal(report.exit_code, EXIT.PASS);
});

test('policy finding maps to exit 1', async () => {
  const host = fixedHost();
  const plan = { kind: 'audit-provider-plan', binding: { repositoryRevision: 'abc' }, coverageGaps: [], providers: [] };
  const facts = {
    workspace: '/tmp/repo', out_dir: '/tmp/out',
    checks: [{ check: 'repo', status: 'ran', execution_status: 'ran', verdict: 'pass' }],
    network_policy: { mode: 'deny' },
    plan_binding_verification: { valid: true },
    provider_reconciliation: { providerResults: [], missingChecks: [], unplannedChecks: [], unresolvedCoverage: [], missingRuntimeProviders: [], denominatorMismatches: [] },
    plan,
  };
  const report = await finalizeRun({
    plan, facts,
    results: {
      securityCandidates: [{ id: 'c1', provider: 'security.x', claim: 'leak' }],
      adjudication: { complete: true, verdicts: [{ candidateId: 'c1', candidateProvider: 'security.x', verdict: 'TRUE_POSITIVE', severity: 'critical', evidenceStrength: 'verified', threatModel: 'remote', attackerControl: 'proven', reachability: 'proven', impact: 'x', rationale: 'y' }] },
    },
  }, host);
  assert.equal(report.audit_status, 'fail');
  assert.equal(report.exit_code, EXIT.POLICY_FAIL);
});
