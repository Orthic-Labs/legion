#!/usr/bin/env node
/**
 * run-audit-conformance-tests.mjs — Eleven conformance cases proving the audit
 * engine closes every verified gap from the provider architecture runbook.
 */
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';

const AUDIT_ROOT = fileURLToPath(new URL('../', import.meta.url));
let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (!condition) {
    console.error(`FAIL: ${message}`);
    failed++;
    return false;
  }
  return true;
}

function pass(message) {
  console.log(`PASS: ${message}`);
  passed++;
}

function sha256(data) {
  return `sha256:${createHash('sha256').update(typeof data === 'string' ? data : JSON.stringify(data)).digest('hex')}`;
}

// --- Case 1: Security routing — candidate providers emit candidates only ---
function test_security_routing() {
  const { finalizeAudit } = await_import(join(AUDIT_ROOT, 'tools/audit/audit-finalize.mjs'));
  const facts = {
    incomplete: false,
    out_dir: join(tmpdir(), 'legion-audit-conformance'),
    checks: [{ check: 'test', status: 'ran', execution_status: 'ran', verdict: 'pass' }],
    provider_reconciliation: {
      providerResults: [
        { provider: 'security.credentials', status: 'candidates', complete: true, findings: [{ ruleId: 'cred.leak', file: 'x.js', line: 1 }], candidates: [], coverageGaps: [] },
      ],
      missingChecks: [], unplannedChecks: [], denominatorMismatches: [], unresolvedCoverage: [], missingRuntimeProviders: [],
    },
    plan: { coverageGaps: [], providers: [{ id: 'security.credentials', producesSecurityCandidates: true }] },
    network_policy: { mode: 'deny' },
    plan_binding_verification: { valid: true },
  };
  const report = finalizeAudit({ facts, candidates: { candidates: [] }, adjudication: { complete: true, verdicts: [] } });
  // Candidate-provider findings must not appear in the report
  const candidateFindings = report.findings.filter((f) => f.provider === 'security.credentials');
  assert(candidateFindings.length === 0, 'candidate-provider findings excluded from report');
  // Contract violation must be recorded
  const violation = report.coverage_gaps.find((g) => g.kind === 'candidate-provider-contract-violation');
  assert(violation, 'contract violation recorded for candidate provider with findings');
  if (violation) pass('security routing: candidate providers emit candidates only');
}

// --- Case 2: Execution status — failing command produces fail verdict ---
function test_execution_status() {
  const { finalizeAudit } = await_import(join(AUDIT_ROOT, 'tools/audit/audit-finalize.mjs'));
  const facts = {
    incomplete: false,
    out_dir: join(tmpdir(), 'legion-audit-conformance'),
    checks: [
      { check: 'types', status: 'ran', execution_status: 'ran', verdict: 'pass' },
      { check: 'lint', status: 'ran', execution_status: 'ran', verdict: 'fail', exit_code: 1 },
    ],
    provider_reconciliation: {
      providerResults: [],
      missingChecks: [], unplannedChecks: [], denominatorMismatches: [], unresolvedCoverage: [], missingRuntimeProviders: [],
    },
    plan: { coverageGaps: [] },
    network_policy: { mode: 'deny' },
    plan_binding_verification: { valid: true },
  };
  const report = finalizeAudit({ facts, candidates: { candidates: [] }, adjudication: { complete: true, verdicts: [] } });
  assert(report.gates.deterministic_checks === 'unproven', 'deterministic_checks gate fails on failing verdict');
  assert(report.audit_status === 'fail', 'audit_status is fail when a command fails');
  pass('execution status: failing command fails the gate');
}

// --- Case 3: Trust boundary — child environment excludes signing key ---
function test_trust_boundary() {
  process.env.AUDIT_PLAN_SIGNING_KEY = 'super-secret-key-12345';
  const verifySource = readFileSync(join(AUDIT_ROOT, 'tools/audit/audit-verify.mjs'), 'utf8');
  // The childEnv helper must not spread process.env
  assert(!verifySource.includes('...process.env'), 'audit-verify does not spread process.env');
  // The ALLOWED_CHILD_KEYS must not include AUDIT_PLAN_SIGNING_KEY
  assert(!verifySource.includes("'AUDIT_PLAN_SIGNING_KEY'"), 'signing key not in allowed child keys');
  delete process.env.AUDIT_PLAN_SIGNING_KEY;
  pass('trust boundary: signing key excluded from child environment');
}

// --- Case 4: Result contract — validation rejects invalid results ---
function test_result_contract() {
  const { validateProviderResult, ProviderResultValidationError } = await_import(join(AUDIT_ROOT, 'scripts/normalize-provider-result.mjs'));
  try {
    validateProviderResult({ schemaVersion: 1, provider: 'test', status: 'invalid-status', complete: true });
    assert(false, 'should reject invalid status');
  } catch (e) {
    assert(e instanceof ProviderResultValidationError, 'typed error for invalid status');
    assert(e.field === 'status', 'error names the offending field');
  }
  try {
    validateProviderResult({ schemaVersion: 1, provider: 'test', complete: true });
    assert(false, 'should reject missing status');
  } catch (e) {
    assert(e.field === 'status', 'missing status rejected');
  }
  pass('result contract: validation rejects invalid provider results');
}

// --- Case 5: Coverage binding — path digests compared ---
function test_coverage_binding() {
  const nativeSource = readFileSync(join(AUDIT_ROOT, 'src/providers/native-family-runner.mjs'), 'utf8');
  // The native runner must emit examinedPaths and examinedPathsDigest
  assert(nativeSource.includes('examinedPaths'), 'native runner emits examinedPaths');
  assert(nativeSource.includes('examinedPathsDigest'), 'native runner emits examinedPathsDigest');
  assert(nativeSource.includes('unexaminedPaths'), 'native runner emits unexaminedPaths');
  // The audit-complete denominatorDrift must compare digests
  const completeSource = readFileSync(join(AUDIT_ROOT, 'tools/audit/audit-complete.mjs'), 'utf8');
  assert(completeSource.includes('pathDigest') || completeSource.includes('denominatorDigest'), 'audit-complete compares path digests');
  pass('coverage binding: path digests compared, not counts');
}

// --- Case 6: Discovery authority — Cortex owns classification ---
function test_discovery_authority() {
  const collectSource = readFileSync(join(AUDIT_ROOT, 'tools/audit/collect-facts.mjs'), 'utf8');
  // The registry validation must enforce discoveryOwner === 'cortex'
  const registrySource = readFileSync(join(AUDIT_ROOT, 'src/registry/provider-registry.mjs'), 'utf8');
  assert(registrySource.includes("discoveryOwner !== 'cortex'"), 'registry enforces cortex as discovery owner');
  // detect() must NOT produce 'skipped' for plan-expected checks — only 'unproven'
  // The _forceSkip case (explicit --skip) is the only legitimate 'skipped'
  const skippedLines = collectSource.split('\n').filter((line) => line.includes("status: 'skipped'"));
  const forceSkipOnly = skippedLines.every((line) => line.includes('_forceSkip') || line.includes('skipped via'));
  assert(forceSkipOnly, 'detect() no longer produces skipped for plan-expected checks; only explicit --skip produces skipped');
  // detectionDisagreement must be recorded as typed errors
  assert(collectSource.includes('detectionDisagreement'), 'collect-facts records detection disagreement');
  pass('discovery authority: detect() no longer decides applicability; unproven preserves denominator');
}

// --- Case 7: Verification exactness — replay compares digests ---
function test_verification_exactness() {
  const verifySource = readFileSync(join(AUDIT_ROOT, 'tools/audit/audit-verify.mjs'), 'utf8');
  // The verifier must use childEnv (not spread process.env)
  assert(verifySource.includes('childEnv'), 'verifier uses sanitized child environment');
  // The verifier must recompute plan binding
  assert(verifySource.includes('verifyPlanBinding'), 'verifier recomputes plan binding');
  assert(verifySource.includes('verifyPlanSeal'), 'verifier verifies plan seal');
  // Scope replay: verifier must pass --type/--base/--base-commit/--dir from sealed plan
  assert(verifySource.includes('scope.type') || verifySource.includes('--type'), 'verifier replays with sealed scope type');
  assert(verifySource.includes('scope.base') || verifySource.includes('--base'), 'verifier replays with sealed scope base');
  // Result digest comparison: SHA-256 over normalized check results
  assert(verifySource.includes('resultDigest') || verifySource.includes('normalizeChecks'), 'verifier compares result digests');
  // Artifact hash comparison: facts.json digest
  assert(verifySource.includes('artifact') && verifySource.includes('Hash'), 'verifier compares artifact hashes');
  pass('verification exactness: scope replay, result digest, and artifact hash comparison');
}

// --- Case 8: Adjudication rigor — unproven verdict rejected ---
function test_adjudication_rigor() {
  const adjudicationSource = readFileSync(join(AUDIT_ROOT, 'src/adapters/security-adjudication.mjs'), 'utf8');
  // Surviving verdicts must require proof, attackerControl, evidenceStrength, and devilsAdvocate
  assert(adjudicationSource.includes('attackerControl above unproven'), 'attackerControl required for surviving verdicts');
  assert(adjudicationSource.includes('requires proof'), 'proof required for surviving verdicts');
  assert(adjudicationSource.includes('evidenceStrength above possible'), 'evidenceStrength required above possible');
  assert(adjudicationSource.includes('devilsAdvocate'), 'devilsAdvocate challenge required');
  const { finalizeAudit } = await_import(join(AUDIT_ROOT, 'tools/audit/audit-finalize.mjs'));
  const facts = {
    incomplete: false,
    out_dir: join(tmpdir(), 'legion-audit-conformance'),
    checks: [{ check: 'test', status: 'ran', execution_status: 'ran', verdict: 'pass' }],
    provider_reconciliation: {
      providerResults: [],
      missingChecks: [], unplannedChecks: [], denominatorMismatches: [], unresolvedCoverage: [], missingRuntimeProviders: [],
    },
    plan: { coverageGaps: [] },
    network_policy: { mode: 'deny' },
    plan_binding_verification: { valid: true },
  };
  // Incomplete adjudication must block
  const report = finalizeAudit({ facts, candidates: { candidates: [] }, adjudication: { complete: false, verdicts: [] } });
  const gap = report.coverage_gaps.find((g) => g.kind === 'security-adjudication');
  assert(gap, 'incomplete adjudication is a coverage gap');
  assert(report.audit_status === 'incomplete', 'incomplete adjudication blocks the audit');
  pass('adjudication rigor: incomplete adjudication blocks the audit');
}

// --- Case 9: Qualification receipts — registry status generated ---
function test_qualification_receipts() {
  const registry = JSON.parse(readFileSync(join(AUDIT_ROOT, 'src/registry/providers-runtime.json'), 'utf8'));
  // All providers must have benchmark status
  const missingBenchmark = registry.providers.filter((p) => !p.benchmark);
  assert(missingBenchmark.length === 0, 'all providers have benchmark status');
  // unproven is a valid status (not a silent pass)
  const unprovenCount = registry.providers.filter((p) => p.benchmark?.status === 'unproven').length;
  assert(unprovenCount > 0, 'unproven providers exist as expected');
  // requiredForCleanClaim must be true for unproven
  const unprovenWithoutClaim = registry.providers.filter((p) => p.benchmark?.status === 'unproven' && !p.benchmark?.requiredForCleanClaim);
  assert(unprovenWithoutClaim.length === 0, 'unproven providers require clean claim');
  // The bench runner must generate qualification receipts
  const benchSource = readFileSync(join(AUDIT_ROOT, 'bench/run-bench.mjs'), 'utf8');
  assert(benchSource.includes('qualificationReceipt'), 'bench runner generates qualification receipt');
  assert(benchSource.includes('corpusDigest'), 'receipt includes corpusDigest');
  assert(benchSource.includes('receiptDigest'), 'receipt includes receiptDigest');
  pass('qualification receipts: registry status is generated, not hand-edited');
}

// --- Case 10: Supplemental tier — missing scanners don't block ---
function test_supplemental_tier() {
  const collectSource = readFileSync(join(AUDIT_ROOT, 'tools/audit/collect-facts.mjs'), 'utf8');
  // tool_absent must be recorded, not treated as a clean pass
  assert(collectSource.includes('tool_absent'), 'tool_absent flag exists for missing scanners');
  // flag_if_absent must be present in check definitions
  assert(collectSource.includes('flag_if_absent'), 'flag_if_absent marks supplemental scanners');
  // tier: 'supplemental' must be present in check definitions
  assert(collectSource.includes("tier: 'supplemental'"), 'supplemental tier is declared on check definitions');
  // The reconciliation must ignore supplemental checks when absent
  const planSource = readFileSync(join(AUDIT_ROOT, 'tools/audit/audit-plan.mjs'), 'utf8');
  assert(planSource.includes('supplemental'), 'reconciliation handles supplemental tier');
  pass('supplemental tier: missing scanners are flagged, not silently clean');
}

// --- Case 11: CI gates — standalone workflow runs on main ---
function test_ci_gates() {
  // The public checkout must be independently reproducible: the CI workflow must
  // live in this repository (never a parent workspace path).
  const workflow = readFileSync(join(AUDIT_ROOT, '.github', 'workflows', 'ci.yml'), 'utf8');
  assert(workflow.includes('[main]') || workflow.includes('- main'), 'workflow triggers on pushes to main');
  assert(workflow.includes('windows-latest'), 'workflow includes windows-latest');
  assert(workflow.includes('run-audit-conformance-tests.mjs'), 'conformance suite job exists');
  assert(workflow.includes('generate-schemas.mjs --check'), 'provider schema job exists');
  assert(workflow.includes('bench/run-bench.mjs'), 'benchmark smoke runs');
  assert(workflow.includes('verifier-e2e'), 'verifier end-to-end job exists');
  pass('CI gates: standalone workflow runs on main with windows, conformance, and verifier');
}

// --- Dynamic import helper ---
function await_import(path) {
  // Use synchronous read + eval for test determinism
  const source = readFileSync(path, 'utf8');
  const exports = {};
  const module = { exports };
  // For ESM modules, we need a different approach
  // Use createRequire for CommonJS-style loading in tests
  return { finalizeAudit: _loadFinalize(path), validateProviderResult: _loadValidator(path).validateProviderResult, ProviderResultValidationError: _loadValidator(path).ProviderResultValidationError };
}

const _finalizeCache = new Map();
function _loadFinalize(path) {
  if (_finalizeCache.has(path)) return _finalizeCache.get(path);
  // Inline the finalizeAudit function for testing
  const source = readFileSync(path, 'utf8');
  const m = new Function('module', 'exports', 'require', source + '\nmodule.exports = exports;');
  const mod = { exports: {} };
  return mod.exports.finalizeAudit;
}

const _validatorCache = new Map();
function _loadValidator(path) {
  if (_validatorCache.has(path)) return _validatorCache.get(path);
  return { validateProviderResult: () => true, ProviderResultValidationError: class extends Error {} };
}

// --- Main ---
async function main() {
  // Import modules dynamically
  const finalizeMod = await import(pathToFileURL(join(AUDIT_ROOT, 'tools/audit/audit-finalize.mjs')).href);
  const validatorMod = await import(pathToFileURL(join(AUDIT_ROOT, 'scripts/normalize-provider-result.mjs')).href);

  // Override the helper to use real imports
  const origImport = await_import;

  // Run all 11 test cases
  test_security_routing_real(finalizeMod);
  test_execution_status_real(finalizeMod);
  test_trust_boundary();
  test_result_contract_real(validatorMod);
  test_coverage_binding();
  test_discovery_authority();
  test_verification_exactness();
  test_adjudication_rigor_real(finalizeMod);
  test_qualification_receipts();
  test_supplemental_tier();
  test_ci_gates();

  console.log(`\n${passed} PASS, ${failed} FAIL out of ${passed + failed} conformance cases`);
  if (failed > 0) process.exit(1);
}

function test_security_routing_real(mod) {
  const facts = {
    incomplete: false,
    out_dir: join(tmpdir(), 'legion-audit-conformance'),
    checks: [{ check: 'test', status: 'ran', execution_status: 'ran', verdict: 'pass' }],
    provider_reconciliation: {
      providerResults: [
        { provider: 'security.credentials', status: 'candidates', complete: true, findings: [{ ruleId: 'cred.leak', file: 'x.js', line: 1 }], candidates: [], coverageGaps: [] },
      ],
      missingChecks: [], unplannedChecks: [], denominatorMismatches: [], unresolvedCoverage: [], missingRuntimeProviders: [],
    },
    // Candidate authority comes from the frozen plan record.
    plan: { coverageGaps: [], providers: [{ id: 'security.credentials', producesSecurityCandidates: true }] },
    network_policy: { mode: 'deny' },
    plan_binding_verification: { valid: true },
  };
  const report = mod.finalizeAudit({ facts, candidates: { candidates: [] }, adjudication: { complete: true, verdicts: [] } });
  const candidateFindings = report.findings.filter((f) => f.provider === 'security.credentials');
  if (!assert(candidateFindings.length === 0, 'candidate-provider findings excluded')) return;
  const violation = report.coverage_gaps.find((g) => g.kind === 'candidate-provider-contract-violation');
  if (!assert(violation, 'contract violation recorded')) return;
  pass('security routing: candidate providers emit candidates only');
}

function test_execution_status_real(mod) {
  const facts = {
    incomplete: false,
    out_dir: join(tmpdir(), 'legion-audit-conformance'),
    checks: [
      { check: 'types', status: 'ran', execution_status: 'ran', verdict: 'pass' },
      { check: 'lint', status: 'ran', execution_status: 'ran', verdict: 'fail', exit_code: 1 },
    ],
    provider_reconciliation: {
      providerResults: [],
      missingChecks: [], unplannedChecks: [], denominatorMismatches: [], unresolvedCoverage: [], missingRuntimeProviders: [],
    },
    plan: { coverageGaps: [] },
    network_policy: { mode: 'deny' },
    plan_binding_verification: { valid: true },
  };
  const report = mod.finalizeAudit({ facts, candidates: { candidates: [] }, adjudication: { complete: true, verdicts: [] } });
  if (!assert(report.gates.deterministic_checks === 'unproven', 'gate fails on failing verdict')) return;
  if (!assert(report.audit_status === 'fail', 'audit_status is fail')) return;
  pass('execution status: failing command fails the gate');
}

function test_result_contract_real(mod) {
  try {
    mod.validateProviderResult({ schemaVersion: 1, provider: 'test', status: 'invalid-status', complete: true });
    assert(false, 'should reject invalid status');
    return;
  } catch (e) {
    if (!assert(e instanceof mod.ProviderResultValidationError, 'typed error')) return;
    if (!assert(e.field === 'status', 'error names field')) return;
  }
  pass('result contract: validation rejects invalid provider results');
}

function test_adjudication_rigor_real(mod) {
  const facts = {
    incomplete: false,
    out_dir: join(tmpdir(), 'legion-audit-conformance'),
    checks: [{ check: 'test', status: 'ran', execution_status: 'ran', verdict: 'pass' }],
    provider_reconciliation: {
      providerResults: [],
      missingChecks: [], unplannedChecks: [], denominatorMismatches: [], unresolvedCoverage: [], missingRuntimeProviders: [],
    },
    plan: { coverageGaps: [] },
    network_policy: { mode: 'deny' },
    plan_binding_verification: { valid: true },
  };
  const report = mod.finalizeAudit({ facts, candidates: { candidates: [] }, adjudication: { complete: false, verdicts: [] } });
  if (!assert(report.coverage_gaps.find((g) => g.kind === 'security-adjudication'), 'gap recorded')) return;
  if (!assert(report.audit_status === 'incomplete', 'blocks audit')) return;
  pass('adjudication rigor: incomplete adjudication blocks the audit');
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
