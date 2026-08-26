#!/usr/bin/env node
import { readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { reportToSarif } from '../../scripts/report-to-sarif.mjs';

const SURVIVING = new Set(['TRUE_POSITIVE', 'LIKELY_TRUE_POSITIVE']);

// Reasoning lenses selected by the sealed plan must be recorded as run before
// any audit may read as complete — a scanner-only pass is never an audit.
function requiredLenses(facts) {
  return [...new Set(facts?.plan?.reasoningProviders ?? [])].sort();
}
function ranLenses(facts) {
  return Array.isArray(facts?.lenses_ran) ? [...new Set(facts.lenses_ran)].sort() : [];
}

// Windows argv[1] may differ from import.meta.url only by drive-letter case or
// path normalization; compare normalized file URLs so the direct entrypoint is
// detected reliably on every host.
function normalizedExecutableHref(href, platform = process.platform) {
  let normalized = String(href);
  try { normalized = pathToFileURL(realpathSync(fileURLToPath(normalized))).href; }
  catch {}
  return platform === 'win32' ? normalized.toLowerCase() : normalized;
}
export function isMainEntrypoint(importMetaUrl, argvPath = process.argv[1], platform = process.platform) {
  if (!argvPath) return false;
  try { return normalizedExecutableHref(pathToFileURL(resolve(argvPath)).href, platform) === normalizedExecutableHref(importMetaUrl, platform); }
  catch { return false; }
}
const AUDIT_RUN = fileURLToPath(new URL('./audit-run.mjs', import.meta.url));
const AUDIT_VERIFY = fileURLToPath(new URL('./audit-verify.mjs', import.meta.url));
function command(executable, args) { return { executable, args }; }

function readJson(path) { return JSON.parse(readFileSync(resolve(path), 'utf8')); }
function writeJson(path, value) { writeFileSync(resolve(path), `${JSON.stringify(value, null, 2)}\n`, 'utf8'); }

// Candidate-generator authority comes from the frozen plan record, never from a
// provider name prefix. A provider may emit security candidates only when the
// sealed plan says producesSecurityCandidates: true.
function candidateGeneratorIds(facts) {
  return new Set((facts.plan?.providers ?? [])
    .filter((provider) => provider.producesSecurityCandidates)
    .map((provider) => provider.id));
}

function isCandidateGenerator(facts, provider) {
  const ids = candidateGeneratorIds(facts);
  return ids.has(provider.provider) || ids.has(provider.ownerProvider);
}

function providerFindings(facts) {
  return (facts.provider_reconciliation?.providerResults ?? []).flatMap((provider) => {
    if (isCandidateGenerator(facts, provider)) return [];
    return (provider.findings ?? []).map((finding) => ({
      id: finding.id ?? `${provider.provider}:${finding.ruleId}:${finding.file ?? finding.surface ?? 'unknown'}:${finding.line ?? 1}`,
      category: String(finding.ruleId ?? provider.provider).split('.')[0],
      ruleId: finding.ruleId ?? provider.provider,
      severity: finding.severity ?? (finding.level === 'error' ? 'high' : finding.level === 'warning' ? 'medium' : 'low'),
      title: finding.title ?? finding.ruleId ?? provider.provider,
      detail: finding.detail ?? finding.message ?? 'Provider finding',
      file: finding.file ?? null,
      line: finding.line ?? 1,
      evidence: finding.evidence ?? (finding.screenshot ? [{ screenshot: finding.screenshot, surface: finding.surface }] : []),
      evidence_strength: finding.evidence_strength ?? 'observed',
      status: 'open',
      tier: finding.tier ?? 'GUIDED',
      provider: provider.provider,
    }));
  });
}

// Redaction happens upstream (secrets provider). Adjudication must carry the
// redacted values through to report findings verbatim — never dropped, never
// un-redacted. Only digest/metadata plus the redacted marker survive.
const SECRET_CARRIER_KEYS = ['match', 'secretDigest', 'secretType', 'mode', 'classification', 'validity', 'commit'];
function redactedSecretCarrier(candidate) {
  const carrier = {};
  for (const key of SECRET_CARRIER_KEYS) {
    if (candidate?.[key] !== undefined && candidate[key] !== null) carrier[key] = candidate[key];
  }
  return Object.keys(carrier).length ? carrier : null;
}

export function orphanSecurityVerdicts(adjudication, candidates) {
  const known = new Set((candidates?.candidates ?? []).map((candidate) => candidate.id));
  return (adjudication?.verdicts ?? [])
    .filter((verdict) => !known.has(verdict.candidateId))
    .map((verdict) => ({ candidateId: verdict.candidateId }));
}

function securityFindings(adjudication, candidates) {
  const candidateById = new Map((candidates.candidates ?? []).map((candidate) => [candidate.id, candidate]));
  return (adjudication.verdicts ?? []).filter((verdict) => SURVIVING.has(verdict.verdict)).map((verdict) => {
    const candidate = candidateById.get(verdict.candidateId) ?? {};
    const location = candidate.evidence?.[0] ?? {};
    const secretCarrier = redactedSecretCarrier(candidate);
    return {
      id: verdict.candidateId,
      category: 'security',
      ruleId: candidate.ruleId ?? candidate.allegedRootCause ?? 'security.verified',
      severity: verdict.severity,
      title: candidate.claim ?? 'Verified security finding',
      detail: verdict.rationale ?? verdict.impact,
      file: location.file ?? null,
      line: location.line ?? 1,
      evidence: candidate.evidence ?? [],
      evidence_strength: verdict.evidenceStrength,
      status: 'open',
      tier: 'GUIDED',
      provider: verdict.candidateProvider,
      security: verdict,
      ...(secretCarrier ? { redacted_secret: secretCarrier } : {}),
    };
  });
}

function nonSecurityGaps(facts) {
  const reconciliation = facts.provider_reconciliation ?? {};
  const gaps = [];
  if (!facts.plan_binding_verification?.valid) gaps.push({ kind: 'plan-binding', detail: facts.plan_binding_verification?.drift ?? [] });
  for (const gap of facts.plan?.coverageGaps ?? []) gaps.push({ kind: 'plan-coverage', detail: gap });
  for (const check of reconciliation.missingChecks ?? []) gaps.push({ kind: 'missing-check', check });
  for (const check of reconciliation.unplannedChecks ?? []) gaps.push({ kind: 'unplanned-check', check });
  for (const mismatch of reconciliation.denominatorMismatches ?? []) gaps.push({ kind: 'provider-denominator-mismatch', detail: mismatch });
  for (const provider of reconciliation.providerResults ?? []) {
    if (provider.provider === 'security.adjudication' || provider.provider === 'security.variant-analysis') continue;
    if (provider.complete === false || ['missing', 'skipped', 'error', 'unproven', 'pending', 'fail'].includes(provider.status)) {
      gaps.push({ kind: 'provider-incomplete', provider: provider.provider, status: provider.status });
    }
  }
  for (const gap of reconciliation.unresolvedCoverage ?? []) gaps.push({ kind: 'coverage-family', family: gap.id, detail: gap });
  for (const provider of reconciliation.missingRuntimeProviders ?? []) gaps.push({ kind: 'missing-runtime-provider', provider });
  const ranLensSet = new Set(ranLenses(facts));
  for (const lens of requiredLenses(facts)) {
    if (!ranLensSet.has(lens)) gaps.push({ kind: 'missing-reasoning-lens', lens });
  }
  if (facts.network_policy?.mode !== 'deny') gaps.push({ kind: 'network-policy', detail: facts.network_policy ?? null });
  if (facts.incomplete && gaps.length === 0) gaps.push({ kind: 'facts-incomplete', detail: 'facts.json is marked incomplete without a more specific normalized gap' });
  return gaps;
}

// One canonical count model shared by JSON consumers, the Markdown renderer,
// and SARIF: every surface derives from these numbers, never from its own recount.
function canonicalCounts({ facts, findings, candidates, adjudication, lenses, requiredLensList }) {
  const providerResults = facts.provider_reconciliation?.providerResults ?? [];
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) bySeverity[finding.severity] = (bySeverity[finding.severity] ?? 0) + 1;
  const selectedProviderIds = facts.plan?.selectedProviderIds ?? [];
  const ranProviders = new Set(providerResults.map((provider) => provider.provider));
  return {
    schemaVersion: 1,
    providers_selected: selectedProviderIds.length,
    providers_ran: providerResults.filter((provider) => provider.status !== 'pending').length,
    providers_missing: selectedProviderIds.filter((id) => !ranProviders.has(id)).length,
    findings_total: findings.length,
    findings_by_severity: bySeverity,
    findings_open: findings.filter((finding) => finding.status === 'open').length,
    security_candidates: candidates?.candidates?.length ?? 0,
    security_verdicts: adjudication?.verdicts?.length ?? 0,
    security_findings_surviving: findings.filter((finding) => Boolean(finding.security)).length,
    lenses_required: requiredLensList.length,
    lenses_ran: lenses.length,
  };
}

export function finalizeAudit({ facts, candidates, adjudication }) {
  const gaps = nonSecurityGaps(facts);
  if (!adjudication?.complete) gaps.push({ kind: 'security-adjudication', detail: adjudication ?? null });
  for (const orphan of orphanSecurityVerdicts(adjudication ?? {}, candidates ?? {})) {
    gaps.push({ kind: 'orphan-security-verdict', candidateId: orphan.candidateId });
  }

  // Contract violation: candidate-generating providers must not emit findings directly
  for (const provider of (facts.provider_reconciliation?.providerResults ?? [])) {
    if (isCandidateGenerator(facts, provider) && (provider.findings ?? []).length > 0) {
      gaps.push({ kind: 'candidate-provider-contract-violation', provider: provider.provider, findingsCount: provider.findings.length });
    }
  }

  const findings = [...providerFindings(facts), ...securityFindings(adjudication ?? {}, candidates ?? {})];

  // Reject duplicate candidate IDs and finding IDs
  const findingIds = new Set();
  const duplicateFindings = [];
  for (const finding of findings) {
    if (findingIds.has(finding.id)) duplicateFindings.push(finding.id);
    findingIds.add(finding.id);
  }
  if (duplicateFindings.length) gaps.push({ kind: 'duplicate-finding-ids', ids: duplicateFindings });

  const candidateIds = new Set();
  const duplicateCandidates = [];
  for (const candidate of (candidates?.candidates ?? [])) {
    if (candidateIds.has(candidate.id)) duplicateCandidates.push(candidate.id);
    candidateIds.add(candidate.id);
  }
  if (duplicateCandidates.length) gaps.push({ kind: 'duplicate-candidate-ids', ids: duplicateCandidates });

  const lenses = ranLenses(facts);
  const requiredLensList = requiredLenses(facts);
  const summary = canonicalCounts({ facts, findings, candidates, adjudication, lenses, requiredLensList });
  const incomplete = Boolean(facts.incomplete) || gaps.length > 0;
  const executionFailed = (facts.checks ?? []).some((check) => (check.verdict ?? (check.status === 'ran' ? 'pass' : 'unproven')) === 'fail');
  const auditStatus = incomplete ? 'incomplete' : executionFailed ? 'fail' : findings.length ? 'fail' : 'pass';
  const qualityGate = incomplete ? 'unproven' : findings.some((finding) => ['critical', 'high'].includes(finding.severity)) ? 'blocked' : findings.length ? 'attention' : 'pass';
  return {
    schemaVersion: 4,
    kind: 'repository-audit-report',
    generated_at: new Date().toISOString(),
    workspace: facts.workspace,
    commit: facts.plan?.binding?.repositoryRevision ?? null,
    audit_status: auditStatus,
    quality_gate: qualityGate,
    incomplete,
    plan: facts.plan,
    blueprint: facts.blueprint,
    network_policy: facts.network_policy ?? null,
    lenses_ran: lenses,
    lenses: { required: requiredLensList, ran: lenses },
    summary,
    gates: {
      deterministic_checks: (facts.checks ?? []).every((check) => (check.execution_status ?? check.status) === 'ran' && (check.verdict ?? 'pass') === 'pass') ? 'pass' : 'unproven',
      provider_reconciliation: gaps.some((gap) => gap.kind !== 'security-adjudication') ? 'unproven' : 'pass',
      security_adjudication: adjudication?.complete ? 'pass' : 'unproven',
      visual: (facts.provider_reconciliation?.providerResults ?? []).find((provider) => provider.provider === 'visual.core')?.status ?? 'not_applicable',
      runtime: (facts.provider_reconciliation?.providerResults ?? []).find((provider) => provider.provider === 'runtime.app')?.status ?? 'not_applicable',
    },
    coverage_gaps: gaps,
    findings,
    security: {
      candidate_count: candidates?.candidates?.length ?? 0,
      adjudication_complete: Boolean(adjudication?.complete),
      verdicts: adjudication?.verdicts ?? [],
    },
    rerun: {
      audit: command(process.execPath, [AUDIT_RUN, facts.workspace]),
      verify: command(process.execPath, [AUDIT_VERIFY, '--facts', join(facts.out_dir, 'facts.json')]),
    },
  };
}

function arg(args, name) { const index = args.indexOf(name); return index >= 0 ? args[index + 1] : null; }
function main() {
  const args = process.argv.slice(2);
  const factsPath = arg(args, '--facts');
  const candidatesPath = arg(args, '--candidates');
  const adjudicationPath = arg(args, '--adjudication');
  const outPath = arg(args, '--out') ?? resolve(dirname(factsPath), 'report.json');
  const sarifPath = arg(args, '--sarif') ?? resolve(dirname(outPath), 'report.sarif');
  if (!factsPath || !candidatesPath || !adjudicationPath) throw new Error('usage: audit-finalize.mjs --facts facts.json --candidates security-candidates.json --adjudication security-adjudication-result.json [--out report.json] [--sarif report.sarif]');
  const report = finalizeAudit({ facts: readJson(factsPath), candidates: readJson(candidatesPath), adjudication: readJson(adjudicationPath) });
  writeJson(outPath, report);
  writeJson(sarifPath, reportToSarif(report));
  console.log(JSON.stringify({
    report: resolve(outPath), sarif: resolve(sarifPath),
    auditStatus: report.audit_status, qualityGate: report.quality_gate,
    findings: report.summary.findings_total,
    findingsBySeverity: report.summary.findings_by_severity,
    providersSelected: report.summary.providers_selected,
    providersMissing: report.summary.providers_missing,
    securityCandidates: report.summary.security_candidates,
    securityFindingsSurviving: report.summary.security_findings_surviving,
    lensesRequired: report.summary.lenses_required,
    lensesRan: report.lenses_ran,
    coverageGaps: report.coverage_gaps.length,
  }, null, 2));
  if (report.audit_status !== 'pass') process.exitCode = 2;
}

if (isMainEntrypoint(import.meta.url)) main();
