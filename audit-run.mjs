#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { runCompleteAudit, reconcileCompleteRun } from './audit-complete.mjs';
import { runGenericSourceAccounting } from './providers/generic-source-suite.mjs';
import { runAccessibilitySuite } from './providers/accessibility-suite.mjs';
import { prepareAdjudicationBundle } from './security-pipeline.mjs';

function arg(args, name) { const index = args.indexOf(name); return index >= 0 ? args[index + 1] : null; }
function values(args, name) { const raw = arg(args, name); return raw ? raw.split(',').map((value) => value.trim()).filter(Boolean) : []; }
function firstPositional(args) {
  const takesValue = new Set(['--out', '--only', '--skip', '--type', '--base', '--base-commit', '--dir', '--cortex-out', '--url', '--surfaces', '--visual-spec', '--visual-baselines', '--width', '--height']);
  for (let index = 0; index < args.length; index += 1) {
    const value = args[index];
    if (value.startsWith('--')) { if (takesValue.has(value)) index += 1; continue; }
    return value;
  }
  return process.cwd();
}
function scopeFromArgs(args) {
  return {
    mode: ['--type', '--base', '--base-commit', '--dir'].some((name) => args.includes(name)) ? 'diff' : 'whole-repo',
    type: arg(args, '--type') ?? 'all', base: arg(args, '--base'), baseCommit: arg(args, '--base-commit'), dir: arg(args, '--dir'),
  };
}
function writeJson(path, value) { writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, 'utf8'); }
function stableId(value) { return `sha256:${createHash('sha256').update(value).digest('hex')}`; }
function planProvider(plan, id) { return (plan.providers ?? []).find((provider) => provider.id === id) ?? null; }
function frozenFiles(plan, id, fallback = []) { return planProvider(plan, id)?.denominator?.paths ?? fallback; }

function onlyWrapperProvidersCausedPriorIncomplete(facts, addedProviderIds) {
  if (!facts?.incomplete) return false;
  const reconciliation = facts.provider_reconciliation ?? {};
  const missing = [...(reconciliation.missingRuntimeProviders ?? [])].sort();
  const expected = [...addedProviderIds].sort();
  if (JSON.stringify(missing) !== JSON.stringify(expected)) return false;
  if ((reconciliation.unresolvedCoverage ?? []).length > 0) return false;
  if ((reconciliation.denominatorMismatches ?? []).length > 0) return false;
  if (facts.security?.adjudicationRequired) return false;
  if (facts.cortex?.state !== 'ready' || facts.plan_binding_verification?.valid !== true) return false;
  return (reconciliation.providerResults ?? [])
    .filter((provider) => !addedProviderIds.has(provider.provider) && provider.status !== 'pending')
    .every((provider) => provider.complete !== false && !['unproven', 'error', 'missing'].includes(provider.status));
}

function severityHint(level) {
  if (level === 'error' || level === 'critical') return 'high';
  if (level === 'warning') return 'medium';
  return 'low';
}

// Candidate authority comes from the frozen plan record, never from a provider
// name prefix or a local family heuristic. A provider is a candidate provider
// only when the sealed plan says producesSecurityCandidates: true.
export function candidateProviderIds(plan) {
  return new Set((plan.providers ?? [])
    .filter((provider) => provider.producesSecurityCandidates)
    .map((provider) => provider.id));
}

export function aggregateSecurityCandidates(plan, internalReport, providerResults) {
  const allowed = candidateProviderIds(plan);
  const candidates = [...(internalReport?.candidates ?? [])];
  for (const result of providerResults ?? []) {
    // A result is authorized when its provider id is a plan candidate provider,
    // or when its ownerProvider (the plan record that ran the suite) is.
    const authorized = allowed.has(result.provider) || allowed.has(result.ownerProvider);
    if (!authorized) continue;
    if ((result.findings ?? []).length > 0) {
      throw new Error(`candidate provider ${result.provider} emitted findings; candidate providers must emit candidates with findings: []`);
    }
    for (const candidate of result.candidates ?? []) {
      candidates.push({
        ...candidate,
        id: candidate.id ?? stableId(`${result.provider}\0${candidate.ruleId}\0${candidate.file ?? ''}\0${candidate.line ?? 1}`),
        provider: candidate.provider ?? result.provider,
        role: 'candidate-generator',
        evidence: candidate.evidence ?? (candidate.file ? [{ file: candidate.file, line: Number(candidate.line ?? 1) }] : []),
        verdict: 'UNADJUDICATED',
        adjudicationRequired: true,
      });
    }
  }
  const unique = [...new Map(candidates.map((candidate) => [candidate.id, candidate])).values()];
  return {
    schemaVersion: 1, kind: 'audit-security-candidates', provider: 'security.multi-provider',
    complete: internalReport?.complete !== false,
    coverage: { ...(internalReport?.coverage ?? {}), candidateProviders: [...new Set(unique.map((candidate) => candidate.provider))].sort() },
    candidates: unique, coverageGaps: internalReport?.coverageGaps ?? [],
  };
}

export function enrichFactsWithPlan({ facts, plan, projection, bindingVerification, providerResults = [], securityResult = { candidates: [] } }) {
  const enriched = reconcileCompleteRun({ plan, facts, providerResults, securityResult, projection, bindingVerification });
  if ((plan.coverageGaps ?? []).length || plan.qualification?.state === 'unproven') enriched.incomplete = true;
  return enriched;
}

export async function runAuditProviders(options) {
  const result = await runCompleteAudit(options);
  if (!result.facts) return result;

  const selectedIds = new Set(result.plan.denominator.providerIds ?? []);
  const addedProviderIds = new Set();
  const appended = [];

  if (selectedIds.has('generic.source-accounting')) {
    const generic = runGenericSourceAccounting({
      files: frozenFiles(result.plan, 'generic.source-accounting', result.projection.files ?? []),
      parsedExtensions: result.projection.parsedExtensions ?? [],
    });
    writeJson(join(result.outDir, 'generic-source-results.json'), generic);
    appended.push(generic);
    addedProviderIds.add(generic.provider);
  }

  if (selectedIds.has('accessibility.internal-suite')) {
    const accessibility = runAccessibilitySuite({ root: result.plan.root, files: frozenFiles(result.plan, 'accessibility.internal-suite', result.projection.files ?? []) });
    writeJson(join(result.outDir, 'accessibility-results.json'), accessibility);
    appended.push(accessibility);
    addedProviderIds.add(accessibility.provider);
  }

  const providerResults = [
    ...(result.providerResults ?? []).filter((provider) => !addedProviderIds.has(provider.provider)),
    ...appended,
  ];
  const securityResult = aggregateSecurityCandidates(result.plan, result.securityResult, providerResults);
  writeJson(join(result.outDir, 'security-candidates.json'), securityResult);

  const bindingVerification = result.facts.plan_binding_verification ?? { valid: false, drift: [{ field: 'binding', observed: 'missing' }] };
  const rawFacts = {
    ...result.facts,
    incomplete: addedProviderIds.size && onlyWrapperProvidersCausedPriorIncomplete(result.facts, addedProviderIds) ? false : result.facts.incomplete,
    provider_reconciliation: undefined,
    security: undefined,
  };
  const facts = enrichFactsWithPlan({
    plan: result.plan, facts: rawFacts, providerResults, securityResult,
    projection: result.projection, bindingVerification,
  });
  facts.plan.path = result.planPath;
  facts.network_policy = {
    ...(result.facts.network_policy ?? {}),
    mode: 'deny',
    environment: ['AUDIT_OFFLINE', 'AUDIT_NETWORK_GUARD', 'npm_config_offline', 'CARGO_NET_OFFLINE', 'PIP_NO_INDEX', 'GOPROXY=off', 'GOSUMDB=off', 'BUNDLE_FROZEN', 'MAVEN_ARGS=-o', 'GRADLE_OPTS=offline'],
  };
  writeJson(join(result.outDir, 'facts.json'), facts);
  return { ...result, facts, providerResults, securityResult };
}

async function main() {
  const args = process.argv.slice(2);
  const result = await runAuditProviders({
    root: firstPositional(args), outDir: arg(args, '--out'), cortexOut: arg(args, '--cortex-out') ?? '.agent',
    only: values(args, '--only'), skip: values(args, '--skip'), scope: scopeFromArgs(args),
    planOnly: args.includes('--plan-only'), quiet: args.includes('--quiet'), url: arg(args, '--url'),
    surfaces: arg(args, '--surfaces'), visualSpec: arg(args, '--visual-spec'), visualBaselines: arg(args, '--visual-baselines'),
    width: Number(arg(args, '--width') ?? 1280), height: Number(arg(args, '--height') ?? 800),
  });

  let bundlePath = null;
  if (result.securityResult?.candidates?.length) {
    const bundle = prepareAdjudicationBundle(result.securityResult);
    bundlePath = join(result.outDir, 'security-adjudication-bundle.json');
    writeJson(bundlePath, bundle);
  }

  console.log(JSON.stringify({
    kind: 'audit-provider-run', outDir: result.outDir, plan: result.planPath,
    facts: result.facts ? join(result.outDir, 'facts.json') : null,
    incomplete: result.facts?.incomplete ?? true,
    selectedProviders: result.plan.denominator.providerIds,
    securityCandidates: result.securityResult?.candidates?.length ?? 0,
    adjudicationBundle: bundlePath,
    next: bundlePath
      ? `Adjudicate every packet in ${bundlePath} from its own fresh context, then run security-pipeline.mjs and audit-finalize.mjs.`
      : 'Run audit-finalize.mjs with an empty complete adjudication result.',
  }, null, 2));
  if (result.facts?.incomplete) process.exitCode = 2;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => { console.error(error.stack ?? error.message); process.exit(1); });
}
