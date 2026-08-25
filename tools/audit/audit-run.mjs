#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { existsSync, writeFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { runCompleteAudit, reconcileCompleteRun } from './audit-complete.mjs';
import { prepareAdjudicationBundle } from './security-pipeline.mjs';
import { normalizeProviderResult, validateProviderResult } from '../../scripts/normalize-provider-result.mjs';
import { validateProviderOutputAuthority } from '../../src/lib/providers/sdk/contracts.mjs';
import { resolveRepositoryModule } from '../../src/lib/providers/provider-executor.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

function arg(args, name) { const index = args.indexOf(name); return index >= 0 ? args[index + 1] : null; }
function values(args, name) { const raw = arg(args, name); return raw ? raw.split(',').map((value) => value.trim()).filter(Boolean) : []; }
function firstPositional(args) {
  const takesValue = new Set(['--out', '--only', '--skip', '--type', '--base', '--base-commit', '--dir', '--blueprint-out', '--url', '--surfaces', '--visual-spec', '--visual-baselines', '--width', '--height']);
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

function normalizedExecutableHref(href, platform = process.platform) {
  return platform === 'win32' ? String(href).toLowerCase() : String(href);
}
export function sameExecutableHref(leftHref, rightHref, platform = process.platform) {
  return normalizedExecutableHref(leftHref, platform) === normalizedExecutableHref(rightHref, platform);
}
// Windows argv[1] may differ from import.meta.url only by drive-letter case or
// path normalization; compare normalized file URLs so the direct entrypoint is
// detected reliably on every host.
export function isMainEntrypoint(importMetaUrl, argvPath = process.argv[1], platform = process.platform) {
  if (!argvPath) return false;
  try { return sameExecutableHref(pathToFileURL(resolve(argvPath)).href, importMetaUrl, platform); }
  catch { return false; }
}

// The --out directory is run-owned state: it must stay strictly inside the
// <root>/.audit scope so an audit can never scatter reports into arbitrary
// workspace locations (or overwrite a sibling's artifacts).
export function assertRunOwnedOutScope({ root, outDir }) {
  const scopeRoot = resolve(root, '.audit');
  const target = resolve(outDir);
  const rel = relative(scopeRoot, target);
  if (!rel || rel.startsWith('..') || isAbsolute(rel)) {
    throw new Error(`--out must stay under the run-owned .audit scope (${scopeRoot}); received ${target}`);
  }
  return target;
}

// Measurement evidence (benchmark qualification per provider) is integrated
// when tools/audit/provider-benchmarks.mjs exists; its absence degrades to a
// recorded null rather than blocking the pipeline.
export async function loadMeasurementEvidence() {
  const benchmarksPath = join(HERE, 'provider-benchmarks.mjs');
  if (!existsSync(benchmarksPath)) return null;
  try {
    const mod = await import(pathToFileURL(benchmarksPath).href);
    return typeof mod.measurementEvidence === 'function' ? mod.measurementEvidence : (mod.default ?? null);
  } catch { return null; }
}

function executionErrorResult(provider, error) {
  const gap = { kind: 'provider-execution-error', error: error.message };
  const result = {
    schemaVersion: 1, provider: provider.id, applicable: true,
    status: 'unproven', complete: false,
    coverage: {}, candidates: [], findings: [], coverageGaps: [gap], degradation: [gap],
  };
  return normalizeProviderResult(provider, result);
}

// Every selected provider that runCompleteAudit did not already execute is
// dispatched through the existing registry/runner contracts — never hard-coded
// per suite:
//   - runtime-script: sealed module resolution + moduleDigest verification +
//     analyze({ root, plan, projection, artifacts, provider, host })
//   - reasoning-contract: host.reviewer.review(packet) with fresh-context
//     enforcement for adjudicator-role lenses
// Results flow through validateProviderOutputAuthority and the pipeline's
// normalizeProviderResult boundary. A reasoning lens joins lenses_ran ONLY when
// it actually executed to completion (complete=true, terminal status) — never
// by mere selection or record.
export async function executeUnexecutedProviders({ result, host = {} }) {
  const handled = new Set((result.providerResults ?? []).map((provider) => provider.provider));
  const artifacts = new Map(Object.entries({
    ...(result.projection ? { 'blueprint-packet': result.projection } : {}),
    ...(result.securityResult ? { 'security-candidates': result.securityResult } : {}),
  }));
  const appended = [];
  const invokedIds = new Set();
  const ranReasoning = [];
  for (const provider of result.plan.providers ?? []) {
    if (handled.has(provider.id)) continue;
    // runtime.app and visual.core are condition-invoked inside runCompleteAudit and always emit a result record.
    if (provider.id === 'runtime.app' || provider.id === 'visual.core') continue;
    const kind = provider.runner?.kind;
    if (kind !== 'runtime-script' && kind !== 'reasoning-contract') continue;

    let outcome;
    try {
      if (kind === 'runtime-script') {
        const modulePath = resolveRepositoryModule(provider.runner.module ?? provider.runner.script);
        const moduleBytes = await readFile(modulePath);
        const moduleDigest = `sha256:${createHash('sha256').update(moduleBytes).digest('hex')}`;
        if (moduleDigest !== provider.runner.moduleDigest) throw new Error(`provider ${provider.id} module digest mismatch`);
        const module = await import(pathToFileURL(modulePath).href);
        const analyze = module.analyze ?? module.default?.analyze;
        if (typeof analyze !== 'function') throw new Error(`runtime-script ${provider.runner.module} exports no runnable analyze function`);
        const raw = await analyze({
          root: result.plan.root, plan: result.plan, projection: result.projection,
          artifacts, provider: provider.id, host,
        });
        outcome = normalizeProviderResult(provider, validateProviderOutputAuthority(provider, { ...raw, provider: raw.provider ?? provider.id }));
        validateProviderResult(outcome);
      } else {
        // reasoning-contract: fresh-context adjudicators must run in their own
        // review context; the injected host reviewer owns that isolation.
        const review = host.reviewer?.review ?? host.reviewer?.run;
        if (typeof review !== 'function') throw new Error('reasoning-reviewer-unavailable');
        const packet = {
          schemaVersion: 1, kind: 'legion-reasoning-packet', provider: provider.id,
          contract: provider.runner.contract, binding: result.plan.binding ?? null,
          projection: result.projection, artifactIds: [...artifacts.keys()],
        };
        const raw = await review.call(host.reviewer, packet);
        if (!raw || typeof raw.complete !== 'boolean') throw new Error('reasoning-receipt-invalid');
        outcome = {
          schemaVersion: 1,
          provider: provider.id,
          applicable: raw.applicable ?? true,
          required: true,
          status: raw.status ?? 'unproven',
          complete: raw.complete === true,
          coverage: raw.denominator ?? raw.coverage ?? {},
          candidates: Array.isArray(raw.candidates) ? raw.candidates : [],
          findings: Array.isArray(raw.findings) ? raw.findings : [],
          coverageGaps: Array.isArray(raw.coverageGaps) ? raw.coverageGaps : [],
          degradation: Array.isArray(raw.degradation) ? raw.degradation : [],
        };
      }
    } catch (error) {
      outcome = executionErrorResult(provider, error);
    }

    appended.push(outcome);
    invokedIds.add(provider.id);
    if (kind === 'reasoning-contract' && outcome.complete === true && ['pass', 'fail', 'candidates'].includes(outcome.status)) {
      ranReasoning.push(provider.id);
    }
  }
  return { appended, invokedIds, ranReasoning };
}

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
  if (facts.blueprint?.state !== 'ready' || facts.plan_binding_verification?.valid !== true) return false;
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

  const trustedSandbox = options.host?.capabilities?.networkSandbox ?? {};
  const trustedSandboxActive = process.env.AUDIT_NETWORK_GUARD === 'active'
    && trustedSandbox.active === true
    && Boolean(trustedSandbox.receipt);
  const host = {
    ...(options.host ?? {}),
    capabilities: {
      ...(options.host?.capabilities ?? {}),
      networkSandbox: { ...trustedSandbox, active: trustedSandboxActive },
    },
  };
  const { appended, invokedIds, ranReasoning } = await executeUnexecutedProviders({ result, host });
  const addedProviderIds = invokedIds;

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
  // Reasoning lenses enter lenses_ran only when they ACTUALLY executed through
  // the runner contract this invocation (see executeUnexecutedProviders).
  // Selected-but-not-run lenses stay in reasoning_lenses_required and are
  // rejected downstream by audit-finalize (missing-reasoning-lens gap).
  const requiredLenses = [...new Set(result.plan.denominator.reasoningProviders ?? [])].sort();
  facts.lenses_ran = [...new Set(ranReasoning)].sort();
  facts.reasoning_lenses_required = requiredLenses;
  const measurementEvidence = await loadMeasurementEvidence();
  if (measurementEvidence !== null) {
    try {
      facts.provider_benchmarks = typeof measurementEvidence === 'function'
        ? (await measurementEvidence(result.plan))
        : measurementEvidence;
    } catch (error) {
      facts.provider_benchmarks = { state: 'unavailable', reason: error.message };
    }
  }
  facts.network_policy = {
    ...(result.facts.network_policy ?? {}),
    environment: ['AUDIT_OFFLINE', 'AUDIT_NETWORK_GUARD', 'npm_config_offline', 'CARGO_NET_OFFLINE', 'PIP_NO_INDEX', 'GOPROXY=off', 'GOSUMDB=off', 'BUNDLE_FROZEN', 'MAVEN_ARGS=-o', 'GRADLE_OPTS=offline'],
  };
  writeJson(join(result.outDir, 'facts.json'), facts);
  return { ...result, facts, providerResults, securityResult };
}

async function main() {
  const args = process.argv.slice(2);
  const rootArg = firstPositional(args);
  const requestedOut = arg(args, '--out');
  const outDir = requestedOut ? assertRunOwnedOutScope({ root: rootArg || process.cwd(), outDir: requestedOut }) : undefined;
  const result = await runAuditProviders({
    root: rootArg, outDir, blueprintOut: arg(args, '--blueprint-out') ?? undefined,
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
    lensesRan: result.facts?.lenses_ran ?? [],
    securityCandidates: result.securityResult?.candidates?.length ?? 0,
    adjudicationBundle: bundlePath,
    next: bundlePath
      ? `Adjudicate every packet in ${bundlePath} from its own fresh context, then run security-pipeline.mjs and audit-finalize.mjs.`
      : 'Run audit-finalize.mjs with an empty complete adjudication result.',
  }, null, 2));
  if (result.facts?.incomplete) process.exitCode = 2;
}

if (isMainEntrypoint(import.meta.url)) {
  main().catch((error) => { console.error(error.stack ?? error.message); process.exit(1); });
}
