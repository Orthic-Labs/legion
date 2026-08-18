#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { readCortexManifestBinding, readCortexProjection, collectRepositoryBinding } from '../../src/adapters/cortex-projection.mjs';
import { enrichProjectionWithEcosystems } from '../../src/adapters/ecosystem-manifests.mjs';
import { buildAuditPlan, reconcilePlanWithFacts, verifyPlanBinding, writeAuditPlan } from './audit-plan.mjs';
import { loadProviderRegistry } from '../../src/registry/provider-registry.mjs';
import { runNativeFamilies } from '../../src/providers/native-family-runner.mjs';
import { runFrameworkSuite } from '../../src/providers/framework-suite.mjs';
import { runDataSuite } from '../../src/providers/data-suite.mjs';
import { runInfrastructureSuite } from '../../src/providers/infrastructure-suite.mjs';
import { generateSecurityCandidates, mergeSecurityCandidateReports } from '../../src/providers/security-suite.mjs';
import { auditVisualArtifacts } from '../../src/providers/visual-core.mjs';
import { normalizeProviderResult } from '../../scripts/normalize-provider-result.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const COLLECT_FACTS = join(HERE, 'collect-facts.mjs');
const AUDIT_RUNTIME = join(HERE, 'audit-runtime.mjs');
const NETWORK_DEPENDENT_CHECKS = new Set(['deps_cve', 'py_deps_cve', 'cargo_audit', 'cargo_deny', 'outdated', 'cargo_outdated', 'binary_pins']);
const PROJECT_EXECUTION_CHECKS = new Set(['types', 'lint', 'build', 'dead_code', 'duplication', 'ci_lint', 'docker', 'sast', 'swift_lint', 'js_licenses', 'cargo_unsafe', 'cargo_unused_deps']);
const writeJson = (path, value) => writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, 'utf8');

function applyOfflinePolicy(options) {
  const networkSandboxActive = process.env.AUDIT_NETWORK_GUARD === 'active';
  process.env.AUDIT_OFFLINE = '1';
  process.env.npm_config_offline = 'true';
  process.env.CARGO_NET_OFFLINE = 'true';
  process.env.PIP_NO_INDEX = '1';
  process.env.GOPROXY = 'off';
  process.env.GOSUMDB = 'off';
  process.env.BUNDLE_FROZEN = 'true';
  process.env.MAVEN_ARGS = [process.env.MAVEN_ARGS, '-o'].filter(Boolean).join(' ');
  process.env.GRADLE_OPTS = [process.env.GRADLE_OPTS, '-Dorg.gradle.offline=true'].filter(Boolean).join(' ');
  const guardedSkips = networkSandboxActive ? [] : [...PROJECT_EXECUTION_CHECKS];
  return {
    ...options,
    networkSandboxActive,
    skip: [...new Set([...(options.skip ?? []), ...NETWORK_DEPENDENT_CHECKS, ...guardedSkips])].sort(),
  };
}

function providerPlan(plan, id) { return (plan.providers ?? []).find((provider) => provider.id === id) ?? null; }
function selected(plan, id) { return Boolean(providerPlan(plan, id)); }
function frozenFiles(plan, id, fallback = []) {
  const provider = providerPlan(plan, id);
  if (!provider) return [];
  return provider.denominator?.paths ?? fallback;
}

function runtimeEvidence({ root, outDir, plan, options }) {
  if (!selected(plan, 'runtime.app')) return null;
  if (!options.networkSandboxActive) return { provider: 'runtime.app', phase: 'runtime', status: 'unproven', complete: false, findings: [], coverageGaps: [{ kind: 'network-sandbox', detail: 'Runtime evidence may execute project code and requires AUDIT_NETWORK_GUARD=active.' }] };
  if (!options.url) return { provider: 'runtime.app', phase: 'runtime', status: 'unproven', complete: false, findings: [], coverageGaps: [{ kind: 'runtime-url', detail: 'Runnable UI detected but --url was not supplied.' }] };
  const runtimeOut = join(outDir, 'runtime');
  mkdirSync(runtimeOut, { recursive: true });
  const args = [AUDIT_RUNTIME, '--url', options.url, '--out', runtimeOut, '--width', String(options.width ?? 1280), '--height', String(options.height ?? 800)];
  if (options.surfaces) args.push('--surfaces', options.surfaces);
  const run = spawnSync(process.execPath, args, { cwd: root, encoding: 'utf8', stdio: options.quiet ? 'pipe' : 'inherit', timeout: 300000, maxBuffer: 64 * 1024 * 1024 });
  const path = join(runtimeOut, 'runtime.json');
  if (!existsSync(path)) return { provider: 'runtime.app', phase: 'runtime', status: 'error', complete: false, findings: [], coverageGaps: [{ kind: 'runtime-execution', detail: run.stderr || run.error?.message || `exit ${run.status}` }] };
  const raw = JSON.parse(readFileSync(path, 'utf8'));
  const findings = (raw.findings ?? []).flatMap((surface) => (surface.flags ?? []).map((flag) => ({ ruleId: 'runtime.observation', level: 'warning', message: flag, surface: surface.surface, screenshot: surface.screenshot ?? null })));
  const complete = run.status === 0 && !raw.incomplete && !raw.shallow;
  return { provider: 'runtime.app', phase: 'runtime', status: findings.length ? 'fail' : complete ? 'pass' : 'unproven', complete, reportPath: path, coverage: { surfacesFound: raw.surfaces_found, surfacesTested: raw.surfaces_tested }, findings, coverageGaps: complete ? [] : [{ kind: raw.incomplete ? 'runtime-not-ready' : 'runtime-shallow' }], raw };
}

function visualEvidence({ root, plan, runtime, options }) {
  if (!selected(plan, 'visual.core')) return null;
  let spec = null;
  if (options.visualSpec) spec = JSON.parse(readFileSync(resolve(options.visualSpec), 'utf8'));
  else if (runtime?.raw) {
    const baselines = options.visualBaselines ? JSON.parse(readFileSync(resolve(options.visualBaselines), 'utf8')) : {};
    const captures = (runtime.raw.findings ?? []).filter((surface) => surface.screenshot).map((surface) => {
      const id = String(surface.surface ?? 'surface').replace(/[^A-Za-z0-9_.-]+/g, '-');
      const actual = isAbsolute(surface.screenshot) ? surface.screenshot : resolve(root, surface.screenshot);
      const baseline = baselines[id] ?? baselines[surface.surface] ?? null;
      return { id, route: surface.surface ?? '/', state: 'default', viewport: `${options.width ?? 1280}x${options.height ?? 800}`, theme: 'default', locale: 'default', platform: `web-${process.platform}`, path: actual, ...(baseline ? { baseline: isAbsolute(baseline) ? baseline : resolve(root, baseline) } : {}) };
    });
    spec = { expected: { cases: captures.map(({ route, state, viewport, theme, locale, platform }) => ({ route, state, viewport, theme, locale, platform })) }, captures };
  }
  if (!spec) return { provider: 'visual.core', phase: 'runtime', status: 'unproven', complete: false, findings: [], coverageGaps: [{ kind: 'visual-evidence' }] };
  return { provider: 'visual.core', phase: 'runtime', ...auditVisualArtifacts({ root, spec }) };
}

function familyCoverage(plan, results) {
  const byFamily = new Map();
  for (const result of results) {
    if (!result.family) continue;
    if (!byFamily.has(result.family)) byFamily.set(result.family, []);
    byFamily.get(result.family).push(result);
  }
  const families = (plan.coverageFamilies ?? []).map((family) => {
    const executions = byFamily.get(family.id) ?? [];
    return executions.length ? { ...family, executions: executions.map(({ provider, status, complete, coverage }) => ({ provider, status, complete, coverage })) } : family;
  });
  return {
    families,
    unresolved: families.filter((family) => !family.executions?.length
      ? family.qualification !== 'complete' || family.missingProviders?.length
      : family.executions.some((item) => !item.complete || ['unproven', 'error'].includes(item.status))),
  };
}

function denominatorDrift(plan, providerResults) {
  const byId = new Map((plan.providers ?? []).map((provider) => [provider.id, provider]));
  const gaps = [];
  for (const result of providerResults) {
    const contract = byId.get(result.provider);
    if (!contract || !result.coverage || !contract.denominator) continue;
    // Compare path digests when available; fall back to counts only as a last resort
    const expectedDigest = contract.denominator.pathDigest;
    const observedDigest = result.coverage.pathDigest ?? result.coverage.denominatorDigest ?? null;
    if (expectedDigest && observedDigest && expectedDigest !== observedDigest) {
      gaps.push({ provider: result.provider, kind: 'denominator-digest-mismatch', expectedDigest, observedDigest });
      continue;
    }
    const expected = contract.denominator.pathCount;
    const observed = result.coverage.expectedFiles ?? result.coverage.pathCount ?? result.coverage.fileCount ?? result.coverage.paths?.length ?? null;
    if (observed !== null && Number(observed) !== Number(expected)) gaps.push({ provider: result.provider, expectedPathCount: expected, observedPathCount: observed });
  }
  return gaps;
}

export function reconcileCompleteRun({ plan, facts, providerResults, securityResult, projection, bindingVerification }) {
  const legacy = reconcilePlanWithFacts(plan, facts);
  const { families, unresolved } = familyCoverage(plan, providerResults);
  const selectedRuntime = new Set(plan.providers.filter((provider) => provider.phase === 'runtime').map((provider) => provider.id));
  const observed = new Set(providerResults.map((provider) => provider.provider));
  const missingRuntimeProviders = [...selectedRuntime].filter((id) => !observed.has(id));
  const factsComplete = legacy.providerResults.filter((provider) => provider.phase === 'facts').every((provider) => provider.complete);
  const providerIncomplete = providerResults.some((provider) => provider.complete === false || ['unproven', 'error', 'missing', 'fail'].includes(provider.status));
  const securityPending = (securityResult?.candidates?.length ?? 0) > 0;
  const planIncomplete = (plan.coverageGaps ?? []).length > 0 || plan.qualification?.state === 'unproven';
  const denominatorMismatches = denominatorDrift(plan, providerResults);
  const incomplete = Boolean(facts.incomplete) || planIncomplete || projection.state !== 'ready' || !legacy.valid || !factsComplete || !bindingVerification.valid || providerIncomplete || missingRuntimeProviders.length > 0 || unresolved.length > 0 || securityPending || denominatorMismatches.length > 0;
  return {
    ...facts,
    incomplete,
    cortex: { state: projection.state, reason: projection.reason ?? null, generationId: projection.generationId ?? null, manifestDigest: projection.manifestDigest ?? null, fileCount: projection.fileCount ?? 0, sourceFileCount: projection.sourceFileCount ?? 0, parsedExtensions: projection.parsedExtensions ?? [], unsupportedExtensions: projection.unsupportedExtensions ?? [] },
    plan: { schemaVersion: plan.schemaVersion, seal: plan.seal, binding: plan.binding, expectedChecks: plan.denominator.expectedChecks, selectedProviderIds: plan.denominator.providerIds, coverageGaps: plan.coverageGaps },
    provider_reconciliation: { ...legacy, providerResults: [...legacy.providerResults.filter((provider) => provider.status !== 'pending'), ...providerResults], coverageFamilies: families, unresolvedCoverage: unresolved, missingRuntimeProviders, denominatorMismatches },
    security: { candidatesPath: 'security-candidates.json', candidatesCount: securityResult?.candidates?.length ?? 0, adjudicationRequired: securityPending },
    plan_binding_verification: bindingVerification,
  };
}

function securityProviderPlans(plan) {
  return (plan.providers ?? []).filter((provider) => provider.runner?.kind === 'runtime-script' && provider.runner?.script === 'src/providers/security-suite.mjs');
}

export async function runCompleteAudit(inputOptions) {
  const options = applyOfflinePolicy(inputOptions);
  const root = resolve(options.root);
  const outDir = resolve(options.outDir ?? join(root, '.audit', new Date().toISOString().replace(/[:.]/g, '-')));
  const cortexOut = options.cortexOut ?? '.agent';
  mkdirSync(outDir, { recursive: true });
  const registry = loadProviderRegistry(options.registryPath);
  const projection = enrichProjectionWithEcosystems(readCortexProjection(root, { outDir: cortexOut }), root);
  const plan = buildAuditPlan({ root, registry, projection, repositoryBinding: collectRepositoryBinding(root), scope: options.scope, only: options.only, skip: options.skip });
  const planPath = join(outDir, 'plan.json');
  writeAuditPlan(planPath, plan);
  if (options.planOnly) return { plan, planPath, projection, outDir, facts: null };

  if (plan.denominator.expectedChecks.length) {
    const args = [COLLECT_FACTS, root, '--out', outDir, '--only', plan.denominator.expectedChecks.join(',')];
    if (options.scope?.type && options.scope.type !== 'all') args.push('--type', options.scope.type);
    if (options.scope?.base) args.push('--base', options.scope.base);
    if (options.scope?.baseCommit) args.push('--base-commit', options.scope.baseCommit);
    if (options.scope?.dir) args.push('--dir', options.scope.dir);
    spawnSync(process.execPath, args, { cwd: root, encoding: 'utf8', stdio: options.quiet ? 'pipe' : 'inherit', maxBuffer: 128 * 1024 * 1024 });
  }

  const factsPath = join(outDir, 'facts.json');
  const rawFacts = existsSync(factsPath) ? JSON.parse(readFileSync(factsPath, 'utf8')) : { kind: 'audit-facts', workspace: root, out_dir: outDir, checks: [], incomplete: true };
  const files = projection.files ?? [];
  const nativeSelected = selected(plan, 'native.family-suite');
  const nativeResults = nativeSelected && options.networkSandboxActive ? runNativeFamilies({ root, plan }) : [];
  const nativeSummary = nativeSelected
    ? options.networkSandboxActive
      ? { provider: 'native.family-suite', phase: 'runtime', status: nativeResults.length === 0 ? 'unproven' : nativeResults.some((result) => ['fail', 'error'].includes(result.status)) ? 'fail' : nativeResults.some((result) => result.status === 'unproven') ? 'unproven' : 'pass', complete: nativeResults.length > 0 && nativeResults.every((result) => result.complete), coverage: providerPlan(plan, 'native.family-suite')?.denominator ?? null, coverageGaps: nativeResults.length ? [] : [{ kind: 'native-family-empty' }] }
      : { provider: 'native.family-suite', phase: 'runtime', status: 'unproven', complete: false, coverage: providerPlan(plan, 'native.family-suite')?.denominator ?? null, coverageGaps: [{ kind: 'network-sandbox', detail: 'Project-native commands require AUDIT_NETWORK_GUARD=active.' }] }
    : null;
  const frameworkResults = selected(plan, 'framework.major-suite') ? runFrameworkSuite({ root, plan }) : [];
  const dataFiles = frozenFiles(plan, 'data.internal-suite', files);
  const infrastructureFiles = frozenFiles(plan, 'infrastructure.internal-suite', files);
  const data = selected(plan, 'data.internal-suite') ? runDataSuite({ root, files: dataFiles }) : null;
  const infrastructure = selected(plan, 'infrastructure.internal-suite') ? runInfrastructureSuite({ root, files: infrastructureFiles }) : null;
  const securityReports = securityProviderPlans(plan).map((provider) => generateSecurityCandidates({ root, files: provider.denominator?.paths ?? files, pack: provider.runner.pack, provider: provider.id }));
  const securityResult = mergeSecurityCandidateReports(securityReports);

  writeJson(join(outDir, 'native-results.json'), { schemaVersion: 1, kind: 'audit-native-family-results', results: nativeResults });
  writeJson(join(outDir, 'framework-results.json'), { schemaVersion: 1, kind: 'audit-framework-results', results: frameworkResults });
  if (data) writeJson(join(outDir, 'data-results.json'), data);
  if (infrastructure) writeJson(join(outDir, 'infrastructure-results.json'), infrastructure);
  writeJson(join(outDir, 'security-provider-results.json'), { schemaVersion: 1, kind: 'audit-security-provider-results', results: securityReports });
  writeJson(join(outDir, 'security-candidates.json'), securityResult);

  const runtime = runtimeEvidence({ root, outDir, plan, options });
  const visual = visualEvidence({ root, plan, runtime, options });
  if (visual) writeJson(join(outDir, 'visual.json'), visual);
  const providerResults = [
    ...nativeResults,
    ...frameworkResults,
    ...(nativeSummary ? [nativeSummary] : []),
    ...(selected(plan, 'framework.major-suite') ? [{ provider: 'framework.major-suite', phase: 'runtime', status: frameworkResults.some((result) => ['fail', 'error'].includes(result.status)) ? 'fail' : frameworkResults.length ? 'pass' : 'unproven', complete: frameworkResults.length > 0 && frameworkResults.every((result) => result.complete !== false), coverage: providerPlan(plan, 'framework.major-suite')?.denominator ?? null, coverageGaps: frameworkResults.length ? [] : [{ kind: 'framework-suite-empty' }] }] : []),
    ...(data ? [data] : []),
    ...(infrastructure ? [infrastructure] : []),
    ...securityReports.map((report) => ({ provider: report.provider, phase: 'runtime', status: report.candidates.length ? 'candidates' : report.complete ? 'pass' : 'unproven', complete: report.complete, candidatesCount: report.candidates.length, coverage: report.coverage, coverageGaps: report.coverageGaps })),
    ...(runtime ? [runtime] : []),
    ...(visual ? [visual] : []),
  ];
  const planById = new Map(plan.providers.map((p) => [p.id, p]));
  const normalizedResults = providerResults.map((result) => {
    const contract = planById.get(result.provider);
    try {
      return normalizeProviderResult(contract, result);
    } catch (error) {
      return { ...result, status: 'error', complete: false, coverageGaps: [{ kind: 'provider-validation', provider: result.provider, error: error.message }] };
    }
  });
  const bindingVerification = verifyPlanBinding(plan, collectRepositoryBinding(root), readCortexManifestBinding(root, { outDir: cortexOut }));
  const facts = reconcileCompleteRun({ plan, facts: rawFacts, providerResults: normalizedResults, securityResult, projection, bindingVerification });
  facts.plan.path = planPath;
  facts.network_policy = {
    mode: 'deny',
    sandboxActive: options.networkSandboxActive,
    requiredGuard: 'AUDIT_NETWORK_GUARD=active',
    skippedChecks: [...new Set([...NETWORK_DEPENDENT_CHECKS, ...(!options.networkSandboxActive ? PROJECT_EXECUTION_CHECKS : [])])].sort(),
  };
  writeJson(factsPath, facts);
  return { plan, planPath, projection, outDir, facts, providerResults: normalizedResults, securityResult, securityReports };
}

function arg(args, name) { const index = args.indexOf(name); return index >= 0 ? args[index + 1] : null; }
function values(args, name) { const raw = arg(args, name); return raw ? raw.split(',').map((value) => value.trim()).filter(Boolean) : []; }
function first(args) {
  const valued = new Set(['--out', '--only', '--skip', '--type', '--base', '--base-commit', '--dir', '--cortex-out', '--url', '--surfaces', '--visual-spec', '--visual-baselines', '--width', '--height']);
  for (let index = 0; index < args.length; index += 1) {
    if (args[index].startsWith('--')) { if (valued.has(args[index])) index += 1; continue; }
    return args[index];
  }
  return process.cwd();
}
async function main() {
  const args = process.argv.slice(2);
  const result = await runCompleteAudit({
    root: first(args), outDir: arg(args, '--out'), cortexOut: arg(args, '--cortex-out') ?? '.agent',
    only: values(args, '--only'), skip: values(args, '--skip'),
    scope: { mode: ['--type', '--base', '--base-commit', '--dir'].some((name) => args.includes(name)) ? 'diff' : 'whole-repo', type: arg(args, '--type') ?? 'all', base: arg(args, '--base'), baseCommit: arg(args, '--base-commit'), dir: arg(args, '--dir') },
    planOnly: args.includes('--plan-only'), quiet: args.includes('--quiet'), url: arg(args, '--url'),
    surfaces: arg(args, '--surfaces'), visualSpec: arg(args, '--visual-spec'), visualBaselines: arg(args, '--visual-baselines'),
    width: Number(arg(args, '--width') ?? 1280), height: Number(arg(args, '--height') ?? 800),
  });
  console.log(JSON.stringify({ kind: 'audit-complete-run', outDir: result.outDir, plan: result.planPath, facts: result.facts ? join(result.outDir, 'facts.json') : null, incomplete: result.facts?.incomplete ?? true, securityCandidates: result.securityResult?.candidates?.length ?? 0 }, null, 2));
  if (result.facts?.incomplete) process.exitCode = 2;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main().catch((error) => { console.error(error.stack ?? error.message); process.exit(1); });
