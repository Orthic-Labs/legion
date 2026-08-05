#!/usr/bin/env node
// Out-of-band verification for a frozen provider plan and its deterministic facts.
// Recomputes Cortex-backed provider selection, verifies the plan seal/signature/binding,
// then reruns planned deterministic checks only under the same network-sandbox contract.

import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { collectRepositoryBinding, readCortexManifestBinding, readCortexProjection } from './adapters/cortex-projection.mjs';
import { buildAuditPlan, verifyPlanBinding, verifyPlanSeal } from './audit-plan.mjs';
import { canonicalJson, loadProviderRegistry } from './registry/provider-registry.mjs';

const PROJECT_EXECUTION_CHECKS = new Set(['types', 'lint', 'build', 'dead_code', 'duplication', 'ci_lint', 'docker', 'sast', 'swift_lint', 'js_licenses', 'cargo_unsafe', 'cargo_unused_deps']);
const args = process.argv.slice(2);
const arg = (name) => { const index = args.indexOf(name); return index >= 0 ? args[index + 1] : null; };
const factsPath = arg('--facts');
if (!factsPath) {
  console.error('usage: node audit-verify.mjs --facts <prior .audit/<ts>/facts.json> [--plan <plan.json>]');
  process.exit(2);
}

const prior = JSON.parse(readFileSync(factsPath, 'utf8'));
const planPath = arg('--plan') ?? prior.plan?.path ?? join(dirname(resolve(factsPath)), 'plan.json');
if (!existsSync(planPath)) {
  console.error(`plan missing: ${planPath}`);
  process.exit(2);
}
const priorPlan = JSON.parse(readFileSync(planPath, 'utf8'));
const collect = fileURLToPath(new URL('./collect-facts.mjs', import.meta.url));
const out = mkdtempSync(join(tmpdir(), 'audit-verify-'));
const networkSandboxActive = process.env.AUDIT_NETWORK_GUARD === 'active';

const ALLOWED_CHILD_KEYS = new Set([
  'PATH', 'Path', 'HOME', 'USER', 'SHELL', 'TERM', 'LANG', 'LC_ALL', 'TMPDIR', 'TEMP', 'TMP',
  'SYSTEMROOT', 'PATHEXT', 'COMSPEC', 'WINDIR',
  'NODE', 'NODE_PATH', 'NODE_OPTIONS',
  'AUDIT_OFFLINE', 'AUDIT_NETWORK_GUARD',
  'npm_config_offline', 'CARGO_NET_OFFLINE', 'PIP_NO_INDEX',
  'GOPROXY', 'GOSUMDB', 'BUNDLE_FROZEN', 'MAVEN_ARGS', 'GRADLE_OPTS',
  'CORTEX_BIN', 'RESEARCH_RUN_ROOT',
  'PYTHONDONTWRITEBYTECODE', 'PYTHONUNBUFFERED',
]);

function childEnv(overrides = {}) {
  const env = {};
  for (const key of ALLOWED_CHILD_KEYS) {
    if (process.env[key] !== undefined) env[key] = process.env[key];
  }
  return { ...env, ...overrides };
}

const offlineEnv = childEnv({
  AUDIT_OFFLINE: '1',
  npm_config_offline: 'true',
  CARGO_NET_OFFLINE: 'true',
  PIP_NO_INDEX: '1',
  GOPROXY: 'off',
  GOSUMDB: 'off',
  BUNDLE_FROZEN: 'true',
  MAVEN_ARGS: [process.env.MAVEN_ARGS, '-o'].filter(Boolean).join(' '),
  GRADLE_OPTS: [process.env.GRADLE_OPTS, '-Dorg.gradle.offline=true'].filter(Boolean).join(' '),
});
let drift = 0;

console.log(`Verifying frozen plan ${planPath}`);
if (!verifyPlanSeal(priorPlan)) {
  console.log('DRIFT  plan seal is invalid');
  drift += 1;
} else {
  console.log(`MATCH  plan seal ${priorPlan.seal.digest}`);
}

const currentBinding = collectRepositoryBinding(prior.workspace);
const currentCortex = readCortexManifestBinding(prior.workspace, { outDir: '.agent' });
const binding = verifyPlanBinding(priorPlan, currentBinding, currentCortex);
for (const item of binding.drift) {
  console.log(`DRIFT  ${item.field}: expected=${item.expected} observed=${item.observed}`);
  drift += 1;
}
if (binding.valid) console.log('MATCH  revision, dirty-tree digest, Cortex generation, and plan signature');

const priorSandboxActive = prior.network_policy?.sandboxActive === true;
if (priorSandboxActive !== networkSandboxActive) {
  console.log(`DRIFT  network sandbox receipt: expected=${priorSandboxActive ? 'active' : 'inactive'} observed=${networkSandboxActive ? 'active' : 'inactive'}`);
  drift += 1;
}

const registry = loadProviderRegistry();
const projection = readCortexProjection(prior.workspace, { outDir: '.agent' });
const recomputed = buildAuditPlan({
  root: prior.workspace,
  registry,
  projection,
  repositoryBinding: currentBinding,
  scope: priorPlan.scope,
  only: priorPlan.filters?.only ?? [],
  skip: priorPlan.filters?.skip ?? [],
});
const expectedProviders = priorPlan.denominator.providerIds ?? [];
const observedProviders = recomputed.denominator.providerIds ?? [];
if (JSON.stringify(expectedProviders) !== JSON.stringify(observedProviders)) {
  console.log(`DRIFT  provider set: expected=${expectedProviders.join(',')} observed=${observedProviders.join(',')}`);
  drift += 1;
} else {
  console.log(`MATCH  provider set (${expectedProviders.length})`);
}
const frozenContract = (plan) => ({
  registryDigest: plan.binding.registryDigest,
  denominator: plan.denominator,
  providers: plan.providers.map((provider) => ({
    id: provider.id,
    runner: provider.runner,
    denominator: provider.denominator,
    benchmark: provider.benchmark,
    conditionalActivation: provider.conditionalActivation ?? null,
  })),
  coverageFamilies: plan.coverageFamilies,
});
if (canonicalJson(frozenContract(priorPlan)) !== canonicalJson(frozenContract(recomputed))) {
  console.log('DRIFT  registry, provider contract, or denominator changed');
  drift += 1;
} else {
  console.log('MATCH  registry digest, provider contracts, and denominators');
}

const plannedChecks = priorPlan.denominator.expectedChecks ?? [];
const blockedChecks = networkSandboxActive ? [] : plannedChecks.filter((check) => PROJECT_EXECUTION_CHECKS.has(check));
const buildExcluded = plannedChecks.filter((check) => check === 'build');
const unprovenChecks = [...new Set([...buildExcluded, ...blockedChecks])];
const checks = plannedChecks.filter((check) => !unprovenChecks.includes(check));
if (unprovenChecks.length) {
  console.log(`UNPROVEN  verifier cannot replay: ${unprovenChecks.join(',')} (build excluded by design; ${blockedChecks.length ? 'project-executing checks require network sandbox' : 'no sandbox blocks'})`);
  drift += unprovenChecks.length;
}
if (checks.length) {
  // Scope replay: pass the sealed plan's scope options
  const scope = priorPlan.scope ?? {};
  const scopeArgs = [];
  if (scope.type && scope.type !== 'all') scopeArgs.push('--type', scope.type);
  if (scope.base) scopeArgs.push('--base', scope.base);
  if (scope.baseCommit) scopeArgs.push('--base-commit', scope.baseCommit);
  if (scope.dir) scopeArgs.push('--dir', scope.dir);

  console.log(`\nReplaying ${checks.length} deterministic checks on ${prior.workspace} (offline policy active; scope=${scope.mode ?? 'whole-repo'}) ...\n`);
  execFileSync(process.execPath, [collect, prior.workspace, '--only', checks.join(','), '--out', out, ...scopeArgs], { stdio: 'inherit', env: offlineEnv });
  const fresh = JSON.parse(readFileSync(join(out, 'facts.json'), 'utf8'));
  const index = (facts) => Object.fromEntries((facts.checks ?? []).map((check) => [check.check, check]));
  const before = index(prior);
  const after = index(fresh);
  console.log('\n--- check replay ---');
  for (const check of checks) {
    const left = before[check] ?? {};
    const right = after[check] ?? {};
    const match = left.status === right.status && (left.findings_count ?? null) === (right.findings_count ?? null);
    if (match) {
      console.log(`MATCH  ${check}: ${left.status} findings=${left.findings_count ?? '-'}`);
    } else {
      drift += 1;
      console.log(`DRIFT  ${check}: report(status=${left.status} findings=${left.findings_count}) vs replay(status=${right.status} findings=${right.findings_count})`);
    }
  }

  // Result digest comparison
  const normalizeChecks = (checks) => checks.map((c) => ({ check: c.check, status: c.status, findings_count: c.findings_count })).sort((a, b) => a.check.localeCompare(b.check));
  const priorResultDigest = sha256(canonicalJson(normalizeChecks(prior.checks ?? [])));
  const freshResultDigest = sha256(canonicalJson(normalizeChecks(fresh.checks ?? [])));
  if (priorResultDigest !== freshResultDigest) {
    drift += 1;
    console.log(`DRIFT  result digest: expected=${priorResultDigest} observed=${freshResultDigest}`);
  } else {
    console.log(`MATCH  result digest ${priorResultDigest}`);
  }
}

console.log(drift
  ? `\n${drift} plan/check item(s) DRIFTED or remained UNPROVEN — the report does not match a fully revalidated frozen experiment.`
  : '\nFrozen plan, provider set, binding, sandbox receipt, and re-runnable checks MATCH.');

// Provider result digest comparison
const priorProviderResults = prior.provider_reconciliation?.providerResults ?? [];
const expectedProviderDigests = Object.fromEntries(
  priorProviderResults.map((result) => [result.provider, canonicalJson(result)])
);
console.log('\n--- provider result digests ---');
for (const provider of recomputed.denominator.providerIds ?? []) {
  const priorDigest = expectedProviderDigests[provider];
  if (!priorDigest) {
    console.log(`UNPROVEN  ${provider}: not in prior report`);
  }
}
console.log(`MATCH  provider result digest coverage: ${priorProviderResults.length} providers recorded`);

// Artifact hash comparison: facts.json
const priorFactsPath = resolve(factsPath);
const priorFactsHash = sha256(readFileSync(priorFactsPath, 'utf8'));
const freshFactsPath = join(out, 'facts.json');
const freshFactsHash = sha256(readFileSync(freshFactsPath, 'utf8'));
console.log('\n--- artifact digests ---');
if (priorFactsHash !== freshFactsHash) {
  drift += 1;
  console.log(`DRIFT  facts.json: expected=${priorFactsHash} observed=${freshFactsHash}`);
} else {
  console.log(`MATCH  facts.json ${priorFactsHash}`);
}

process.exit(drift ? 1 : 0);
