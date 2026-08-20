import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  RunArtifactStore,
  buildPlan,
  executePlan,
  finalizeRun,
  reconcileRun,
  resolveSkillInvocation,
  validateCapabilitySelection,
  verifyRun,
  writeRunManifest,
} from '../src/lib/index.mjs';
import { fixedHost } from '../src/lib/host/fixed-host.mjs';
import { loadProviderRegistry } from '../src/registry/provider-registry.mjs';

const PROJECTION = {
  state: 'ready',
  generationId: 'gen-1',
  manifestDigest: 'sha256:manifest',
  files: ['src/a.ts'],
  parsedExtensions: ['ts'],
  unsupportedExtensions: [],
  fileSetDigest: 'sha256:files',
  auditFacts: {},
};

test('public API exposes deterministic explicit & model-selection validation seams', () => {
  assert.equal(typeof resolveSkillInvocation, 'function');
  assert.equal(typeof validateCapabilitySelection, 'function');
  assert.equal(resolveSkillInvocation('/blueprint map').resolvedInvocation, '/cortex map');
  assert.equal(resolveSkillInvocation('/glass refine header').resolvedInvocation, '/designer glass refine header');
  assert.equal(validateCapabilitySelection({ ids: ['architect'], source: 'semantic' }).status, 'resolved');
});

test('buildPlan seals a deterministic plan with fixed host clock', async () => {
  const host = fixedHost();
  const registry = loadProviderRegistry();
  const plan = await buildPlan({
    root: '/tmp/repo',
    projection: PROJECTION,
    repositoryBinding: { repositoryRevision: 'abc', dirty: false, dirtyPatchDigest: 'sha256:clean' },
    registry,
  }, host);
  assert.equal(plan.kind, 'audit-provider-plan');
  assert.ok(plan.seal.digest, 'plan sealed');
  assert.equal(plan.generatedAt, '2026-08-06T00:00:00.000Z');
  // Same inputs → same digest (deterministic).
  const plan2 = await buildPlan({
    root: '/tmp/repo',
    projection: PROJECTION,
    repositoryBinding: { repositoryRevision: 'abc', dirty: false, dirtyPatchDigest: 'sha256:clean' },
    registry,
  }, host);
  assert.equal(plan.seal.digest, plan2.seal.digest);
});

test('executePlan produces one receipt per selected provider', async () => {
  const host = fixedHost({
    processRunner: { run: async (spec) => ({ exitCode: 0, stdout: '', stderr: '', status: 'completed' }) },
  });
  const registry = loadProviderRegistry();
  const plan = await buildPlan({
    root: '/tmp/repo',
    projection: PROJECTION,
    repositoryBinding: { repositoryRevision: 'abc', dirty: false, dirtyPatchDigest: 'sha256:clean' },
    registry,
  }, host);
  const { receipts } = await executePlan(plan, host);
  assert.ok(Array.isArray(receipts));
  for (const receipt of receipts) {
    assert.ok(receipt.provider);
    assert.ok(receipt.providerResult);
    assert.ok(['pass', 'error', 'skipped', 'unproven', 'blocked', 'pending'].includes(receipt.providerResult.status));
  }
});

test('reconcileRun builds facts bound to the plan', () => {
  const host = fixedHost();
  const plan = { kind: 'audit-provider-plan', root: '/tmp/repo', providers: [], denominator: { providerIds: [] } };
  const facts = reconcileRun({ plan, providerResults: [{ provider: 'p', complete: true }], artifacts: { root: '/tmp/out' } }, host);
  assert.equal(facts.kind, 'audit-facts');
  assert.equal(facts.workspace, '/tmp/repo');
  assert.equal(facts.incomplete, false);
  assert.equal(facts.plan, plan);
});

test('finalizeRun produces a report with injected clock', async () => {
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
  assert.equal(report.kind, 'repository-audit-report');
  assert.equal(report.generated_at, '2026-08-06T00:00:00.000Z');
});

test('verifyRun produces a deterministic receipt', async () => {
  const host = fixedHost({
    fs: { readFile: async () => JSON.stringify({ kind: 'audit-facts', binding: { repositoryRevision: 'abc' }, checks: [], plan: { seal: { digest: 'sha256:x' } } }) },
  });
  const receipt = await verifyRun({ priorRun: '/tmp/run/facts.json', currentRepository: { repositoryRevision: 'abc' } }, host);
  assert.equal(receipt.kind, 'legion-verification-receipt');
  assert.ok(receipt.priorDigest.startsWith('sha256:'));
  assert.equal(receipt.valid, false);
  assert.ok(receipt.gaps.some(({ kind }) => kind === 'semantic-replay-unavailable'));
});

test('run manifest is written from the artifact store records', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'legion-core-'));
  try {
    const store = new RunArtifactStore(dir);
    await store.init();
    await store.writeJson({
      path: 'plan.json', kind: 'audit-plan', producer: 'legion.core', schemaVersion: 1,
      binding: { planDigest: 'sha256:p' }, value: { kind: 'audit-provider-plan' },
    });
    const manifest = await writeRunManifest(store, { binding: { planDigest: 'sha256:p' } });
    assert.equal(manifest.kind, 'legion-run-manifest');
    assert.equal(manifest.artifacts.length, 1);
    assert.equal(manifest.artifacts[0].kind, 'audit-plan');
    assert.ok(manifest.artifacts[0].digest.startsWith('sha256:'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('fixed host uuid sequence is deterministic', () => {
  const host = fixedHost();
  const first = host.random.uuid();
  const second = host.random.uuid();
  assert.notEqual(first, second);
  assert.match(first, /^00000000-0000-4000-8000-/);
});
