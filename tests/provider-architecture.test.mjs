import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import test from 'node:test';
import { collectRepositoryBinding, projectCortexPayloads } from '../adapters/cortex-projection.mjs';
import { buildAuditPlan, reconcilePlanWithFacts, verifyPlanBinding, verifyPlanSeal } from '../audit-plan.mjs';
import { createAdjudicationPacket, createSecurityCandidate, finalizeSecurityVerdict } from '../adapters/security-adjudication.mjs';
import { calculatePrecisionRecall } from '../bench/precision-recall.mjs';
import { runProviderSelectionBenchmark } from '../bench/run-provider-selection-benchmark.mjs';
import { generatedManifestText } from '../scripts/generate-manifest.mjs';
import { reportToSarif } from '../scripts/report-to-sarif.mjs';
import { loadProviderRegistry, renderManifest, validateProviderRegistry } from '../registry/provider-registry.mjs';
import { enrichFactsWithPlan } from '../audit-run.mjs';

function fixtureRepo(files) {
  const root = mkdtempSync(join(tmpdir(), 'audit-provider-'));
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(join(root, path, '..'), { recursive: true });
    writeFileSync(join(root, path), content, 'utf8');
  }
  return root;
}

function projection(root, generation = 'gen-1') {
  return projectCortexPayloads({
    root,
    status: {
      state: 'fresh',
      capabilities: {
        parsedExtensions: ['js', 'jsx', 'ts', 'tsx', 'rs', 'sh'],
        unsupportedExtensions: [],
      },
    },
    manifestBefore: {
      generationId: generation,
      manifestDigest: 'sha256:manifest',
      complete: true,
      sourceObservation: { head: 'abc', dirty: false, statusDigest: 'status-1' },
    },
    generation: {
      manifest: { generationId: generation, manifestDigest: 'sha256:manifest', complete: true },
      nodes: [
        { kind: 'file', path: 'package.json' },
        { kind: 'file', path: 'src/App.tsx' },
        { kind: 'file', path: 'src-tauri/Cargo.toml' },
        { kind: 'file', path: 'src-tauri/Cargo.lock' },
        { kind: 'file', path: 'src-tauri/src/lib.rs' },
        { kind: 'file', path: 'src-tauri/tauri.conf.json' },
        { kind: 'file', path: 'scripts/release.sh' },
      ],
    },
    manifestAfter: {
      generationId: generation,
      manifestDigest: 'sha256:manifest',
      complete: true,
      sourceObservation: { head: 'abc', dirty: false, statusDigest: 'status-1' },
    },
  });
}

test('registry is executable and generated manifest is derived from it', () => {
  const registry = loadProviderRegistry();
  assert.equal(validateProviderRegistry(registry), registry);
  const manifest = renderManifest(registry);
  assert.equal(manifest.generated_from, 'registry/providers.json');
  assert.ok(manifest.checks.some((check) => check.provider === 'core.repo' && check.check === 'repo'));
  assert.equal(generatedManifestText(), `${JSON.stringify(manifest, null, 2)}\n`);
});

test('Cortex projection pins one generation and extracts the file denominator', () => {
  const root = fixtureRepo({
    'package.json': JSON.stringify({ dependencies: { react: '^19.0.0' }, scripts: { dev: 'vite' } }),
    'src/App.tsx': 'export function App() { return null; }',
    'src-tauri/Cargo.toml': '[package]\nname="app"\n',
    'src-tauri/Cargo.lock': '',
    'src-tauri/src/lib.rs': 'pub fn run() {}',
    'src-tauri/tauri.conf.json': '{}',
    'scripts/release.sh': 'echo release',
  });
  try {
    const result = projection(root);
    assert.equal(result.state, 'ready');
    assert.equal(result.generationId, 'gen-1');
    assert.equal(result.fileCount, 7);
    assert.equal(result.sourceFileCount, 3);
    assert.ok(result.auditFacts.packageManifests[0].dependencies.includes('react'));
    assert.ok(result.auditFacts.projectRoots.includes('.'));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('Cortex generation movement fails closed instead of narrowing discovery', () => {
  const root = fixtureRepo({ 'src/a.ts': 'export const a = 1;' });
  try {
    const result = projectCortexPayloads({
      root,
      status: { state: 'fresh', capabilities: { parsedExtensions: ['ts'] } },
      manifestBefore: { generationId: 'gen-a', complete: true },
      generation: { manifest: { generationId: 'gen-a', complete: true }, nodes: [{ kind: 'file', path: 'src/a.ts' }] },
      manifestAfter: { generationId: 'gen-b', complete: true },
    });
    assert.equal(result.state, 'unproven');
    assert.equal(result.reason, 'cortex-generation-changed');
    assert.deepEqual(result.files, []);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('mixed React, Rust, Tauri plan is additive, denominator-bound, and tamper-evident', () => {
  const root = fixtureRepo({
    'package.json': JSON.stringify({ dependencies: { react: '^19.0.0' }, scripts: { dev: 'vite' } }),
    'src/App.tsx': 'export function App() { return null; }',
    'src-tauri/Cargo.toml': '[package]\nname="app"\n',
    'src-tauri/Cargo.lock': '',
    'src-tauri/src/lib.rs': 'pub fn run() {}',
    'src-tauri/tauri.conf.json': '{}',
    'scripts/release.sh': 'echo release',
  });
  try {
    const registry = loadProviderRegistry();
    const plan = buildAuditPlan({
      root,
      registry,
      projection: projection(root),
      repositoryBinding: { repositoryRevision: 'abc', dirty: false, dirtyPatchDigest: 'sha256:clean' },
    });
    assert.equal(verifyPlanSeal(plan), true);
    for (const id of ['quality.types', 'security.rust-advisories', 'tauri.contract-mirror', 'react.hooks-config', 'runtime.app', 'security.adjudication', 'security.variant-analysis']) {
      assert.ok(plan.denominator.providerIds.includes(id), id);
    }
    assert.equal(
      plan.providers.find((provider) => provider.id === 'security.variant-analysis').conditionalActivation,
      'confirmed-security-finding',
    );
    assert.ok(plan.denominator.expectedChecks.includes('cargo_audit'));
    assert.ok(plan.coverageFamilies.some((family) => family.id === 'framework.react'));
    assert.ok(plan.coverageFamilies.some((family) => family.id === 'framework.tauri'));
    assert.equal(plan.qualification.state, 'unproven');
    const tampered = structuredClone(plan);
    tampered.providers.pop();
    assert.equal(verifyPlanSeal(tampered), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('missing Cortex selects only explicitly safe universal providers and stays UNPROVEN', () => {
  const registry = loadProviderRegistry();
  const plan = buildAuditPlan({
    root: '/tmp/repo',
    registry,
    projection: { state: 'unproven', reason: 'cortex-missing', files: [], parsedExtensions: [], fileSetDigest: 'sha256:none' },
    repositoryBinding: { repositoryRevision: 'abc', dirty: false, dirtyPatchDigest: 'sha256:clean' },
  });
  assert.equal(plan.qualification.discovery, 'unproven');
  assert.ok(plan.denominator.providerIds.includes('core.repo'));
  assert.ok(!plan.denominator.providerIds.includes('quality.types'));
  assert.ok(plan.coverageGaps.some((gap) => gap.kind === 'cortex-discovery'));
});

test('dirty-tree binding changes when tracked or untracked content changes', () => {
  const root = fixtureRepo({ 'tracked.txt': 'one' });
  try {
    execFileSync('git', ['init'], { cwd: root });
    execFileSync('git', ['config', 'user.email', 'audit@example.invalid'], { cwd: root });
    execFileSync('git', ['config', 'user.name', 'Audit Test'], { cwd: root });
    execFileSync('git', ['add', 'tracked.txt'], { cwd: root });
    execFileSync('git', ['commit', '-m', 'fixture'], { cwd: root });
    const clean = collectRepositoryBinding(root);
    assert.equal(clean.dirty, false);

    writeFileSync(join(root, 'tracked.txt'), 'two', 'utf8');
    const trackedA = collectRepositoryBinding(root);
    writeFileSync(join(root, 'tracked.txt'), 'three', 'utf8');
    const trackedB = collectRepositoryBinding(root);
    assert.equal(trackedA.dirty, true);
    assert.notEqual(trackedA.dirtyPatchDigest, trackedB.dirtyPatchDigest);

    writeFileSync(join(root, 'new.txt'), 'alpha', 'utf8');
    const untrackedA = collectRepositoryBinding(root);
    writeFileSync(join(root, 'new.txt'), 'beta', 'utf8');
    const untrackedB = collectRepositoryBinding(root);
    assert.notEqual(untrackedA.dirtyPatchDigest, untrackedB.dirtyPatchDigest);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('binding verification includes Cortex source observation', () => {
  const registry = loadProviderRegistry();
  const plan = buildAuditPlan({
    root: '/tmp/repo',
    registry,
    projection: {
      state: 'ready', generationId: 'gen-1', manifestDigest: 'sha256:manifest',
      sourceObservation: { head: 'abc', statusDigest: 'status-a' },
      files: [], parsedExtensions: [], unsupportedExtensions: [], fileSetDigest: 'sha256:files', auditFacts: {},
    },
    repositoryBinding: { repositoryRevision: 'abc', dirty: false, dirtyPatchDigest: 'sha256:clean' },
    signingKey: 'test-signing-key',
  });
  const good = verifyPlanBinding(
    plan,
    { repositoryRevision: 'abc', dirty: false, dirtyPatchDigest: 'sha256:clean' },
    { state: 'ready', generationId: 'gen-1', manifestDigest: 'sha256:manifest', sourceObservation: { head: 'abc', statusDigest: 'status-a' } },
    'test-signing-key',
  );
  assert.equal(good.valid, true);
  const stale = verifyPlanBinding(
    plan,
    { repositoryRevision: 'abc', dirty: false, dirtyPatchDigest: 'sha256:clean' },
    { state: 'ready', generationId: 'gen-1', manifestDigest: 'sha256:manifest', sourceObservation: { head: 'abc', statusDigest: 'status-b' } },
    'test-signing-key',
  );
  assert.equal(stale.valid, false);
  assert.ok(stale.drift.some((item) => item.field === 'cortex.sourceStatusDigest'));
});

test('candidate generator cannot adjudicate itself or reuse its context', () => {
  const candidate = createSecurityCandidate({
    id: 'sec-1',
    provider: 'security.sast',
    contextId: 'context-a',
    claim: 'attacker input reaches a shell sink',
    evidence: ['src/run.ts:42'],
  });
  assert.throws(() => createAdjudicationPacket(candidate, { provider: 'security.sast', contextId: 'context-b' }), /may not adjudicate/);
  assert.throws(() => createAdjudicationPacket(candidate, { provider: 'security.adjudication', contextId: 'context-a' }), /fresh context/);
  const packet = createAdjudicationPacket(candidate, { provider: 'security.adjudication', contextId: 'context-b' });
  const verdict = finalizeSecurityVerdict(packet, {
    verdict: 'TRUE_POSITIVE',
    severity: 'high',
    evidenceStrength: 'verified',
    threatModel: 'remote unauthenticated',
    attackerControl: 'proven',
    reachability: 'proven',
    impact: 'arbitrary command execution',
    proof: { kind: 'repro', artifact: 'tests/security/repro.test.ts' },
    devilsAdvocate: 'false positive excluded: attacker controls the input and the sink is reachable without authentication',
  });
  assert.equal(verdict.variantAnalysisRequired, true);
  assert.ok(verdict.verdictDigest.startsWith('sha256:'));
});

test('precision/recall is reproducible over labeled positives and negatives', () => {
  const result = calculatePrecisionRecall(
    { samples: [
      { id: 'positive-hit', expected: true },
      { id: 'positive-miss', expected: true },
      { id: 'negative-hit', expected: false },
      { id: 'negative-clean', expected: false },
    ] },
    { detections: [
      { id: 'positive-hit', detected: true },
      { id: 'positive-miss', detected: false },
      { id: 'negative-hit', detected: true },
      { id: 'negative-clean', detected: false },
    ] },
  );
  assert.deepEqual(result.counts, {
    samples: 4, positive: 2, negative: 2,
    truePositive: 1, falsePositive: 1, trueNegative: 1, falseNegative: 1,
  });
  assert.equal(result.metrics.precision, 0.5);
  assert.equal(result.metrics.recall, 0.5);
  assert.equal(result.metrics.f1, 0.5);
});

test('provider-selection corpus is labeled, reproducible, and includes negatives', () => {
  const corpus = JSON.parse(readFileSync(new URL('../evals/ground_truth/labeled_samples.json', import.meta.url), 'utf8'));
  const result = runProviderSelectionBenchmark(corpus);
  assert.equal(result.counts.positive, 3);
  assert.equal(result.counts.negative, 3);
  assert.equal(result.counts.falsePositive, 0);
  assert.equal(result.counts.falseNegative, 0);
  assert.equal(result.metrics.precision, 1);
  assert.equal(result.metrics.recall, 1);
});

test('report conversion emits dependency-free SARIF 2.1.0', () => {
  const sarif = reportToSarif({
    commit: 'abc',
    findings: [{
      id: 'ra-1', category: 'security', severity: 'high',
      file: 'src/app.ts', line: 12, title: 'Unsafe shell input', detail: 'Input reaches exec',
      evidence_strength: 'verified', status: 'open', tier: 'GUIDED',
    }],
  });
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0].results[0].ruleId, 'security');
  assert.equal(sarif.runs[0].results[0].level, 'error');
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine, 12);
});

test('selected facts provider that skips remains incomplete', () => {
  const root = fixtureRepo({
    'package.json': JSON.stringify({ dependencies: { react: '^19.0.0' } }),
    'src/App.tsx': 'export function App() { return null; }',
  });
  try {
    const plan = buildAuditPlan({
      root,
      registry: loadProviderRegistry(),
      projection: projection(root),
      repositoryBinding: { repositoryRevision: 'abc', dirty: false, dirtyPatchDigest: 'sha256:clean' },
    });
    plan.qualification = { ...plan.qualification, state: 'ready' };
    const checks = plan.denominator.expectedChecks.map((check) => ({ check, status: 'ran', findings_count: 0 }));
    checks[0].status = 'skipped';
    const facts = enrichFactsWithPlan({
      facts: { checks, incomplete: false },
      plan,
      projection: projection(root),
      bindingVerification: { valid: true, drift: [] },
    });
    assert.equal(facts.incomplete, true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('final reconciliation rejects missing or extra scanner results', () => {
  const root = fixtureRepo({
    'package.json': JSON.stringify({ dependencies: { react: '^19.0.0' } }),
    'src/App.tsx': 'export function App() { return null; }',
    'src-tauri/Cargo.toml': '[package]\nname="app"\n',
    'src-tauri/Cargo.lock': '',
    'src-tauri/src/lib.rs': 'pub fn run() {}',
    'src-tauri/tauri.conf.json': '{}',
    'scripts/release.sh': 'echo release',
  });
  try {
    const plan = buildAuditPlan({
      root,
      registry: loadProviderRegistry(),
      projection: projection(root),
      repositoryBinding: { repositoryRevision: 'abc', dirty: false, dirtyPatchDigest: 'sha256:clean' },
    });
    const facts = { checks: plan.denominator.expectedChecks.slice(1).map((check) => ({ check, status: 'ran', findings_count: 0 })) };
    const result = reconcilePlanWithFacts(plan, facts);
    assert.equal(result.valid, false);
    assert.deepEqual(result.missingChecks, [plan.denominator.expectedChecks[0]]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
