// The Cortex projection tests were dropped with the adapter they exercised:
// discovery ownership moved cortex -> blueprint between manifest v2 and v3, so
// they asserted retired architecture. The rest tests live code, with the paths
// the extraction moved.
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import test from 'node:test';
import { buildAuditPlan, reconcilePlanWithFacts, verifyPlanBinding, verifyPlanSeal } from '../tools/audit/audit-plan.mjs';
import { createAdjudicationPacket, createSecurityCandidate, finalizeSecurityVerdict } from '../src/adapters/security-adjudication.mjs';
import { calculatePrecisionRecall } from '../bench/precision-recall.mjs';
import { runProviderSelectionBenchmark } from '../bench/run-provider-selection-benchmark.mjs';
import { generatedManifestText } from '../scripts/generate-manifest.mjs';
import { reportToSarif } from '../scripts/report-to-sarif.mjs';
import { loadProviderRegistry, renderManifest, validateProviderRegistry } from '../src/registry/provider-registry.mjs';
import { enrichFactsWithPlan } from '../tools/audit/audit-run.mjs';

function fixtureRepo(files) {
  const root = mkdtempSync(join(tmpdir(), 'audit-provider-'));
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(join(root, path, '..'), { recursive: true });
    writeFileSync(join(root, path), content, 'utf8');
  }
  return root;
}


test('registry is executable and generated manifest is derived from it', () => {
  const registry = loadProviderRegistry();
  assert.equal(validateProviderRegistry(registry), registry);
  const manifest = renderManifest(registry);
  // The registry moved under src/ when the skill became a product.
  assert.equal(manifest.generated_from, 'src/registry/providers.json');
  assert.ok(manifest.checks.some((check) => check.provider === 'core.repo' && check.check === 'repo'));
  assert.equal(generatedManifestText(), `${JSON.stringify(manifest, null, 2)}\n`);
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
  const corpus = JSON.parse(readFileSync(new URL('../src/evals/ground_truth/labeled_samples.json', import.meta.url), 'utf8'));
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

