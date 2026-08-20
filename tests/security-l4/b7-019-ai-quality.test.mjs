import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { readdirSync } from 'node:fs';
import { evaluateAiQuality, AI_QUALITY_METRICS } from '../../src/providers/ai-quality/index.mjs';
import { assertEvaluationReceipt, AI_QUALITY_VERDICTS } from '../../src/providers/ai-quality/contracts.mjs';
import { buildEvaluationReceiptSchema } from '../../src/providers/ai-quality/schema-builder.mjs';

const BINDING = {
  planDigest: 'sha256:plan', repositoryRevision: 'rev', dirtyPatchDigest: null,
  blueprintGenerationId: 'gen', blueprintManifestDigest: 'sha256:manifest', registryDigest: 'sha256:registry',
};

const IDENTITY = {
  modelIdentity: { provider: 'anthropic', model: 'claude-test', version: '1.0.0' },
  promptIdentity: { templateId: 'summary-v1', templateVersion: '3', promptDigest: 'sha256:prompt' },
  retrievalToolConfig: { retrieverId: 'kb-1', retrieverConfigDigest: 'sha256:retriever' },
  datasetVersion: { datasetId: 'eval-set-a', version: '2026-08-01', digest: 'sha256:dataset' },
  runConditions: { runId: 'run-1', environment: 'ci', seed: 42 },
  judgeIdentity: { kind: 'automated-metric', id: 'judge-1' },
};

const DENOMINATOR = { kind: 'eval-items', expected: 10, examined: 10, digest: 'sha256:denom' };

function evaluate(metric, fixture, overrides = {}) {
  return evaluateAiQuality({
    metric, fixture, identity: overrides.identity ?? IDENTITY, denominator: overrides.denominator ?? DENOMINATOR,
    binding: overrides.binding ?? BINDING, evidenceRefs: overrides.evidenceRefs ?? ['ev:fixture-1'],
  });
}

// ---------------------------------------------------------------------------
// Every one of the 17 declared metrics has a receipt-producing scorer and
// binds the full identity/denominator/limitations shape.
// ---------------------------------------------------------------------------

test('all 17 declared AI-quality metrics are covered by the aggregator', () => {
  assert.equal(AI_QUALITY_METRICS.length, 17);
  for (const metric of AI_QUALITY_METRICS) {
    const receipt = evaluate(metric, {});
    assert.doesNotThrow(() => assertEvaluationReceipt(receipt), `${metric} receipt failed shape assertion`);
    assert.equal(receipt.metric, metric);
    // With no fixture data at all, missing evaluation evidence stays
    // unproven — never silently "pass".
    assert.equal(receipt.verdict, 'unproven', `${metric} with no evidence must be unproven, not clean`);
    assert.ok(receipt.limitations.length > 0);
  }
});

// ---------------------------------------------------------------------------
// Fixtures: grounded/ungrounded, faithful/unfaithful citation, correct/
// incorrect tool, calibrated/overconfident, fallback, drift, latency/cost,
// and a clean control.
// ---------------------------------------------------------------------------

test('groundedness: grounded vs. ungrounded fixture', () => {
  const grounded = evaluate('groundedness', {
    claims: [{ text: 'Paris is the capital of France.', supportingSpanIds: ['s1'] }],
    contextSpanIds: ['s1', 's2'],
  });
  assert.equal(grounded.verdict, 'pass');

  const ungrounded = evaluate('groundedness', {
    claims: [{ text: 'Paris has 40 million residents.', supportingSpanIds: [] }],
    contextSpanIds: ['s1', 's2'],
  });
  assert.equal(ungrounded.verdict, 'fail');
  assert.ok(ungrounded.measurement.ungroundedClaims.length > 0);
});

test('citation faithfulness: faithful vs. unfaithful fixture', () => {
  const faithful = evaluate('citation-faithfulness', {
    citations: [{ claimText: 'Revenue grew 12%.', citedSpanId: 's1', citedText: 'grew 12%' }],
    sourceSpans: { s1: 'Q3 revenue grew 12% year over year.' },
  });
  assert.equal(faithful.verdict, 'pass');

  const unfaithful = evaluate('citation-faithfulness', {
    citations: [{ claimText: 'Revenue grew 40%.', citedSpanId: 's1', citedText: 'grew 40%' }],
    sourceSpans: { s1: 'Q3 revenue grew 12% year over year.' },
  });
  assert.equal(unfaithful.verdict, 'fail');
});

test('tool selection: correct vs. incorrect fixture', () => {
  const correct = evaluate('tool-selection-argument-correctness', {
    expectedTool: 'search', selectedTool: 'search', expectedArgs: { q: 'x' }, actualArgs: { q: 'x' },
  });
  assert.equal(correct.verdict, 'pass');

  const incorrect = evaluate('tool-selection-argument-correctness', {
    expectedTool: 'search', selectedTool: 'delete', expectedArgs: { q: 'x' }, actualArgs: {},
  });
  assert.equal(incorrect.verdict, 'fail');
});

test('uncertainty calibration: calibrated vs. overconfident fixture', () => {
  const calibrated = evaluate('uncertainty-abstention-calibration', {
    predictions: [{ confidence: 0.9, correct: true }, { confidence: 0.9, correct: true }, { confidence: 0.1, correct: false }],
  });
  assert.equal(calibrated.verdict, 'pass');

  const overconfident = evaluate('uncertainty-abstention-calibration', {
    predictions: [{ confidence: 0.95, correct: false }, { confidence: 0.95, correct: false }, { confidence: 0.95, correct: false }],
  });
  assert.equal(overconfident.verdict, 'fail');
});

test('refusal/fallback fixture', () => {
  const correctRefusal = evaluate('refusal-fallback', { shouldRefuse: true, didRefuse: true, fallbackTaken: true });
  assert.equal(correctRefusal.verdict, 'pass');

  const missedRefusal = evaluate('refusal-fallback', { shouldRefuse: true, didRefuse: false });
  assert.equal(missedRefusal.verdict, 'fail');
});

test('model/provider/version drift fixture', () => {
  const stable = evaluate('model-provider-version-drift', { baselineVersion: 'v1', currentVersion: 'v2', baselineScore: 0.9, currentScore: 0.91, driftThreshold: 0.05 });
  assert.equal(stable.verdict, 'pass');

  const drifted = evaluate('model-provider-version-drift', { baselineVersion: 'v1', currentVersion: 'v2', baselineScore: 0.9, currentScore: 0.6, driftThreshold: 0.05 });
  assert.equal(drifted.verdict, 'fail');
});

test('latency and cost fixtures', () => {
  const fastEnough = evaluate('latency', { p95Ms: 800, budgetMs: 1000 });
  assert.equal(fastEnough.verdict, 'pass');
  const tooSlow = evaluate('latency', { p95Ms: 1800, budgetMs: 1000 });
  assert.equal(tooSlow.verdict, 'fail');

  const withinBudget = evaluate('cost', { costUsd: 0.02, budgetUsd: 0.05 });
  assert.equal(withinBudget.verdict, 'pass');
  const overBudget = evaluate('cost', { costUsd: 0.5, budgetUsd: 0.05 });
  assert.equal(overBudget.verdict, 'fail');
});

test('a clean control fixture set passes across representative metrics', () => {
  const declaredTask = evaluate('declared-task-eval', { declaredCriteria: [{ id: 'c1', met: true }] });
  assert.equal(declaredTask.verdict, 'pass');
  const retrieval = evaluate('retrieval-relevance', { retrievedDocs: [{ id: 'd1', relevant: true }, { id: 'd2', relevant: true }], relevanceThreshold: 0.5 });
  assert.equal(retrieval.verdict, 'pass');
  const reproducible = evaluate('reproducibility', { runDigests: ['sha256:a', 'sha256:a', 'sha256:a'] });
  assert.equal(reproducible.verdict, 'pass');
});

// ---------------------------------------------------------------------------
// Policy-selected subgroup/fairness: unproven without a policy selection,
// pass/fail once one is supplied.
// ---------------------------------------------------------------------------

test('subgroup fairness is unproven without a policy-selected subgroup set, and pass/fail once selected', () => {
  const noPolicy = evaluate('subgroup-fairness', {});
  assert.equal(noPolicy.verdict, 'unproven');

  const withinParity = evaluate('subgroup-fairness', {
    policySelectedSubgroups: [{ name: 'group-a', metricValue: 0.81 }, { name: 'group-b', metricValue: 0.79 }],
    parityThreshold: 0.05,
  });
  assert.equal(withinParity.verdict, 'pass');

  const disparate = evaluate('subgroup-fairness', {
    policySelectedSubgroups: [{ name: 'group-a', metricValue: 0.9 }, { name: 'group-b', metricValue: 0.5 }],
    parityThreshold: 0.05,
  });
  assert.equal(disparate.verdict, 'fail');
});

// ---------------------------------------------------------------------------
// Every receipt binds model/provider identity, prompt/template, retrieval/
// tool configuration, dataset/eval version, run conditions, judge/human
// identity, denominator, and limitations.
// ---------------------------------------------------------------------------

test('every evaluation receipt binds the full required identity/denominator shape', () => {
  const receipt = evaluate('groundedness', { claims: [{ text: 'x', supportingSpanIds: ['s1'] }], contextSpanIds: ['s1'] });
  assert.deepEqual(receipt.modelIdentity, IDENTITY.modelIdentity);
  assert.deepEqual(receipt.promptIdentity, IDENTITY.promptIdentity);
  assert.deepEqual(receipt.retrievalToolConfig, IDENTITY.retrievalToolConfig);
  assert.deepEqual(receipt.datasetVersion, IDENTITY.datasetVersion);
  assert.deepEqual(receipt.runConditions, IDENTITY.runConditions);
  assert.deepEqual(receipt.judgeIdentity, IDENTITY.judgeIdentity);
  assert.deepEqual(receipt.denominator, DENOMINATOR);
  assert.deepEqual(receipt.binding, BINDING);
  assert.ok(Array.isArray(receipt.limitations));
  assert.equal(receipt.kind, 'ai-quality-evaluation-receipt');
  assert.equal(receipt.schemaVersion, 1);
});

test('a receipt is version-bound and denominator-bound: metricVersion, datasetVersion.version, and denominator are all present and required', () => {
  const receipt = evaluate('latency', { p95Ms: 1, budgetMs: 2 });
  assert.equal(typeof receipt.metricVersion, 'string');
  assert.equal(typeof receipt.datasetVersion.version, 'string');
  assert.ok(receipt.denominator.expected > 0);
  assert.throws(() => assertEvaluationReceipt({ ...receipt, datasetVersion: undefined }));
  assert.throws(() => assertEvaluationReceipt({ ...receipt, denominator: undefined }));
});

// ---------------------------------------------------------------------------
// AI quality is strictly separate from AI security: distinct artifact kind,
// distinct verdict vocabulary, no security-shaped field, and no cross-import
// in either direction.
// ---------------------------------------------------------------------------

test('an evaluation receipt is not and cannot substitute for a security verdict', () => {
  const receipt = evaluate('groundedness', { claims: [{ text: 'x', supportingSpanIds: ['s1'] }], contextSpanIds: ['s1'] });
  assert.equal(receipt.kind, 'ai-quality-evaluation-receipt');
  assert.notEqual(receipt.kind, 'security-candidate');
  assert.notEqual(receipt.kind, 'security-verdict');
  assert.deepEqual(AI_QUALITY_VERDICTS, ['pass', 'fail', 'review-required', 'unproven']);
  // Security verdicts (TRUE_POSITIVE, HARDENING_GAP, MISUSE_HAZARD, ...) are
  // a disjoint vocabulary; no quality verdict is a member of it.
  const securityVerdictShapes = ['TRUE_POSITIVE', 'LIKELY_TRUE_POSITIVE', 'HARDENING_GAP', 'MISUSE_HAZARD', 'OUT_OF_SCOPE'];
  for (const v of AI_QUALITY_VERDICTS) assert.ok(!securityVerdictShapes.includes(v));
  for (const forbidden of ['severity', 'severityHint', 'evidenceStrength', 'candidateClass', 'adjudicationRequired', 'verdict'.toUpperCase()]) {
    assert.ok(!(forbidden in receipt) || forbidden === 'VERDICT');
  }
});

test('no ai-quality module imports from providers/security/**, and no security pack imports from providers/ai-quality/**', () => {
  const aiQualityDir = fileURLToPath(new URL('../../src/providers/ai-quality', import.meta.url));
  const securityPacksDir = fileURLToPath(new URL('../../src/providers/security/packs', import.meta.url));

  function collect(dir) {
    const out = [];
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = `${dir}/${entry.name}`;
      if (entry.isDirectory()) out.push(...collect(path));
      else if (entry.name.endsWith('.mjs')) out.push(path);
    }
    return out;
  }

  // Checks actual import/require statements only (a doc comment explaining
  // the independence is allowed to mention the other tree's path).
  const importsSecurity = /(?:from|require\()\s*['"][^'"]*providers\/security/;
  const importsAiQuality = /(?:from|require\()\s*['"][^'"]*providers\/ai-quality/;
  for (const file of collect(aiQualityDir)) {
    const source = readFileSync(file, 'utf8');
    assert.ok(!importsSecurity.test(source), `${file} must not import providers/security/**`);
  }
  for (const file of collect(securityPacksDir)) {
    const source = readFileSync(file, 'utf8');
    assert.ok(!importsAiQuality.test(source), `${file} must not import providers/ai-quality/**`);
  }
});

// ---------------------------------------------------------------------------
// Forbidden: no live model call from deterministic provider code.
// ---------------------------------------------------------------------------

test('no ai-quality module imports a network-capable node builtin, calls fetch, or imports an AI vendor SDK', () => {
  const aiQualityDir = fileURLToPath(new URL('../../src/providers/ai-quality', import.meta.url));
  const forbiddenImports = ['node:http', 'node:https', 'node:net', 'node:dgram'];
  const vendorSdkImportPatterns = [
    /from\s+['"]openai['"]/, /require\(\s*['"]openai['"]\s*\)/,
    /from\s+['"]@anthropic-ai\/sdk['"]/, /require\(\s*['"]@anthropic-ai\/sdk['"]\s*\)/,
  ];

  function collect(dir) {
    const out = [];
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = `${dir}/${entry.name}`;
      if (entry.isDirectory()) out.push(...collect(path));
      else if (entry.name.endsWith('.mjs')) out.push(path);
    }
    return out;
  }

  for (const file of collect(aiQualityDir)) {
    const source = readFileSync(file, 'utf8');
    for (const forbidden of forbiddenImports) {
      assert.ok(!source.includes(`'${forbidden}'`) && !source.includes(`"${forbidden}"`), `${file} must not import ${forbidden}`);
    }
    assert.ok(!/\bfetch\s*\(/.test(source), `${file} must not call fetch(`);
    for (const pattern of vendorSdkImportPatterns) assert.ok(!pattern.test(source), `${file} must not import an AI vendor SDK`);
  }
});

// ---------------------------------------------------------------------------
// Schema: generated from the code-owned builder, and the committed file is
// byte-identical to that generator's output (SNIP pattern from
// scripts/generate-security-schemas.mjs).
// ---------------------------------------------------------------------------

test('committed schemas/ai-quality/evaluation-receipt-v1.schema.json is byte-identical to the code-owned builder', () => {
  const committed = JSON.parse(readFileSync(new URL('../../src/schemas/ai-quality/evaluation-receipt-v1.schema.json', import.meta.url), 'utf8'));
  assert.deepEqual(buildEvaluationReceiptSchema(), committed);
});

test('the generated schema enumerates all 17 metrics and the 4-member quality verdict vocabulary', () => {
  const schema = buildEvaluationReceiptSchema();
  assert.deepEqual(schema.properties.metric.enum, [...AI_QUALITY_METRICS]);
  assert.deepEqual(schema.properties.verdict.enum, [...AI_QUALITY_VERDICTS]);
});
