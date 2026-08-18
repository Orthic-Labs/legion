// AI-quality evaluation aggregator. Dispatches a metric + recorded fixture
// to its scorer and wraps the result into a bound evaluation receipt. This
// module (and everything it imports) never calls a model, never imports
// providers/security/**, and never reads a security candidate/verdict.

import { AI_QUALITY_METRICS, assertMetric } from './contracts.mjs';
import { buildEvaluationReceipt } from './receipt.mjs';
import {
  scoreDeclaredTaskEval,
  scoreGroundedness,
  scoreCitationFaithfulness,
  scoreRetrievalRelevance,
} from './evaluators/grounded-retrieval.mjs';
import {
  scoreStructuredOutputValidity,
  scoreToolSelectionArgumentCorrectness,
} from './evaluators/output-tooling.mjs';
import {
  scoreUncertaintyCalibration,
  scoreRefusalFallback,
  scoreContextTruncation,
  scorePromptRobustness,
} from './evaluators/calibration-fallback.mjs';
import { scoreModelProviderVersionDrift, scoreReproducibility } from './evaluators/drift-repro.mjs';
import { scoreLatency, scoreCost, scoreHumanOverride, scoreFeedbackLoop } from './evaluators/ops.mjs';
import { scoreSubgroupFairness } from './evaluators/fairness.mjs';

export { AI_QUALITY_METRICS };

const SCORERS = Object.freeze({
  'declared-task-eval': scoreDeclaredTaskEval,
  groundedness: scoreGroundedness,
  'citation-faithfulness': scoreCitationFaithfulness,
  'retrieval-relevance': scoreRetrievalRelevance,
  'structured-output-validity': scoreStructuredOutputValidity,
  'tool-selection-argument-correctness': scoreToolSelectionArgumentCorrectness,
  'uncertainty-abstention-calibration': scoreUncertaintyCalibration,
  'refusal-fallback': scoreRefusalFallback,
  'context-truncation': scoreContextTruncation,
  'prompt-robustness': scorePromptRobustness,
  'model-provider-version-drift': scoreModelProviderVersionDrift,
  reproducibility: scoreReproducibility,
  latency: scoreLatency,
  cost: scoreCost,
  'human-override': scoreHumanOverride,
  'feedback-loop': scoreFeedbackLoop,
  'subgroup-fairness': scoreSubgroupFairness,
});

// Every declared metric must have exactly one owning scorer; this is
// asserted at module load so an incomplete dispatch table fails immediately.
for (const metric of AI_QUALITY_METRICS) {
  if (typeof SCORERS[metric] !== 'function') throw new Error(`ai-quality metric ${metric} has no scorer`);
}

export function evaluateAiQuality({ metric, fixture, identity, denominator, binding, evidenceRefs, metricVersion }) {
  assertMetric(metric);
  const scorerResult = SCORERS[metric](fixture);
  return buildEvaluationReceipt({ metric, metricVersion, scorerResult, identity, denominator, binding, evidenceRefs });
}
