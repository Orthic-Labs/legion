// Evaluation-receipt builder. Wraps a metric scorer's raw result with the
// identity/binding fields every AI-quality result must carry: model/provider
// identity, prompt/template identity, retrieval/tool configuration, dataset
// and eval version, run conditions, judge/human identity, denominator, and
// limitations. Deterministic: no Date.now(), no Math.random(), no wall clock
// — run identity comes from the caller-supplied runConditions.

import {
  assertMetric,
  assertQualityVerdict,
  assertBinding,
  requireObject,
  requireArray,
  stableId,
} from './contracts.mjs';

export function buildEvaluationReceipt({
  metric,
  metricVersion = '1.0.0',
  scorerResult,
  identity,
  denominator,
  binding,
  evidenceRefs = [],
}) {
  assertMetric(metric);
  requireObject(scorerResult, 'scorerResult');
  assertQualityVerdict(scorerResult.verdict);
  requireObject(identity, 'identity');
  requireObject(identity.modelIdentity, 'identity.modelIdentity');
  requireObject(identity.promptIdentity, 'identity.promptIdentity');
  requireObject(identity.datasetVersion, 'identity.datasetVersion');
  requireObject(identity.runConditions, 'identity.runConditions');
  requireObject(identity.judgeIdentity, 'identity.judgeIdentity');
  requireObject(denominator, 'denominator');
  assertBinding(binding);
  requireArray(scorerResult.limitations ?? [], 'scorerResult.limitations');
  requireArray(scorerResult.uncertainty ?? [], 'scorerResult.uncertainty');

  const body = {
    schemaVersion: 1,
    kind: 'ai-quality-evaluation-receipt',
    metric,
    metricVersion,
    verdict: scorerResult.verdict,
    modelIdentity: identity.modelIdentity,
    promptIdentity: identity.promptIdentity,
    retrievalToolConfig: identity.retrievalToolConfig ?? null,
    datasetVersion: identity.datasetVersion,
    runConditions: identity.runConditions,
    judgeIdentity: identity.judgeIdentity,
    denominator,
    measurement: scorerResult.measurement ?? {},
    limitations: [...(scorerResult.limitations ?? [])].sort(),
    uncertainty: [...(scorerResult.uncertainty ?? [])].sort(),
    evidenceRefs: [...new Set(evidenceRefs)].sort(),
    binding,
  };
  return { ...body, id: stableId('ai-quality-evaluation-receipt', body) };
}
