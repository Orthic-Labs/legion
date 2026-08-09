import { captureWebEvidence } from '../capture/index.mjs';
import { finalize } from '../shared.mjs';

const percentile75 = (values) => values.length ? [...values].sort((a, b) => a - b)[Math.ceil(values.length * 0.75) - 1] : null;

export function verifyWebPerformance(input = {}) {
  if (!Array.isArray(input.captures) || input.captures.some((item) => !item || typeof item !== 'object' || Array.isArray(item))) return finalize('legion-web-performance-evidence', { provider: 'runtime.web.performance', status: 'error', terminal: true, claimLevel: 'runtime', evidenceClass: 'measured', binding: input.binding ?? {}, metrics: { lcp: null, longTasks: null, layoutShifts: null }, budgets: input.budgets ?? {}, captureDigest: null, artifacts: [], coverageGaps: ['performance-captures-invalid'] });
  const capture = captureWebEvidence(input);
  const samples = input.captures;
  const gaps = [...capture.coverageGaps];
  const numericArray = (value) => Array.isArray(value) && value.length > 0 && value.every((item) => typeof item === 'number' && Number.isFinite(item) && item >= 0);
  for (const sample of samples) { const id = sample.repeat ?? sample.sampleId ?? 'missing'; if (!sample.performance || typeof sample.performance !== 'object' || Array.isArray(sample.performance)) gaps.push(`performance-sample-invalid:${id}`); else { if (!Number.isFinite(sample.performance.lcp) || sample.performance.lcp < 0) gaps.push(`performance-lcp-invalid:${id}`); for (const metric of ['longTasks', 'layoutShifts', 'paints', 'userTimings']) if (!numericArray(sample.performance[metric])) gaps.push(`performance-${metric}-invalid:${id}`); if (!Number.isFinite(sample.performance.memory) || sample.performance.memory < 0) gaps.push(`performance-memory-invalid:${id}`); } }
  const metrics = { lcp: percentile75(samples.map((item) => item.performance?.lcp).filter((value) => Number.isFinite(value) && value >= 0)), longTasks: percentile75(samples.map((item) => numericArray(item.performance?.longTasks) ? item.performance.longTasks.length : null).filter(Number.isFinite)), layoutShifts: percentile75(samples.map((item) => numericArray(item.performance?.layoutShifts) ? item.performance.layoutShifts.reduce((sum, value) => sum + value, 0) : null).filter(Number.isFinite)) };
  if (!input.budgets || Object.keys(input.budgets).length === 0) gaps.push('performance-budget-missing');
  for (const [metric, limit] of Object.entries(input.budgets ?? {})) if (typeof limit !== 'number' || !Number.isFinite(limit) || limit < 0) gaps.push(`budget-invalid:${metric}`); else if (!Number.isFinite(metrics[metric])) gaps.push(`metric-missing:${metric}`); else if (metrics[metric] > limit) gaps.push(`budget-exceeded:${metric}`);
  return finalize('legion-web-performance-evidence', { provider: 'runtime.web.performance', status: gaps.some((gap) => gap.startsWith('budget-exceeded:')) ? 'fail' : gaps.length ? 'unproven' : 'pass', terminal: true, claimLevel: 'runtime', evidenceClass: 'measured', binding: input.binding ?? {}, metrics, budgets: input.budgets ?? {}, captureDigest: capture.digest, artifacts: capture.captures, coverageGaps: [...new Set(gaps)].sort() });
}
