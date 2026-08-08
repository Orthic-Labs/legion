export function analyzeNetworkEvidence({ requests = [] } = {}) {
  const candidates = [];
  for (const request of requests) {
    const base = { requestId: request.id, url: request.url, evidenceClass: request.traceRef ? 'runtime-trace' : 'runtime-observation' };
    if (request.serializedBehind) candidates.push({ ...base, ruleId: 'performance.network-independent-serialization', serializedBehind: request.serializedBehind });
    if (request.duplicateConcurrent) candidates.push({ ...base, ruleId: 'performance.network-duplicate-concurrent' });
    if (request.unboundedRetry || request.retryWithoutBackoff) candidates.push({ ...base, ruleId: 'performance.network-retry-policy' });
    if (request.compressed === false) candidates.push({ ...base, ruleId: 'performance.network-compression' });
    if (request.timeoutMissing) candidates.push({ ...base, ruleId: 'performance.network-timeout-missing' });
    if (request.payloadOversized) candidates.push({ ...base, ruleId: 'performance.network-payload-size', bytes: request.bytes ?? null });
    if (request.paginationMissing) candidates.push({ ...base, ruleId: 'performance.network-pagination-missing' });
  }
  return { provider: 'performance.network', status: candidates.length ? 'candidates' : requests.length ? 'pass' : 'unproven', candidates, coverageGaps: requests.length ? [] : ['request-evidence-missing'] };
}
