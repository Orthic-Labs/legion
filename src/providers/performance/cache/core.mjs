export function analyzeCacheEvidence({ entries = [] } = {}) {
  const candidates = [];
  const recommendations = [];
  for (const entry of entries) {
    if ((entry.sensitive || entry.mutable) && entry.ttl > 0 && !entry.invalidationEvidence) candidates.push({ ruleId: 'performance.cache-correctness-risk', entryId: entry.id, kind: 'correctness-risk', sensitive: Boolean(entry.sensitive), mutable: Boolean(entry.mutable), invalidationEvidence: null });
    if (entry.opportunity && entry.invalidationEvidence && entry.correctnessAnalysis) recommendations.push({ ruleId: 'performance.cache-opportunity', entryId: entry.id, invalidationEvidence: entry.invalidationEvidence, correctnessAnalysis: entry.correctnessAnalysis });
  }
  return { provider: 'performance.cache', status: candidates.length ? 'candidates' : entries.length ? 'pass' : 'unproven', candidates, recommendations, coverageGaps: entries.length ? [] : ['cache-evidence-missing'] };
}
