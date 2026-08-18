export function analyzeDataInteractions({ interactions = [] } = {}) {
  const findings = [];
  const coverageGaps = [];
  if (!interactions.length) coverageGaps.push('interaction-denominator-missing');
  for (const item of interactions) {
    if (item.largeDataClaim && !item.scaleEvidence) coverageGaps.push(`scale-evidence-missing:${item.id}`);
    if (item.kind === 'table' && item.headersAccessible === false) findings.push({ ruleId: 'ux.data-table-headers', interactionId: item.id, dataset: item.dataset, action: 'read', judgmentClass: 'deterministic' });
    if (item.kind === 'chart' && item.misleadingEncoding) findings.push({ ruleId: 'ux.chart-encoding-candidate', interactionId: item.id, dataset: item.dataset, action: 'interpret', judgmentClass: 'interpretive' });
    if (item.destructiveBulkAmbiguity) findings.push({ ruleId: 'ux.bulk-action-ambiguous', interactionId: item.id, dataset: item.dataset, action: 'bulk', judgmentClass: 'deterministic' });
    for (const [flag, ruleId] of Object.entries({ unstableSort: 'ux.data-sort-unstable', hiddenFilterState: 'ux.data-filter-hidden', unboundedList: 'ux.data-list-unbounded', lostSelection: 'ux.data-selection-lost', exportMismatch: 'ux.data-export-mismatch', missingSystemStates: 'ux.data-system-states-missing' })) if (item[flag]) findings.push({ ruleId, interactionId: item.id, dataset: item.dataset, action: item.kind, judgmentClass: 'deterministic' });
  }
  return { provider: 'ux.data-interaction', status: findings.length ? 'candidates' : coverageGaps.length ? 'unproven' : 'pass', findings, coverageGaps };
}
