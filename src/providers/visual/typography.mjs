export function analyzeTypography({ textItems = [], fontEvidence = null } = {}) {
  const findings = [];
  for (const item of textItems) {
    const context = { role: item.role ?? 'unknown', surfaceId: item.surfaceId ?? null, viewport: item.viewport ?? null, locale: item.locale ?? null };
    if (item.clipped || item.overflow || item.truncatedUnexpectedly) findings.push({ ruleId: 'visual.typography-text-layout', itemId: item.id, context, copyItemId: item.copyItemId ?? null, evidence: item.evidence ?? null });
    if (item.fauxHierarchy || item.semanticRankMismatch) findings.push({ ruleId: 'visual.typography-role-mismatch', itemId: item.id, context, copyItemId: item.copyItemId ?? null });
    if (item.lineLengthExceeded || item.localeBreakage || item.wrappingFailure) findings.push({ ruleId: 'visual.typography-readability', itemId: item.id, context, copyItemId: item.copyItemId ?? null });
    if (item.fontFlash || item.missingFallback) findings.push({ ruleId: 'visual.typography-font-loading', itemId: item.id, context, copyItemId: item.copyItemId ?? null });
  }
  const coverageGaps = [];
  if (!fontEvidence) coverageGaps.push('font-evidence-missing');
  for (const item of textItems.filter((entry) => !entry.viewport || !entry.locale)) coverageGaps.push(`render-context-incomplete:${item.id}`);
  return { provider: 'visual.typography', status: findings.length ? 'candidates' : coverageGaps.length ? 'unproven' : 'pass', findings, coverageGaps };
}
