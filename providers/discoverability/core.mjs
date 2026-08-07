export function assessDiscoverability({ pages = [], policy = {} } = {}) {
  const findings = []; for (const page of pages) { if (page.indexable && !page.title) findings.push({ ruleId: 'discoverability.title-missing', page: page.id }); if (page.indexable && !page.description) findings.push({ ruleId: 'discoverability.description-missing', page: page.id }); if (page.indexable && policy.requireCanonical && !page.canonical) findings.push({ ruleId: 'discoverability.canonical-missing', page: page.id }); }
  return { schemaVersion: 1, provider: 'discoverability.core', status: findings.length ? 'candidates' : 'pass', findings, coverageGaps: pages.filter((page) => page.indexable === undefined).map((page) => `indexability-unknown:${page.id}`) };
}
