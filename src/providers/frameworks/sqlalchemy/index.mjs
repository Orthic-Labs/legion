// SQLAlchemy framework pack: session/transaction/query/tenant/migration.

export default Object.freeze({
  id: 'framework.sqlalchemy',
  version: '1.0.0',
  detect({ projection }) {
    return (projection?.auditFacts?.packageManifests ?? []).some((m) => JSON.stringify(m).includes('sqlalchemy'));
  },
  analyze({ files, readFile }) {
    const observations = [];
    for (const file of files) {
      const text = readFile(file) ?? '';
      if (/text\s*\(\s*f["']/.test(text) || /execute\s*\(\s*f["']/.test(text)) {
        observations.push({ ruleId: 'sqlalchemy.raw-sql-interpolation', severityHint: 'high', claim: 'Raw SQL text with interpolated input.', file });
      }
      // Query without visible tenant filter on a tenant-scoped model.
      if (/\.query\s*\([^)]*\)\s*\.(?:filter|all|first)\s*\(/.test(text) && !/tenant|workspace|org_?id/.test(text)) {
        observations.push({ ruleId: 'sqlalchemy.missing-tenant-filter', severityHint: 'medium', claim: 'Query has no visible tenant filter.', file });
      }
      if (/\bsession\.commit\s*\(/.test(text) && !/begin|transaction/.test(text.slice(0, Math.max(0, text.indexOf('session.commit'))))) {
        observations.push({ ruleId: 'sqlalchemy.transaction-boundary', severityHint: 'low', claim: 'Commit without a visible transaction boundary.', file });
      }
    }
    return observations;
  },
});
