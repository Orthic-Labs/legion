// Entity Framework framework pack: LINQ/raw SQL/migration/tracking/tenant/
// transaction.

export default Object.freeze({
  id: 'framework.entity-framework',
  version: '1.0.0',
  detect({ projection }) {
    const deps = projection?.auditFacts?.packageManifests ?? [];
    return deps.some((m) => /entityframework|microsoft\.entityframework/.test(JSON.stringify(m)));
  },
  analyze({ files, readFile }) {
    const observations = [];
    for (const file of files) {
      if (!/\.cs$/.test(file)) continue;
      const text = readFile(file) ?? '';
      if (/FromSqlRaw\s*\([^)]*(?:\$|f"|\+)/.test(text) || /ExecuteSqlRaw\s*\([^)]*\+/.test(text)) {
        observations.push({ ruleId: 'ef.raw-sql-interpolation', severityHint: 'high', claim: 'Raw SQL with interpolated input.', file });
      }
      // Query without tenant filter.
      if (/\.(?:Where|FirstOrDefault|ToList|SingleOrDefault)\s*\(/.test(text) && !/tenant|workspace|org_?id/.test(text)) {
        observations.push({ ruleId: 'ef.missing-tenant-filter', severityHint: 'medium', claim: 'EF query has no visible tenant filter.', file });
      }
      if (/\.SaveChangesAsync?\s*\(/.test(text) && !/BeginTransaction|TransactionScope/.test(text)) {
        observations.push({ ruleId: 'ef.no-transaction', severityHint: 'low', claim: 'Save without a visible transaction.', file });
      }
    }
    return observations;
  },
});
