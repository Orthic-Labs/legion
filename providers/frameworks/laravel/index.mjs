// Laravel framework pack: routes/middleware/policies/Eloquent/Blade/queues/
// config.

export default Object.freeze({
  id: 'framework.laravel',
  version: '1.0.0',
  detect({ projection }) {
    return (projection?.auditFacts?.packageManifests ?? []).some((m) => /laravel/.test(JSON.stringify(m)));
  },
  analyze({ files, readFile }) {
    const observations = [];
    for (const file of files) {
      const text = readFile(file) ?? '';
      if (/DB::(?:select|statement|unprepared)\s*\([^)]*(\$|\.)/.test(text)) {
        observations.push({ ruleId: 'laravel.raw-sql-interpolation', severityHint: 'high', claim: 'Raw SQL with interpolated input.', file });
      }
      if (/\{!![^!]*\$[^!]*!!\}/.test(text)) {
        observations.push({ ruleId: 'laravel.unescaped-blade', severityHint: 'medium', claim: 'Unescaped Blade output.', file });
      }
      // Mass assignment: model::create with request input.
      if (/(?:Model::|\w+::create|\w+::update|->fill)\s*\([^)]*(?:request|input)/.test(text) && !/fillable|guarded/.test(text)) {
        observations.push({ ruleId: 'laravel.mass-assignment', severityHint: 'medium', claim: 'Mass assignment without visible fillable/guarded.', file });
      }
    }
    return observations;
  },
});
