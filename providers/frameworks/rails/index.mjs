// Rails framework pack: controllers/policies/ActiveRecord/templates/jobs/
// config.

export default Object.freeze({
  id: 'framework.rails',
  version: '1.0.0',
  detect({ projection }) {
    return (projection?.auditFacts?.packageManifests ?? []).some((m) => /rails/.test(JSON.stringify(m)))
      || (projection?.files ?? []).some((file) => /(Gemfile|\.gemspec)$/.test(file) && true);
  },
  analyze({ files, readFile }) {
    const observations = [];
    for (const file of files) {
      const text = readFile(file) ?? '';
      if (/skip_(?:before_action|before_filter)\s+:verify_authenticity_token|skip_forgery_protection/.test(text)) {
        observations.push({ ruleId: 'rails.forgery-bypass', severityHint: 'medium', claim: 'Request forgery protection bypassed.', file });
      }
      if (/\.html_safe\b|raw\s*\(/.test(text)) {
        observations.push({ ruleId: 'rails.raw-html', severityHint: 'medium', claim: 'Output marked HTML-safe.', file });
      }
      if (/\.constantize\b/.test(text) && /params|request/.test(text)) {
        observations.push({ ruleId: 'rails.constantize-input', severityHint: 'high', claim: 'Request-controlled value selects a constant.', file });
      }
      if (/\.where\s*\([^)]*params/.test(text) && !/strong_params|permit/.test(text)) {
        observations.push({ ruleId: 'rails.mass-assignment-query', severityHint: 'medium', claim: 'Query built from raw params without visible permitting.', file });
      }
    }
    return observations;
  },
});
