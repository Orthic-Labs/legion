// Flask framework pack: routes/extensions/session/templates/config.

export default Object.freeze({
  id: 'framework.flask',
  version: '1.0.0',
  detect({ projection }) {
    return (projection?.auditFacts?.packageManifests ?? []).some((m) => JSON.stringify(m).includes('flask'));
  },
  analyze({ files, readFile }) {
    const observations = [];
    for (const file of files) {
      const text = readFile(file) ?? '';
      if (/app\.run\s*\([^)]*debug\s*=\s*True/.test(text)) {
        observations.push({ ruleId: 'flask.debug-enabled', severityHint: 'high', claim: 'Flask debug mode is enabled.', file });
      }
      if (/(?:secret_key|SECRET_KEY)['"]?\s*\]?\s*=\s*(?:os\.environ\.get\([^)]*\)\s+or\s+)?['"][^'"]+['"]/.test(text)) {
        observations.push({ ruleId: 'flask.secret-fallback', severityHint: 'high', claim: 'Secret key has a tracked fallback value.', file });
      }
      if (/render_template_string\s*\([^\n]*(?:request|input|user)/.test(text)) {
        observations.push({ ruleId: 'flask.template-string-input', severityHint: 'high', claim: 'Request-controlled data reaches a Jinja template source.', file });
      }
    }
    return observations;
  },
});
