// Django framework pack: views/DRF/auth/ORM/CSRF/templates/settings/
// migrations. Deterministic structural rules.

export default Object.freeze({
  id: 'framework.django',
  version: '1.0.0',
  detect({ projection }) {
    return (projection?.auditFacts?.packageManifests ?? []).some((m) => JSON.stringify(m).includes('django'));
  },
  analyze({ files, readFile }) {
    const observations = [];
    for (const file of files) {
      const text = readFile(file) ?? '';
      if (/^\s*DEBUG\s*=\s*True\b/m.test(text)) {
        observations.push({ ruleId: 'django.settings.debug', severityHint: 'high', claim: 'Django DEBUG is enabled.', file });
      }
      if (/^\s*ALLOWED_HOSTS\s*=\s*\[[^\]]*['"]\*['"]/m.test(text)) {
        observations.push({ ruleId: 'django.settings.hosts-all', severityHint: 'medium', claim: 'ALLOWED_HOSTS accepts every host.', file });
      }
      if (/@csrf_exempt\b/.test(text)) {
        observations.push({ ruleId: 'django.csrf-exempt', severityHint: 'medium', claim: 'CSRF protection bypassed for this view.', file });
      }
      if (/\bmark_safe\s*\(/.test(text)) {
        observations.push({ ruleId: 'django.output-mark-safe', severityHint: 'medium', claim: 'Output explicitly marked safe.', file });
      }
      // ORM: raw SQL with interpolation.
      if (/\.raw\s*\(\s*f["']/.test(text) || /\.extra\s*\(\s*where\s*=/.test(text)) {
        observations.push({ ruleId: 'django.orm.raw-sql', severityHint: 'high', claim: 'Raw SQL with interpolated input.', file });
      }
    }
    return observations;
  },
});
