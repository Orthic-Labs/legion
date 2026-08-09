const DIRECTIVE = /\b(?:edit|write|publish|deploy|create|delete)\b/i;

export function compileDesignerAuditProfile({ entries = [], sourceUri = 'legion-skill://designer/' } = {}) {
  const rules = []; const exclusions = [];
  for (const entry of entries) {
    if (!entry?.id || !entry?.text) { exclusions.push({ id: entry?.id ?? null, reason: 'skill-entry-incomplete' }); continue; }
    if (DIRECTIVE.test(entry.text) || entry.audit === false) { exclusions.push({ id: entry.id, reason: 'authoring-instruction-excluded' }); continue; }
    rules.push({ id: `designer.${entry.id}`, family: entry.family ?? 'visual', kind: entry.kind ?? 'interpretive',
      evidenceRequirement: entry.evidenceRequirement ?? 'rendered-surface', remediationOwner: entry.remediationOwner ?? 'design', sourceUri: entry.sourceUri ?? sourceUri });
  }
  return { schemaVersion: 1, kind: 'legion-designer-audit-profile', sourceUri, rules, exclusions,
    status: entries.length ? 'pass' : 'unproven', coverageGaps: entries.length ? [] : ['designer-skill-bundle-missing'] };
}
