const AUTHORING = /\b(?:write|rewrite|publish|send|create|delete)\b/i;

export function compileWritingAuditProfile({ entries = [], sourceUri = 'nemesis-skill://writing/' } = {}) {
  const rules = []; const exclusions = [];
  for (const entry of entries) {
    if (!entry?.id || !entry?.text) { exclusions.push({ id: entry?.id ?? null, reason: 'skill-entry-incomplete' }); continue; }
    if (AUTHORING.test(entry.text) || entry.audit === false) { exclusions.push({ id: entry.id, reason: 'authoring-instruction-excluded' }); continue; }
    rules.push({ id: `writing.${entry.id}`, family: entry.family ?? 'copy', kind: entry.kind ?? 'interpretive', evidenceRequirement: entry.evidenceRequirement ?? 'content-inventory', remediationOwner: entry.remediationOwner ?? 'writing', sourceUri: entry.sourceUri ?? sourceUri });
  }
  return { schemaVersion: 1, kind: 'nemesis-writing-audit-profile', sourceUri, rules, exclusions, status: entries.length ? 'pass' : 'unproven', coverageGaps: entries.length ? [] : ['writing-skill-bundle-missing'] };
}
