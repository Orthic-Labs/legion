// Deterministic, read-only projection of canonical report JSON.

function escapeMarkdown(value) {
  return String(value ?? '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('\\', '\\\\').replaceAll('|', '\\|').replaceAll('\n', ' ');
}

export function renderMarkdownReport(report = {}) {
  const findings = [...(report.findings ?? [])].sort((a, b) => String(a.id ?? '').localeCompare(String(b.id ?? '')));
  const gaps = [...(report.coverage_gaps ?? [])].sort((a, b) => String(a.kind ?? '').localeCompare(String(b.kind ?? '')));
  const lines = [
    '# Legion audit report', '',
    `- Status: ${escapeMarkdown(report.audit_status ?? 'unknown')}`,
    `- Quality gate: ${escapeMarkdown(report.quality_gate ?? 'unknown')}`,
    `- Findings: ${findings.length}`, '',
    '## Findings', '',
    '| ID | Rule | Severity | Title | File |', '|---|---|---|---|---|',
  ];
  for (const finding of findings) lines.push(`| ${escapeMarkdown(finding.id)} | ${escapeMarkdown(finding.ruleId)} | ${escapeMarkdown(finding.severity)} | ${escapeMarkdown(finding.title ?? finding.detail)} | ${escapeMarkdown(finding.file)} |`);
  if (!findings.length) lines.push('| — | — | — | No findings | — |');
  lines.push('', '## Coverage gaps', '');
  if (gaps.length) for (const gap of gaps) lines.push(`- ${escapeMarkdown(gap.kind)}${gap.detail ? `: ${escapeMarkdown(JSON.stringify(gap.detail))}` : ''}`);
  else lines.push('- None.');
  return `${lines.join('\n')}\n`;
}
