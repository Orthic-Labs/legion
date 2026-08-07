// Deterministic, read-only projection of canonical report JSON.

function escape(value) {
  return String(value ?? '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('\\', '\\\\').replaceAll('|', '\\|').replaceAll('\n', ' ');
}

export function renderMarkdownReport(report = {}) {
  const findings = [...(report.findings ?? [])].sort((a, b) => String(a.id ?? '').localeCompare(String(b.id ?? '')));
  const gaps = [...(report.coverage_gaps ?? [])].sort((a, b) => String(a.kind ?? '').localeCompare(String(b.kind ?? '')));
  const lines = [
    '# Nemesis audit report', '',
    `- Status: ${escape(report.audit_status ?? 'unknown')}`,
    `- Quality gate: ${escape(report.quality_gate ?? 'unknown')}`,
    `- Findings: ${findings.length}`, '',
    '## Findings', '',
    '| ID | Rule | Severity | Title | File |', '|---|---|---|---|---|',
  ];
  for (const finding of findings) lines.push(`| ${escape(finding.id)} | ${escape(finding.ruleId)} | ${escape(finding.severity)} | ${escape(finding.title ?? finding.detail)} | ${escape(finding.file)} |`);
  if (!findings.length) lines.push('| — | — | — | No findings | — |');
  lines.push('', '## Coverage gaps', '');
  if (gaps.length) for (const gap of gaps) lines.push(`- ${escape(gap.kind)}${gap.detail ? `: ${escape(JSON.stringify(gap.detail))}` : ''}`);
  else lines.push('- None.');
  return `${lines.join('\n')}\n`;
}
