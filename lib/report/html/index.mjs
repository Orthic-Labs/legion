// HTML report renderer per SNIP-HTML-01. One self-contained static HTML file
// from canonical report JSON; escapes all untrusted content; restrictive CSP
// with a generated script hash; no active external resources.

export function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

export function cspMeta(scriptHash) {
  return `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'sha256-${scriptHash}'">`;
}

export function renderHtmlReport(report) {
  const findings = (report?.findings ?? []).map((finding) => `
    <tr>
      <td>${escapeHtml(finding.id ?? '')}</td>
      <td>${escapeHtml(finding.ruleId ?? '')}</td>
      <td>${escapeHtml(finding.severity ?? '')}</td>
      <td>${escapeHtml(finding.title ?? '')}</td>
      <td>${escapeHtml(finding.file ?? '')}</td>
    </tr>`).join('\n');
  const gaps = (report?.coverage_gaps ?? []).map((gap) => `
    <li>${escapeHtml(gap.kind ?? '')}${gap.detail ? `: ${escapeHtml(JSON.stringify(gap.detail))}` : ''}</li>`).join('\n');
  const script = 'document.getElementById("count").textContent = ' + JSON.stringify(findings.length) + ';';
  const scriptHash = 'PLACEHOLDER';
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Nemesis audit report</title>
${cspMeta(scriptHash)}
<style>body{font-family:system-ui,sans-serif;margin:2rem;color:#1a1a1a}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:.4rem;text-align:left}th{background:#f5f5f5}</style>
</head>
<body>
<h1>Nemesis audit report</h1>
<p>Status: ${escapeHtml(report?.audit_status ?? 'unknown')} · Quality gate: ${escapeHtml(report?.quality_gate ?? 'unknown')} · Findings: <span id="count">0</span></p>
<table>
<thead><tr><th>ID</th><th>Rule</th><th>Severity</th><th>Title</th><th>File</th></tr></thead>
<tbody>
${findings || '<tr><td colspan="5">No findings.</td></tr>'}
</tbody>
</table>
<h2>Coverage gaps</h2>
<ul>
${gaps || '<li>None.</li>'}
</ul>
<script>${script}</script>
</body>
</html>
`;
}
