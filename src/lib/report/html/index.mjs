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

import { createHash } from 'node:crypto';

const anchor = (value) => String(value ?? '').replace(/[^a-zA-Z0-9_.:-]/g, '-');
const links = (ids = []) => ids.map((id) => `<a href="#evidence-${anchor(id)}">${escapeHtml(id)}</a>`).join(', ');
const MAX_ITEMS = 2_000;
const evidenceIds = (item) => [...new Set([...(item?.evidenceIds ?? []), ...(item?.evidence ?? []).map((entry) => entry.id ?? entry)].filter(Boolean))];
const section = (title, value) => {
  const items = (Array.isArray(value) ? value : value ? [value] : []).slice(0, MAX_ITEMS);
  const rows = items.map((item, index) => {
    const label = item?.title ?? item?.name ?? item?.id ?? `${title} ${index + 1}`;
    const search = escapeHtml(JSON.stringify(item).toLowerCase());
    return `<details data-search="${search}"><summary>${escapeHtml(label)}</summary><pre>${escapeHtml(JSON.stringify(item, null, 2))}</pre><p>Evidence: ${links(evidenceIds(item)) || 'none'}</p></details>`;
  }).join('');
  const truncated = (Array.isArray(value) ? value.length : items.length) > MAX_ITEMS ? `<p>Showing first ${MAX_ITEMS} records.</p>` : '';
  return `<section data-kind="${anchor(title.toLowerCase().replaceAll(' ', '-'))}"><h2>${escapeHtml(title)}</h2>${rows || '<p>Unavailable.</p>'}${truncated}</section>`;
};

export function renderHtmlReport(report) {
  const findingRows = (report?.findings ?? []).map((finding) => `
    <tr data-search="${escapeHtml([finding.id, finding.ruleId, finding.title, finding.file].join(' ').toLowerCase())}">
      <td>${escapeHtml(finding.id ?? '')}</td>
      <td>${escapeHtml(finding.ruleId ?? '')}</td>
      <td>${escapeHtml(finding.severity ?? '')}</td>
      <td>${escapeHtml(finding.title ?? '')}</td>
      <td>${escapeHtml(finding.file ?? '')}</td><td>${links((finding.evidence ?? []).map(({ id }) => id))}</td>
    </tr>`).join('\n');
  const evidenceItems = [...new Map((report?.findings ?? []).flatMap((finding) => finding.evidence ?? []).map((item) => [item.id, item])).values()].slice(0, MAX_ITEMS);
  const evidence = evidenceItems.map((item) => `<details id="evidence-${anchor(item.id)}" data-search="${escapeHtml(JSON.stringify(item).toLowerCase())}"><summary>${escapeHtml(item.id)}</summary><pre>${escapeHtml(JSON.stringify(item, null, 2))}</pre></details>`).join('\n');
  const coverage = (report?.familyCoverage ?? []).map((family) => `<li>${escapeHtml(family.id)}: ${escapeHtml(family.status)} ${links(family.evidenceIds)}</li>`).join('\n');
  const gaps = (report?.coverage_gaps ?? []).map((gap) => `
    <li>${escapeHtml(gap.kind ?? '')}${gap.detail ? `: ${escapeHtml(JSON.stringify(gap.detail))}` : ''}</li>`).join('\n');
  const script = `const rows=[...document.querySelectorAll('[data-search]')];const q=document.getElementById('search');document.getElementById('count').textContent=String(document.querySelectorAll('tbody [data-search]').length);q.addEventListener('input',()=>{const value=q.value.toLowerCase();for(const row of rows)row.hidden=!row.dataset.search.includes(value);});`;
  const scriptHash = createHash('sha256').update(script).digest('base64');
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Legion audit report</title>
${cspMeta(scriptHash)}
<style>body{font-family:system-ui,sans-serif;margin:2rem;color:#1a1a1a}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:.4rem;text-align:left}th{background:#f5f5f5}</style>
</head>
<body>
<h1>Legion audit report</h1>
<p>Status: ${escapeHtml(report?.audit_status ?? 'unknown')} · Quality gate: ${escapeHtml(report?.quality_gate ?? 'unknown')} · Findings: <span id="count">0</span></p>
<label>Search <input id="search" type="search" autocomplete="off"></label>
<table>
<thead><tr><th>ID</th><th>Rule</th><th>Severity</th><th>Title</th><th>File</th><th>Evidence</th></tr></thead>
<tbody>
${findingRows || '<tr><td colspan="6">No findings.</td></tr>'}
</tbody>
</table>
<h2>Family coverage</h2><ul>${coverage || '<li>Unavailable.</li>'}</ul>
<h2>Evidence</h2>${evidence || '<p>No evidence records.</p>'}
${section('Flow diagrams', report?.flows)}
${section('Path diagrams', report?.paths)}
${section('Screenshot views', report?.screenshots)}
${section('Copy and narrative maps', report?.copyNarrativeMaps)}
${section('Baselines', report?.baselines)}
${section('Remediation previews', report?.remediationPreviews)}
${section('Verification state', report?.verification)}
<h2>Coverage gaps</h2>
<ul>
${gaps || '<li>None.</li>'}
</ul>
<script>${script}</script>
</body>
</html>
`;
}
