// Editor diagnostics per SNIP-HTML-01's editor surface. Emits stable
// diagnostics/code-action preview JSON; LSP transport is a thin process around
// this artifact.

export function editorDiagnostics({ report, runDir }) {
  return (report?.findings ?? []).map((finding) => ({
    schemaVersion: 1,
    kind: 'nemesis-editor-diagnostic',
    file: finding.file ? String(finding.file).replaceAll('\\', '/') : null,
    line: Number(finding.line ?? 1),
    column: Number(finding.column ?? 0),
    severity: severityFor(finding.severity),
    code: finding.ruleId ?? 'nemesis.finding',
    message: finding.title ? `${finding.title}${finding.detail ? ` — ${finding.detail}` : ''}` : (finding.detail ?? 'Nemesis finding'),
    fingerprint: finding.fingerprint ?? finding.id ?? finding.ruleId,
    run: runDir ?? null,
    codeActions: finding.ruleId
      ? [{ title: 'Explain with Nemesis', kind: 'explain', id: finding.id ?? finding.ruleId }]
      : [],
  }));
}

function severityFor(severity) {
  if (severity === 'critical' || severity === 'high') return 1; // error
  if (severity === 'medium') return 2; // warning
  return 3; // info
}
