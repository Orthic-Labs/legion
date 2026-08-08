// Editor diagnostics per SNIP-HTML-01's editor surface. Emits stable
// diagnostics/code-action preview JSON; LSP transport is a thin process around
// this artifact.

export function editorDiagnostics({ report, runDir }) {
  const findings = (report?.findings ?? []).map((finding) => {
    const fingerprintBound = !finding.remediation?.findingFingerprint || finding.remediation.findingFingerprint === finding.fingerprint;
    const remediationBound = finding.remediation?.qualified === true && /^sha256:[0-9a-f]{64}$/i.test(finding.remediation?.patch?.digest ?? '') && (finding.remediation.findingIds ?? [finding.id]).includes(finding.id) && fingerprintBound;
    const range = finding.range ?? { start: { line: Number(finding.line ?? 1), column: Number(finding.column ?? 0) }, end: { line: Number(finding.endLine ?? finding.line ?? 1), column: Number(finding.endColumn ?? finding.column ?? 0) } };
    // Convenience projection retained for editor integrations that only read a
    // single-position diagnostic; the canonical location is `range`.
    const line = range.start?.line ?? Number(finding.line ?? 1);
    const column = range.start?.column ?? Number(finding.column ?? 0);
    return {
      schemaVersion: 1,
      kind: 'nemesis-editor-diagnostic',
      file: finding.file ? String(finding.file).replaceAll('\\', '/') : null,
      range,
      line,
      column,
      severity: severityFor(finding.severity),
      code: finding.ruleId ?? 'nemesis.finding',
      message: finding.title ? `${finding.title}${finding.detail ? ` — ${finding.detail}` : ''}` : (finding.detail ?? 'Nemesis finding'),
      fingerprint: finding.fingerprint ?? finding.id ?? finding.ruleId,
      findingId: finding.id ?? null,
      family: finding.family ?? null,
      evidenceClass: finding.evidenceClass ?? null,
      explanation: { kind: 'nemesis-finding-explanation', findingId: finding.id ?? null, evidenceRefs: finding.evidenceRefs ?? [] },
      contentId: finding.contentId ?? null,
      lineage: finding.lineage ?? { state: finding.staleContentId ? 'stale' : 'current', priorContentId: finding.staleContentId ?? null, contentId: finding.contentId ?? null },
      run: runDir ?? null,
      codeActions: finding.id || finding.ruleId
        ? [...(remediationBound ? [{ title: 'Preview Nemesis remediation', kind: 'preview', previewOnly: true, proposalId: finding.remediation.id, findingId: finding.id, fingerprint: finding.fingerprint ?? null, patch: finding.remediation.patch }] : []), { title: 'Explain with Nemesis', kind: 'explain', id: finding.id ?? finding.ruleId }]
        : [],
    };
  });
  const gaps = (report?.coverage_gaps ?? []).filter((gap) => gap.reviewRequired).map((gap) => ({
    schemaVersion: 1, kind: 'nemesis-editor-diagnostic', file: null,
    range: null, severity: 2, code: 'nemesis.coverage-gap', message: gap.detail ?? gap.kind ?? 'Incomplete coverage',
    fingerprint: gap.id ?? `gap:${gap.kind}`, findingId: null, family: gap.family ?? null,
    evidenceClass: 'missing', explanation: { kind: 'nemesis-gap-explanation', gapId: gap.id ?? null },
    lineage: { state: 'current' }, run: runDir ?? null, codeActions: [], coverageIncomplete: true,
  }));
  return [...findings, ...gaps];
}

function severityFor(severity) {
  if (severity === 'critical' || severity === 'high') return 1; // error
  if (severity === 'medium') return 2; // warning
  return 3; // info
}
