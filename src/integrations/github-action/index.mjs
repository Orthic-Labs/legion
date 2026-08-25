// GitHub Action adapter translates native Legion output into provider upload
// requests and a summary. It neither installs nor launches a Node Legion copy.

export function actionSummary({ report, scoped, runDir }) {
  return {
    schemaVersion: 1,
    kind: 'legion-github-action-summary',
    runDir,
    auditStatus: report?.audit_status ?? null,
    qualityGate: report?.quality_gate ?? null,
    introducedCount: scoped?.introduced?.length ?? 0,
    existingCount: scoped?.existing?.length ?? 0,
    coverageGaps: report?.coverage_gaps?.length ?? 0,
    commentIds: (scoped?.introduced ?? []).map((finding) => finding.fingerprint ?? finding.id),
  };
}

export function sarifUploadCommand({ sarifPath, githubToken }) {
  return {
    executable: 'gh',
    args: ['api', 'repos/{owner}/{repo}/code-scanning/sarifs', '-f', `sarif=@${sarifPath}`],
    env: githubToken ? { GH_TOKEN: githubToken } : {},
  };
}
